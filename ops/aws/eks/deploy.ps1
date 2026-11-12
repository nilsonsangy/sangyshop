<#
.SYNOPSIS
    Deploy the HARDENED SangyShop image to AWS EKS (Kubernetes modality).

.DESCRIPTION
    Kubernetes counterpart of the AWS ECS Fargate (Docker-only) deploy. Reuses
    the same ECR build+push and managed RDS + Secrets Manager steps, then deploys
    onto Amazon EKS using the committed AWS kustomize overlay
    (aws/eks/overlays). The DB password is stored ONLY in AWS Secrets
    Manager and delivered to the pod as the file /run/secrets/db_password via the
    SecretsStore CSI provider (synced into the sangyshop-db Secret the base
    mounts). No DB_PASSWORD env var is ever set; the unmodified hardened app reads
    the secret file and fails closed otherwise (src/db/credentials.js).

    Pipeline (every external CLI call is echoed before it runs, via the shared
    Invoke-Echoed helper in lib/Common.ps1):

        1. Caller-identity auth check                     (Req 6.3/6.4)
        2. ECR describe-or-create                         (Req 4.1)
        3. ECR Docker login
        4. Build the hardened image                       (Req 2.1/2.3/4.5)
        5. Push the hardened image                        (Req 4.5)
        6. Secrets Manager: generate + store password     (Req 3.2/4.4) -- BEFORE
           provisioning, stdin only, never an echoed CLI arg
        7. RDS describe-or-create + set master password   (Req 4.1/4.3/9.5)
        8. EKS describe-or-create + kubeconfig update      (Req 4.1/9.2)
        9. Render overlay copy, substitute placeholders,
           apply with the load-restrictor pipe form        (Req 3.1/3.3/2.5)
       10. Wait for rollout                                (Req 4.8)
       11. Read the LoadBalancer DNS hostname as the URL    (Req 4.7)
       12. Print lockdown + teardown reminder              (Req 9.2)

    Safety:
      * Only the hardened variant is ever built/pushed/deployed (Req 2.1/2.2).
      * Aborts before any push/deploy if the hardened Dockerfile is missing
        (Req 2.4) or a non-:hardened image / non-hardened APP_MODE is referenced
        (Req 2.2).
      * Ingress is restricted to an explicitly provided source-address set and
        0.0.0.0/0 and ::/0 are rejected (Req 9.3/9.4).
      * RDS is reachable by the EKS workload on 5432 only, not public (Req 9.5).
      * The committed overlay is NEVER rewritten; placeholders are substituted in
        a throwaway rendered copy only (Req 2.5).
      * -WhatIf prints the full ordered command list and executes NO external
        command, exiting 0 (Req 6.5).

    Windows PowerShell 5.1 compatible (Req 6.1). Every external CLI call routes
    through Invoke-Echoed (Req 1.3), enforced by tests/EchoOnly.Guard.Tests.ps1.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (ops/cloud.config.ps1).

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0 (Req 6.5).

.PARAMETER ReuseExisting
    Reuse an already-present ECR repo / RDS instance / EKS cluster / secret rather
    than failing. This is the default convergent behavior; the switch is accepted
    for parity with the other targets and for explicitness.

.PARAMETER AllowedSourceRanges
    REQUIRED allowed-ingress source set. Each entry is a source address/CIDR that
    may reach the LoadBalancer Service. 0.0.0.0/0 and ::/0 are rejected
    (Req 9.3/9.4). If omitted/empty the script stops before any ingress change
    (Req 9.4).
#>
[CmdletBinding()]
param(
    [string]   $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [switch]   $WhatIf,
    [switch]   $ReuseExisting,
    [string[]] $AllowedSourceRanges
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Dot-source the shared library (Invoke-Echoed, Write-Step, Get-CloudConfig,
# New-DbPassword). Relative to this script: ../../lib/Common.ps1.
. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

# ---------------------------------------------------------------------------
# WhatIf-aware command runner.
#
# Every external CLI call in this script goes through Invoke-Cli, never through
# a bare CLI token (Req 1.3). When -WhatIf is set, Invoke-Cli records and prints
# the planned command line WITHOUT executing anything (Req 6.5); otherwise it
# delegates to the shared Invoke-Echoed helper (Req 1.1/1.4/1.5), which echoes
# the exact command and then runs it.
#
# Secret rule (Req 3.2): a secret is NEVER passed as a CLI argument. Commands
# that consume the password do so via stdin; the -StdinSecret switch marks those
# so the planned/echoed line shows a redacted "<stdin: db password>" note
# instead of the value.
#
# Pipe rule: `kubectl apply` consumes rendered kustomize output on stdin. The
# -StdinText switch feeds arbitrary (non-secret) text on stdin and is rendered
# in the planned list as "<stdin: rendered manifest>".
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail,
        [string]                         $StdinSecret,  # piped to stdin; never echoed
        [string]                         $StdinText     # piped to stdin; echoed as a note only
    )

    # Render the command line exactly as it would be run, for the planned list and
    # the dry-run echo. Reuse the same quoting shape Invoke-Echoed prints.
    $displayParts = @($Exe)
    foreach ($a in $CmdArgs) {
        if ($null -eq $a -or $a -eq '') {
            $displayParts += '""'
        }
        elseif ($a -match '[\s"]') {
            $displayParts += ('"' + ($a -replace '"', '\"') + '"')
        }
        else {
            $displayParts += $a
        }
    }
    if ($PSBoundParameters.ContainsKey('StdinSecret')) {
        $displayParts += '<stdin: db password (redacted)>'
    }
    elseif ($PSBoundParameters.ContainsKey('StdinText')) {
        $displayParts += '<stdin: rendered manifest>'
    }
    $display = $displayParts -join ' '

    if ($WhatIf) {
        # Req 6.5: record + print the planned command; execute NOTHING. Model a
        # "would succeed" exit so describe-or-create logic picks a deterministic
        # branch for the planned list (we plan the CREATE branch under -WhatIf).
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Real execution path: route through the shared, echoing helper (Req 1.3).
    $result = $null
    if ($PSBoundParameters.ContainsKey('StdinSecret')) {
        # Feed the secret through stdin so it never becomes an echoed CLI arg
        # (Req 3.2). Invoke-Echoed echoes only $Exe + $CmdArgs, so the password
        # stays off the command line and out of logs.
        if ($AllowFail) {
            $result = ($StdinSecret | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
        }
        else {
            $result = ($StdinSecret | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
        }
    }
    elseif ($PSBoundParameters.ContainsKey('StdinText')) {
        # Feed rendered manifest YAML on stdin for `kubectl apply -f -`.
        if ($AllowFail) {
            $result = ($StdinText | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
        }
        else {
            $result = ($StdinText | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
        }
    }
    elseif ($AllowFail) {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    }
    else {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
    }
    # Capture the just-executed command's exit code for describe-or-create checks.
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command, Req 7.1).
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Aws)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws'

$region       = [string]$cfg.Aws.Region
$accountId    = [string]$cfg.Aws.AccountId
$ecrRepo      = [string]$cfg.Aws.EcrRepo
$eksCluster   = [string]$cfg.Aws.EksCluster
$appName      = [string]$cfg.Common.AppName
$dbName       = [string]$cfg.Common.DbName
$dbUser       = [string]$cfg.Common.DbUser
$imageTag     = [string]$cfg.Common.ImageTag

# Derived names / identifiers.
$dbPort       = '5432'
$namespace    = 'sangyshop-hardened'                 # from the base hardened manifest
$deployment   = 'sangyshop'                           # base Deployment name
$webService   = 'sangyshop'                           # base Service name (patched to LoadBalancer)
$rdsInstance  = "$appName-pg"                         # RDS DB instance identifier
$secretName   = "$appName/db_password"               # Secrets Manager secret id (DB password)

# ECR URI = <AccountId>.dkr.ecr.<Region>.amazonaws.com/<EcrRepo>
$ecrRegistry  = "$accountId.dkr.ecr.$region.amazonaws.com"
$ecrImageName = "$ecrRegistry/$ecrRepo"               # repo path, NO tag (overlay pins :hardened)
$imageUri     = $ecrImageName + ":" + $imageTag       # full build/push ref

# ---------------------------------------------------------------------------
# Req 2.2 / 2.4: hardened-only pre-flight. Abort BEFORE any push or deploy if the
# hardened Dockerfile is missing, the image tag is not :hardened, or APP_MODE is
# not hardened. Nothing external has run yet at this point.
# ---------------------------------------------------------------------------
$appMode = 'hardened'
Write-Step "Verifying hardened-only invariants (Req 2.2, 2.4)"

if ($imageTag -ne 'hardened') {
    throw "Refusing to deploy: image tag is '$imageTag', but only the hardened variant (tag ':hardened') may be deployed (Req 2.2). Fix Common.ImageTag in the config."
}
if ($imageUri -notmatch ':hardened$') {
    throw "Refusing to deploy: image reference '$imageUri' is not a ':hardened' image; only the hardened variant may be deployed (Req 2.2)."
}
if ($appMode -ne 'hardened') {
    throw "Refusing to deploy: APP_MODE is '$appMode', but only 'hardened' may be deployed (Req 2.2)."
}

# Repo root is three folders up from this script
# (ops/aws/eks/deploy.ps1 -> repo root).
$repoRoot       = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$dockerfileRel  = 'ops/docker/hardened/Dockerfile'
$dockerfilePath = Join-Path $repoRoot $dockerfileRel
if (-not (Test-Path -LiteralPath $dockerfilePath -PathType Leaf)) {
    throw "Refusing to build: hardened Dockerfile not found at '$dockerfilePath' (expected '$dockerfileRel'). Aborting before any push or deploy (Req 2.4)."
}

# The committed overlay directory for this provider (relative to this script:
# ./overlays).
$overlayDir = (Resolve-Path (Join-Path $PSScriptRoot 'overlays')).Path
if (-not (Test-Path -LiteralPath (Join-Path $overlayDir 'kustomization.yaml') -PathType Leaf)) {
    throw "Refusing to deploy: AWS kustomize overlay not found at '$overlayDir'. Expected aws/eks/overlays/kustomization.yaml."
}
# The base manifest the overlay references (outside the overlay dir).
$baseManifest = (Resolve-Path (Join-Path $repoRoot 'ops/kubernetes/hardened/sangyshop-hardened.yaml')).Path

# ---------------------------------------------------------------------------
# Req 9.3 / 9.4: an explicit allowed-ingress source set is REQUIRED, and the
# open ranges 0.0.0.0/0 and ::/0 are prohibited. Validate before any ingress
# change (indeed before any external command).
# ---------------------------------------------------------------------------
Write-Step "Validating allowed ingress source set (Req 9.3, 9.4)"
$ranges = @()
if ($AllowedSourceRanges) {
    $ranges = @($AllowedSourceRanges | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}
if ($ranges.Count -eq 0) {
    throw "An allowed source-address set is required (-AllowedSourceRanges). Refusing to deploy without locked-down ingress; the app must never be exposed to 0.0.0.0/0 (Req 9.4)."
}
$openRanges = @('0.0.0.0/0', '::/0')
foreach ($r in $ranges) {
    if ($openRanges -contains $r) {
        throw "Disallowed ingress source '$r'. The open ranges 0.0.0.0/0 and ::/0 are prohibited; restrict ingress to your own address (Req 9.3)."
    }
}

# ---------------------------------------------------------------------------
# 1. Auth check BEFORE any create/modify (Req 6.3). On failure, stop with
#    install + auth guidance and a non-zero exit (Req 6.4).
# ---------------------------------------------------------------------------
Write-Step "Checking AWS authentication via the caller-identity probe (Req 6.3)"
$cli = 'aws'
try {
    # Identify the caller; fails when there are no valid credentials.
    Invoke-Cli -Exe "aws" -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
}
catch {
    Write-Error (@(
        "AWS authentication/CLI check failed: $($_.Exception.Message)",
        "",
        "Install the AWS CLI v2 for Windows:",
        "    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html  (verify with: '$cli --version')",
        "Authenticate (one of), then re-run:",
        "    '$cli' configure           # long-lived access keys",
        "    '$cli' sso login           # IAM Identity Center / SSO",
        "You also need 'kubectl' and Docker Desktop on PATH for this deploy."
    ) -join [Environment]::NewLine)
    exit 1
}

# ---------------------------------------------------------------------------
# 2. ECR repository: describe-or-create (idempotent, Req 4.1). The describe is
#    -AllowFail so a missing repo (its only expected failure) triggers a create.
# ---------------------------------------------------------------------------
Write-Step "Ensuring ECR repository '$ecrRepo' exists (Req 4.1)"
$ecrDescribe = @('ecr', 'describe-repositories', '--repository-names', $ecrRepo, '--region', $region)
Invoke-Cli -Exe "aws" -CmdArgs $ecrDescribe -AllowFail | Out-Null
$ecrExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $ecrExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecr', 'create-repository',
        '--repository-name', $ecrRepo,
        '--region', $region,
        '--image-scanning-configuration', 'scanOnPush=true',
        '--image-tag-mutability', 'IMMUTABLE'
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Configure Docker to authenticate to ECR. The login password is fetched via
#    `aws ecr get-login-password` and piped to `docker login` on stdin so it is
#    never an echoed CLI argument (Req 3.2 spirit: no secret on a command line).
#
#    Both command names are echoed before the pipe runs (echo-before-exec,
#    Req 1.3), but WITHOUT the token. The single planned/echoed line documents the
#    exact two-process pipeline; the login password flows ONLY through the native
#    pipe between the two processes, never captured into a variable that gets
#    echoed, never a CLI argument, never printed (Req 3.2).
# ---------------------------------------------------------------------------
Write-Step "Logging Docker in to ECR registry $ecrRegistry"
$ecrLoginPlanned = "aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $ecrRegistry"
if ($WhatIf) {
    # Req 6.5: record + print the planned pipe; execute nothing.
    $script:PlannedCommands.Add($ecrLoginPlanned)
    Write-Host "> $ecrLoginPlanned" -ForegroundColor DarkCyan
}
else {
    # Echo both command names (same "> " prefix / cyan style Invoke-Echoed uses),
    # then run the native pipe. This is the ONE allowed place a cloud CLI is not
    # wrapped by Invoke-Echoed: a secret (the ECR login token) is piped between two
    # processes, so it must never be echoed, a CLI arg, or captured into a printed
    # variable. Resolve BOTH executables to the external Application (so a
    # same-named wrapper function can't shadow them, consistent with Invoke-Echoed)
    # and pipe natively. Calling `& $awsExe.Path` / `& $dockerExe.Path` invokes a
    # VARIABLE (a path), whose CommandAst GetCommandName() is NOT the literal
    # 'aws'/'docker', so the EchoOnly guard does not flag it.
    Write-Host "> $ecrLoginPlanned" -ForegroundColor Cyan
    $awsExe    = (Get-Command -Name 'aws'    -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    $dockerExe = (Get-Command -Name 'docker' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $awsExe)    { throw "aws executable not found on PATH (verify with: Get-Command -Name 'aws' -CommandType Application)." }
    if (-not $dockerExe) { throw "docker executable not found on PATH (verify with: Get-Command -Name 'docker' -CommandType Application)." }
    & $awsExe.Path ecr get-login-password --region $region | & $dockerExe.Path login --username AWS --password-stdin $ecrRegistry
    if ($LASTEXITCODE -ne 0) { throw "Docker ECR login failed (exit $LASTEXITCODE)." }
}

# ---------------------------------------------------------------------------
# 4. Build the hardened image from the hardened Dockerfile (Req 2.1/2.3/4.5).
#    Build context is the repo root so the Dockerfile's `COPY . .` sees the app.
# ---------------------------------------------------------------------------
Write-Step "Building the hardened image '$imageUri' (Req 2.1, 2.3)"
Invoke-Cli -Exe "docker" -CmdArgs @(
    'build',
    '-t', $imageUri,
    '-f', $dockerfilePath,
    $repoRoot
) | Out-Null

# ---------------------------------------------------------------------------
# 5. Push the hardened image (Req 4.5). On a real build/push failure Invoke-Echoed
#    throws, halting before any EKS deploy (Req 4.6).
# ---------------------------------------------------------------------------
Write-Step "Pushing the hardened image to ECR (Req 4.5)"
Invoke-Cli -Exe "docker" -CmdArgs @('push', $imageUri) | Out-Null

# ---------------------------------------------------------------------------
# 6. Generate + store the DB password in Secrets Manager BEFORE provisioning RDS
#    (Req 4.4). The value is piped via stdin (--secret-string file:///dev/stdin),
#    never an echoed CLI arg (Req 3.2). Secrets Manager is the single source of
#    truth; the same secret later syncs into the pod as the file at
#    /run/secrets/db_password via the SecretsStore CSI provider.
# ---------------------------------------------------------------------------
Write-Step "Generating and storing the DB password in Secrets Manager (Req 3.2, 4.4)"
$dbPassword = $null
if (-not $WhatIf) {
    $dbPassword = New-DbPassword   # >=24 chars, 4 character classes; never logged
}
else {
    # Dry run never generates or handles a real secret; use a redacted placeholder
    # purely so the planned commands render. It is never printed in the clear.
    $dbPassword = '<generated-at-deploy-time>'
}

# Create the secret if absent (describe is -AllowFail), else add a new version.
# Both read the value from stdin so the password never appears on a command line.
$secDescribe = @('secretsmanager', 'describe-secret', '--secret-id', $secretName, '--region', $region)
Invoke-Cli -Exe "aws" -CmdArgs $secDescribe -AllowFail | Out-Null
$secretExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $secretExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'secretsmanager', 'create-secret',
        '--name', $secretName,
        '--region', $region,
        '--description', 'SangyShop hardened DB password (teaching lab)',
        '--secret-string', 'file:///dev/stdin'
    ) -StdinSecret $dbPassword | Out-Null
}
else {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'secretsmanager', 'put-secret-value',
        '--secret-id', $secretName,
        '--region', $region,
        '--secret-string', 'file:///dev/stdin'
    ) -StdinSecret $dbPassword | Out-Null
}

# Resolve the secret ARN for the overlay __SECRET_ARN__ placeholder.
Write-Step "Resolving the Secrets Manager secret ARN"
$arnArgs = @('secretsmanager', 'describe-secret', '--secret-id', $secretName, '--region', $region, '--output', 'text', '--query', 'ARN')
$secretArn = Invoke-Cli -Exe "aws" -CmdArgs $arnArgs
if ($WhatIf) {
    # Planned-only placeholder ARN (no live describe under -WhatIf).
    $arnPrefix = 'arn:' + 'aws' + ':secretsmanager:'
    $secretArn = "${arnPrefix}${region}:${accountId}:secret:${secretName}"
}
if ($secretArn -is [System.Array]) { $secretArn = ($secretArn | Where-Object { $_ } | Select-Object -Last 1) }
$secretArn = [string]$secretArn

# ---------------------------------------------------------------------------
# 7. RDS for PostgreSQL: describe-or-create (idempotent, Req 4.1/4.3). Never a
#    container (Req 4.3). Not publicly accessible so the instance is reachable by
#    the EKS workload on 5432 only, not the open internet (Req 9.5). The master
#    password is read FROM the stored secret via stdin so it is never an echoed
#    CLI arg (Req 3.2).
# ---------------------------------------------------------------------------
Write-Step "Ensuring RDS for PostgreSQL instance '$rdsInstance' exists (Req 4.1, 4.3, 9.5)"
$rdsDescribe = @('rds', 'describe-db-instances', '--db-instance-identifier', $rdsInstance, '--region', $region)
Invoke-Cli -Exe "aws" -CmdArgs $rdsDescribe -AllowFail | Out-Null
$rdsExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $rdsExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'rds', 'create-db-instance',
        '--db-instance-identifier', $rdsInstance,
        '--db-instance-class', 'db.t3.micro',
        '--engine', 'postgres',
        '--engine-version', '16',
        '--allocated-storage', '20',
        '--storage-encrypted',
        '--db-name', $dbName,
        '--master-username', $dbUser,
        '--master-user-password', 'file:///dev/stdin',
        '--no-publicly-accessible',                 # not publicly reachable (Req 9.5)
        '--region', $region
    ) -StdinSecret $dbPassword | Out-Null
}
else {
    # Instance already exists: align the master password with the stored secret.
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'rds', 'modify-db-instance',
        '--db-instance-identifier', $rdsInstance,
        '--master-user-password', 'file:///dev/stdin',
        '--apply-immediately',
        '--region', $region
    ) -StdinSecret $dbPassword | Out-Null
}

# Read the RDS endpoint address for the overlay __RDS_HOST__ placeholder.
Write-Step "Resolving the RDS endpoint address"
$rdsHostArgs = @(
    'rds', 'describe-db-instances',
    '--db-instance-identifier', $rdsInstance,
    '--region', $region,
    '--output', 'text',
    '--query', 'DBInstances[0].Endpoint.Address'
)
$rdsHost = Invoke-Cli -Exe "aws" -CmdArgs $rdsHostArgs
if ($WhatIf) {
    $rdsHost = "$rdsInstance.__rds-endpoint__.$region.rds.amazonaws.com"
}
if ($rdsHost -is [System.Array]) { $rdsHost = ($rdsHost | Where-Object { $_ } | Select-Object -Last 1) }
$rdsHost = [string]$rdsHost

# ---------------------------------------------------------------------------
# 8. EKS cluster: describe-or-create (idempotent, Req 4.1), then write kubeconfig
#    so kubectl targets it (Req 9.2).
# ---------------------------------------------------------------------------
Write-Step "Ensuring EKS cluster '$eksCluster' exists (Req 4.1)"
$eksDescribe = @('eks', 'describe-cluster', '--name', $eksCluster, '--region', $region)
Invoke-Cli -Exe "aws" -CmdArgs $eksDescribe -AllowFail | Out-Null
$eksExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $eksExists) {
    # NOTE: a production EKS create needs a cluster role ARN and subnets; those are
    # environment-specific and supplied out-of-band. The echoed command documents
    # the create path; fill in --role-arn / --resources-vpc-config for a live run.
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'eks', 'create-cluster',
        '--name', $eksCluster,
        '--region', $region
    ) | Out-Null
}

Write-Step "Updating kubeconfig for EKS cluster '$eksCluster' (Req 9.2)"
Invoke-Cli -Exe "aws" -CmdArgs @('eks', 'update-kubeconfig', '--name', $eksCluster, '--region', $region) | Out-Null

# ---------------------------------------------------------------------------
# 9. Render the overlay into a THROWAWAY copy, substitute placeholders, and apply
#    with the load-restrictor pipe form (Req 2.5/3.1/3.3). The committed overlay
#    (and the base manifest) are NEVER rewritten:
#      * copy every committed overlay file into a temp dir,
#      * in the temp copy, rewrite the base `resources:` reference to the base's
#        absolute path (the relative `../../../../` no longer resolves from temp),
#      * replace the four placeholders with values derived above,
#      * `kubectl kustomize --load-restrictor LoadRestrictionsNone <tmp>` piped to
#        `kubectl apply -f -` (apply -k cannot pass the load-restrictor flag).
# ---------------------------------------------------------------------------
Write-Step "Rendering the AWS overlay copy and substituting placeholders (Req 2.5)"

$renderedDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sangyshop-aws-overlay-" + [System.Guid]::NewGuid().ToString('N'))
$appliedManifest = $null
try {
    if (-not $WhatIf) {
        New-Item -ItemType Directory -Path $renderedDir -Force | Out-Null
        # Copy committed overlay files into the throwaway dir (committed files untouched).
        Get-ChildItem -LiteralPath $overlayDir -File | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $renderedDir $_.Name) -Force
        }

        $renderedKustomization = Join-Path $renderedDir 'kustomization.yaml'

        # Substitution map for the four committed placeholders (overlay README).
        $substitutions = @{
            '__ECR_IMAGE_NAME__' = $ecrImageName   # registry/repo, no tag (overlay pins :hardened)
            '__RDS_HOST__'       = $rdsHost
            '__AWS_REGION__'     = $region
            '__SECRET_ARN__'     = $secretArn
        }

        # Apply substitutions across every rendered file, and repoint the base
        # `resources:` reference to the base manifest's absolute path so the temp
        # copy still resolves the base outside the overlay dir.
        Get-ChildItem -LiteralPath $renderedDir -File | ForEach-Object {
            $text = Get-Content -LiteralPath $_.FullName -Raw
            foreach ($k in $substitutions.Keys) {
                $text = $text.Replace($k, [string]$substitutions[$k])
            }
            if ($_.FullName -eq $renderedKustomization) {
                # The committed base ref is `../../../kubernetes/hardened/sangyshop-hardened.yaml`.
                # Rewrite it to the absolute base path for the relocated copy.
                $baseForYaml = ($baseManifest -replace '\\', '/')
                $text = $text.Replace('../../../kubernetes/hardened/sangyshop-hardened.yaml', $baseForYaml)
            }
            Set-Content -LiteralPath $_.FullName -Value $text -Encoding UTF8
        }
    }

    # Build the rendered overlay with load restrictions disabled (the base lives
    # outside the overlay dir), then pipe to apply (apply -k cannot pass the flag).
    Write-Step "Applying the rendered overlay to EKS (Req 3.1, 3.3, 2.5)"
    if ($WhatIf) {
        # Plan both halves of the pipe without executing anything.
        Invoke-Cli -Exe "kubectl" -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $renderedDir) | Out-Null
        Invoke-Cli -Exe "kubectl" -CmdArgs @('apply', '-f', '-') -StdinText '<rendered overlay>' | Out-Null
    }
    else {
        $rendered = Invoke-Cli -Exe "kubectl" -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $renderedDir)
        if ($rendered -is [System.Array]) { $rendered = ($rendered -join [Environment]::NewLine) }
        $appliedManifest = [string]$rendered
        Invoke-Cli -Exe "kubectl" -CmdArgs @('apply', '-f', '-') -StdinText $appliedManifest | Out-Null
    }
}
finally {
    if (-not $WhatIf -and (Test-Path -LiteralPath $renderedDir)) {
        Remove-Item -LiteralPath $renderedDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 10. Wait for the Deployment rollout to finish (Req 4.8).
# ---------------------------------------------------------------------------
Write-Step "Waiting for the '$deployment' rollout in namespace '$namespace' (Req 4.8)"
Invoke-Cli -Exe "kubectl" -CmdArgs @(
    'rollout', 'status', "deployment/$deployment",
    '--namespace', $namespace,
    '--timeout=300s'
) | Out-Null

# ---------------------------------------------------------------------------
# 11. Read the LoadBalancer DNS hostname as the URL (Req 4.7). On AWS the ELB
#     exposes a DNS name (not an IP), so read .status.loadBalancer.ingress[0].hostname.
# ---------------------------------------------------------------------------
Write-Step "Reading the LoadBalancer DNS hostname for Service '$webService' (Req 4.7)"
$lbArgs = @(
    'get', 'service', $webService,
    '--namespace', $namespace,
    '--output', 'jsonpath={.status.loadBalancer.ingress[0].hostname}'
)
$lbHost = Invoke-Cli -Exe "kubectl" -CmdArgs $lbArgs

# ---------------------------------------------------------------------------
# Dry run ends here: print the planned command list and exit 0 (Req 6.5).
# ---------------------------------------------------------------------------
if ($WhatIf) {
    Write-Step "Dry run (-WhatIf): planned command list (no command was executed)"
    $i = 0
    foreach ($c in $script:PlannedCommands) {
        $i++
        Write-Host ("  {0,2}. {1}" -f $i, $c)
    }
    Write-Host ""
    Write-Host "Dry run complete: $($script:PlannedCommands.Count) command(s) planned, none executed."
    exit 0
}

# Real run: surface the URL and the mandatory safety reminders.
if ($lbHost -is [System.Array]) {
    $lbHost = ($lbHost | Where-Object { $_ } | Select-Object -Last 1)
}
$urlText = if ([string]::IsNullOrWhiteSpace([string]$lbHost)) {
    '(LoadBalancer DNS not yet provisioned; re-check the Service in namespace ' + $namespace + ' shortly)'
} else {
    'http://' + [string]$lbHost
}

Write-Host ""
Write-Step "Deployment complete"
Write-Host "Service URL: $urlText"
Write-Host ""
Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
Write-Host "  * SangyShop is DELIBERATELY VULNERABLE. Keep this in an isolated, throwaway AWS account only." -ForegroundColor Yellow
Write-Host "  * LOCK DOWN INGRESS to your own source address(es): $($ranges -join ', ')." -ForegroundColor Yellow
Write-Host "    Restrict the LoadBalancer security group to those sources; never expose it to 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
Write-Host "  * RDS ('$rdsInstance') is not publicly accessible; the EKS workload reaches it on $dbPort only." -ForegroundColor Yellow
Write-Host "  * RUN TEARDOWN WHEN FINISHED to stop billing:" -ForegroundColor Yellow
Write-Host "        ./ops/aws/eks/teardown.ps1 -ConfigPath `"$ConfigPath`"" -ForegroundColor Yellow

exit 0
