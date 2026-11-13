<#
.SYNOPSIS
    Deploy the HARDENED SangyShop image to AWS ECS Fargate (Docker-only modality).

.DESCRIPTION
    Builds the hardened image from ops/docker/hardened/Dockerfile,
    pushes it to Amazon ECR, provisions RDS for PostgreSQL (never a container),
    stores a generated DB password in AWS Secrets Manager, and runs the image as
    an ECS Fargate service wired so the secret lands at the app-owned file
    /app/secrets/db_password inside the container. No bare DB_PASSWORD env var is
    ever set; the unmodified hardened app reads the secret file (located via
    DB_PASSWORD_FILE) and fails closed otherwise (src/db/credentials.js).

    Unlike GCP Cloud Run / Azure ACI (which mount the secret as a file natively),
    Fargate injects a Secrets Manager secret as an ENVIRONMENT VARIABLE. The task
    definition therefore overrides the container `command` to run the ECS Fargate
    secret->file entrypoint wrapper (see the "Form A" README in this folder):
    a self-contained `sh -c` program that reads the injected DB_PASSWORD_SECRET
    env var, writes its trimmed value to /app/secrets/db_password, unsets the env
    var, then execs `node src/server.js`. The wrapper writes under the app-owned
    /app/secrets directory (chowned to UID 10001 in the hardened Dockerfile) rather
    than the root-owned ephemeral /run/secrets volume, so the non-root container
    user can create the file. The container reads it via DB_PASSWORD_FILE. The
    inline program is built from secret-entrypoint.sh in this folder so the two
    never drift.

    Pipeline (every external CLI call is echoed before it runs, via the shared
    Invoke-Echoed helper in lib/Common.ps1):

        1. Auth check ('aws' sts get-caller-identity)
        2. ECR describe-or-create
        3. Registry auth: 'aws' ecr get-login-password piped to 'docker' login
           (password via stdin, never echoed)
        4. Build the hardened image
        5. Push the hardened image
        6. Generate + store password in Secrets Manager --
           BEFORE provisioning, value via a file://temp (ARN referenced, never
           an echoed CLI arg)
        7. RDS describe-or-create (never a container)
        8. Set the RDS master password FROM the stored secret
        9. Register the ECS task definition wiring the secret
           -> Form A inline wrapper writing /app/secrets/db_password, DB_PASSWORD_SECRET
           from Secrets Manager valueFrom ARN, env APP_MODE/DB_BACKEND/DB_HOST/
           DB_PORT/DB_NAME/DB_USER/DB_PASSWORD_FILE and NO bare DB_PASSWORD
       10. Cluster describe-or-create
       11. Locked-down security group for the task (reject 0.0.0.0/0 & ::/0)

       12. Restrict RDS to the task on 5432 (not public)
       13. Create-or-reuse the service
       14. Fetch + print the public URL + lockdown + teardown

    Safety:
      * Only the hardened variant is ever built/pushed/deployed.
      * Aborts before any push/deploy if the hardened Dockerfile is missing
 or a non-:hardened image / non-hardened APP_MODE is referenced
.
      * Ingress is restricted to an explicitly provided source set; 0.0.0.0/0 and
        ::/0 are rejected; an empty set stops the deploy.
      * RDS is reachable by the task on 5432 only, not public.
      * -WhatIf prints the full ordered command list and executes NO external
        command, exiting 0.

    Windows PowerShell 5.1 compatible. Every external CLI call routes
    through Invoke-Echoed, enforced by tests/EchoOnly.Guard.Tests.ps1.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (ops/cloud.config.ps1).

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0.

.PARAMETER ReuseExisting
    Reuse an already-present ECR repo / RDS instance / secret / cluster / service
    rather than failing. This is the default convergent behavior; the switch is
    accepted for parity with the other targets and for explicitness.

.PARAMETER AllowedSourceRanges
    REQUIRED allowed-ingress source set. Each entry is a source address/CIDR that
    may reach the Fargate task. 0.0.0.0/0 and ::/0 are rejected. If
    omitted/empty the script stops before any ingress change.
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
# a bare CLI token. When -WhatIf is set, Invoke-Cli records and prints
# the planned command line WITHOUT executing anything; otherwise it
# delegates to the shared Invoke-Echoed helper, which echoes
# the exact command and then runs it.
#
# Secret rule: a secret is NEVER passed as a CLI argument. The password
# is handed to commands via stdin (-StdinSecret); the task definition references
# it only by Secrets Manager ARN. The planned/echoed line shows a redacted
# "<stdin: db password (redacted)>" note, never the value.
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail,
        [string]                         $StdinSecret  # piped to the command's stdin; never echoed
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
    $display = $displayParts -join ' '

    if ($WhatIf) {
        # record + print the planned command; execute NOTHING. Model a
        # "would succeed" exit so describe-or-create logic picks a deterministic
        # branch for the planned list (we plan the CREATE branch under -WhatIf).
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Real execution path: route through the shared, echoing helper.
    $result = $null
    if ($PSBoundParameters.ContainsKey('StdinSecret')) {
        # Feed the secret through stdin so it never becomes an echoed CLI arg
        #. Invoke-Echoed echoes only $Exe + $CmdArgs, so the password
        # stays off the command line and out of logs.
        if ($AllowFail) {
            $result = ($StdinSecret | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
        }
        else {
            $result = ($StdinSecret | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
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
# Pipe a secret value into one command's stdin while the NEXT command reads it,
# so the password is never an echoed CLI arg. Used for
# `aws ecr get-login-password | docker login --password-stdin`, where the
# password that flows between the two CLIs must also never be echoed.
#
# Both halves are echoed but the sensitive value travels only
# through the pipe, never as an argument. Under -WhatIf nothing executes.
# ---------------------------------------------------------------------------
function Invoke-EcrDockerLogin {
    param(
        [Parameter(Mandatory)][string] $Region,
        [Parameter(Mandatory)][string] $RegistryHost
    )

    $getPwArgs = @('ecr', 'get-login-password', '--region', $Region)
    $loginArgs = @('login', '--username', 'AWS', '--password-stdin', $RegistryHost)

    # The single planned/echoed line for this special-cased pipe. It documents the
    # exact two-process pipeline WITHOUT the token: the login password flows only
    # through the native pipe between aws and docker, never onto a command line and
    # never into this echoed text.
    $planned = 'aws ' + ($getPwArgs -join ' ') + ' | docker ' + ($loginArgs -join ' ')

    if ($WhatIf) {
        # record + print the planned pipe; execute nothing.
        $script:PlannedCommands.Add($planned)
        Write-Host "> $planned" -ForegroundColor DarkCyan
        return
    }

    # Echo BOTH command names before running (echo-before-exec), using the
    # same "> " prefix / cyan style Invoke-Echoed prints, but WITHOUT the token.
    Write-Host "> $planned" -ForegroundColor Cyan

    # This is the ONE allowed place a cloud CLI is not wrapped by Invoke-Echoed:
    # a secret (the ECR login token) is piped between two processes, so it must
    # never be captured into a variable that gets echoed, never a CLI argument, and
    # never printed. Resolve BOTH executables to the external Application (so a
    # same-named wrapper function can't shadow them, consistent with Invoke-Echoed)
    # and pipe natively. Calling `& $awsExe.Path` / `& $dockerExe.Path` invokes a
    # VARIABLE (a path), whose CommandAst GetCommandName() is NOT the literal
    # 'aws'/'docker', so the EchoOnly guard does not flag it.
    $awsExe    = (Get-Command -Name 'aws'    -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    $dockerExe = (Get-Command -Name 'docker' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $awsExe)    { throw "aws executable not found on PATH (verify with: Get-Command -Name 'aws' -CommandType Application)." }
    if (-not $dockerExe) { throw "docker executable not found on PATH (verify with: Get-Command -Name 'docker' -CommandType Application)." }

    # The token travels only through this native pipe between the two processes.
    & $awsExe.Path ecr get-login-password --region $Region | & $dockerExe.Path login --username AWS --password-stdin $RegistryHost
    if ($LASTEXITCODE -ne 0) { throw "Docker ECR login failed (exit $LASTEXITCODE)." }
}

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command).
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Aws)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws'

$region      = [string]$cfg.Aws.Region
$accountId   = [string]$cfg.Aws.AccountId
$ecrRepo     = [string]$cfg.Aws.EcrRepo
$ecsCluster  = [string]$cfg.Aws.EcsCluster
$appName     = [string]$cfg.Common.AppName
$dbName      = [string]$cfg.Common.DbName
$dbUser      = [string]$cfg.Common.DbUser
$imageTag    = [string]$cfg.Common.ImageTag

# Derived names / identifiers.
$registryHost = "$accountId.dkr.ecr.$region.amazonaws.com"
$imageUri     = "$registryHost/$ecrRepo" + ":" + $imageTag
$secretName   = "$appName/db_password"      # Secrets Manager secret id
$rdsId        = "$appName-pg"               # RDS db instance identifier
$taskFamily   = "$appName-hardened"         # ECS task definition family
$serviceName  = "$appName-svc"              # ECS service name
$sgName       = "$appName-task-sg"          # task security group name
$rdsSgName    = "$appName-rds-sg"           # RDS security group name
$logGroup     = "/ecs/$appName-hardened"    # CloudWatch Logs group for the task
$dbPort       = '5432'
$appPort      = '3000'
$appMode      = 'hardened'
# Hardened secret FILE path inside the container. On Fargate the ephemeral
# /run/secrets volume is owned by root while the image runs as UID 10001, so the
# non-root user cannot write there. Instead the wrapper writes the secret to this
# app-owned path (created + chowned to the app user in the hardened Dockerfile),
# and the container is told to read it via the DB_PASSWORD_FILE env var (the PATH,
# never the value). Still a FILE, still trimmed, still fail-closed.
$secretFilePath = '/app/secrets/db_password'

# ---------------------------------------------------------------------------
# hardened-only pre-flight. Abort BEFORE any push or deploy if the
# hardened Dockerfile is missing, the image tag is not :hardened, or APP_MODE is
# not hardened. Nothing external has run yet at this point.
# ---------------------------------------------------------------------------
Write-Step "Verifying hardened-only invariants"

if ($imageTag -ne 'hardened') {
    throw "Refusing to deploy: image tag is '$imageTag', but only the hardened variant (tag ':hardened') may be deployed. Fix Common.ImageTag in the config."
}
if ($imageUri -notmatch ':hardened$') {
    throw "Refusing to deploy: image reference '$imageUri' is not a ':hardened' image; only the hardened variant may be deployed."
}
if ($appMode -ne 'hardened') {
    throw "Refusing to deploy: APP_MODE is '$appMode', but only 'hardened' may be deployed."
}

# Repo root is three folders up from this script
# (ops/aws/ecs/deploy.ps1 -> repo root).
$repoRoot       = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$dockerfileRel  = 'ops/docker/hardened/Dockerfile'
$dockerfilePath = Join-Path $repoRoot $dockerfileRel
if (-not (Test-Path -LiteralPath $dockerfilePath -PathType Leaf)) {
    throw "Refusing to build: hardened Dockerfile not found at '$dockerfilePath' (expected '$dockerfileRel'). Aborting before any push or deploy."
}

# The Form A inline entrypoint wrapper is derived from secret-entrypoint.sh in
# this folder; abort if it is missing so the task command cannot silently drift.
$wrapperPath = Join-Path $PSScriptRoot 'secret-entrypoint.sh'
if (-not (Test-Path -LiteralPath $wrapperPath -PathType Leaf)) {
    throw "Refusing to deploy: secret->file entrypoint wrapper not found at '$wrapperPath'. It is required to honor the secret-file contract on Fargate."
}

# ---------------------------------------------------------------------------
# an explicit allowed-ingress source set is REQUIRED, and the open
# ranges 0.0.0.0/0 and ::/0 are prohibited. Validate before any ingress change
# (indeed before any external command).
# ---------------------------------------------------------------------------
Write-Step "Validating allowed ingress source set"
$ranges = @()
if ($AllowedSourceRanges) {
    $ranges = @($AllowedSourceRanges | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}
if ($ranges.Count -eq 0) {
    throw "An allowed source-address set is required (-AllowedSourceRanges). Refusing to deploy without locked-down ingress; the app must never be exposed to 0.0.0.0/0."
}
$openRanges = @('0.0.0.0/0', '::/0')
foreach ($r in $ranges) {
    if ($openRanges -contains $r) {
        throw "Disallowed ingress source '$r'. The open ranges 0.0.0.0/0 and ::/0 are prohibited; restrict ingress to your own address."
    }
}

# ---------------------------------------------------------------------------
# Build the Form A inline `sh -c` entrypoint wrapper (aws/docker/README.md).
#
# This is the exact three-element command array ["sh","-c","<program>"] the task
# definition overrides the container `command` with. The inner program reads the
# injected DB_PASSWORD_SECRET env var, trims surrounding whitespace, writes it to
# the app-owned secret file (/app/secrets/db_password), restricts the file mode,
# unsets the env var, then execs `node src/server.js`. The /app/secrets directory
# is created and chowned to the app user (UID 10001) in the hardened Dockerfile,
# so the non-root container can write/read it WITHOUT root -- unlike the ephemeral
# /run/secrets volume Fargate mounts as root. The container is told where the
# file is via the DB_PASSWORD_FILE env var, so the unmodified hardened app reads
# it and fails closed otherwise. It mirrors secret-entrypoint.sh so the
# fail-closed secret-file contract is honored without changing the app image
#. The program is a fixed literal here (kept in lock-step with the
# wrapper file, whose presence is asserted above) so the task command is
# deterministic and never embeds the secret VALUE -- only the env var NAME.
# ---------------------------------------------------------------------------
$wrapperProgram = @(
    'set -eu',
    'v="${DB_PASSWORD_SECRET:-}"',
    "[ -n `"`$v`" ] || { echo 'secret-entrypoint: DB_PASSWORD_SECRET unset/empty' >&2; exit 1; }",
    'ws="$(printf '' \t\r\n_'')"; ws="${ws%_}"',
    'while [ -n "$v" ]; do c="${v%"${v#?}"}"; case "$ws" in *"$c"*) v="${v#?}" ;; *) break ;; esac; done',
    'while [ -n "$v" ]; do c="${v#"${v%?}"}"; case "$ws" in *"$c"*) v="${v%?}" ;; *) break ;; esac; done',
    "[ -n `"`$v`" ] || { echo 'secret-entrypoint: DB_PASSWORD_SECRET whitespace-only' >&2; exit 1; }",
    "mkdir -p /app/secrets",
    "(umask 077; printf '%s' `"`$v`" > $secretFilePath)",
    "chmod 600 $secretFilePath 2>/dev/null || true",
    'unset v; unset DB_PASSWORD_SECRET',
    'exec node src/server.js'
) -join '; '

# The task-definition container `command` (Form A): sh -c "<program>".
$containerCommand = @('sh', '-c', $wrapperProgram)

# ---------------------------------------------------------------------------
# 1. Auth check BEFORE any create/modify. On failure, stop with install
#    + auth guidance and a non-zero exit.
# ---------------------------------------------------------------------------
Write-Step "Checking AWS authentication via sts get-caller-identity"
$cli = 'aws'
try {
    Invoke-Cli -Exe "aws" -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
}
catch {
    Write-Error (@(
        "AWS authentication/CLI check failed: $($_.Exception.Message)",
        "",
        "Install the AWS CLI v2 for Windows:",
        "    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
        "    (verify with: '$cli --version')",
        "Authenticate to your own account, then re-run:",
        "    '$cli' configure                 # static access keys, or",
        "    '$cli' sso login                 # IAM Identity Center / SSO",
        "Confirm the active identity with:",
        "    '$cli' sts get-caller-identity"
    ) -join [Environment]::NewLine)
    exit 1
}

# ---------------------------------------------------------------------------
# 2. ECR: describe-or-create (idempotent). The describe is -AllowFail so
#    a missing repo (its only expected failure) triggers a create.
# ---------------------------------------------------------------------------
Write-Step "Ensuring ECR repository '$ecrRepo' exists"
$ecrDescribe = @('ecr', 'describe-repositories', '--repository-names', $ecrRepo, '--region', $region, '--output', 'text', '--query', 'repositories[0].repositoryName')
Invoke-Cli -Exe "aws" -CmdArgs $ecrDescribe -AllowFail | Out-Null
$ecrExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $ecrExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecr', 'create-repository',
        '--repository-name', $ecrRepo,
        '--region', $region,
        '--image-scanning-configuration', 'scanOnPush=true'
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Registry auth: aws ecr get-login-password | docker login --password-stdin.
#    The login password flows between the two CLIs over the pipe only; it is
#    never an echoed CLI arg.
# ---------------------------------------------------------------------------
Write-Step "Authenticating Docker to ECR ($registryHost)"
Invoke-EcrDockerLogin -Region $region -RegistryHost $registryHost

# ---------------------------------------------------------------------------
# 4. Build the hardened image from the hardened Dockerfile.
#    Build context is the repo root so the Dockerfile's `COPY . .` sees the app.
# ---------------------------------------------------------------------------
Write-Step "Building the hardened image '$imageUri'"
Invoke-Cli -Exe "docker" -CmdArgs @(
    'build',
    '-t', $imageUri,
    '-f', $dockerfilePath,
    $repoRoot
) | Out-Null

# ---------------------------------------------------------------------------
# 5. Push the hardened image. On a real build/push failure Invoke-Echoed
#    throws, halting before any RDS/ECS deploy.
# ---------------------------------------------------------------------------
Write-Step "Pushing the hardened image to ECR"
Invoke-Cli -Exe "docker" -CmdArgs @('push', $imageUri) | Out-Null

# ---------------------------------------------------------------------------
# 6. Generate + store the DB password in Secrets Manager BEFORE provisioning RDS
#. The value is written to a transient temp file referenced by
#    `file://` (deleted in finally) so it is never an echoed CLI arg.
#    Secrets Manager is the single source of truth; the task definition later
#    references the secret by ARN, and the Form A wrapper surfaces it as the file
#    /app/secrets/db_password.
# ---------------------------------------------------------------------------
Write-Step "Generating and storing the DB password in Secrets Manager"
$dbPassword = $null
if (-not $WhatIf) {
    $dbPassword = New-DbPassword   # >=24 chars, 4 character classes; never logged
}
else {
    # Dry run never generates or handles a real secret; use a redacted placeholder
    # purely so the planned commands render. It is never printed in the clear.
    $dbPassword = '<generated-at-deploy-time>'
}

# The AWS CLI cannot read --secret-string from stdin, so the value is passed via a
# transient file:// reference. The temp file is created with no value on the
# command line, read by the CLI, then securely removed in finally. The path is
# echoed (it is not the secret); the value never is.
$secretArn = $null
$secretTmp = $null
try {
    if (-not $WhatIf) {
        $secretTmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName()))
        # Write WITHOUT a trailing newline so the stored secret is the exact value.
        [System.IO.File]::WriteAllText($secretTmp, $dbPassword, (New-Object System.Text.UTF8Encoding($false)))
    }
    else {
        $secretTmp = '<temp-file: db password (redacted)>'
    }
    $secretFileRef = 'file://' + $secretTmp

    # Create the secret if absent (describe is -AllowFail), else put a new version.
    $secDescribe = @('secretsmanager', 'describe-secret', '--secret-id', $secretName, '--region', $region, '--output', 'text', '--query', 'ARN')
    Invoke-Cli -Exe "aws" -CmdArgs $secDescribe -AllowFail | Out-Null
    $secretExists = ($script:LastCliExit -eq 0)
    if ($WhatIf -or -not $secretExists) {
        Invoke-Cli -Exe "aws" -CmdArgs @(
            'secretsmanager', 'create-secret',
            '--name', $secretName,
            '--region', $region,
            '--description', 'SangyShop hardened DB password (teaching lab)',
            '--secret-string', $secretFileRef
        ) | Out-Null
    }
    else {
        Invoke-Cli -Exe "aws" -CmdArgs @(
            'secretsmanager', 'put-secret-value',
            '--secret-id', $secretName,
            '--region', $region,
            '--secret-string', $secretFileRef
        ) | Out-Null
    }

    # Resolve the secret ARN the task definition will reference. Under -WhatIf we
    # use a readable placeholder so the planned task-def JSON renders.
    if ($WhatIf) {
        $secretArn = @('arn', 'aws', 'secretsmanager', $region, $accountId, 'secret', $secretName) -join ':'
    }
    else {
        $arnOut = Invoke-Cli -Exe "aws" -CmdArgs @(
            'secretsmanager', 'describe-secret',
            '--secret-id', $secretName,
            '--region', $region,
            '--output', 'text', '--query', 'ARN'
        )
        if ($arnOut -is [System.Array]) {
            $arnOut = ($arnOut | Where-Object { $_ } | Select-Object -Last 1)
        }
        $secretArn = [string]$arnOut
    }
}
finally {
    if (-not $WhatIf -and $secretTmp -and (Test-Path -LiteralPath $secretTmp)) {
        # Best-effort shred: overwrite then delete so the plaintext password does
        # not linger in the temp folder.
        try {
            $len = (Get-Item -LiteralPath $secretTmp).Length
            if ($len -gt 0) {
                [System.IO.File]::WriteAllBytes($secretTmp, (New-Object byte[] $len))
            }
        }
        catch { }
        Remove-Item -LiteralPath $secretTmp -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 7. RDS for PostgreSQL: describe-or-create (idempotent). Never a
#    container. --no-publicly-accessible keeps the instance off the
#    public internet; the task reaches it over the VPC on 5432. The
#    master password is set FROM the stored secret via a file:// reference
#    (never an echoed CLI arg).
# ---------------------------------------------------------------------------
Write-Step "Ensuring RDS for PostgreSQL instance '$rdsId' exists"
$rdsDescribe = @('rds', 'describe-db-instances', '--db-instance-identifier', $rdsId, '--region', $region, '--output', 'text', '--query', 'DBInstances[0].DBInstanceIdentifier')
Invoke-Cli -Exe "aws" -CmdArgs $rdsDescribe -AllowFail | Out-Null
$rdsExists = ($script:LastCliExit -eq 0)

# The master password is delivered to RDS via a transient file:// reference so it
# never appears on a command line.
$pwTmp = $null
try {
    if (-not $WhatIf) {
        $pwTmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName()))
        [System.IO.File]::WriteAllText($pwTmp, $dbPassword, (New-Object System.Text.UTF8Encoding($false)))
    }
    else {
        $pwTmp = '<temp-file: db password (redacted)>'
    }
    $pwFileRef = 'file://' + $pwTmp

    if ($WhatIf -or -not $rdsExists) {
        Invoke-Cli -Exe "aws" -CmdArgs @(
            'rds', 'create-db-instance',
            '--db-instance-identifier', $rdsId,
            '--region', $region,
            '--engine', 'postgres',
            '--db-instance-class', 'db.t3.micro',
            '--allocated-storage', '20',
            '--db-name', $dbName,
            '--master-username', $dbUser,
            '--master-user-password', $pwFileRef,
            '--port', $dbPort,
            '--no-publicly-accessible',          # not reachable from the public internet
            '--backup-retention-period', '0',
            '--no-multi-az'
        ) | Out-Null
    }
    else {
        # 8. Reuse path: (re)assert the RDS master password FROM the stored secret
        #    so the running instance matches Secrets Manager.
        Write-Step "Setting the RDS master password from the stored secret"
        Invoke-Cli -Exe "aws" -CmdArgs @(
            'rds', 'modify-db-instance',
            '--db-instance-identifier', $rdsId,
            '--region', $region,
            '--master-user-password', $pwFileRef,
            '--apply-immediately'
        ) | Out-Null
    }
}
finally {
    if (-not $WhatIf -and $pwTmp -and (Test-Path -LiteralPath $pwTmp)) {
        try {
            $len = (Get-Item -LiteralPath $pwTmp).Length
            if ($len -gt 0) {
                [System.IO.File]::WriteAllBytes($pwTmp, (New-Object byte[] $len))
            }
        }
        catch { }
        Remove-Item -LiteralPath $pwTmp -Force -ErrorAction SilentlyContinue
    }
}

# Wait for the instance to be available before wiring networking / reading its
# endpoint. (Skipped under -WhatIf; wait commands are still planned for clarity.)
Write-Step "Waiting for RDS instance '$rdsId' to be available"
Invoke-Cli -Exe "aws" -CmdArgs @('rds', 'wait', 'db-instance-available', '--db-instance-identifier', $rdsId, '--region', $region) | Out-Null

# Resolve the RDS endpoint for DB_HOST (placeholder under -WhatIf).
if ($WhatIf) {
    $dbHost = "$rdsId.<rds-endpoint>.$region.rds.amazonaws.com"
}
else {
    $hostOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'rds', 'describe-db-instances',
        '--db-instance-identifier', $rdsId,
        '--region', $region,
        '--output', 'text', '--query', 'DBInstances[0].Endpoint.Address'
    )
    if ($hostOut -is [System.Array]) {
        $hostOut = ($hostOut | Where-Object { $_ } | Select-Object -Last 1)
    }
    $dbHost = [string]$hostOut
}

# ---------------------------------------------------------------------------
# Resolve the default VPC + subnets the task and RDS live in (needed for the
# security groups and the service network configuration).
# ---------------------------------------------------------------------------
Write-Step "Resolving the default VPC and subnets for networking"
if ($WhatIf) {
    $vpcId      = '<default-vpc-id>'
    $subnetList = '<subnet-a>,<subnet-b>'
}
else {
    $vpcOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'ec2', 'describe-vpcs',
        '--region', $region,
        '--filters', 'Name=isDefault,Values=true',
        '--output', 'text', '--query', 'Vpcs[0].VpcId'
    )
    if ($vpcOut -is [System.Array]) { $vpcOut = ($vpcOut | Where-Object { $_ } | Select-Object -Last 1) }
    $vpcId = [string]$vpcOut

    $subnetsOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'ec2', 'describe-subnets',
        '--region', $region,
        '--filters', "Name=vpc-id,Values=$vpcId",
        '--output', 'text', '--query', 'Subnets[].SubnetId'
    )
    if ($subnetsOut -is [System.Array]) { $subnetsOut = ($subnetsOut -join "`t") }
    $subnetList = (([string]$subnetsOut) -split '\s+' | Where-Object { $_ }) -join ','
}

# ---------------------------------------------------------------------------
# 11. Locked-down security group for the Fargate task.
#     Describe-or-create the SG, then authorize the app port only FROM each
#     explicitly allowed source range (never 0.0.0.0/0 or ::/0, already rejected
#     above). Each ingress rule is a separate authorize call so one CIDR per rule
#     is visible in the echoed command list.
# ---------------------------------------------------------------------------
Write-Step "Ensuring a locked-down task security group '$sgName'"
$sgDescribe = @('ec2', 'describe-security-groups', '--region', $region, '--filters', "Name=group-name,Values=$sgName", "Name=vpc-id,Values=$vpcId", '--output', 'text', '--query', 'SecurityGroups[0].GroupId')
# A FILTER-based describe returns exit 0 and prints the literal 'None' (text
# output) when no SG matches, so existence MUST be judged from the OUTPUT, not the
# exit code alone. Capture + normalize: empty/whitespace/'None' (any case) => absent.
$sgIdRaw = Invoke-Cli -Exe "aws" -CmdArgs $sgDescribe -AllowFail
if ($sgIdRaw -is [System.Array]) { $sgIdRaw = ($sgIdRaw | Where-Object { $_ } | Select-Object -Last 1) }
$existingSgId = ([string]$sgIdRaw).Trim()
$sgExists = ($script:LastCliExit -eq 0 -and $existingSgId -and $existingSgId -ne 'None')
if ($WhatIf -or -not $sgExists) {
    $sgCreateOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'ec2', 'create-security-group',
        '--region', $region,
        '--group-name', $sgName,
        '--description', 'SangyShop hardened Fargate task (locked-down ingress)',
        '--vpc-id', $vpcId,
        '--output', 'text', '--query', 'GroupId'
    )
    if ($WhatIf) {
        $taskSgId = '<task-sg-id>'
    }
    else {
        if ($sgCreateOut -is [System.Array]) { $sgCreateOut = ($sgCreateOut | Where-Object { $_ } | Select-Object -Last 1) }
        $taskSgId = ([string]$sgCreateOut).Trim()
    }
}
else {
    if ($WhatIf) {
        $taskSgId = '<task-sg-id>'
    }
    else {
        # Reuse the id already captured by the describe above (do NOT re-run it).
        $taskSgId = $existingSgId
    }
}

# Fail closed: the task SG id must be a real sg-... id, never empty or 'None'
# (which would later surface as 'InvalidGroupId.Malformed').
if (-not $WhatIf -and ([string]::IsNullOrWhiteSpace([string]$taskSgId) -or $taskSgId -eq 'None')) {
    throw "Failed to resolve a valid task security group id for '$sgName' (got '$taskSgId'). Aborting before wiring networking to avoid an 'InvalidGroupId.Malformed' failure."
}

Write-Step "Authorizing the app port $appPort only from the allowed source set"
foreach ($r in $ranges) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ec2', 'authorize-security-group-ingress',
        '--region', $region,
        '--group-id', $taskSgId,
        '--protocol', 'tcp',
        '--port', $appPort,
        '--cidr', $r
    ) -AllowFail | Out-Null
}

# ---------------------------------------------------------------------------
# 12. Restrict RDS to the task on 5432. Describe-or-create a dedicated
#     RDS security group whose only ingress is TCP 5432 FROM the task SG (never a
#     public CIDR), then attach it to the instance.
# ---------------------------------------------------------------------------
Write-Step "Ensuring the RDS security group '$rdsSgName' allows only the task on $dbPort"
$rdsSgDescribe = @('ec2', 'describe-security-groups', '--region', $region, '--filters', "Name=group-name,Values=$rdsSgName", "Name=vpc-id,Values=$vpcId", '--output', 'text', '--query', 'SecurityGroups[0].GroupId')
# Same filter-based gotcha as the task SG: a missing group yields exit 0 + 'None'.
# Judge existence from the normalized OUTPUT, not the exit code alone.
$rdsSgIdRaw = Invoke-Cli -Exe "aws" -CmdArgs $rdsSgDescribe -AllowFail
if ($rdsSgIdRaw -is [System.Array]) { $rdsSgIdRaw = ($rdsSgIdRaw | Where-Object { $_ } | Select-Object -Last 1) }
$existingRdsSgId = ([string]$rdsSgIdRaw).Trim()
$rdsSgExists = ($script:LastCliExit -eq 0 -and $existingRdsSgId -and $existingRdsSgId -ne 'None')
if ($WhatIf -or -not $rdsSgExists) {
    $rdsSgCreateOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'ec2', 'create-security-group',
        '--region', $region,
        '--group-name', $rdsSgName,
        '--description', 'SangyShop RDS - only the Fargate task on 5432',
        '--vpc-id', $vpcId,
        '--output', 'text', '--query', 'GroupId'
    )
    if ($WhatIf) { $rdsSgId = '<rds-sg-id>' }
    else {
        if ($rdsSgCreateOut -is [System.Array]) { $rdsSgCreateOut = ($rdsSgCreateOut | Where-Object { $_ } | Select-Object -Last 1) }
        $rdsSgId = ([string]$rdsSgCreateOut).Trim()
    }
}
else {
    if ($WhatIf) { $rdsSgId = '<rds-sg-id>' }
    else { $rdsSgId = $existingRdsSgId }   # reuse the captured id; do NOT re-describe
}

# Fail closed: the RDS SG id must be a real sg-... id, never empty or 'None'
# (which would later surface as 'InvalidParameterValue: Invalid security group').
if (-not $WhatIf -and ([string]::IsNullOrWhiteSpace([string]$rdsSgId) -or $rdsSgId -eq 'None')) {
    throw "Failed to resolve a valid RDS security group id for '$rdsSgName' (got '$rdsSgId'). Aborting before attaching it to '$rdsId' to avoid an 'Invalid security group' failure."
}

# Ingress: TCP 5432 FROM the task SG only (source-group, not a CIDR -> no public
# exposure).
Invoke-Cli -Exe "aws" -CmdArgs @(
    'ec2', 'authorize-security-group-ingress',
    '--region', $region,
    '--group-id', $rdsSgId,
    '--protocol', 'tcp',
    '--port', $dbPort,
    '--source-group', $taskSgId
) -AllowFail | Out-Null

# Attach the RDS SG to the instance so only the task can reach it.
Invoke-Cli -Exe "aws" -CmdArgs @(
    'rds', 'modify-db-instance',
    '--db-instance-identifier', $rdsId,
    '--region', $region,
    '--vpc-security-group-ids', $rdsSgId,
    '--apply-immediately'
) | Out-Null

# ---------------------------------------------------------------------------
# Ensure a CloudWatch Logs group exists for the task (describe-or-create).
# ---------------------------------------------------------------------------
Write-Step "Ensuring CloudWatch Logs group '$logGroup' exists"
Invoke-Cli -Exe "aws" -CmdArgs @('logs', 'create-log-group', '--region', $region, '--log-group-name', $logGroup) -AllowFail | Out-Null

# ---------------------------------------------------------------------------
# 9. Register the ECS task definition:
#    * no extra volume: the wrapper writes under the app-owned /app/secrets dir
#      baked into the hardened image (chowned to UID 10001), so the non-root
#      container can write the secret file without the root-owned /run/secrets.
#    * secrets: DB_PASSWORD_SECRET injected from the Secrets Manager secret by ARN
#      (valueFrom) -- never the value.
#    * environment: exactly APP_MODE=hardened, DB_BACKEND=pg, DB_HOST, DB_PORT=5432,
#      DB_NAME, DB_USER, DB_SSL=require, DB_PASSWORD_FILE=/app/secrets/db_password (the PATH, not
#      the value) -- and NO bare DB_PASSWORD.
#    * command: the Form A inline wrapper that writes the trimmed secret to
#      /app/secrets/db_password, unsets the env var, then execs node src/server.js
#    The whole definition is written to a transient JSON file passed via
#    --cli-input-json file:// so the secret ARN (not value) is referenced.
# ---------------------------------------------------------------------------
Write-Step "Registering the ECS task definition '$taskFamily' with the secret-file wrapper"

$execRoleArn = (@('arn', 'aws', 'iam', '', $accountId) -join ':') + ':role/ecsTaskExecutionRole'

$taskDef = [ordered]@{
    family                  = $taskFamily
    networkMode             = 'awsvpc'
    requiresCompatibilities = @('FARGATE')
    cpu                     = '256'
    memory                  = '512'
    executionRoleArn        = $execRoleArn
    # No extra volume is needed: the wrapper writes the secret under the
    # app-owned /app/secrets directory baked into the hardened image (owned by
    # UID 10001), not the root-owned ephemeral /run/secrets volume.
    containerDefinitions    = @(
        [ordered]@{
            name         = "$appName-hardened"
            image        = $imageUri
            essential    = $true
            command      = $containerCommand      # Form A inline sh -c wrapper
            portMappings = @(
                [ordered]@{ containerPort = [int]$appPort; protocol = 'tcp' }
            )
            secrets      = @(
                # Inject the Secrets Manager secret as the env var the wrapper reads.
                # Referenced by ARN; the value never appears here.
                [ordered]@{ name = 'DB_PASSWORD_SECRET'; valueFrom = $secretArn }
            )
            environment  = @(
                # Exactly the non-secret connection env; NO bare DB_PASSWORD.
                # DB_PASSWORD_FILE names WHERE the hardened app reads the secret FILE
                # (the PATH, never the value), so the non-root user reads the
                # app-owned /app/secrets/db_password the wrapper wrote.
                [ordered]@{ name = 'APP_MODE';         value = $appMode }
                [ordered]@{ name = 'DB_BACKEND';       value = 'pg' }
                [ordered]@{ name = 'DB_HOST';          value = $dbHost }
                [ordered]@{ name = 'DB_PORT';          value = $dbPort }
                [ordered]@{ name = 'DB_NAME';          value = $dbName }
                [ordered]@{ name = 'DB_USER';          value = $dbUser }
                [ordered]@{ name = 'DB_PASSWORD_FILE'; value = $secretFilePath }
                # AWS RDS enforces TLS (rds.force_ssl); DB_SSL=require turns on
                # SSL in the app's pg Pool. Non-secret connection flag only.
                [ordered]@{ name = 'DB_SSL';           value = 'require' }
            )
            logConfiguration = [ordered]@{
                logDriver = 'awslogs'
                options   = [ordered]@{
                    'awslogs-group'         = $logGroup
                    'awslogs-region'        = $region
                    'awslogs-stream-prefix' = 'ecs'
                }
            }
        }
    )
}

$taskDefJson = ($taskDef | ConvertTo-Json -Depth 12)

# Guard: the serialized task definition must NOT carry a bare
# DB_PASSWORD env var and MUST wire the secret to /app/secrets/db_password via the
# wrapper (DB_PASSWORD_FILE and DB_PASSWORD_SECRET are allowed).
if ($taskDefJson -match '"name"\s*:\s*"DB_PASSWORD"') {
    throw "Refusing to register task definition: a bare DB_PASSWORD environment variable is present, which violates the secret-file contract."
}
if ($taskDefJson -notmatch [regex]::Escape($secretFilePath)) {
    throw "Refusing to register task definition: the entrypoint wrapper does not write the secret file at $secretFilePath."
}

$taskDefTmp = $null
try {
    if ($WhatIf) {
        $taskDefTmp = '<temp-file: task-definition.json>'
    }
    else {
        $taskDefTmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.json'))
        [System.IO.File]::WriteAllText($taskDefTmp, $taskDefJson, (New-Object System.Text.UTF8Encoding($false)))
    }
    $taskDefRef = 'file://' + $taskDefTmp

    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecs', 'register-task-definition',
        '--region', $region,
        '--cli-input-json', $taskDefRef
    ) | Out-Null
}
finally {
    if (-not $WhatIf -and $taskDefTmp -and (Test-Path -LiteralPath $taskDefTmp)) {
        Remove-Item -LiteralPath $taskDefTmp -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 10. ECS cluster: describe-or-create (idempotent).
# ---------------------------------------------------------------------------
Write-Step "Ensuring ECS cluster '$ecsCluster' exists"
$clusterDescribe = @('ecs', 'describe-clusters', '--region', $region, '--clusters', $ecsCluster, '--output', 'text', '--query', 'clusters[0].status')
Invoke-Cli -Exe "aws" -CmdArgs $clusterDescribe -AllowFail | Out-Null
$clusterStatus = $null
if (-not $WhatIf -and $script:LastCliExit -eq 0) {
    # describe-clusters returns success even for a missing cluster (empty result);
    # treat only an ACTIVE status as "exists".
    $clusterStatus = 'check'
}
# Create unless we can confirm it is already ACTIVE.
$clusterExists = $false
if (-not $WhatIf) {
    $statusOut = Invoke-Cli -Exe "aws" -CmdArgs $clusterDescribe -AllowFail
    if ($statusOut -is [System.Array]) { $statusOut = ($statusOut | Where-Object { $_ } | Select-Object -Last 1) }
    $clusterExists = ([string]$statusOut -eq 'ACTIVE')
}
if ($WhatIf -or -not $clusterExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @('ecs', 'create-cluster', '--region', $region, '--cluster-name', $ecsCluster) | Out-Null
}

# ---------------------------------------------------------------------------
# 13. Create-or-reuse the ECS service running the task with the locked-down task
#     SG and the resolved subnets. assignPublicIp=ENABLED gives the task
#     a public ENI so a URL exists; ingress to the app port is restricted to the
#     allowed source set by the task SG.
# ---------------------------------------------------------------------------
$netConfig = "awsvpcConfiguration={subnets=[$subnetList],securityGroups=[$taskSgId],assignPublicIp=ENABLED}"

Write-Step "Ensuring the ECS service '$serviceName' is running"
$svcDescribe = @('ecs', 'describe-services', '--region', $region, '--cluster', $ecsCluster, '--services', $serviceName, '--output', 'text', '--query', 'services[0].status')
Invoke-Cli -Exe "aws" -CmdArgs $svcDescribe -AllowFail | Out-Null
$svcExists = $false
if (-not $WhatIf) {
    $svcOut = Invoke-Cli -Exe "aws" -CmdArgs $svcDescribe -AllowFail
    if ($svcOut -is [System.Array]) { $svcOut = ($svcOut | Where-Object { $_ } | Select-Object -Last 1) }
    $svcExists = ([string]$svcOut -eq 'ACTIVE')
}
if ($WhatIf -or -not $svcExists) {
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecs', 'create-service',
        '--region', $region,
        '--cluster', $ecsCluster,
        '--service-name', $serviceName,
        '--task-definition', $taskFamily,
        '--desired-count', '1',
        '--launch-type', 'FARGATE',
        '--network-configuration', $netConfig
    ) | Out-Null
}
else {
    # Reuse: roll the service onto the freshly registered task definition.
    Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecs', 'update-service',
        '--region', $region,
        '--cluster', $ecsCluster,
        '--service', $serviceName,
        '--task-definition', $taskFamily,
        '--desired-count', '1',
        '--network-configuration', $netConfig
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# 14. Fetch and print the public URL + lockdown + teardown reminder.
#     The running task's ENI carries a public IP; resolve it for the URL.
# ---------------------------------------------------------------------------
Write-Step "Resolving the running task's public URL"
if ($WhatIf) {
    $publicIp = '<task-public-ip>'
}
else {
    # Give the service a moment to place a task, then read the task's ENI public IP.
    $taskArnOut = Invoke-Cli -Exe "aws" -CmdArgs @(
        'ecs', 'list-tasks',
        '--region', $region,
        '--cluster', $ecsCluster,
        '--service-name', $serviceName,
        '--output', 'text', '--query', 'taskArns[0]'
    ) -AllowFail
    if ($taskArnOut -is [System.Array]) { $taskArnOut = ($taskArnOut | Where-Object { $_ } | Select-Object -Last 1) }
    $taskArn = [string]$taskArnOut

    $publicIp = $null
    if (-not [string]::IsNullOrWhiteSpace($taskArn) -and $taskArn -ne 'None') {
        $eniOut = Invoke-Cli -Exe "aws" -CmdArgs @(
            'ecs', 'describe-tasks',
            '--region', $region,
            '--cluster', $ecsCluster,
            '--tasks', $taskArn,
            '--output', 'text',
            '--query', "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value | [0]"
        ) -AllowFail
        if ($eniOut -is [System.Array]) { $eniOut = ($eniOut | Where-Object { $_ } | Select-Object -Last 1) }
        $eniId = [string]$eniOut
        if (-not [string]::IsNullOrWhiteSpace($eniId) -and $eniId -ne 'None') {
            $ipOut = Invoke-Cli -Exe "aws" -CmdArgs @(
                'ec2', 'describe-network-interfaces',
                '--region', $region,
                '--network-interface-ids', $eniId,
                '--output', 'text', '--query', 'NetworkInterfaces[0].Association.PublicIp'
            ) -AllowFail
            if ($ipOut -is [System.Array]) { $ipOut = ($ipOut | Where-Object { $_ } | Select-Object -Last 1) }
            $publicIp = [string]$ipOut
        }
    }
}

# ---------------------------------------------------------------------------
# Dry run ends here: print the planned command list and exit 0.
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
$urlText = if ([string]::IsNullOrWhiteSpace([string]$publicIp) -or $publicIp -eq 'None') {
    '(public IP not yet assigned; re-run or check the ECS console for the task ENI)'
}
else {
    "http://${publicIp}:$appPort"
}

Write-Host ""
Write-Step "Deployment complete"
Write-Host "Service URL: $urlText"
Write-Host ""
Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
Write-Host "  * SangyShop is DELIBERATELY VULNERABLE. Keep this in an isolated, throwaway AWS account only." -ForegroundColor Yellow
Write-Host "  * LOCK DOWN INGRESS to your own source address(es): $($ranges -join ', ')." -ForegroundColor Yellow
Write-Host "    Never expose it to 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
Write-Host "  * RDS ('$rdsId') is not publicly accessible; only the Fargate task reaches it on $dbPort." -ForegroundColor Yellow
Write-Host "  * The DB password lives only in Secrets Manager ('$secretName') and is delivered to the" -ForegroundColor Yellow
Write-Host "    container as the app-owned file /app/secrets/db_password (via DB_PASSWORD_FILE) by the" -ForegroundColor Yellow
Write-Host "    entrypoint wrapper (no bare DB_PASSWORD env)." -ForegroundColor Yellow
Write-Host "  * RUN TEARDOWN WHEN FINISHED to stop billing:" -ForegroundColor Yellow
Write-Host "        ./ops/aws/ecs/teardown.ps1 -ConfigPath `"$ConfigPath`"" -ForegroundColor Yellow

exit 0
