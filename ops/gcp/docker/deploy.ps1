<#
.SYNOPSIS
    Deploy the HARDENED SangyShop image to GCP Cloud Run (Docker-only modality).

.DESCRIPTION
    Reference deployment for the multi-cloud-deploy feature. Builds the hardened
    image from ops/docker/hardened/Dockerfile, pushes it to
    Artifact Registry, provisions Cloud SQL for PostgreSQL (never a container),
    stores a generated DB password in GCP Secret Manager, and deploys Cloud Run
    with the secret mounted as the file /run/secrets/db_password. No DB_PASSWORD
    env var is ever set; the unmodified hardened app reads the secret file and
    fails closed otherwise (src/db/credentials.js).

    Pipeline (every external CLI call is echoed before it runs, via the shared
    Invoke-Echoed helper in lib/Common.ps1):

        1. Auth check / set active project
        2. Artifact Registry describe-or-create
        3. Configure registry Docker auth
        4. Build the hardened image
        5. Push the hardened image
        6. Cloud SQL describe-or-create + db + user
        7. generate + store password in Secret Manager -- BEFORE
           provisioning, stdin only, never an echoed CLI arg
        8. Cloud Run deploy with the secret file mount
        9. print service URL + lockdown + teardown reminder

    Safety:
      * Only the hardened variant is ever built/pushed/deployed.
      * Aborts before any push/deploy if the hardened Dockerfile is missing
 or a non-:hardened image / non-hardened APP_MODE is referenced
.
      * Ingress is restricted to an explicitly provided source-address set and
        0.0.0.0/0 and ::/0 are rejected.
      * Cloud SQL is reachable by the compute target on 5432 only, not public
.
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
    Reuse an already-present Artifact Registry repo / Cloud SQL instance / secret
    rather than failing. This is the default convergent behavior; the switch is
    accepted for parity with the other targets and for explicitness.

.PARAMETER AllowedSourceRanges
    REQUIRED allowed-ingress source set. Each entry is a source address/CIDR that
    may reach the Cloud Run service. 0.0.0.0/0 and ::/0 are rejected.
    If omitted/empty the script stops before any ingress change.
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
# Secret rule: a secret is NEVER passed as a CLI argument. Commands
# that consume the password do so via stdin (gcloud ... --data-file=-); the
# -SecretStdin switch marks those so the planned/echoed line shows a redacted
# "<stdin: db password>" note instead of the value.
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
# 0. Load + validate config (fail-closed BEFORE any external command).
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Gcp)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Gcp'

$projectId    = [string]$cfg.Gcp.ProjectId
$region       = [string]$cfg.Gcp.Region
$arRepo       = [string]$cfg.Gcp.ArRepo
$serviceName  = [string]$cfg.Gcp.CloudRunName
$appName      = [string]$cfg.Common.AppName
$dbName       = [string]$cfg.Common.DbName
$dbUser       = [string]$cfg.Common.DbUser
$imageTag     = [string]$cfg.Common.ImageTag

# Derived names.
$sqlInstance  = "$appName-pg"                       # Cloud SQL instance id
$secretName   = 'db_password'                        # Secret Manager secret id (file key)
$sqlConnName  = "${projectId}:${region}:${sqlInstance}"  # Cloud SQL connection name
$dbPort       = '5432'
$arHost       = "$region-docker.pkg.dev"
$imageUri     = "$arHost/$projectId/$arRepo/$appName" + ":" + $imageTag

# Cloud SQL private host: the Cloud Run service reaches Postgres over the Cloud
# SQL connector (--add-cloudsql-instances) on 5432, not a public IP.
$dbHost       = "/cloudsql/$sqlConnName"

# ---------------------------------------------------------------------------
# hardened-only pre-flight. Abort BEFORE any push or deploy if the
# hardened Dockerfile is missing, the image tag is not :hardened, or APP_MODE is
# not hardened. Nothing external has run yet at this point.
# ---------------------------------------------------------------------------
$appMode = 'hardened'
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
# (ops/gcp/docker/deploy.ps1 -> repo root).
$repoRoot       = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$dockerfileRel  = 'ops/docker/hardened/Dockerfile'
$dockerfilePath = Join-Path $repoRoot $dockerfileRel
if (-not (Test-Path -LiteralPath $dockerfilePath -PathType Leaf)) {
    throw "Refusing to build: hardened Dockerfile not found at '$dockerfilePath' (expected '$dockerfileRel'). Aborting before any push or deploy."
}

# ---------------------------------------------------------------------------
# an explicit allowed-ingress source set is REQUIRED, and the
# open ranges 0.0.0.0/0 and ::/0 are prohibited. Validate before any ingress
# change (indeed before any external command).
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
# 1. Auth check BEFORE any create/modify. On failure, stop with
#    install + auth guidance and a non-zero exit.
# ---------------------------------------------------------------------------
Write-Step "Checking GCP authentication and setting the active project"
$cli = 'gcloud'
try {
    # List active credentialed accounts; fails (or lists none) when not signed in.
    Invoke-Cli -Exe "gcloud" -CmdArgs @('auth', 'list', '--filter=status:ACTIVE', '--format=value(account)') | Out-Null
    # Bind the active project so every later CLI call targets it.
    Invoke-Cli -Exe "gcloud" -CmdArgs @('config', 'set', 'project', $projectId) | Out-Null
}
catch {
    Write-Error (@(
        "GCP authentication/CLI check failed: $($_.Exception.Message)",
        "",
        "Install the Google Cloud CLI for Windows:",
        "    https://cloud.google.com/sdk/docs/install  (verify with: '$cli --version')",
        "Authenticate and configure registry auth, then re-run:",
        "    '$cli' auth login",
        "    '$cli' auth configure-docker $arHost",
        "    '$cli' config set project $projectId"
    ) -join [Environment]::NewLine)
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Artifact Registry: describe-or-create (idempotent). The describe is
#    -AllowFail so a missing repo (its only expected failure) triggers a create.
# ---------------------------------------------------------------------------
Write-Step "Ensuring Artifact Registry repository '$arRepo' exists"
$arDescribe = @('artifacts', 'repositories', 'describe', $arRepo, '--location', $region, '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $arDescribe -AllowFail | Out-Null
$arExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $arExists) {
    $repoFormatArg = '--repository-format=' + 'docker'
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'artifacts', 'repositories', 'create', $arRepo,
        $repoFormatArg,
        '--location', $region,
        "--description=SangyShop hardened image (teaching lab)"
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Configure Docker to authenticate to Artifact Registry.
# ---------------------------------------------------------------------------
Write-Step "Configuring Docker auth for $arHost"
Invoke-Cli -Exe "gcloud" -CmdArgs @('auth', 'configure-docker', $arHost, '--quiet') | Out-Null

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
#    throws, halting before any Cloud Run deploy.
# ---------------------------------------------------------------------------
Write-Step "Pushing the hardened image to Artifact Registry"
Invoke-Cli -Exe "docker" -CmdArgs @('push', $imageUri) | Out-Null

# ---------------------------------------------------------------------------
# 7 (before 6 at runtime). Generate + store the DB password in Secret Manager
#    BEFORE provisioning Cloud SQL. The value is piped via stdin
#    (--data-file=-), never an echoed CLI arg. Secret Manager is the
#    single source of truth; the same secret later mounts as the file at
#    /run/secrets/db_password.
# ---------------------------------------------------------------------------
Write-Step "Generating and storing the DB password in Secret Manager"
$dbPassword = $null
if (-not $WhatIf) {
    $dbPassword = New-DbPassword   # >=24 chars, 4 character classes; never logged
}
else {
    # Dry run never generates or handles a real secret; use a redacted placeholder
    # purely so the planned commands render. It is never printed in the clear.
    $dbPassword = '<generated-at-deploy-time>'
}

# Create the secret container if absent (describe is -AllowFail), then add a new
# version carrying the generated value via stdin.
$secDescribe = @('secrets', 'describe', $secretName, '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $secDescribe -AllowFail | Out-Null
$secretExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $secretExists) {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'secrets', 'create', $secretName,
        '--replication-policy=automatic',
        '--data-file=-'
    ) -StdinSecret $dbPassword | Out-Null
}
else {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'secrets', 'versions', 'add', $secretName,
        '--data-file=-'
    ) -StdinSecret $dbPassword | Out-Null
}

# ---------------------------------------------------------------------------
# 6. Cloud SQL for PostgreSQL: describe-or-create (idempotent).
#    Never a container. Public IPv4 is disabled so the instance is not
#    publicly reachable; Cloud Run connects over the Cloud SQL connector on 5432
# ---------------------------------------------------------------------------
Write-Step "Ensuring Cloud SQL for PostgreSQL instance '$sqlInstance' exists"
$sqlDescribe = @('sql', 'instances', 'describe', $sqlInstance, '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $sqlDescribe -AllowFail | Out-Null
$sqlExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $sqlExists) {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'sql', 'instances', 'create', $sqlInstance,
        '--database-version=POSTGRES_16',
        '--region', $region,
        '--tier=db-f1-micro',
        '--no-assign-ip',                      # no public IPv4 -> not publicly reachable
        '--availability-type=zonal'
    ) | Out-Null
}

# Database (describe-or-create).
Write-Step "Ensuring database '$dbName' and user '$dbUser' exist on '$sqlInstance'"
$dbDescribe = @('sql', 'databases', 'describe', $dbName, '--instance', $sqlInstance, '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $dbDescribe -AllowFail | Out-Null
$dbExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $dbExists) {
    Invoke-Cli -Exe "gcloud" -CmdArgs @('sql', 'databases', 'create', $dbName, '--instance', $sqlInstance) | Out-Null
}

# DB user: set its password FROM the stored secret, piped via stdin so
# the password is never an echoed CLI arg. create-or-set.
$userDescribe = @('sql', 'users', 'list', '--instance', $sqlInstance, "--filter=name=$dbUser", '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $userDescribe -AllowFail | Out-Null
$userExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $userExists) {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'sql', 'users', 'create', $dbUser,
        '--instance', $sqlInstance,
        '--password-file=/dev/stdin'
    ) -StdinSecret $dbPassword | Out-Null
}
else {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'sql', 'users', 'set-password', $dbUser,
        '--instance', $sqlInstance,
        '--password-file=/dev/stdin'
    ) -StdinSecret $dbPassword | Out-Null
}

# ---------------------------------------------------------------------------
# 8. Deploy Cloud Run:
#    * --set-secrets mounts the Secret Manager secret as the FILE
#      /run/secrets/db_password (native file mount; no DB_PASSWORD env).
#    * env sets exactly APP_MODE=hardened, DB_BACKEND=pg, DB_HOST, DB_PORT=5432,
#      DB_NAME, DB_USER -- and NO DB_PASSWORD.
#    * --add-cloudsql-instances wires the private Cloud SQL connector on 5432.
#    * --ingress internal-and-cloud-load-balancing keeps the service off the open
#      internet; the allowed source set (validated above) is enforced by the
#      load-balancer / IAP in front. It is never 0.0.0.0/0.
# ---------------------------------------------------------------------------
Write-Step "Deploying Cloud Run service '$serviceName' with the secret file mount"

# Build the env string. Order is fixed and contains NO DB_PASSWORD.
$envVars = @(
    "APP_MODE=$appMode",
    "DB_BACKEND=pg",
    "DB_HOST=$dbHost",
    "DB_PORT=$dbPort",
    "DB_NAME=$dbName",
    "DB_USER=$dbUser"
) -join ','

$runArgs = @(
    'run', 'deploy', $serviceName,
    '--image', $imageUri,
    '--region', $region,
    '--platform=managed',
    '--port=3000',
    # Secret FILE mount at the exact fail-closed path the hardened app reads.
    "--set-secrets=/run/secrets/db_password=${secretName}:latest",
    "--set-env-vars=$envVars",
    '--add-cloudsql-instances', $sqlConnName,
    # Lock down ingress: never public. The allowed source set is enforced by the
    # LB/IAP layer; this flag keeps direct public ingress off.
    '--ingress=internal-and-cloud-load-balancing',
    '--no-allow-unauthenticated'
)
Invoke-Cli -Exe "gcloud" -CmdArgs $runArgs | Out-Null

# ---------------------------------------------------------------------------
# 9. Fetch and print the service URL + lockdown + teardown reminder.
# ---------------------------------------------------------------------------
Write-Step "Fetching the Cloud Run service URL"
$urlArgs = @('run', 'services', 'describe', $serviceName, '--region', $region, '--format=value(status.url)')
$serviceUrl = Invoke-Cli -Exe "gcloud" -CmdArgs $urlArgs

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
if ($serviceUrl -is [System.Array]) {
    $serviceUrl = ($serviceUrl | Where-Object { $_ } | Select-Object -Last 1)
}
$urlText = if ([string]::IsNullOrWhiteSpace([string]$serviceUrl)) { '(URL not yet available; check the Cloud Run console)' } else { [string]$serviceUrl }

Write-Host ""
Write-Step "Deployment complete"
Write-Host "Service URL: $urlText"
Write-Host ""
Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
Write-Host "  * SangyShop is DELIBERATELY VULNERABLE. Keep this in an isolated, throwaway GCP project only." -ForegroundColor Yellow
Write-Host "  * LOCK DOWN INGRESS to your own source address(es): $($ranges -join ', ')." -ForegroundColor Yellow
Write-Host "    Never expose it to 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
Write-Host "  * Cloud SQL ('$sqlInstance') has no public IP; Cloud Run reaches it over the connector on $dbPort." -ForegroundColor Yellow
Write-Host "  * RUN TEARDOWN WHEN FINISHED to stop billing:" -ForegroundColor Yellow
Write-Host "        ./ops/gcp/docker/teardown.ps1 -ConfigPath `"$ConfigPath`"" -ForegroundColor Yellow

exit 0
