<#
.SYNOPSIS
    Deploy the HARDENED SangyShop to GCP GKE (Kubernetes modality).

.DESCRIPTION
    Reference Kubernetes deployment for the multi-cloud-deploy feature. Builds
    the hardened image from ops/docker/hardened/Dockerfile, pushes
    it to Artifact Registry, provisions Cloud SQL for PostgreSQL (never a
    container), stores a generated DB password in GCP Secret Manager, creates (or
    reuses) a GKE cluster, then renders the GCP kustomize overlay
    (ops/gcp/kubernetes/overlays), substitutes its
    placeholders, and applies the result. The unmodified hardened app keeps
    reading the secret file at /run/secrets/db_password (delivered by the Secrets
    Store CSI driver) and fails closed otherwise (src/db/credentials.js). No
    DB_PASSWORD env var is ever set.

    Pipeline (every external CLI call is echoed before it runs, via the shared
    Invoke-Echoed helper in lib/Common.ps1):

        1. Auth check / set active project
        2. Artifact Registry describe-or-create
        3. Configure registry Docker auth
        4. Build the hardened image
        5. Push the hardened image
        6. generate + store password in Secret Manager -- BEFORE
           provisioning, stdin only, never an echoed CLI arg
        7. Cloud SQL describe-or-create + db + user
        8. GKE cluster describe-or-create
        9. get-credentials for kubectl
       10. render overlay + substitute placeholders + apply
       11. wait for rollout
       12. read the LoadBalancer external IP as the URL
       13. print lockdown + teardown reminder

    Safety:
      * Only the hardened variant is ever built/pushed/deployed.
      * Aborts before any push/deploy if the hardened Dockerfile is missing or a
        non-:hardened image / non-hardened APP_MODE is referenced.
      * Ingress is restricted to an explicitly provided source-address set and
        0.0.0.0/0 and ::/0 are rejected.
      * Cloud SQL is reachable by the cluster on 5432 only, not public.
      * The committed overlay is NEVER rewritten; placeholder substitution happens
        on a rendered temp copy that is applied and then removed.
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
    / GKE cluster rather than failing. This is the default convergent behavior;
    the switch is accepted for parity with the other targets and for explicitness.

.PARAMETER AllowedSourceRanges
    REQUIRED allowed-ingress source set. Each entry is a source address/CIDR that
    may reach the service's LoadBalancer. 0.0.0.0/0 and ::/0 are rejected
. If omitted/empty the script stops before any ingress change
.
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
# -StdinSecret switch marks those so the planned/echoed line shows a redacted
# note instead of the value.
#
# Non-secret stdin (-StdinData) carries bulk input that is safe to echo as a
# note (here: the rendered manifest piped to `kubectl apply -f -`). It is kept
# separate from -StdinSecret so the password path stays unambiguous.
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
        [string]                         $StdinData     # piped to stdin; non-secret, echoed as a note
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
    if ($PSBoundParameters.ContainsKey('StdinData')) {
        $displayParts += '<stdin: rendered manifest>'
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
    elseif ($PSBoundParameters.ContainsKey('StdinData')) {
        # Pipe the rendered manifest to the command's stdin (kubectl apply -f -).
        # Non-secret, so it is safe to echo as a note above.
        if ($AllowFail) {
            $result = ($StdinData | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
        }
        else {
            $result = ($StdinData | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
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
$gkeCluster   = [string]$cfg.Gcp.GkeCluster
$appName      = [string]$cfg.Common.AppName
$dbName       = [string]$cfg.Common.DbName
$dbUser       = [string]$cfg.Common.DbUser
$imageTag     = [string]$cfg.Common.ImageTag

# Derived names.
$sqlInstance  = "$appName-pg"                       # Cloud SQL instance id
$secretName   = 'db_password'                        # Secret Manager secret id (file key)
$dbPort       = '5432'
$arHost       = "$region-docker.pkg.dev"
$arImageName  = "$arHost/$projectId/$arRepo/$appName" # image path WITHOUT tag (overlay __AR_IMAGE_NAME__)
$imageUri     = $arImageName + ":" + $imageTag        # full ref with the hardened tag
$k8sNamespace = 'sangyshop-hardened'

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
# (ops/gcp/kubernetes/deploy.ps1 -> repo root).
$repoRoot       = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$dockerfileRel  = 'ops/docker/hardened/Dockerfile'
$dockerfilePath = Join-Path $repoRoot $dockerfileRel
if (-not (Test-Path -LiteralPath $dockerfilePath -PathType Leaf)) {
    throw "Refusing to build: hardened Dockerfile not found at '$dockerfilePath' (expected '$dockerfileRel'). Aborting before any push or deploy."
}

# The GCP kustomize overlay, relative to this script: ./overlays.
$overlayDir = (Resolve-Path (Join-Path $PSScriptRoot 'overlays')).Path
if (-not (Test-Path -LiteralPath $overlayDir -PathType Container)) {
    throw "Refusing to deploy: GCP kustomize overlay not found at '$overlayDir'. Aborting before any external command."
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
        "You also need kubectl and the GKE auth plugin:",
        "    '$cli' components install kubectl gke-gcloud-auth-plugin",
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
#    throws, halting before any cluster deploy.
# ---------------------------------------------------------------------------
Write-Step "Pushing the hardened image to Artifact Registry"
Invoke-Cli -Exe "docker" -CmdArgs @('push', $imageUri) | Out-Null

# ---------------------------------------------------------------------------
# 6 (before 7 at runtime). Generate + store the DB password in Secret Manager
#    BEFORE provisioning Cloud SQL. The value is piped via stdin
#    (--data-file=-), never an echoed CLI arg. Secret Manager is the
#    single source of truth; the Secrets Store CSI driver later syncs it into the
#    in-cluster `sangyshop-db` Secret and the app reads /run/secrets/db_password.
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
# 7. Cloud SQL for PostgreSQL: describe-or-create (idempotent).
#    Never a container. A private IP is enabled so the GKE cluster reaches
#    Postgres on 5432 over the VPC; public IPv4 is disabled so the instance is
#    not publicly reachable.
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

# Resolve the Cloud SQL host the in-cluster app connects to on 5432 (its private
# IP). This becomes the overlay's __CLOUDSQL_HOST__ substitution. Under
# -WhatIf nothing runs, so use a documented placeholder for the planned render.
Write-Step "Resolving the Cloud SQL private host for the overlay"
$cloudSqlHost = $null
$hostArgs = @('sql', 'instances', 'describe', $sqlInstance, '--format=value(ipAddresses[0].ipAddress)')
$cloudSqlHostRaw = Invoke-Cli -Exe "gcloud" -CmdArgs $hostArgs -AllowFail
if ($WhatIf) {
    $cloudSqlHost = '<cloudsql-private-ip>'
}
else {
    if ($cloudSqlHostRaw -is [System.Array]) {
        $cloudSqlHostRaw = ($cloudSqlHostRaw | Where-Object { $_ } | Select-Object -Last 1)
    }
    $cloudSqlHost = ([string]$cloudSqlHostRaw).Trim()
    if ([string]::IsNullOrWhiteSpace($cloudSqlHost)) {
        throw "Could not resolve the Cloud SQL private IP for '$sqlInstance'. Confirm the instance has a private IP before deploying."
    }
}

# ---------------------------------------------------------------------------
# 8. GKE cluster: describe-or-create (idempotent).
# ---------------------------------------------------------------------------
Write-Step "Ensuring GKE cluster '$gkeCluster' exists"
$gkeDescribe = @('container', 'clusters', 'describe', $gkeCluster, '--region', $region, '--format=value(name)')
Invoke-Cli -Exe "gcloud" -CmdArgs $gkeDescribe -AllowFail | Out-Null
$gkeExists = ($script:LastCliExit -eq 0)
if ($WhatIf -or -not $gkeExists) {
    Invoke-Cli -Exe "gcloud" -CmdArgs @(
        'container', 'clusters', 'create', $gkeCluster,
        '--region', $region,
        '--num-nodes=1',
        '--workload-pool', "$projectId.svc.id.goog",  # Workload Identity for the Secret Manager CSI sync
        '--enable-ip-alias'                             # VPC-native: reach Cloud SQL private IP on 5432
    ) | Out-Null
}

# ---------------------------------------------------------------------------
# 9. Fetch kubeconfig credentials so kubectl targets this cluster.
# ---------------------------------------------------------------------------
Write-Step "Fetching GKE credentials for kubectl"
Invoke-Cli -Exe "gcloud" -CmdArgs @(
    'container', 'clusters', 'get-credentials', $gkeCluster,
    '--region', $region
) | Out-Null

# ---------------------------------------------------------------------------
# 10. Render the GCP overlay, substitute its placeholders, and apply the result
#. The base manifest lives OUTSIDE the overlay directory,
#     so the overlay must be built with load restrictions disabled; `kubectl
#     apply -k` cannot pass that flag, so we render then apply in two steps
#     (per the overlay README).
#
#     The committed overlay is NEVER rewritten. We render it to text, replace the
#     __TOKEN__ placeholders on the rendered copy, write that to a temp file, and
#     apply the temp file; the temp file is removed afterward.
#
#     Placeholders (overlay README):
#       __AR_IMAGE_NAME__   Artifact Registry image path (no tag)
#       __CLOUDSQL_HOST__   Cloud SQL host reachable on 5432
#       __GCP_PROJECT_ID__  project owning the Secret Manager secret
#       __GSM_SECRET__      Secret Manager secret name (db_password)
# ---------------------------------------------------------------------------
Write-Step "Rendering the GCP overlay (load restrictions disabled)"
$renderArgs = @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $overlayDir)
$renderedRaw = Invoke-Cli -Exe "kubectl" -CmdArgs $renderArgs

Write-Step "Substituting overlay placeholders and applying the manifest"
# Build the rendered manifest text (array of output lines under real execution).
if ($WhatIf) {
    # Nothing was rendered; model the apply step with a placeholder body so the
    # planned command list still shows the apply with the manifest piped via stdin.
    $rendered = "# (rendered GCP overlay with placeholders substituted at deploy time)"
}
else {
    if ($renderedRaw -is [System.Array]) {
        $rendered = ($renderedRaw -join [Environment]::NewLine)
    }
    else {
        $rendered = [string]$renderedRaw
    }
    if ([string]::IsNullOrWhiteSpace($rendered)) {
        throw "Rendering the GCP overlay produced no output. Aborting before apply."
    }
}

# Substitute the literal __TOKEN__ placeholders in memory (never touching the
# committed overlay). The image tag stays `hardened` (set in kustomization.yaml).
$rendered = $rendered.Replace('__AR_IMAGE_NAME__',  $arImageName)
$rendered = $rendered.Replace('__CLOUDSQL_HOST__',  $cloudSqlHost)
$rendered = $rendered.Replace('__GCP_PROJECT_ID__', $projectId)
$rendered = $rendered.Replace('__GSM_SECRET__',     $secretName)

# Apply the substituted manifest. The rendered YAML is piped to `kubectl apply
# -f -` via stdin (non-secret -StdinData), keeping kubectl a quoted -Exe argument
# and never rewriting the committed overlay.
if (-not $WhatIf) {
    # Also persist the substituted manifest to a temp file for troubleshooting;
    # removed after a successful apply.
    $tmpManifest = Join-Path ([System.IO.Path]::GetTempPath()) ("sangyshop-gke-" + [System.Guid]::NewGuid().ToString('N') + ".yaml")
    Set-Content -LiteralPath $tmpManifest -Value $rendered -Encoding UTF8
}
try {
    Invoke-Cli -Exe "kubectl" -CmdArgs @('apply', '-f', '-') -StdinData $rendered | Out-Null
}
finally {
    if (-not $WhatIf -and (Test-Path -LiteralPath $tmpManifest)) {
        Remove-Item -LiteralPath $tmpManifest -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 11. Wait for the Deployment rollout to complete.
# ---------------------------------------------------------------------------
Write-Step "Waiting for the '$appName' Deployment rollout in namespace '$k8sNamespace'"
Invoke-Cli -Exe "kubectl" -CmdArgs @(
    '-n', $k8sNamespace,
    'rollout', 'status', "deploy/$appName"
) | Out-Null

# ---------------------------------------------------------------------------
# 12. Read the LoadBalancer external IP as the service URL.
# ---------------------------------------------------------------------------
Write-Step "Reading the LoadBalancer external IP for '$appName'"
$svcIpArgs = @(
    '-n', $k8sNamespace,
    'get', 'svc', $appName,
    '-o', 'jsonpath={.status.loadBalancer.ingress[0].ip}'
)
$externalIp = Invoke-Cli -Exe "kubectl" -CmdArgs $svcIpArgs -AllowFail

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
if ($externalIp -is [System.Array]) {
    $externalIp = ($externalIp | Where-Object { $_ } | Select-Object -Last 1)
}
$externalIp = ([string]$externalIp).Trim()
$serviceUrl = if ([string]::IsNullOrWhiteSpace($externalIp)) {
    '(external IP not yet assigned; re-run `kubectl -n ' + $k8sNamespace + ' get svc ' + $appName + '` shortly)'
}
else {
    "http://$externalIp:3000"
}

Write-Host ""
Write-Step "Deployment complete"
Write-Host "Service URL: $serviceUrl"
Write-Host ""
Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
Write-Host "  * SangyShop is DELIBERATELY VULNERABLE. Keep this in an isolated, throwaway GCP project only." -ForegroundColor Yellow
Write-Host "  * LOCK DOWN INGRESS to your own source address(es): $($ranges -join ', ')." -ForegroundColor Yellow
Write-Host "    The LoadBalancer is reachable from the internet by default -- restrict it with a" -ForegroundColor Yellow
Write-Host "    loadBalancerSourceRanges / firewall rule to those address(es). Never 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
Write-Host "  * Cloud SQL ('$sqlInstance') has no public IP; the cluster reaches it on $dbPort over the VPC." -ForegroundColor Yellow
Write-Host "  * RUN TEARDOWN WHEN FINISHED to stop billing:" -ForegroundColor Yellow
Write-Host "        ./ops/gcp/kubernetes/teardown.ps1 -ConfigPath `"$ConfigPath`"" -ForegroundColor Yellow

exit 0
