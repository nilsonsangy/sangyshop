<#
.SYNOPSIS
    Tear down the HARDENED SangyShop GCP Cloud Run deployment (Docker-only modality).

.DESCRIPTION
    Matching teardown for gcp/docker/deploy.ps1. Removes every resource that
    deploy.ps1 created, in REVERSE dependency order so a dependent resource is
    gone before the thing it depends on:

        1. Cloud Run service         (compute)
        2. Cloud SQL for PostgreSQL  (managed Postgres instance)
        3. Secret Manager secret     (stored DB password)
        4. Artifact Registry repo    (native registry) -- LAST, and
           only unless -KeepRegistry

    Every external CLI call routes through the shared Invoke-Echoed helper in
    lib/Common.ps1, so each command is echoed before it runs. The
    executable name is only ever passed as the -Exe argument, never a bare token.

    Convergent / idempotent: every deletion uses -AllowFail, so a
    resource that is already gone is treated as successfully removed and skipped,
    and a second run of this script converges to zero remaining resources and
    exits success. Each resource whose deletion command ran without a real error
    has its identifier printed.

    Fail-but-continue: a real removal failure (a non-zero exit that is
    NOT the "already deleted / not found" case) does NOT stop teardown. The script
    records the failure, reports it to stderr naming the resource, keeps removing
    the remaining resources, and finally exits with a NON-success status. Only an
    already-deleted resource is tolerated silently.

    -WhatIf: print the full ordered command list that WOULD run, execute
    no external command, and exit 0.

    Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (ops/cloud.config.ps1).

.PARAMETER Force
    Skip the interactive confirmation prompt and proceed with the (destructive)
    teardown. Without it, an interactive host is asked to confirm before anything
    is deleted; under -WhatIf no confirmation is needed (nothing is deleted).

.PARAMETER KeepRegistry
    Preserve the Artifact Registry repository (and the pushed hardened image).
    When set, step 4 is skipped so the registry survives teardown.

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0.
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [switch] $Force,
    [switch] $KeepRegistry,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Dot-source the shared library (Invoke-Echoed, Write-Step, Get-CloudConfig).
# Relative to this script: ../../lib/Common.ps1.
. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

# ---------------------------------------------------------------------------
# WhatIf-aware command runner (mirrors deploy.ps1's Invoke-Cli).
#
# Every external CLI call goes through Invoke-Cli, never a bare CLI token
#. Under -WhatIf it records and prints the planned command line and
# executes NOTHING; otherwise it delegates to the shared Invoke-Echoed
# helper, which echoes the exact command and then runs it.
#
# Teardown always passes -AllowFail: a non-zero exit must not throw,
# so the caller can inspect $script:LastCliExit, decide whether it was an
# "already deleted" case, and keep going regardless.
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs
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
    $display = $displayParts -join ' '

    if ($WhatIf) {
        # record + print the planned command; execute NOTHING.
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Real execution path: route through the shared, echoing helper.
    # -AllowFail so an already-deleted resource's non-zero exit returns control
    # here instead of throwing.
    $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# ---------------------------------------------------------------------------
# Removal bookkeeping.
#
# $removed       : identifiers whose deletion command ran without a real error
#                  (deleted now OR already gone). Printed on success.
# $failures      : identifiers that hit a real (non-"already deleted") failure.
# $realFailure   : the flag that drives the final non-success exit code.
# ---------------------------------------------------------------------------
$script:removed     = New-Object System.Collections.Generic.List[string]
$script:failures    = New-Object System.Collections.Generic.List[string]
$script:realFailure = $false

# Run one deletion and classify its outcome. A non-zero exit whose output looks
# like a "not found / already deleted" case is tolerated as success;
# any other non-zero exit is a real failure that is reported to stderr and flips
# the exit code, but DOES NOT stop the remaining deletions.
function Remove-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Identifier,  # human-readable id for reporting
        [Parameter(Mandatory)][string[]] $CmdArgs       # CLI args (without the exe)
    )

    $output = Invoke-Cli -Exe 'gcloud' -CmdArgs $CmdArgs

    if ($WhatIf) {
        # Nothing executed; planning only. Do not record removal under a dry run.
        return
    }

    if ($script:LastCliExit -eq 0) {
        $script:removed.Add($Identifier)
        Write-Host "    removed: $Identifier" -ForegroundColor Green
        return
    }

    # Non-zero exit. Distinguish "already deleted / not found" (tolerated)
    # from a real failure (reported + non-success).
    $text = ''
    if ($null -ne $output) { $text = ($output | Out-String) }
    $alreadyGone = $text -match '(?i)\b(not\s*found|does\s*not\s*exist|was\s*not\s*found|no\s*such|NOT_FOUND|could\s*not\s*be\s*found)\b'

    if ($alreadyGone) {
        # Converge: treat an already-absent resource as removed.
        $script:removed.Add("$Identifier (already absent)")
        Write-Host "    already absent (skipped): $Identifier" -ForegroundColor DarkGray
    }
    else {
        # Real failure: record, report to stderr, continue.
        $script:realFailure = $true
        $script:failures.Add($Identifier)
        Write-Error "Failed to remove: $Identifier (CLI exit $($script:LastCliExit)). Continuing with remaining resources."
    }
}

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command).
#    Config-derived names mirror deploy.ps1 exactly.
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Gcp)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Gcp'

$projectId   = [string]$cfg.Gcp.ProjectId
$region      = [string]$cfg.Gcp.Region
$arRepo      = [string]$cfg.Gcp.ArRepo
$serviceName = [string]$cfg.Gcp.CloudRunName
$appName     = [string]$cfg.Common.AppName

# Derived names (identical to deploy.ps1).
$sqlInstance = "$appName-pg"     # Cloud SQL instance id
$secretName  = 'db_password'      # Secret Manager secret id (file key)

# ---------------------------------------------------------------------------
# Confirmation (destructive). Skipped under -WhatIf (nothing is deleted) and
# when -Force is passed. The delete commands themselves also carry --quiet so
# they never prompt on their own.
# ---------------------------------------------------------------------------
if (-not $WhatIf -and -not $Force) {
    Write-Host ""
    Write-Host "This will PERMANENTLY DELETE the following GCP resources for project '$projectId':" -ForegroundColor Yellow
    Write-Host "  * Cloud Run service        : $serviceName (region $region)" -ForegroundColor Yellow
    Write-Host "  * Cloud SQL instance       : $sqlInstance" -ForegroundColor Yellow
    Write-Host "  * Secret Manager secret    : $secretName" -ForegroundColor Yellow
    if ($KeepRegistry) {
        Write-Host "  * Artifact Registry repo   : $arRepo  (KEPT: -KeepRegistry)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  * Artifact Registry repo   : $arRepo (region $region)" -ForegroundColor Yellow
    }
    Write-Host ""
    $answer = Read-Host "Type 'yes' to proceed (or re-run with -Force to skip this prompt)"
    if ($answer -ne 'yes') {
        Write-Host "Teardown aborted; nothing was deleted." -ForegroundColor Cyan
        exit 0
    }
}

# ---------------------------------------------------------------------------
# 1. Cloud Run service (compute first).
# ---------------------------------------------------------------------------
Write-Step "Removing Cloud Run service '$serviceName'"
Remove-Resource -Identifier "cloud-run/$serviceName" -CmdArgs @(
    'run', 'services', 'delete', $serviceName,
    '--region', $region,
    '--platform=managed',
    '--quiet'
)

# ---------------------------------------------------------------------------
# 2. Cloud SQL for PostgreSQL instance (managed Postgres).
# ---------------------------------------------------------------------------
Write-Step "Removing Cloud SQL instance '$sqlInstance'"
Remove-Resource -Identifier "cloud-sql/$sqlInstance" -CmdArgs @(
    'sql', 'instances', 'delete', $sqlInstance,
    '--quiet'
)

# ---------------------------------------------------------------------------
# 3. Secret Manager secret (stored DB password).
# ---------------------------------------------------------------------------
Write-Step "Removing Secret Manager secret '$secretName'"
Remove-Resource -Identifier "secret-manager/$secretName" -CmdArgs @(
    'secrets', 'delete', $secretName,
    '--quiet'
)

# ---------------------------------------------------------------------------
# 4. Artifact Registry repository (native registry, removed LAST).
#    Skipped entirely when -KeepRegistry preserves the registry + image.
# ---------------------------------------------------------------------------
if ($KeepRegistry) {
    Write-Step "Keeping Artifact Registry repository '$arRepo' (-KeepRegistry)"
}
else {
    Write-Step "Removing Artifact Registry repository '$arRepo' (last)"
    Remove-Resource -Identifier "artifact-registry/$arRepo" -CmdArgs @(
        'artifacts', 'repositories', 'delete', $arRepo,
        '--location', $region,
        '--quiet'
    )
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

# ---------------------------------------------------------------------------
# Final report.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Step "Teardown summary"
if ($script:removed.Count -gt 0) {
    Write-Host "Removed resource(s):"
    foreach ($id in $script:removed) {
        Write-Host "  - $id"
    }
}
else {
    Write-Host "No resources were removed (nothing to remove, or all were already absent)."
}

if ($script:realFailure) {
    Write-Host ""
    Write-Error (@(
        "Teardown finished with failures. The following resource(s) could NOT be removed:",
        ($script:failures | ForEach-Object { "  - $_" })
    ) -join [Environment]::NewLine)
    # a real removal failure means a NON-success exit status.
    exit 1
}

# every resource was removed (or already absent); exit success.
Write-Host ""
Write-Host "Teardown complete: zero billable resources remain for this target." -ForegroundColor Green
if ($KeepRegistry) {
    Write-Host "(Artifact Registry repository '$arRepo' was kept at your request.)" -ForegroundColor Cyan
}
exit 0
