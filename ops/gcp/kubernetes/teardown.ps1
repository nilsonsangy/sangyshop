<#
.SYNOPSIS
    Tear down the HARDENED SangyShop GCP GKE deployment (Kubernetes modality).

.DESCRIPTION
    Matching teardown for gcp/kubernetes/deploy.ps1. Removes every resource that
    deploy.ps1 created, in REVERSE dependency order so a dependent resource is
    gone before the thing it depends on (Req 5.2):

        1. In-cluster app workload   (rendered GCP overlay)         (Req 5.1/5.2)
        2. GKE cluster               (compute)                      (Req 5.2)
        3. Cloud SQL for PostgreSQL  (managed Postgres instance)    (Req 5.2)
        4. Secret Manager secret     (stored DB password)           (Req 5.2)
        5. Artifact Registry repo    (native registry) -- LAST, and
           only unless -KeepRegistry                                (Req 5.3)

    Every external CLI call routes through the shared Invoke-Echoed helper in
    lib/Common.ps1 (Req 1.3), so each command is echoed before it runs. The
    executable name ('gcloud' / 'kubectl') is only ever passed as the -Exe
    argument, never a bare token, satisfying the AST-based echo-only guard.

    Step 1 (the in-cluster workload) is removed the same way deploy.ps1 applied
    it: the base hardened manifest lives OUTSIDE the overlay directory, so the
    GCP overlay is rendered with load restrictions disabled and piped to a
    delete (kubectl kustomize --load-restrictor LoadRestrictionsNone <dir> |
    kubectl delete -f -). As a convergent safety net, the whole
    'sangyshop-hardened' namespace is also deleted with --ignore-not-found, which
    removes anything the overlay delete missed and makes a re-run idempotent.
    Both cluster deletes use -AllowFail, so when the cluster credentials are gone
    (because the GKE cluster was already removed on a prior run) the step is
    tolerated and teardown continues.

    Convergent / idempotent (Req 5.4): every deletion uses -AllowFail, so a
    resource that is already gone is treated as successfully removed and skipped,
    and a second run of this script converges to zero remaining resources and
    exits success. Each resource whose deletion command ran without a real error
    has its identifier printed (Req 5.5).

    Fail-but-continue (Req 5.6): a real removal failure (a non-zero exit that is
    NOT the "already deleted / not found" case) does NOT stop teardown. The script
    records the failure, reports it to stderr naming the resource, keeps removing
    the remaining resources, and finally exits with a NON-success status. Only an
    already-deleted resource is tolerated silently.

    -WhatIf (Req 6.5): print the full ordered command list that WOULD run, execute
    no external command, and exit 0.

    Windows PowerShell 5.1 compatible (Req 6.1).

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (ops/cloud.config.ps1).

.PARAMETER Force
    Skip the interactive confirmation prompt and proceed with the (destructive)
    teardown. Without it, an interactive host is asked to confirm before anything
    is deleted; under -WhatIf no confirmation is needed (nothing is deleted).

.PARAMETER KeepRegistry
    Preserve the Artifact Registry repository (and the pushed hardened image).
    When set, the final step is skipped so the registry survives teardown (Req 5.3).

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0 (Req 6.5).
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
# (Req 1.3). Under -WhatIf it records and prints the planned command line and
# executes NOTHING (Req 6.5); otherwise it delegates to the shared Invoke-Echoed
# helper, which echoes the exact command and then runs it.
#
# Teardown always passes -AllowFail (Req 5.4/5.6): a non-zero exit must not throw,
# so the caller can inspect $script:LastCliExit, decide whether it was an
# "already deleted" case, and keep going regardless.
#
# -StdinData carries the rendered manifest piped to `kubectl delete -f -`. It is
# non-secret, so it is echoed as a note; this teardown never handles the DB
# password at all (the stored secret is removed by id, not read).
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [string]                         $StdinData   # piped to stdin; non-secret, echoed as a note
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
    if ($PSBoundParameters.ContainsKey('StdinData')) {
        $displayParts += '<stdin: rendered manifest>'
    }
    $display = $displayParts -join ' '

    if ($WhatIf) {
        # Req 6.5: record + print the planned command; execute NOTHING.
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Real execution path: route through the shared, echoing helper (Req 1.3).
    # -AllowFail so an already-deleted resource's non-zero exit returns control
    # here instead of throwing (Req 5.4/5.6).
    $result = $null
    if ($PSBoundParameters.ContainsKey('StdinData')) {
        # Pipe the rendered manifest to the command's stdin (kubectl delete -f -).
        $result = ($StdinData | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    }
    else {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    }
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# ---------------------------------------------------------------------------
# Removal bookkeeping (Req 5.5 / 5.6).
#
# $removed       : identifiers whose deletion command ran without a real error
#                  (deleted now OR already gone). Printed on success.
# $failures      : identifiers that hit a real (non-"already deleted") failure.
# $realFailure   : the flag that drives the final non-success exit code.
# ---------------------------------------------------------------------------
$script:removed     = New-Object System.Collections.Generic.List[string]
$script:failures    = New-Object System.Collections.Generic.List[string]
$script:realFailure = $false

# Classify the outcome of the most recent Invoke-Cli call for $Identifier. A
# non-zero exit whose output looks like a "not found / already deleted" case is
# tolerated as success (Req 5.4); any other non-zero exit is a real failure that
# is reported to stderr and flips the exit code, but DOES NOT stop the remaining
# deletions (Req 5.6). $Output is the captured command output used to detect the
# already-gone case.
function Resolve-RemovalOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Identifier,  # human-readable id for reporting
        [object]                       $Output        # captured CLI output (for already-gone detection)
    )

    if ($WhatIf) {
        # Nothing executed; planning only. Do not record removal under a dry run.
        return
    }

    if ($script:LastCliExit -eq 0) {
        $script:removed.Add($Identifier)
        Write-Host "    removed: $Identifier" -ForegroundColor Green
        return
    }

    # Non-zero exit. Distinguish "already deleted / not found" (tolerated,
    # Req 5.4) from a real failure (reported + non-success, Req 5.6).
    $text = ''
    if ($null -ne $Output) { $text = ($Output | Out-String) }
    $alreadyGone = $text -match '(?i)\b(not\s*found|does\s*not\s*exist|was\s*not\s*found|no\s*such|NOT_FOUND|could\s*not\s*be\s*found|no\s*objects\s*passed)\b'

    if ($alreadyGone) {
        # Converge: treat an already-absent resource as removed (Req 5.4).
        $script:removed.Add("$Identifier (already absent)")
        Write-Host "    already absent (skipped): $Identifier" -ForegroundColor DarkGray
    }
    else {
        # Real failure: record, report to stderr, continue (Req 5.6).
        $script:realFailure = $true
        $script:failures.Add($Identifier)
        Write-Error "Failed to remove: $Identifier (CLI exit $($script:LastCliExit)). Continuing with remaining resources."
    }
}

# Convenience wrapper for the gcloud-based removals (steps 3-5): run one delete
# and immediately classify its outcome.
function Remove-GcloudResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Identifier,  # human-readable id for reporting
        [Parameter(Mandatory)][string[]] $CmdArgs       # CLI args (without the exe)
    )
    $output = Invoke-Cli -Exe 'gcloud' -CmdArgs $CmdArgs
    Resolve-RemovalOutcome -Identifier $Identifier -Output $output
}

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command, Req 7.1).
#    Config-derived names mirror deploy.ps1 exactly.
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Gcp)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Gcp'

$projectId   = [string]$cfg.Gcp.ProjectId
$region      = [string]$cfg.Gcp.Region
$arRepo      = [string]$cfg.Gcp.ArRepo
$gkeCluster  = [string]$cfg.Gcp.GkeCluster
$appName     = [string]$cfg.Common.AppName

# Derived names (identical to deploy.ps1).
$sqlInstance  = "$appName-pg"           # Cloud SQL instance id
$secretName   = 'db_password'            # Secret Manager secret id (file key)
$k8sNamespace = 'sangyshop-hardened'     # namespace the base hardened manifest creates

# The GCP kustomize overlay, relative to this script: ./overlays.
# Resolved so the render pipe (step 1) can point at it. Resolve-Path fails loudly
# if the committed overlay is missing, before any external command runs.
$overlayDir = (Resolve-Path (Join-Path $PSScriptRoot 'overlays')).Path

# ---------------------------------------------------------------------------
# Confirmation (destructive). Skipped under -WhatIf (nothing is deleted) and
# when -Force is passed. The gcloud delete commands themselves also carry --quiet
# so they never prompt on their own.
# ---------------------------------------------------------------------------
if (-not $WhatIf -and -not $Force) {
    Write-Host ""
    Write-Host "This will PERMANENTLY DELETE the following GCP resources for project '$projectId':" -ForegroundColor Yellow
    Write-Host "  * In-cluster workload      : overlay 'gcp' + namespace '$k8sNamespace' on cluster '$gkeCluster'" -ForegroundColor Yellow
    Write-Host "  * GKE cluster              : $gkeCluster (region $region)" -ForegroundColor Yellow
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
# 1. In-cluster app workload (compute first, Req 5.1/5.2). Delete what deploy.ps1
#    applied. The base manifest lives OUTSIDE the overlay dir, so the overlay is
#    rendered with load restrictions disabled and piped to `kubectl delete -f -`
#    (mirror of deploy.ps1's apply pipe). kubectl must first target the cluster,
#    so get-credentials runs ahead of it; that step is -AllowFail so a
#    non-existent cluster (already torn down) is tolerated.
#
#    The 'sangyshop-hardened' namespace is then deleted with --ignore-not-found as
#    a convergent catch-all: it removes anything the overlay delete missed and
#    makes a re-run idempotent (--ignore-not-found yields exit 0 when it is gone).
# ---------------------------------------------------------------------------
Write-Step "Fetching GKE credentials so kubectl targets '$gkeCluster' (Req 5.1)"
$credOutput = Invoke-Cli -Exe 'gcloud' -CmdArgs @(
    'container', 'clusters', 'get-credentials', $gkeCluster,
    '--region', $region
)
$clusterReachable = ($WhatIf -or $script:LastCliExit -eq 0)
if (-not $clusterReachable) {
    # The cluster is already gone (or credentials cannot be fetched); the overlay
    # and namespace deletes below would only error on the same missing cluster.
    # Record the workload as already absent and skip to the cluster delete (Req 5.4).
    $txt = ''
    if ($null -ne $credOutput) { $txt = ($credOutput | Out-String) }
    Write-Host "    cluster credentials unavailable; treating in-cluster workload as already absent." -ForegroundColor DarkGray
    $script:removed.Add("gke-workload/overlay+namespace:$k8sNamespace (already absent)")
}
else {
    Write-Step "Rendering the GCP overlay (load restrictions disabled) for deletion (Req 5.1)"
    $renderArgs  = @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $overlayDir)
    $renderedRaw = Invoke-Cli -Exe 'kubectl' -CmdArgs $renderArgs

    if ($WhatIf) {
        # Nothing was rendered; model the delete step with a placeholder body so the
        # planned command list still shows the delete with the manifest piped via stdin.
        $rendered = "# (rendered GCP overlay to delete at teardown time)"
    }
    else {
        if ($renderedRaw -is [System.Array]) {
            $rendered = ($renderedRaw -join [Environment]::NewLine)
        }
        else {
            $rendered = [string]$renderedRaw
        }
    }

    Write-Step "Deleting the in-cluster workload (rendered overlay) (Req 5.1/5.2)"
    if ($WhatIf -or -not [string]::IsNullOrWhiteSpace($rendered)) {
        $delOutput = Invoke-Cli -Exe 'kubectl' -CmdArgs @(
            'delete', '-f', '-', '--ignore-not-found'
        ) -StdinData $rendered
        Resolve-RemovalOutcome -Identifier "gke-workload/overlay:gcp" -Output $delOutput
    }

    Write-Step "Deleting the namespace '$k8sNamespace' as a convergent catch-all (Req 5.1/5.4)"
    $nsOutput = Invoke-Cli -Exe 'kubectl' -CmdArgs @(
        'delete', 'namespace', $k8sNamespace, '--ignore-not-found'
    )
    Resolve-RemovalOutcome -Identifier "gke-namespace/$k8sNamespace" -Output $nsOutput
}

# ---------------------------------------------------------------------------
# 2. GKE cluster (compute, Req 5.2). Removed after its workload.
# ---------------------------------------------------------------------------
Write-Step "Removing GKE cluster '$gkeCluster' (Req 5.2)"
Remove-GcloudResource -Identifier "gke-cluster/$gkeCluster" -CmdArgs @(
    'container', 'clusters', 'delete', $gkeCluster,
    '--region', $region,
    '--quiet'
)

# ---------------------------------------------------------------------------
# 3. Cloud SQL for PostgreSQL instance (managed Postgres, Req 5.2).
# ---------------------------------------------------------------------------
Write-Step "Removing Cloud SQL instance '$sqlInstance' (Req 5.2)"
Remove-GcloudResource -Identifier "cloud-sql/$sqlInstance" -CmdArgs @(
    'sql', 'instances', 'delete', $sqlInstance,
    '--quiet'
)

# ---------------------------------------------------------------------------
# 4. Secret Manager secret (stored DB password, Req 5.2).
# ---------------------------------------------------------------------------
Write-Step "Removing Secret Manager secret '$secretName' (Req 5.2)"
Remove-GcloudResource -Identifier "secret-manager/$secretName" -CmdArgs @(
    'secrets', 'delete', $secretName,
    '--quiet'
)

# ---------------------------------------------------------------------------
# 5. Artifact Registry repository (native registry, removed LAST, Req 5.3).
#    Skipped entirely when -KeepRegistry preserves the registry + image.
# ---------------------------------------------------------------------------
if ($KeepRegistry) {
    Write-Step "Keeping Artifact Registry repository '$arRepo' (-KeepRegistry) (Req 5.3)"
}
else {
    Write-Step "Removing Artifact Registry repository '$arRepo' (last) (Req 5.3)"
    Remove-GcloudResource -Identifier "artifact-registry/$arRepo" -CmdArgs @(
        'artifacts', 'repositories', 'delete', $arRepo,
        '--location', $region,
        '--quiet'
    )
}

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

# ---------------------------------------------------------------------------
# Final report (Req 5.5 / 5.6).
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
    # Req 5.6: a real removal failure means a NON-success exit status.
    exit 1
}

# Req 5.4 / 5.5: every resource was removed (or already absent); exit success.
Write-Host ""
Write-Host "Teardown complete: zero billable resources remain for this target." -ForegroundColor Green
if ($KeepRegistry) {
    Write-Host "(Artifact Registry repository '$arRepo' was kept at your request.)" -ForegroundColor Cyan
}
exit 0
