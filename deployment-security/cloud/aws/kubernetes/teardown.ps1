<#
.SYNOPSIS
    Tear down the HARDENED SangyShop AWS EKS deployment (Kubernetes modality).

.DESCRIPTION
    Matching teardown for aws/kubernetes/deploy.ps1. Removes every resource that
    deploy.ps1 created, in REVERSE dependency order so a dependent resource is
    gone before the thing it depends on (Req 5.2):

        1. Kubernetes workload       (compute, in-cluster)          (Req 5.2)
           Pointed at the cluster first via `aws eks update-kubeconfig`,
           then removed with `kubectl delete namespace sangyshop-hardened
           --ignore-not-found`. Deleting the namespace removes the whole
           overlay (Deployment, Service/LoadBalancer, Secret, PVCs, ...) in
           one convergent, already-idempotent command, which is simpler and
           more reliable than re-rendering the overlay just to delete it.
        2. RDS for PostgreSQL        (managed Postgres instance)    (Req 5.2)
        3. Secrets Manager secret    (stored DB password)           (Req 5.2)
        4. EKS cluster               (managed Kubernetes control plane)
        5. ECR repository            (native registry) -- LAST, and
           only unless -KeepRegistry                                (Req 5.3)

    Every external CLI call routes through the shared Invoke-Echoed helper in
    lib/Common.ps1 (Req 1.3), so each command is echoed before it runs. The
    executable name is only ever passed as the -Exe argument, never a bare token;
    this script never calls `aws` or `kubectl` directly (echo-only rule).

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

    Windows PowerShell 5.1 compatible (Req 6.1). No bash/sh is ever invoked (Req 6.2).

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (deployment-security/cloud/cloud.config.ps1).

.PARAMETER Force
    Skip the interactive confirmation prompt and proceed with the (destructive)
    teardown. Without it, an interactive host is asked to confirm before anything
    is deleted; under -WhatIf no confirmation is needed (nothing is deleted).

.PARAMETER KeepRegistry
    Preserve the ECR repository (and the pushed hardened image). When set, step 5
    is skipped so the registry survives teardown (Req 5.3).

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0 (Req 6.5).

.EXAMPLE
    .\teardown.ps1

.EXAMPLE
    .\teardown.ps1 -KeepRegistry

.EXAMPLE
    .\teardown.ps1 -WhatIf
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
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
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
    if ($AllowFail) {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    }
    else {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
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

# Run one deletion and classify its outcome. A non-zero exit whose output looks
# like a "not found / already deleted" case is tolerated as success (Req 5.4);
# any other non-zero exit is a real failure that is reported to stderr and flips
# the exit code, but DOES NOT stop the remaining deletions (Req 5.6).
function Remove-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Identifier,  # human-readable id for reporting
        [Parameter(Mandatory)][string]   $Exe,         # 'aws' or 'kubectl'
        [Parameter(Mandatory)][string[]] $CmdArgs       # CLI args (without the exe)
    )

    $output = Invoke-Cli -Exe $Exe -CmdArgs $CmdArgs -AllowFail

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
    # Req 5.4) from a real failure (reported + non-success, Req 5.6). The AWS CLI
    # reports a missing resource with messages/codes such as "ResourceNotFound",
    # "DBInstanceNotFound", "RepositoryNotFoundException", "ResourceNotFoundException",
    # or a kubectl "NotFound"/"not found".
    $text = ''
    if ($null -ne $output) { $text = ($output | Out-String) }
    $alreadyGone = $text -match '(?i)(not\s*found|notfound|does\s*not\s*exist|was\s*not\s*found|no\s*such|could\s*not\s*be\s*found|ResourceNotFoundException|RepositoryNotFoundException|DBInstanceNotFound)'

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

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command, Req 7.1).
#    Config-derived names mirror deploy.ps1 exactly.
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Aws)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws'

$region      = [string]$cfg.Aws.Region
$ecrRepo     = [string]$cfg.Aws.EcrRepo
$eksCluster  = [string]$cfg.Aws.EksCluster
$appName     = [string]$cfg.Common.AppName

# Derived names / identifiers (identical to deploy.ps1).
$namespace   = 'sangyshop-hardened'          # from the base hardened manifest / overlay
$rdsInstance = "$appName-pg"                  # RDS DB instance identifier
$secretName  = "$appName/db_password"         # Secrets Manager secret id (DB password)

# ---------------------------------------------------------------------------
# Confirmation (destructive). Skipped under -WhatIf (nothing is deleted) and
# when -Force is passed. The delete commands themselves also carry non-interactive
# flags so they never prompt on their own.
# ---------------------------------------------------------------------------
if (-not $WhatIf -and -not $Force) {
    Write-Host ""
    Write-Host "This will PERMANENTLY DELETE the following AWS resources (region $region):" -ForegroundColor Yellow
    Write-Host "  * Kubernetes namespace     : $namespace (on EKS cluster $eksCluster)" -ForegroundColor Yellow
    Write-Host "  * RDS for PostgreSQL        : $rdsInstance" -ForegroundColor Yellow
    Write-Host "  * Secrets Manager secret    : $secretName" -ForegroundColor Yellow
    Write-Host "  * EKS cluster               : $eksCluster" -ForegroundColor Yellow
    if ($KeepRegistry) {
        Write-Host "  * ECR repository           : $ecrRepo  (KEPT: -KeepRegistry)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  * ECR repository           : $ecrRepo" -ForegroundColor Yellow
    }
    Write-Host ""
    $answer = Read-Host "Type 'yes' to proceed (or re-run with -Force to skip this prompt)"
    if ($answer -ne 'yes') {
        Write-Host "Teardown aborted; nothing was deleted." -ForegroundColor Cyan
        exit 0
    }
}

if ($WhatIf) {
    Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
}

# ---------------------------------------------------------------------------
# 1. Kubernetes workload (compute first, Req 5.2).
#
#    Point kubectl at the EKS cluster, then delete the namespace the overlay
#    deploys into. `--ignore-not-found` makes the delete itself idempotent, and
#    deleting the namespace removes the entire in-cluster footprint (Deployment,
#    LoadBalancer Service, synced Secret, PVCs) in one convergent command -- the
#    simplest reliable approach vs. re-rendering the overlay just to delete it.
#
#    update-kubeconfig is not a delete; route it through Invoke-Cli (echo-only,
#    -AllowFail so a missing/unreachable cluster does not stop the rest of the
#    teardown -- RDS/Secrets Manager/EKS/ECR still get cleaned up).
# ---------------------------------------------------------------------------
Write-Step "Pointing kubectl at EKS cluster '$eksCluster' (Req 5.2)"
Invoke-Cli -Exe "aws" -CmdArgs @(
    'eks', 'update-kubeconfig',
    '--name', $eksCluster,
    '--region', $region
) -AllowFail | Out-Null

Write-Step "Removing Kubernetes namespace '$namespace' (Req 5.2)"
Remove-Resource -Identifier "k8s-namespace/$namespace" -Exe "kubectl" -CmdArgs @(
    'delete', 'namespace', $namespace,
    '--ignore-not-found'
)

# ---------------------------------------------------------------------------
# 2. RDS for PostgreSQL instance (managed Postgres, Req 5.2). --skip-final-snapshot
#    so no retained (billable) snapshot survives teardown; --no-... keeps it
#    non-interactive.
# ---------------------------------------------------------------------------
Write-Step "Removing RDS instance '$rdsInstance' (Req 5.2)"
Remove-Resource -Identifier "rds/$rdsInstance" -Exe "aws" -CmdArgs @(
    'rds', 'delete-db-instance',
    '--db-instance-identifier', $rdsInstance,
    '--skip-final-snapshot',
    '--delete-automated-backups',
    '--region', $region
)

# ---------------------------------------------------------------------------
# 3. Secrets Manager secret (stored DB password, Req 5.2).
#    --force-delete-without-recovery removes it immediately with no recovery
#    window, so the secret is truly gone and re-runs converge (Req 5.4).
# ---------------------------------------------------------------------------
Write-Step "Removing Secrets Manager secret '$secretName' (Req 5.2)"
Remove-Resource -Identifier "secrets-manager/$secretName" -Exe "aws" -CmdArgs @(
    'secretsmanager', 'delete-secret',
    '--secret-id', $secretName,
    '--force-delete-without-recovery',
    '--region', $region
)

# ---------------------------------------------------------------------------
# 4. EKS cluster (managed Kubernetes control plane, Req 5.2). The cluster is
#    removed after the in-cluster workload and the managed Postgres + secret.
# ---------------------------------------------------------------------------
Write-Step "Removing EKS cluster '$eksCluster' (Req 5.2)"
Remove-Resource -Identifier "eks-cluster/$eksCluster" -Exe "aws" -CmdArgs @(
    'eks', 'delete-cluster',
    '--name', $eksCluster,
    '--region', $region
)

# ---------------------------------------------------------------------------
# 5. ECR repository (native registry, removed LAST, Req 5.3).
#    Skipped entirely when -KeepRegistry preserves the registry + image.
#    --force deletes the repository even if it still contains the pushed images.
# ---------------------------------------------------------------------------
if ($KeepRegistry) {
    Write-Step "Keeping ECR repository '$ecrRepo' (-KeepRegistry) (Req 5.3)"
}
else {
    Write-Step "Removing ECR repository '$ecrRepo' (last) (Req 5.3)"
    Remove-Resource -Identifier "ecr/$ecrRepo" -Exe "aws" -CmdArgs @(
        'ecr', 'delete-repository',
        '--repository-name', $ecrRepo,
        '--force',
        '--region', $region
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
    Write-Host "(ECR repository '$ecrRepo' was kept at your request.)" -ForegroundColor Cyan
}
exit 0
