<#
.SYNOPSIS
    Tears down everything the matching azure/kubernetes/deploy.ps1 created: the
    in-cluster app workload (the Azure kustomize overlay / the
    'sangyshop-hardened' namespace), the AKS cluster, Azure DB for PostgreSQL
    Flexible Server, the Key Vault secret + vault, the Key-Vault-reader
    user-assigned managed identity (and its Key Vault access policy), and
    (unless -KeepRegistry) the Azure Container Registry. Kubernetes modality.

.DESCRIPTION
    The destroy half of the Azure Kubernetes (AKS) target in the
    multi-cloud-deploy spec. Resources are removed in REVERSE dependency order
    (Req 5.2): the in-cluster workload first, then the AKS cluster (compute),
    then the managed Postgres server, then the stored DB password (secret) and
    its vault, then the Key-Vault reader identity + access policy, then
    (optionally) the registry.

      1. Validates config and checks `az` authentication (fail-closed).
      2. Points kubectl at the AKS cluster (`az aks get-credentials`, tolerated)
         and deletes the in-cluster workload. The base hardened manifest lives
         OUTSIDE the overlay dir, so the committed overlay is rendered with load
         restrictions disabled and piped to `kubectl delete -f -`; the whole
         'sangyshop-hardened' namespace is then deleted with --ignore-not-found
         as the simplest convergent catch-all that removes anything the overlay
         delete missed and makes a re-run idempotent.
      3. Deletes the AKS cluster.
      4. Deletes the Flexible Server.
      5. Deletes the Key Vault secret, then the Key Vault itself.
      6. Removes the Key Vault `get` access policy for the reader identity, then
         deletes the user-assigned identity deploy created so no orphaned
         principal/policy is left behind.
      7. Deletes the ACR unless -KeepRegistry (Req 5.3).

    EVERY external CLI call goes through Invoke-Echoed from lib/Common.ps1
    (echo-before-exec, Req 1.3). This script never calls `az`/`kubectl` directly.

    Every delete is issued with -AllowFail so an already-deleted resource is
    skipped and treated as successfully removed; this makes re-runs converge to
    "nothing left" and exit success (Req 5.4). The identifier of each removed
    resource is printed to stdout (Req 5.5). On a REAL removal failure (anything
    other than "not found"), teardown keeps going, records the resource, writes an
    error indication to stderr, and exits non-success (Req 5.6).

    As a documented catch-all, `az group delete --name <rg> --yes --no-wait`
    removes everything in the lab resource group in one shot. It is destructive
    and resource-group-wide, so it only runs when -Force is given; otherwise the
    exact command is printed for the operator to run manually.

    SECURITY NOTE: SangyShop is deliberately vulnerable. Tearing it down promptly
    is mandatory: these resources are billable and must never be left exposed.

    Windows PowerShell 5.1 compatible (Req 6.1). No bash/sh is ever invoked (Req 6.2).

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the shared config two levels up.

.PARAMETER Force
    Also issue the resource-group-wide catch-all `az group delete --yes --no-wait`
    after the targeted deletes. Without -Force, that command is only PRINTED (not
    run) so the operator can decide; the per-resource deletes still happen.

.PARAMETER KeepRegistry
    Preserve the Azure Container Registry (and its images). By default the ACR is
    deleted, since deploy.ps1 created it (Req 5.3).

.PARAMETER WhatIf
    Dry run (Req 6.5): prints the full ordered list of external commands that
    WOULD run, executes nothing, and exits 0.

.EXAMPLE
    .\teardown.ps1

.EXAMPLE
    .\teardown.ps1 -KeepRegistry

.EXAMPLE
    .\teardown.ps1 -Force          # also runs the resource-group-wide catch-all

.EXAMPLE
    .\teardown.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $Force,
    [switch] $KeepRegistry,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve the script directory robustly (works whether invoked by path, dot-source,
# or via the call operator) and default -ConfigPath to the shared config two levels up.
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = (Join-Path $scriptDir '..\..\cloud.config.ps1')
}

# --- Dot-source the shared library (Invoke-Echoed, Write-Step, config). ---
. (Join-Path $scriptDir '..\..\lib\Common.ps1')

# =============================================================================
# -WhatIf planning: in dry-run we only print the command line that WOULD run and
# execute nothing. Invoke-Planned is the single gate every external call passes
# through so the echo-only rule (Req 1.3) and the dry-run rule (Req 6.5) are both
# satisfied from one place. Mirrors azure/docker/teardown.ps1, with -StdinText
# added so the rendered overlay can be piped to `kubectl delete -f -` (the body
# is non-secret and echoed as a redacted note).
# =============================================================================
$script:PlanOrdinal = 0
$script:LastCliExit  = 0

function Invoke-Planned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail,
        [string]                         $StdinText     # piped to stdin; non-secret, echoed as a note
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
    if ($PSBoundParameters.ContainsKey('StdinText')) {
        $displayParts += '<stdin: rendered manifest>'
    }
    $display = $displayParts -join ' '

    if ($WhatIf) {
        $script:PlanOrdinal++
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    $result = $null
    if ($PSBoundParameters.ContainsKey('StdinText')) {
        # Pipe the (non-secret) rendered manifest to the command's stdin.
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
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# Convenience wrappers so call sites read cleanly. Teardown always tolerates
# failure (every delete uses -AllowFail, Req 5.4), so AzTry forwards -AllowFail;
# Az is kept for parity/read-only shape in the plan.
# kubectl calls use single-dash flags (-n / -o / -f) that collide with the
# parameter binder through a ValueFromRemainingArguments wrapper, so they go
# through Invoke-Planned -Exe 'kubectl' -CmdArgs @(...) directly instead.
function Az    { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A }
function AzTry { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A -AllowFail }

# -----------------------------------------------------------------------------
# Teardown bookkeeping. $removed holds the identifiers of resources we removed
# (or confirmed already gone) for the stdout summary (Req 5.5); $failed holds any
# resource whose delete returned a REAL error so we can report to stderr and exit
# non-success (Req 5.6).
# -----------------------------------------------------------------------------
$script:removed = New-Object System.Collections.Generic.List[string]
$script:failed  = New-Object System.Collections.Generic.List[string]

# Classify the outcome of the most recent CLI call for $Id. A zero exit means the
# resource was removed (or the no-op was accepted). A non-zero exit is inspected:
# a "not found / does not exist" style failure is an already-deleted resource and
# counts as success (Req 5.4); any other non-zero is a real failure recorded for
# stderr + non-success exit (Req 5.6). $Output is the captured command output.
function Resolve-RemovalOutcome {
    param(
        [Parameter(Mandatory)][string] $Id,
        [object]                       $Output
    )

    if ($WhatIf) { return }   # planning only; nothing executed

    if ($script:LastCliExit -eq 0) {
        $script:removed.Add($Id)
        Write-Host ("  removed: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }

    $text = ''
    if ($null -ne $Output) { $text = ($Output | Out-String) }
    if ($text -match '(?i)(not\s*found|does\s*not\s*exist|was\s*not\s*found|resourcenotfound|could\s*not\s*be\s*found|no\s*such|no\s*objects\s*passed)') {
        $script:removed.Add($Id + ' (already absent)')
        Write-Host ("  already absent: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }

    $script:failed.Add($Id)
    Write-Host ("  FAILED to remove (continuing): {0}" -f $Id) -ForegroundColor Red
}

# Issue one `az` delete command, tolerate "already deleted", and classify it.
# In -WhatIf we only enqueue the command into the plan (nothing executes).
function Remove-Resource {
    param(
        [Parameter(Mandatory)][string]   $Id,       # human-readable resource identifier
        [Parameter(Mandatory)][string[]] $CmdArgs   # az arguments (without the leading 'az')
    )

    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail | Out-Null
        return
    }

    $output = Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail
    Resolve-RemovalOutcome -Id $Id -Output $output
}

# =============================================================================
# Main
# =============================================================================
try {
    Write-Step "Loading and validating configuration (Azure)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure'

    # --- Resolve names from config (mirror deploy.ps1 exactly so the same
    #     resources are targeted). ---
    $suffix  = [string]$cfg['UniqueSuffix']
    $common  = $cfg['Common']
    $azure   = $cfg['Azure']

    $appName = [string]$common['AppName']

    $rg      = [string]$azure['ResourceGroup']
    $acrBase = [string]$azure['AcrNameBase']
    $kvBase  = [string]$azure['KeyVaultBase']
    $aksName = [string]$azure['AksCluster']

    $acrName  = ($acrBase + $suffix)                 # ACR = base + suffix (alnum only)
    $kvName   = ($kvBase + '-' + $suffix)            # Key Vault = base + '-' + suffix
    $kvSecret = 'db-password'                         # Key Vault secret NAME (not a value)
    $pgServer = ($appName + '-pg-' + $suffix)        # Flexible Server name
    $idName   = ($appName + '-aks-kv-' + $suffix)    # user-assigned identity: KV reader for the CSI provider

    # The in-cluster workload lives in this namespace (created by the base
    # hardened manifest). Deleting it is the simplest convergent catch-all.
    $k8sNamespace = 'sangyshop-hardened'

    # The committed Azure kustomize overlay, relative to this script:
    # ../../manifests/overlays/azure. The base hardened manifest lives OUTSIDE it,
    # so deletion renders the overlay with load restrictions disabled and pipes it
    # to `kubectl delete -f -` (mirror of deploy.ps1's apply pipe). Resolve now so
    # a missing overlay fails loudly before any external command runs.
    $overlayDir = $null
    try {
        $overlayDir = (Resolve-Path (Join-Path $scriptDir '..\..\manifests\overlays\azure')).Path
    }
    catch {
        $overlayDir = $null
    }

    Write-Step "Teardown target summary (reverse dependency order)"
    Write-Host ("  Resource group : {0}" -f $rg)
    Write-Host ("  In-cluster     : overlay 'azure' + namespace '{0}' on cluster '{1}'" -f $k8sNamespace, $aksName)
    Write-Host ("  AKS cluster    : {0}" -f $aksName)
    Write-Host ("  Flexible Server: {0}" -f $pgServer)
    Write-Host ("  Key Vault      : {0} (secret: {1})" -f $kvName, $kvSecret)
    Write-Host ("  KV reader id   : {0}" -f $idName)
    if ($KeepRegistry) {
        Write-Host ("  ACR            : {0} (KEPT; -KeepRegistry)" -f $acrName)
    }
    else {
        Write-Host ("  ACR            : {0} (will be deleted)" -f $acrName)
    }

    if ($WhatIf) {
        Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
    }

    # -------------------------------------------------------------------------
    # Authentication check (fail-closed). `az account show` succeeds only when the
    # CLI is installed AND a session is active. On failure, print install + auth
    # guidance and exit non-zero so we never report a false "nothing left".
    # -------------------------------------------------------------------------
    Write-Step "Checking Azure CLI authentication"
    if ($WhatIf) {
        Az account show --output none | Out-Null
    }
    else {
        $null = AzTry account show --output none
        if ($LASTEXITCODE -ne 0) {
            Write-Error (@(
                "Azure authentication check failed (az account show).",
                "",
                "Install the Azure CLI (Windows):",
                "  winget install --exact --id Microsoft.AzureCLI",
                "  (or download the MSI from https://aka.ms/installazurecliwindows )",
                "Verify:  az version",
                "",
                "This teardown also uses the cluster CLI; install it (if missing) with:",
                "  az aks install-cli",
                "",
                "Authenticate to the SAME (isolated / throwaway) subscription you deployed to:",
                "  az login",
                "  az account set --subscription <your-subscription-id>",
                "",
                "Then re-run this script."
            ) -join [Environment]::NewLine)
            exit 1
        }
    }

    # -------------------------------------------------------------------------
    # 1. In-cluster workload first (Req 5.1/5.2). Point kubectl at the AKS cluster
    #    (get-credentials is -AllowFail so an already-deleted cluster is tolerated
    #    and teardown continues to the cluster delete). If the cluster is
    #    reachable, render the committed overlay with load restrictions disabled
    #    and pipe it to `kubectl delete -f -`, then delete the whole namespace with
    #    --ignore-not-found as the simplest convergent catch-all (removes anything
    #    the overlay delete missed; a re-run converges, Req 5.4).
    # -------------------------------------------------------------------------
    Write-Step "Pointing kubectl at AKS cluster '$aksName' (tolerated if already gone)"
    $credOutput = $null
    if ($WhatIf) {
        Az aks get-credentials --name $aksName --resource-group $rg --overwrite-existing --output none | Out-Null
    }
    else {
        $credOutput = AzTry aks get-credentials --name $aksName --resource-group $rg --overwrite-existing --output none
    }
    $clusterReachable = ($WhatIf -or $script:LastCliExit -eq 0)

    if (-not $clusterReachable) {
        # The cluster is already gone (or credentials cannot be fetched); the
        # overlay/namespace deletes would only error on the same missing cluster.
        # Record the workload as already absent and skip to the cluster delete.
        Write-Host "  cluster credentials unavailable; treating in-cluster workload as already absent." -ForegroundColor DarkGray
        $script:removed.Add("in-cluster workload (overlay 'azure' + namespace '" + $k8sNamespace + "') (already absent)")
    }
    else {
        # 1a. Delete the committed overlay (rendered, load-restrictor pipe form).
        if ($null -ne $overlayDir) {
            Write-Step "Deleting the in-cluster workload from the rendered Azure overlay (Req 5.1/5.2)"
            if ($WhatIf) {
                # Plan both halves of the pipe without executing anything. The
                # committed overlay path documents the build source for the plan.
                Invoke-Planned -Exe 'kubectl' -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $overlayDir) | Out-Null
                Invoke-Planned -Exe 'kubectl' -CmdArgs @('delete', '-f', '-', '--ignore-not-found') -StdinText '<rendered overlay>' | Out-Null
            }
            else {
                $renderedRaw = Invoke-Planned -Exe 'kubectl' -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $overlayDir) -AllowFail
                if ($renderedRaw -is [System.Array]) { $renderedRaw = ($renderedRaw -join [Environment]::NewLine) }
                $rendered = [string]$renderedRaw
                if (-not [string]::IsNullOrWhiteSpace($rendered)) {
                    $delOutput = Invoke-Planned -Exe 'kubectl' -CmdArgs @('delete', '-f', '-', '--ignore-not-found') -StdinText $rendered -AllowFail
                    Resolve-RemovalOutcome -Id ("in-cluster overlay: azure") -Output $delOutput
                }
                else {
                    Write-Host "  overlay rendered empty; relying on the namespace catch-all below." -ForegroundColor DarkGray
                }
            }
        }
        else {
            Write-Host "  Azure overlay directory not found; relying on the namespace catch-all below." -ForegroundColor DarkGray
        }

        # 1b. Namespace catch-all: simplest convergent approach (Req 5.1/5.4).
        Write-Step "Deleting the namespace '$k8sNamespace' as a convergent catch-all (Req 5.1/5.4)"
        if ($WhatIf) {
            Invoke-Planned -Exe 'kubectl' -CmdArgs @('delete', 'namespace', $k8sNamespace, '--ignore-not-found') | Out-Null
        }
        else {
            $nsOutput = Invoke-Planned -Exe 'kubectl' -CmdArgs @('delete', 'namespace', $k8sNamespace, '--ignore-not-found') -AllowFail
            Resolve-RemovalOutcome -Id ("namespace: " + $k8sNamespace) -Output $nsOutput
        }
    }

    # -------------------------------------------------------------------------
    # 2. Compute: delete the AKS cluster (Req 5.2). Removed after its workload.
    # -------------------------------------------------------------------------
    Write-Step "Deleting the AKS cluster '$aksName'"
    Remove-Resource -Id ("AKS cluster: " + $aksName) `
        -CmdArgs @('aks', 'delete', '--resource-group', $rg, '--name', $aksName, '--yes', '--output', 'none')

    # -------------------------------------------------------------------------
    # 3. Managed Postgres: delete the Flexible Server (Req 5.2). Removing the
    #    server also removes its firewall rules, so they need no separate delete.
    # -------------------------------------------------------------------------
    Write-Step "Deleting the PostgreSQL Flexible Server '$pgServer'"
    Remove-Resource -Id ("Flexible Server: " + $pgServer) `
        -CmdArgs @('postgres', 'flexible-server', 'delete', '--resource-group', $rg, '--name', $pgServer, '--yes', '--output', 'none')

    # -------------------------------------------------------------------------
    # 4. Stored DB password: delete the Key Vault secret, then the vault itself
    #    (Req 5.2 - the stored DB password comes after compute + DB). Deleting the
    #    secret before the vault keeps the removed-id log precise even when the
    #    vault lingers in a soft-deleted state.
    # -------------------------------------------------------------------------
    Write-Step "Deleting the Key Vault secret '$kvSecret' and the vault '$kvName'"
    Remove-Resource -Id ("Key Vault secret: " + $kvName + '/' + $kvSecret) `
        -CmdArgs @('keyvault', 'secret', 'delete', '--vault-name', $kvName, '--name', $kvSecret, '--output', 'none')
    Remove-Resource -Id ("Key Vault: " + $kvName) `
        -CmdArgs @('keyvault', 'delete', '--name', $kvName, '--resource-group', $rg, '--output', 'none')

    # -------------------------------------------------------------------------
    # 5. KV reader identity + its Key Vault access policy. deploy.ps1 created a
    #    user-assigned managed identity and granted it `get` on Key Vault secrets
    #    for the Secrets Store CSI provider; both MUST be removed so no orphaned
    #    principal/policy lingers. The access policy is resolved by the identity's
    #    principalId; if the identity (or the vault) is already gone the lookup
    #    comes back empty and we treat the policy as already absent (Req 5.4).
    # -------------------------------------------------------------------------
    Write-Step "Removing the Key Vault access policy and the KV reader identity '$idName'"
    if ($WhatIf) {
        # Show the shape without resolving real ids in dry-run.
        Az identity show --name $idName --resource-group $rg --query 'principalId' --output tsv | Out-Null
        Remove-Resource -Id ("Key Vault access policy for " + $idName) `
            -CmdArgs @('keyvault', 'delete-policy', '--name', $kvName, '--resource-group', $rg, '--object-id', '<identity-principal-id>', '--output', 'none')
        Remove-Resource -Id ("user-assigned identity: " + $idName) `
            -CmdArgs @('identity', 'delete', '--name', $idName, '--resource-group', $rg)
    }
    else {
        $idPrincipalId = ([string](AzTry identity show --name $idName --resource-group $rg --query 'principalId' --output tsv)).Trim()

        if (-not [string]::IsNullOrWhiteSpace($idPrincipalId)) {
            Remove-Resource -Id ("Key Vault access policy for " + $idName) `
                -CmdArgs @('keyvault', 'delete-policy', '--name', $kvName, '--resource-group', $rg, '--object-id', $idPrincipalId, '--output', 'none')
        }
        else {
            # The identity is already gone, so its access policy cannot exist
            # either (the vault may also be gone). Count it as already absent.
            $script:removed.Add("Key Vault access policy for " + $idName + ' (already absent)')
            Write-Host ("  already absent: Key Vault access policy for {0}" -f $idName) -ForegroundColor DarkGray
        }

        Remove-Resource -Id ("user-assigned identity: " + $idName) `
            -CmdArgs @('identity', 'delete', '--name', $idName, '--resource-group', $rg)
    }

    # -------------------------------------------------------------------------
    # 6. Native registry: delete the ACR unless -KeepRegistry. deploy.ps1 created
    #    it, so by default teardown removes it LAST, after the stored DB password
    #    (Req 5.3).
    # -------------------------------------------------------------------------
    if ($KeepRegistry) {
        Write-Step "Keeping the Azure Container Registry '$acrName' (-KeepRegistry)"
        Write-Host ("  kept: ACR " + $acrName) -ForegroundColor DarkGray
    }
    else {
        Write-Step "Deleting the Azure Container Registry '$acrName'"
        Remove-Resource -Id ("ACR: " + $acrName) `
            -CmdArgs @('acr', 'delete', '--name', $acrName, '--resource-group', $rg, '--yes', '--output', 'none')
    }

    # -------------------------------------------------------------------------
    # 7. Catch-all: the resource-group-wide delete removes everything in the lab
    #    RG in one shot. It is destructive and RG-wide, so only run it with -Force;
    #    otherwise print the exact command for the operator to run manually.
    # -------------------------------------------------------------------------
    $groupDeleteArgs = @('group', 'delete', '--name', $rg, '--yes', '--no-wait')
    if ($Force) {
        Write-Step "Catch-all: deleting the entire resource group '$rg' (-Force)"
        Remove-Resource -Id ("resource group (catch-all): " + $rg) -CmdArgs $groupDeleteArgs
    }
    else {
        Write-Step "Catch-all available (not run without -Force)"
        Write-Host "  To remove ALL resources in the lab resource group in one shot, run:" -ForegroundColor Yellow
        Write-Host ("    az " + ($groupDeleteArgs -join ' ')) -ForegroundColor Yellow
        if ($WhatIf) {
            # Still surface it in the dry-run plan so the ordered list is complete.
            Az group delete --name $rg --yes --no-wait | Out-Null
        }
    }

    # -------------------------------------------------------------------------
    # Summary + exit status.
    # -------------------------------------------------------------------------
    if ($WhatIf) {
        Write-Step "DRY RUN complete. $script:PlanOrdinal command(s) listed; none executed."
        exit 0
    }

    Write-Step "Teardown summary"
    if ($script:removed.Count -gt 0) {
        Write-Host "  Removed (or already absent):" -ForegroundColor Green
        foreach ($r in $script:removed) { Write-Host ("    - " + $r) -ForegroundColor Green }
    }
    else {
        Write-Host "  Nothing to remove." -ForegroundColor Green
    }

    if ($script:failed.Count -gt 0) {
        # Req 5.6: report each resource that could not be removed to stderr and
        # exit non-success, after having attempted every other delete.
        Write-Error (@(
            "Teardown finished but the following resource(s) could NOT be removed:",
            ($script:failed | ForEach-Object { "  - $_" })
            "",
            "Re-run this script to retry (already-deleted resources are skipped), or use the",
            ("catch-all: az " + ($groupDeleteArgs -join ' '))
        ) -join [Environment]::NewLine)
        exit 1
    }

    Write-Host ""
    Write-Host "  Teardown complete. No billable resources from this target should remain." -ForegroundColor Green
    if ($KeepRegistry) {
        Write-Host ("  (ACR '{0}' was kept at your request.)" -f $acrName) -ForegroundColor Yellow
    }
    Write-Host ""
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
