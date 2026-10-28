<#
.SYNOPSIS
    Tears down everything the matching azure/docker/deploy.ps1 created: the ACI
    container group, Azure DB for PostgreSQL Flexible Server, the Key Vault
    secret + vault, the ACR-pull user-assigned managed identity (and its AcrPull
    role assignment), and (unless -KeepRegistry) the Azure Container Registry.
    Docker-only modality.

.DESCRIPTION
    The destroy half of one of the six (cloud, modality) targets in the
    multi-cloud-deploy spec. Resources are removed in REVERSE dependency order
    (Req 5.2): compute first, then the managed Postgres server, then the stored
    DB password (secret) and its vault, then the pull identity + role assignment,
    then (optionally) the registry.

      1. Validates config and checks `az` authentication (fail-closed).
      2. Deletes the ACI container group.
      3. Deletes the Flexible Server.
      4. Deletes the Key Vault secret, then the Key Vault itself.
      5. Removes the AcrPull role assignment and the user-assigned identity that
         deploy created so no orphaned principal/role is left behind.
      6. Deletes the ACR unless -KeepRegistry (Req 5.3).

    EVERY external CLI call goes through Invoke-Echoed from lib/Common.ps1
    (echo-before-exec, Req 1.3). This script never calls `az` directly.

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
# satisfied from one place. Mirrors azure/docker/deploy.ps1.
# =============================================================================
$script:PlanOrdinal = 0
function Invoke-Planned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
    )
    if ($WhatIf) {
        $script:PlanOrdinal++
        # Keep it copyable: executable followed by its arguments, space-joined.
        $display = (@($Exe) + $CmdArgs) -join ' '
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        return $null
    }
    return (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail:$AllowFail)
}

# Convenience wrappers so call sites read cleanly. Teardown always tolerates
# failure (every delete uses -AllowFail, Req 5.4), so both wrappers forward
# -AllowFail; Az is kept for parity/read-only shape in the plan.
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

# Issue one delete command, tolerate "already deleted", and classify the result.
# In -WhatIf we only enqueue the command into the plan (nothing executes).
# A zero exit means the resource was removed (or the command accepted the no-op).
# A non-zero exit is inspected: a "not found / does not exist" style failure is an
# already-deleted resource and counts as success (Req 5.4); any other non-zero is
# a real failure recorded for stderr + non-success exit (Req 5.6).
function Remove-Resource {
    param(
        [Parameter(Mandatory)][string]   $Id,       # human-readable resource identifier
        [Parameter(Mandatory)][string[]] $CmdArgs   # az arguments (without the leading 'az')
    )

    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail | Out-Null
        return
    }

    $output = Invoke-Echoed -Exe 'az' -CmdArgs $CmdArgs -AllowFail
    $code   = $LASTEXITCODE

    if ($code -eq 0) {
        $script:removed.Add($Id)
        Write-Host ("  removed: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }

    # Non-zero: decide whether this is an already-deleted resource (success) or a
    # real failure. The az CLI prints "not found"/"does not exist"/"was not found"
    # or a ResourceNotFound code when the target is already gone.
    $text = ''
    if ($null -ne $output) { $text = ($output | Out-String) }
    if ($text -match '(?i)(not\s*found|does\s*not\s*exist|was\s*not\s*found|resourcenotfound|could\s*not\s*be\s*found|no\s*such)') {
        $script:removed.Add($Id + ' (already absent)')
        Write-Host ("  already absent: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }

    # A real removal failure. Keep going (Req 5.6); record for the stderr summary.
    $script:failed.Add($Id)
    Write-Host ("  FAILED to remove (continuing): {0}" -f $Id) -ForegroundColor Red
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
    $aciName = [string]$azure['AciName']

    $acrName  = ($acrBase + $suffix)                 # ACR = base + suffix (alnum only)
    $kvName   = ($kvBase + '-' + $suffix)            # Key Vault = base + '-' + suffix
    $kvSecret = 'db-password'                         # Key Vault secret NAME (not a value)
    $pgServer = ($appName + '-pg-' + $suffix)        # Flexible Server name
    $idName   = ($appName + '-aci-pull-' + $suffix)  # user-assigned identity for ACR pull

    Write-Step "Teardown target summary (reverse dependency order)"
    Write-Host ("  Resource group : {0}" -f $rg)
    Write-Host ("  ACI group      : {0}" -f $aciName)
    Write-Host ("  Flexible Server: {0}" -f $pgServer)
    Write-Host ("  Key Vault      : {0} (secret: {1})" -f $kvName, $kvSecret)
    Write-Host ("  Pull identity  : {0}" -f $idName)
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
    # 1. Compute first: delete the ACI container group (Req 5.2).
    # -------------------------------------------------------------------------
    Write-Step "Deleting the ACI container group '$aciName'"
    Remove-Resource -Id ("ACI container group: " + $aciName) `
        -CmdArgs @('container', 'delete', '--resource-group', $rg, '--name', $aciName, '--yes', '--output', 'none')

    # -------------------------------------------------------------------------
    # 2. Managed Postgres: delete the Flexible Server (Req 5.2). Removing the
    #    server also removes its firewall rules, so they need no separate delete.
    # -------------------------------------------------------------------------
    Write-Step "Deleting the PostgreSQL Flexible Server '$pgServer'"
    Remove-Resource -Id ("Flexible Server: " + $pgServer) `
        -CmdArgs @('postgres', 'flexible-server', 'delete', '--resource-group', $rg, '--name', $pgServer, '--yes', '--output', 'none')

    # -------------------------------------------------------------------------
    # 3. Stored DB password: delete the Key Vault secret, then the vault itself
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
    # 4. Pull identity + its role assignment. deploy.ps1 created a user-assigned
    #    managed identity and granted it AcrPull on the registry; both MUST be
    #    removed so no orphaned principal/role lingers. The role assignment is
    #    resolved by the identity's principalId scoped to the ACR; if either the
    #    identity or the ACR is already gone the lookups come back empty and we
    #    treat the assignment as already absent.
    # -------------------------------------------------------------------------
    Write-Step "Removing the AcrPull role assignment and the pull identity '$idName'"
    if ($WhatIf) {
        # Show the shape without resolving real ids in dry-run.
        Az identity show --name $idName --resource-group $rg --query 'principalId' --output tsv | Out-Null
        Az acr show --name $acrName --resource-group $rg --query 'id' --output tsv | Out-Null
        Remove-Resource -Id ("AcrPull role assignment for " + $idName) `
            -CmdArgs @('role', 'assignment', 'delete', '--assignee', '<identity-principal-id>', '--role', 'AcrPull', '--scope', '<acr-id>', '--output', 'none')
        Remove-Resource -Id ("user-assigned identity: " + $idName) `
            -CmdArgs @('identity', 'delete', '--name', $idName, '--resource-group', $rg)
    }
    else {
        $idPrincipalId = ([string](AzTry identity show --name $idName --resource-group $rg --query 'principalId' --output tsv)).Trim()
        $acrId         = ([string](AzTry acr show --name $acrName --resource-group $rg --query 'id' --output tsv)).Trim()

        if (-not [string]::IsNullOrWhiteSpace($idPrincipalId) -and -not [string]::IsNullOrWhiteSpace($acrId)) {
            Remove-Resource -Id ("AcrPull role assignment for " + $idName) `
                -CmdArgs @('role', 'assignment', 'delete', '--assignee', $idPrincipalId, '--role', 'AcrPull', '--scope', $acrId, '--output', 'none')
        }
        else {
            # The identity or the registry is already gone, so the assignment
            # cannot exist either. Count it as already absent (Req 5.4).
            $script:removed.Add("AcrPull role assignment for " + $idName + ' (already absent)')
            Write-Host ("  already absent: AcrPull role assignment for {0}" -f $idName) -ForegroundColor DarkGray
        }

        Remove-Resource -Id ("user-assigned identity: " + $idName) `
            -CmdArgs @('identity', 'delete', '--name', $idName, '--resource-group', $rg)
    }

    # -------------------------------------------------------------------------
    # 5. Native registry: delete the ACR unless -KeepRegistry. deploy.ps1 created
    #    it, so by default teardown removes it AFTER the stored DB password
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
    # 6. Catch-all: the resource-group-wide delete removes everything in the lab
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
