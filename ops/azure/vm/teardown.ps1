<#
.SYNOPSIS
    Removes the Azure VM lab (Deploy_VM_Azure) created by deploy.ps1.

.DESCRIPTION
    Lower-level teardown invoked by the Full_Teardown_Azure. Order:

      1. Checks `az account show` (fail-closed).
      2. Refuses to touch a resource group that does not carry the Tag_Lab
         lab=sangyshop-lab-azure (and, when -RunId is given, the matching run-id tag).
      3. Removes Microsoft Sentinel (if the IR lab enabled it) from the Log
         Analytics workspace, then force-deletes the workspace permanently.
      4. Deletes the lab resource group (VM, disks, public IP, NSG, VNet,
         PostgreSQL Flexible Server, Storage Account, Key Vault, managed identity,
         workspace, DCR) and waits for it.
      5. Purges the soft-deleted Key Vault when purge protection allows it; if not,
         says so in English with the scheduled purge date.
      6. Removes the sp-lab-leaked service principal (and its app registration,
         secrets and role assignments).
      7. Confirms removal: exits 0 ONLY when `az group exists` returns false and
         nothing failed.

    The Evidence resource group (Grupo_Recursos_Evidencias) is NOT removed here; it
    is handled by the Full_Teardown_Azure, which owns the preservation decision.

    Idempotent: a re-run after success skips what is already gone, prints
    "Nothing to remove", and exits 0 quickly. Every external command is echoed
    before it runs. A failed removal is listed on stderr (type and identifier), the
    remaining independent removals continue, and the exit code is non-zero.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to ops/cloud.config.ps1.

.PARAMETER WhatIf
    Prints the ordered commands that WOULD run and the resources that would be
    removed. Removes nothing. Exits 0.

.PARAMETER RunId
    Optional run id. When supplied, the lab resource group must carry the same
    run-id tag or teardown refuses to delete it.

.EXAMPLE
    .\teardown.ps1 -WhatIf

.EXAMPLE
    .\teardown.ps1
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $WhatIf,
    [string] $RunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = (Join-Path $scriptDir '..\..\cloud.config.ps1')
}

. (Join-Path $scriptDir '..\..\lib\Common.ps1')
. (Join-Path $scriptDir 'VmNames.ps1')

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
        $display = (@($Exe) + $CmdArgs) -join ' '
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        return $null
    }
    return (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail:$AllowFail)
}
function Az    { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A }
function AzTry { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A -AllowFail }

function Write-StdErr { param([string] $Message) [Console]::Error.WriteLine($Message) }

# Read-only query returning string lines (tolerates failure; ignores stderr records).
# In -WhatIf prints the command and returns the supplied placeholder lines.
function Get-AzLines {
    param([Parameter(Mandatory)][string[]] $CmdArgs, [string[]] $Placeholder = @())
    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs | Out-Null
        return @($Placeholder)
    }
    $out = Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($out | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}

$script:removed = New-Object System.Collections.Generic.List[string]
$script:failed  = New-Object System.Collections.Generic.List[string]
$script:notes   = New-Object System.Collections.Generic.List[string]

# Issues one removal command. Success or "already gone" counts as removed; any
# other failure is recorded (type + identifier) and the script continues.
function Remove-Resource {
    param(
        [Parameter(Mandatory)][string]   $Id,
        [Parameter(Mandatory)][string[]] $CmdArgs
    )
    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail | Out-Null
        Write-Host ("     would remove: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }
    $output = Invoke-Echoed -Exe 'az' -CmdArgs $CmdArgs -AllowFail
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        $script:removed.Add($Id)
        Write-Host ("  removed: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }
    $text = ''
    if ($null -ne $output) { $text = ($output | Out-String) }
    if ($text -match '(?i)(not\s*found|does\s*not\s*exist|was\s*not\s*found|resourcenotfound|could\s*not\s*be\s*found|no\s*such|notfound)') {
        $script:removed.Add($Id + ' (already absent)')
        Write-Host ("  already absent: {0}" -f $Id) -ForegroundColor DarkGray
        return
    }
    $script:failed.Add($Id)
    Write-Host ("  FAILED to remove (continuing): {0}" -f $Id) -ForegroundColor Red
}

try {
    Write-Step "Loading and validating configuration (Azure, VM modality)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure' -Modality 'vm'
    $names    = Get-VmLabNames -Config $cfg
    $location = $names['Location']
    $rg       = $names['LabGroup']
    $ws       = $names['Workspace']
    $spName   = $names['LeakedSp']

    Write-Step "Teardown target summary"
    Write-Host ("  Lab resource group : {0} ({1})" -f $rg, $location)
    Write-Host ("  Key Vault          : {0}" -f $names['KeyVault'])
    Write-Host ("  Service principal  : {0}" -f $spName)
    Write-Host ("  Evidence group     : {0} (NOT removed here; owned by the Full_Teardown_Azure)" -f $names['EvidenceGroup'])
    if ($WhatIf) { Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed." }

    # --- Auth check. ---
    Write-Step "Checking Azure CLI authentication"
    $subId = '<subscription-id>'
    if ($WhatIf) {
        Az account show --query id --output tsv
    }
    else {
        $idLines = @(Get-AzLines -CmdArgs @('account', 'show', '--query', 'id', '--output', 'tsv'))
        if ($idLines.Count -eq 0) {
            throw (@(
                "Azure authentication check failed (az account show).",
                "Run:  az login   and   az account set --subscription <your-subscription-id>"
            ) -join [Environment]::NewLine)
        }
        $subId = $idLines[$idLines.Count - 1]
    }

    # --- Does the lab group exist? ---
    Write-Step "Checking whether resource group '$rg' exists"
    $groupExists = $true
    if (-not $WhatIf) {
        $ex = @(Get-AzLines -CmdArgs @('group', 'exists', '--name', $rg))
        $groupExists = ($ex.Count -gt 0 -and $ex[$ex.Count - 1] -eq 'true')
    }
    else {
        Az group exists --name $rg
    }

    $vaultCandidates = New-Object System.Collections.Generic.List[string]
    $vaultCandidates.Add($names['KeyVault'])

    if ($groupExists) {
        # --- Tag_Lab guard: never delete a group that is not marked as ours. ---
        Write-Step "Verifying the Tag_Lab on '$rg' before removing anything"
        $labTag = @(Get-AzLines -CmdArgs @('group', 'show', '--name', $rg, '--query', 'tags.lab', '--output', 'tsv') -Placeholder @($script:VmLabName))
        if ($labTag.Count -eq 0 -or $labTag[$labTag.Count - 1] -ne $script:VmLabName) {
            $found = if ($labTag.Count -gt 0) { $labTag[$labTag.Count - 1] } else { '<none>' }
            throw "Resource group '$rg' is not marked lab=$($script:VmLabName) (found tag value: $found). Refusing to remove an unmarked resource group (Recurso_Nao_Marcado)."
        }
        if (-not [string]::IsNullOrWhiteSpace($RunId)) {
            $runTag = @(Get-AzLines -CmdArgs @('group', 'show', '--name', $rg, '--query', 'tags."run-id"', '--output', 'tsv') -Placeholder @($RunId))
            if ($runTag.Count -eq 0 -or $runTag[$runTag.Count - 1] -ne $RunId) {
                throw "Resource group '$rg' has a different run-id tag than -RunId '$RunId'. Refusing to remove it."
            }
        }

        # --- Sentinel + workspace (permanent delete) BEFORE the group. ---
        Write-Step "Removing Microsoft Sentinel (if present) and force-deleting the Log Analytics workspace"
        $workspaces = New-Object System.Collections.Generic.List[string]
        $workspaces.Add($ws)
        foreach ($w in (Get-AzLines -CmdArgs @('monitor', 'log-analytics', 'workspace', 'list', '--resource-group', $rg, '--query', '[].name', '--output', 'tsv'))) {
            if (-not $workspaces.Contains($w)) { $workspaces.Add($w) }
        }
        foreach ($w in $workspaces) {
            $onb = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$w/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01"
            if ($WhatIf) {
                Az rest --method get --url $onb --output none
                Remove-Resource -Id "Microsoft Sentinel onboarding: $w" -CmdArgs @('rest', '--method', 'delete', '--url', $onb, '--output', 'none')
            }
            else {
                $null = AzTry rest --method get --url $onb --output none
                if ($LASTEXITCODE -eq 0) {
                    Remove-Resource -Id "Microsoft Sentinel onboarding: $w" -CmdArgs @('rest', '--method', 'delete', '--url', $onb, '--output', 'none')
                }
                else { Write-Host "  Microsoft Sentinel is not enabled on workspace '$w'." -ForegroundColor DarkGray }
            }
            Remove-Resource -Id "Log Analytics workspace (permanent): $w" `
                -CmdArgs @('monitor', 'log-analytics', 'workspace', 'delete', '--resource-group', $rg, '--workspace-name', $w, '--force', 'true', '--yes')
        }

        # --- Remember every vault in the group so it can be purged afterwards. ---
        foreach ($v in (Get-AzLines -CmdArgs @('keyvault', 'list', '--resource-group', $rg, '--query', '[].name', '--output', 'tsv'))) {
            if (-not $vaultCandidates.Contains($v)) { $vaultCandidates.Add($v) }
        }

        # --- Delete the lab resource group and wait for it. ---
        Write-Step "Deleting resource group '$rg' (waits for completion)"
        Remove-Resource -Id "resource group: $rg" -CmdArgs @('group', 'delete', '--name', $rg, '--yes')
    }
    else {
        Write-Host "  Resource group '$rg' does not exist; nothing to delete there." -ForegroundColor DarkGray
    }

    # --- Purge soft-deleted Key Vaults when purge protection allows. ---
    Write-Step "Purging soft-deleted Key Vault(s) when purge protection allows"
    foreach ($v in $vaultCandidates) {
        $delLoc = @(Get-AzLines -CmdArgs @('keyvault', 'show-deleted', '--name', $v, '--query', 'properties.location', '--output', 'tsv') -Placeholder @($location))
        if ($delLoc.Count -eq 0) {
            Write-Host "  Key Vault '$v' is not in the soft-deleted state." -ForegroundColor DarkGray
            continue
        }
        $pp = @(Get-AzLines -CmdArgs @('keyvault', 'show-deleted', '--name', $v, '--query', 'properties.purgeProtectionEnabled', '--output', 'tsv') -Placeholder @('false'))
        $protected = ($pp.Count -gt 0 -and $pp[$pp.Count - 1] -match '^(?i:true)$')
        if ($protected) {
            $due = @(Get-AzLines -CmdArgs @('keyvault', 'show-deleted', '--name', $v, '--query', 'properties.scheduledPurgeDate', '--output', 'tsv'))
            $dueText = if ($due.Count -gt 0) { $due[$due.Count - 1] } else { 'the retention period end' }
            $msg = "Key Vault '$v' has purge protection enabled and cannot be purged now; Azure removes it automatically at $dueText."
            Write-Host ("  NOTE: " + $msg) -ForegroundColor Yellow
            $script:notes.Add($msg)
        }
        else {
            Remove-Resource -Id "Key Vault (purge): $v" `
                -CmdArgs @('keyvault', 'purge', '--name', $v, '--location', $delLoc[$delLoc.Count - 1], '--output', 'none')
        }
    }

    # --- Service principal (outside the resource group). ---
    Write-Step "Removing the service principal '$spName'"
    $appIds = @(Get-AzLines -CmdArgs @('ad', 'sp', 'list', '--display-name', $spName, '--query', '[].appId', '--output', 'tsv') -Placeholder @('<sp-app-id>'))
    if ($appIds.Count -eq 0) {
        Write-Host "  Service principal '$spName' not found." -ForegroundColor DarkGray
    }
    foreach ($appId in $appIds) {
        Remove-Resource -Id "service principal: $spName ($appId)" -CmdArgs @('ad', 'sp', 'delete', '--id', $appId)
        Remove-Resource -Id "app registration and secrets: $spName ($appId)" -CmdArgs @('ad', 'app', 'delete', '--id', $appId)
    }

    # --- Verify. ---
    Write-Step "Confirming removal with 'az group exists'"
    if ($WhatIf) {
        Az group exists --name $rg
        Write-Step "DRY RUN complete. $script:PlanOrdinal command(s) listed; nothing was removed."
        exit 0
    }
    $after = @(Get-AzLines -CmdArgs @('group', 'exists', '--name', $rg))
    $stillThere = ($after.Count -eq 0 -or $after[$after.Count - 1] -ne 'false')
    if ($stillThere) { $script:failed.Add("resource group: $rg (az group exists did not return false)") }

    Write-Step "Teardown summary"
    if ($script:removed.Count -eq 0 -and $script:failed.Count -eq 0) {
        Write-Host "  Nothing to remove: no lab resources remain." -ForegroundColor Green
    }
    else {
        foreach ($r in $script:removed) { Write-Host ("    - " + $r) -ForegroundColor Green }
    }
    foreach ($n in $script:notes) { Write-Host ("  NOTE: " + $n) -ForegroundColor Yellow }

    if ($script:failed.Count -gt 0) {
        Write-StdErr "Teardown finished but the following resource(s) could NOT be removed:"
        foreach ($f in $script:failed) { Write-StdErr ("  - " + $f) }
        Write-StdErr "Re-run teardown.ps1 to retry (already-removed resources are skipped)."
        exit 1
    }
    Write-Host "  Teardown complete: 'az group exists' returned false." -ForegroundColor Green
    exit 0
}
catch {
    Write-StdErr ("ERROR: " + $_.Exception.Message)
    exit 1
}
