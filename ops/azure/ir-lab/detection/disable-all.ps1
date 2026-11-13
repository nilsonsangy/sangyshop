<#
.SYNOPSIS
    Disables the whole Azure detection stack in reverse dependency order.

.DESCRIPTION
    Runs the individual scripts: disable-alerts, remove-sentinel, disable-defender,
    disable-flowlogs, disable-entra, disable-diagnostics, disable-activitylog and
    delete-workspace. A failure in one component does not stop the others; the exit code is 1
    if any component failed. Skip switches mirror enable-all.ps1:
      -SkipFlowLogs   leave VNet flow logs untouched
      -SkipDefender   leave the Defender plan untouched
      -SkipEntra      leave the Entra ID export untouched
    Use -KeepLogs to keep the workspace and the flow-log storage account for analysis
    (they keep costing until removed). Supports -WhatIf.

.EXAMPLE
    .\disable-all.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$WorkspaceName,
    [string]$StorageAccountName,
    [string]$KeyVaultName,
    [switch]$SkipFlowLogs,
    [switch]$SkipDefender,
    [switch]$SkipEntra,
    [switch]$KeepLogs
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$wi = [bool]$WhatIfPreference
Write-LabInfo "Disabling the Azure detection stack in $($script:LabRegion)."

$ws = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup }
if ($WorkspaceName) { $ws['WorkspaceName'] = $WorkspaceName }

$steps = New-Object System.Collections.ArrayList
[void]$steps.Add(@{ Name = 'alerts'; Script = 'disable-alerts.ps1'; Params = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup } })
[void]$steps.Add(@{ Name = 'sentinel'; Script = 'remove-sentinel.ps1'; Params = $ws.Clone() })
if ($SkipDefender) { Write-LabInfo 'Skipping Defender for Servers (-SkipDefender).' } else {
    [void]$steps.Add(@{ Name = 'defender'; Script = 'disable-defender.ps1'; Params = @{ Subscription = $Subscription } })
}
if ($SkipFlowLogs) { Write-LabInfo 'Skipping VNet flow logs (-SkipFlowLogs).' } else {
    $fp = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup; Region = $Region }
    if ($KeepLogs) { $fp['KeepStorage'] = $true }
    [void]$steps.Add(@{ Name = 'flowlogs'; Script = 'disable-flowlogs.ps1'; Params = $fp })
}
if ($SkipEntra) { Write-LabInfo 'Skipping Entra ID log export (-SkipEntra).' } else {
    [void]$steps.Add(@{ Name = 'entra'; Script = 'disable-entra.ps1'; Params = @{ Subscription = $Subscription } })
}
$dp = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup }
if ($StorageAccountName) { $dp['StorageAccountName'] = $StorageAccountName }
if ($KeyVaultName) { $dp['KeyVaultName'] = $KeyVaultName }
[void]$steps.Add(@{ Name = 'diagnostics'; Script = 'disable-diagnostics.ps1'; Params = $dp })
[void]$steps.Add(@{ Name = 'activitylog'; Script = 'disable-activitylog.ps1'; Params = @{ Subscription = $Subscription } })
if ($KeepLogs) { Write-LabInfo 'Keeping the Log Analytics workspace (-KeepLogs). It keeps costing until removed.' } else {
    [void]$steps.Add(@{ Name = 'workspace'; Script = 'delete-workspace.ps1'; Params = $ws.Clone() })
}

$failed = @()
foreach ($s in $steps) {
    Write-Host ''
    Write-LabInfo "=== $($s.Name) ==="
    $p = $s.Params
    & (Join-Path $PSScriptRoot $s.Script) @p -WhatIf:$wi
    if ($LASTEXITCODE -ne 0) {
        $failed += $s.Name
        [Console]::Error.WriteLine("Error: component '$($s.Name)' failed with exit code $LASTEXITCODE")
    }
}
Write-Host ''
if ($failed.Count -gt 0) {
    Stop-Lab -Code 1 -Message "Some components could not be removed: $($failed -join ', ')"
}
Write-LabInfo 'Detection stack disabled.'
exit 0
