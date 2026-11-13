<#
.SYNOPSIS
    Enables the whole Azure detection stack: workspace, Activity Log, diagnostics, Entra ID, VNet flow logs, Defender, Sentinel, alerts.

.DESCRIPTION
    -Email is optional: it falls back to LAB_ALERT_EMAIL (environment or ops/.env), then a prompt.
    Exits with code 4 when the application is not deployed (VM missing; deploy with ops/azure/vm/deploy.ps1).
    Exits with code 3 on the first component that reports a missing permission. Safe to run again.
    Runs the individual enable-*.ps1 scripts with one shared run-id. A failure in one component
    does not stop the others; the exit code is 1 if any component failed. Optional or costly
    components can be skipped:
      -SkipFlowLogs   do not enable VNet flow logs
      -SkipDefender   do not enable Defender for Servers P2 (trial, then billable)
      -SkipEntra      do not try the Entra ID log export (it needs a P1/P2 licence anyway;
                      without it the script falls back to Activity Log and resource logs)
    The workspace keeps a 1 GB daily ingestion cap. All components are billable beyond the free
    tiers and trials; see the README for the estimated cost. Supports -WhatIf.

.EXAMPLE
    .\enable-all.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$Email,
    [string]$RunId,
    [string]$WorkspaceName,
    [string]$VnetName,
    [string]$StorageAccountName,
    [string]$KeyVaultName,
    [ValidateSet('Auto', 'Yes', 'No')][string]$EntraLicense = 'Auto',
    [switch]$SkipFlowLogs,
    [switch]$SkipDefender,
    [switch]$SkipEntra
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
# Resolve the alert address before anything is created: -Email, then LAB_ALERT_EMAIL (environment or ops/.env), then a prompt.
$Email = Resolve-LabAlertEmail -Email $Email -NonInteractive:([bool]$global:LabAzHandler)
$wi = [bool]$WhatIfPreference

# Gate: the application must be deployed first (the detection stack reads its logs). Read only.
$appVmName = (Get-VmLabNames -Config $script:LabConfig)['VmName']
$appCheck = Invoke-LabAz -CliArgs @('vm', 'show', '--resource-group', $ResourceGroup, '--name', $appVmName, '--query', 'id', '--output', 'tsv')
Stop-LabIfDenied -Result $appCheck -Service 'vm' -Action 'vm show' -Step 'application check'
if ($appCheck.ExitCode -ne 0) {
    if (Test-LabNotFound -Text $appCheck.Output) {
        Write-Host "BLOCKED: the application is not deployed (VM '$appVmName' not found in '$ResourceGroup')." -ForegroundColor Red
        Write-Host '  Next        : run ops/azure/vm/deploy.ps1, then run this script again. Nothing was created.'
        exit 4
    }
    Stop-Lab -Code 1 -Message "Could not read VM '$appVmName' in '$ResourceGroup'. $($appCheck.Output)"
}
Write-LabInfo "Enabling the Azure detection stack in $($script:LabRegion) (run-id $RunId)."

$base = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup; Region = $Region; RunId = $RunId }
if ($WorkspaceName) { $base['WorkspaceName'] = $WorkspaceName }

$steps = New-Object System.Collections.ArrayList
[void]$steps.Add(@{ Name = 'workspace'; Script = 'enable-workspace.ps1'; Params = $base.Clone() })
[void]$steps.Add(@{ Name = 'activitylog'; Script = 'enable-activitylog.ps1'; Params = $base.Clone() })
$dp = $base.Clone()
if ($StorageAccountName) { $dp['StorageAccountName'] = $StorageAccountName }
if ($KeyVaultName) { $dp['KeyVaultName'] = $KeyVaultName }
[void]$steps.Add(@{ Name = 'diagnostics'; Script = 'enable-diagnostics.ps1'; Params = $dp })
if ($SkipEntra) { Write-LabInfo 'Skipping Entra ID log export (-SkipEntra).' } else {
    $ep = $base.Clone(); $ep['EntraLicense'] = $EntraLicense
    [void]$steps.Add(@{ Name = 'entra'; Script = 'enable-entra.ps1'; Params = $ep })
}
if ($SkipFlowLogs) { Write-LabInfo 'Skipping VNet flow logs (-SkipFlowLogs).' } else {
    $fp = @{ Subscription = $Subscription; ResourceGroup = $ResourceGroup; Region = $Region; RunId = $RunId }
    if ($VnetName) { $fp['VnetName'] = $VnetName }
    [void]$steps.Add(@{ Name = 'flowlogs'; Script = 'enable-flowlogs.ps1'; Params = $fp })
}
if ($SkipDefender) { Write-LabInfo 'Skipping Defender for Servers (-SkipDefender).' } else {
    [void]$steps.Add(@{ Name = 'defender'; Script = 'enable-defender.ps1'; Params = @{ Subscription = $Subscription; RunId = $RunId } })
}
[void]$steps.Add(@{ Name = 'sentinel'; Script = 'enable-sentinel.ps1'; Params = $base.Clone() })
$ap = $base.Clone(); $ap['Email'] = $Email
[void]$steps.Add(@{ Name = 'alerts'; Script = 'enable-alerts.ps1'; Params = $ap })

$failed = @()
foreach ($s in $steps) {
    Write-Host ''
    Write-LabInfo "=== $($s.Name) ==="
    $p = $s.Params
    & (Join-Path $PSScriptRoot $s.Script) @p -WhatIf:$wi
    if ($LASTEXITCODE -ne 0) {
        $failed += $s.Name
        [Console]::Error.WriteLine("Error: component '$($s.Name)' failed with exit code $LASTEXITCODE")
        if ($LASTEXITCODE -eq 3) {
            # Permission missing: the component printed the exact role. Later steps depend on this one.
            Write-Host 'Stopped after the permission error above. Fix the account and run this same script again: resources already created are detected and reused.'
            $global:LASTEXITCODE = 3
            exit 3
        }
    }
}
Write-Host ''
if ($failed.Count -gt 0) {
    Stop-Lab -Code 1 -Message "Detection stack incomplete. Failed components: $($failed -join ', ')"
}
Write-LabInfo 'Detection stack enabled. Remember: these services are billable beyond free tiers and trials; run disable-all.ps1 or full-teardown.ps1 when done.'
Write-Host 'Next step: confirm the e-mail that Azure sent for the Action Group, then run ops/azure/ir-lab/check-detection-ready.ps1 (this script does not run it).'
exit 0
