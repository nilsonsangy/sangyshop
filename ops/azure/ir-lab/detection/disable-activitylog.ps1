<#
.SYNOPSIS
    Removes the Activity Log diagnostic setting 'sangyshop-lab-activitylog' (idempotent).

.DESCRIPTION
    Only the lab-named setting is touched. Other diagnostic settings of the subscription are
    left alone. A missing setting exits 0. Supports -WhatIf.

.EXAMPLE
    .\disable-activitylog.ps1 -Subscription <id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
$null = Get-LabSubscriptionId

try {
    $name = $script:LabActivityDiagName
    if (Test-LabManifestReused -Type 'diagnostic-setting-subscription' -Id $name) {
        Write-LabInfo "Activity Log export '$name' kept (not created by the lab)."
        Remove-LabManifestEntry -Type 'diagnostic-setting-subscription' -Id $name
        exit 0
    }
    $s = Invoke-LabAz -CliArgs @('monitor', 'diagnostic-settings', 'subscription', 'show', '--name', $name, '--query', 'name', '--output', 'tsv')
    if ($s.ExitCode -ne 0) {
        if (Test-LabNotFound -Text $s.Output) {
            Write-LabInfo "Activity Log export '$name' not found. Nothing to remove."
        } else {
            Stop-Lab -Code 1 -Message "Could not read the Activity Log diagnostic setting. $($s.Output)"
        }
    } else {
        $d = Invoke-LabAz -Mutating -CliArgs @('monitor', 'diagnostic-settings', 'subscription', 'delete', '--name', $name, '--yes')
        if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete '$name'. $($d.Output)" }
        Write-LabInfo "Removed Activity Log export '$name'."
    }
    Remove-LabManifestEntry -Type 'diagnostic-setting-subscription' -Id $name
} finally {
    Clear-LabTempFiles
}
exit 0
