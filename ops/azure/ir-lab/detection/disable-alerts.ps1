<#
.SYNOPSIS
    Removes the brute-force alert rule and the Action Group (idempotent; only resources with the lab tag).

.DESCRIPTION
    The rule is deleted first, then the Action Group, and each only when it carries the lab tag.
    Remove the Logic App blocker first if it uses this Action Group. A missing rule or group
    exits 0. Supports -WhatIf.

.EXAMPLE
    .\disable-alerts.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$null = Get-LabSubscriptionId

function Remove-LabTaggedResource {
    param([string]$Kind, [string]$Name, [string[]]$ShowArgs, [string[]]$DeleteArgs, [string]$ManifestType)
    $manifestId = "$ResourceGroup/$Name"
    $s = Invoke-LabAz -CliArgs ($ShowArgs + @('--query', 'tags', '--output', 'json'))
    Stop-LabIfDenied -Result $s -Service 'monitor' -Action "$($ShowArgs[1]) show" -Step "$Kind read"
    if ($s.ExitCode -ne 0) {
        if (Test-LabNotFound -Text $s.Output) { Write-LabInfo "$Kind '$Name' not found. Nothing to remove."; return }
        Stop-Lab -Code 1 -Message "Could not read $Kind '$Name'. $($s.Output)"
    }
    if ((Test-LabManifestReused -Type $ManifestType -Id $manifestId) -or -not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $s.Output))) {
        Write-LabWarn "$Kind '$Name' kept (not created by the lab): it is reused or does not carry the lab tag. Left unchanged (untagged resource)."
        Remove-LabManifestEntry -Type $ManifestType -Id $manifestId
        return
    }
    $d = Invoke-LabAz -Mutating -CliArgs $DeleteArgs
    Stop-LabIfDenied -Result $d -Service 'monitor' -Action "$($DeleteArgs[1]) delete" -Step "$Kind delete"
    if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete $Kind '$Name'. $($d.Output)" }
    Write-LabInfo "Deleted $Kind '$Name'."
    Remove-LabManifestEntry -Type $ManifestType -Id $manifestId
}

try {
    $rule = $script:LabAlertRuleName
    Remove-LabTaggedResource -Kind 'Alert rule' -Name $rule `
        -ShowArgs @('monitor', 'scheduled-query', 'show', '--resource-group', $ResourceGroup, '--name', $rule) `
        -DeleteArgs @('monitor', 'scheduled-query', 'delete', '--resource-group', $ResourceGroup, '--name', $rule, '--yes') -ManifestType 'alert-rule'
    $ag = $script:LabActionGroupName
    Remove-LabTaggedResource -Kind 'Action Group' -Name $ag `
        -ShowArgs @('monitor', 'action-group', 'show', '--resource-group', $ResourceGroup, '--name', $ag) `
        -DeleteArgs @('monitor', 'action-group', 'delete', '--resource-group', $ResourceGroup, '--name', $ag) -ManifestType 'action-group'
} finally {
    Clear-LabTempFiles
}
exit 0
