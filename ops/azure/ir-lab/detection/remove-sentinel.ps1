<#
.SYNOPSIS
    Removes the lab analytics rule and Microsoft Sentinel from the workspace (idempotent).

.DESCRIPTION
    Deletes analytics rule 'sangyshop-lab-bruteforce' and then the Sentinel onboarding state of
    the workspace, which stops Sentinel billing. The workspace itself stays (delete it with
    delete-workspace.ps1). Only a workspace that carries the lab tag is touched. A missing workspace,
    rule or onboarding exits 0. Supports -WhatIf.

.EXAMPLE
    .\remove-sentinel.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$WorkspaceName
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -RegionOptional
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$null = Get-LabSubscriptionId

try {
    $ruleId = $script:LabSentinelRuleId
    $ws = Get-LabWorkspace -ResourceGroup $ResourceGroup -Name $WorkspaceName
    if (-not $ws) {
        Write-LabInfo "Workspace '$WorkspaceName' not found, so there is no Sentinel to remove."
    } elseif (-not (Test-LabTagged -Tags $ws.tags)) {
        Write-LabWarn "Workspace '$WorkspaceName' does not carry the lab tag. Sentinel left unchanged (untagged resource)."
    } else {
        $api = $script:LabSentinelApi
        $ruleUrl = Get-LabRestUrl -WorkspaceId "$($ws.id)" -Suffix "/providers/Microsoft.SecurityInsights/alertRules/$ruleId" -ApiVersion $api
        $g = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $ruleUrl, '--query', 'name', '--output', 'tsv')
        Stop-LabIfDenied -Result $g -Service 'sentinel' -Action 'analytics rule read' -Step 'sentinel analytics rule read'
        if (Test-LabManifestReused -Type 'sentinel-analytics-rule' -Id "$ResourceGroup/$WorkspaceName/$ruleId") {
            Write-LabInfo "Analytics rule '$ruleId' kept (not created by the lab)."
        } elseif ($g.ExitCode -eq 0) {
            $d = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'delete', '--url', $ruleUrl)
            if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete the analytics rule. $($d.Output)" }
            Write-LabInfo "Deleted analytics rule '$ruleId'."
        } else {
            Write-LabInfo "Analytics rule '$ruleId' not found. Nothing to remove."
        }

        $onUrl = Get-LabRestUrl -WorkspaceId "$($ws.id)" -Suffix '/providers/Microsoft.SecurityInsights/onboardingStates/default' -ApiVersion $api
        $o = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $onUrl, '--query', 'name', '--output', 'tsv')
        Stop-LabIfDenied -Result $o -Service 'sentinel' -Action 'onboarding state read' -Step 'sentinel onboarding read'
        if (Test-LabManifestReused -Type 'sentinel-onboarding' -Id "$ResourceGroup/$WorkspaceName") {
            Write-LabInfo "Sentinel on '$WorkspaceName' kept (not created by the lab)."
        } elseif ($o.ExitCode -eq 0) {
            $d = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'delete', '--url', $onUrl)
            if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not remove Sentinel from '$WorkspaceName'. $($d.Output)" }
            Write-LabInfo "Sentinel removed from '$WorkspaceName'."
        } else {
            Write-LabInfo "Sentinel is not enabled on '$WorkspaceName'. Nothing to remove."
        }
    }
    Remove-LabManifestEntry -Type 'sentinel-analytics-rule' -Id "$ResourceGroup/$WorkspaceName/$ruleId"
    Remove-LabManifestEntry -Type 'sentinel-onboarding' -Id "$ResourceGroup/$WorkspaceName"
} finally {
    Clear-LabTempFiles
}
exit 0
