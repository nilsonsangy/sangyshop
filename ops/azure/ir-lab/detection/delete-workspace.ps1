<#
.SYNOPSIS
    Permanently deletes the Log Analytics workspace (idempotent; only when it carries the lab tag).

.DESCRIPTION
    Uses a forced delete so the workspace name is released immediately instead of staying in
    the 14-day soft-delete state (which would block re-creating it and keeps data around).
    This also removes the SangyShopApp_CL table and any Sentinel onboarding on the workspace.
    Run remove-sentinel.ps1 first if you want the Sentinel pieces removed explicitly.
    A missing workspace exits 0. Supports -WhatIf.

.EXAMPLE
    .\delete-workspace.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -WhatIf
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
    $ws = Get-LabWorkspace -ResourceGroup $ResourceGroup -Name $WorkspaceName
    if (-not $ws) {
        Write-LabInfo "Workspace '$WorkspaceName' not found. Nothing to delete."
    } elseif ((Test-LabManifestReused -Type 'log-analytics-workspace' -Id "$ResourceGroup/$WorkspaceName") -or -not (Test-LabTagged -Tags $ws.tags)) {
        Write-LabWarn "Workspace '$WorkspaceName' kept (not created by the lab): it is reused or does not carry the lab tag. Left unchanged (untagged resource)."
        # The only thing the lab may have added to a workspace it did not create is its own table.
        $tableId = "$ResourceGroup/$WorkspaceName/$($script:LabAppTable)"
        if (Test-LabManifestEntry -Type 'log-analytics-table' -Id $tableId) {
            $td = Invoke-LabAz -Mutating -CliArgs @('monitor', 'log-analytics', 'workspace', 'table', 'delete', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName, '--name', $script:LabAppTable, '--yes')
            Stop-LabIfDenied -Result $td -Service 'loganalytics' -Action 'workspace table delete' -Step 'workspace table delete'
            if ($td.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $td.Output)) { Stop-Lab -Code 1 -Message "Could not delete table '$($script:LabAppTable)'. $($td.Output)" }
            Write-LabInfo "Deleted table '$($script:LabAppTable)' that the lab added."
            Remove-LabManifestEntry -Type 'log-analytics-table' -Id $tableId
        }
    } else {
        $d = Invoke-LabAz -Mutating -CliArgs @('monitor', 'log-analytics', 'workspace', 'delete', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName, '--force', 'true', '--yes')
        Stop-LabIfDenied -Result $d -Service 'loganalytics' -Action 'workspace delete' -Step 'workspace delete'
        if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete workspace '$WorkspaceName'. $($d.Output)" }
        Write-LabInfo "Deleted workspace '$WorkspaceName' (permanent)."
    }
    Remove-LabManifestEntry -Type 'log-analytics-workspace' -Id "$ResourceGroup/$WorkspaceName"
} finally {
    Clear-LabTempFiles
}
exit 0
