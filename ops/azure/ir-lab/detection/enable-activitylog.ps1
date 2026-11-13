<#
.SYNOPSIS
    Exports the subscription Activity Log to the lab Log Analytics workspace (idempotent).

.DESCRIPTION
    Creates the subscription-level diagnostic setting 'sangyshop-lab-activitylog' with the
    categories Administrative, Security, Alert and Policy (control-plane evidence, table
    AzureActivity). Volume stays small; high-volume categories are not exported. The Activity
    Log keeps its own 90-day retention even when this export is off.
    A diagnostic setting cannot carry tags, so it is recorded in the lab manifest.
    Re-running creates nothing new. Supports -WhatIf.

.EXAMPLE
    .\enable-activitylog.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $ws = Get-LabWorkspaceRequired -ResourceGroup $ResourceGroup -Name $WorkspaceName
    $name = $script:LabActivityDiagName

    $s = Invoke-LabAz -CliArgs @('monitor', 'diagnostic-settings', 'subscription', 'show', '--name', $name, '--query', 'workspaceId', '--output', 'tsv')
    Stop-LabIfDenied -Result $s -Service 'monitor' -Action 'diagnostic-settings subscription show' -Step 'activity log export read'
    if ($s.ExitCode -eq 0 -and "$($s.Output)".Trim() -ieq "$($ws.id)") {
        $own = Get-LabExistingOwnership -Type 'diagnostic-setting-subscription' -Id $name
        if ($own -eq 'reused') { Write-LabInfo "Activity Log export '$name' already exists and was not created by the lab. Reusing it as is; it is never changed or removed." }
        else { Write-LabInfo "Activity Log export '$name' already points to '$WorkspaceName'. Nothing to create." }
    } else {
        $logs = '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Alert","enabled":true},{"category":"Policy","enabled":true}]'
        $c = Invoke-LabAz -Mutating -CliArgs @('monitor', 'diagnostic-settings', 'subscription', 'create', '--name', $name, '--location', $script:LabRegion,
            '--workspace', "$($ws.id)", '--logs', (New-LabTempFile -Text $logs))
        Assert-LabAzOk -Result $c -Service 'monitor' -Action 'diagnostic-settings subscription create' -Failure 'Could not create the Activity Log diagnostic setting.'
        Write-LabInfo "Activity Log export '$name' enabled -> $WorkspaceName (table AzureActivity)."
        $own = 'created'
    }
    Add-LabManifestEntry -Type 'diagnostic-setting-subscription' -Id $name -RunId $RunId -Ownership $own
} finally {
    Clear-LabTempFiles
}
exit 0
