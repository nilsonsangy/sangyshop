<#
.SYNOPSIS
    Creates the Log Analytics workspace with a 1 GB daily quota and the SangyShopApp_CL table (idempotent).

.DESCRIPTION
    Starts with one read-only discovery of the subscription and prints one line for the workspace.
    1. The workspace named by the VM lab config (Get-VmLabNames, key Workspace), tagged with the lab tag (lab=sangyshop-lab-azure) and run-id.
       The daily ingestion cap (dailyQuotaGb=1) is the cost trap: once the
       cap is hit, ingestion stops until the next day. A re-run re-applies the cap if it drifted.
    2. Custom table SangyShopApp_CL (columns TimeGenerated, RawData) so that the alert rule and
       the Sentinel analytics rule can reference it before the Azure Monitor Agent sends data.
    A same-named workspace without the lab tag is reused as is: it is not tagged, resized or
    removed, only the missing table is added (and recorded, so teardown can remove just that table).
    It is recorded in the lab manifest as reused. -AdoptExisting is the explicit opt-in that
    tags the workspace and takes over its quota, after which the lab manages it.
    Each resource is written to the manifest right after it is created. A denied call exits
    with code 3 and names the exact built-in role. Re-running creates nothing new.
    Supports -WhatIf.

.EXAMPLE
    .\enable-workspace.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName,
    [int]$RetentionDays = 30,
    [switch]$AdoptExisting
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $null = Get-LabPreflightDecision -Type workspace -ExpectedName $WorkspaceName
    $manifestId = "$ResourceGroup/$WorkspaceName"
    $workspaceIsForeign = $false

    $ws = Get-LabWorkspace -ResourceGroup $ResourceGroup -Name $WorkspaceName
    if ($ws) {
        $setQuota = $true
        if (-not (Test-LabTagged -Tags $ws.tags)) {
            if ($AdoptExisting) {
                $t = Invoke-LabAz -Mutating -CliArgs (@('tag', 'update', '--resource-id', "$($ws.id)", '--operation', 'merge', '--tags') + (Get-LabTagArgs -RunId $RunId))
                Assert-LabAzOk -Result $t -Service 'loganalytics' -Action 'tag update' -Failure "Could not tag workspace '$WorkspaceName'."
                Write-LabInfo "Adopted existing workspace '$WorkspaceName' (tagged)."
            } else {
                $workspaceIsForeign = $true
                $setQuota = $false
                Write-LabInfo "Workspace '$WorkspaceName' already exists and was not created by the lab. Reusing it as is: no tag, quota or retention change, and it is never removed."
            }
        } else {
            Write-LabInfo "Workspace '$WorkspaceName' already exists with the lab tag."
        }
        # Recorded before the next call, so an interrupted run still knows what it owns.
        $own = if ($workspaceIsForeign) { 'reused' } else { 'created' }
        Add-LabManifestEntry -Type 'log-analytics-workspace' -Id $manifestId -RunId $RunId -Ownership $own

        if ($setQuota) {
            if ("$($ws.quota)" -ne "$($script:LabDailyQuotaGb)") {
                $u = Invoke-LabAz -Mutating -CliArgs @('monitor', 'log-analytics', 'workspace', 'update', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName, '--quota', "$($script:LabDailyQuotaGb)")
                Assert-LabAzOk -Result $u -Service 'loganalytics' -Action 'workspace update' -Failure 'Could not set the daily quota.'
                Write-LabInfo "Daily ingestion quota set to $($script:LabDailyQuotaGb) GB."
            } else {
                Write-LabInfo "Daily ingestion quota is already $($script:LabDailyQuotaGb) GB."
            }
        }
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs (@('monitor', 'log-analytics', 'workspace', 'create', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName,
                '--location', $script:LabRegion, '--quota', "$($script:LabDailyQuotaGb)", '--retention-time', "$RetentionDays", '--tags') + (Get-LabTagArgs -RunId $RunId))
        Assert-LabAzOk -Result $c -Service 'loganalytics' -Action 'workspace create' -Failure "Could not create workspace '$WorkspaceName'."
        Write-LabInfo "Created workspace '$WorkspaceName' (daily quota $($script:LabDailyQuotaGb) GB, retention $RetentionDays days)."
        Add-LabManifestEntry -Type 'log-analytics-workspace' -Id $manifestId -RunId $RunId -Ownership 'created'
    }

    # Application table (filled later by the Azure Monitor Agent through the DCR)
    $tb = Invoke-LabAz -CliArgs @('monitor', 'log-analytics', 'workspace', 'table', 'show', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName, '--name', $script:LabAppTable, '--query', 'name', '--output', 'tsv')
    Stop-LabIfDenied -Result $tb -Service 'loganalytics' -Action 'workspace table show' -Step 'workspace table show'
    if ($tb.ExitCode -eq 0 -and "$($tb.Output)".Trim() -eq $script:LabAppTable) {
        Write-LabInfo "Table '$($script:LabAppTable)' already exists. Nothing to create."
    } else {
        $tc = Invoke-LabAz -Mutating -CliArgs @('monitor', 'log-analytics', 'workspace', 'table', 'create', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName,
            '--name', $script:LabAppTable, '--columns', 'TimeGenerated=datetime', 'RawData=string')
        Assert-LabAzOk -Result $tc -Service 'loganalytics' -Action 'workspace table create' -Failure "Could not create table '$($script:LabAppTable)'."
        Write-LabInfo "Created table '$($script:LabAppTable)'."
        # A table added to a workspace the lab did not create is the lab's own and is recorded for teardown.
        if ($workspaceIsForeign) {
            Add-LabManifestEntry -Type 'log-analytics-table' -Id "$manifestId/$($script:LabAppTable)" -RunId $RunId -Ownership 'created'
        }
    }
    Write-Host ("Result workspace: {0} ({1})" -f $WorkspaceName, $(if ($workspaceIsForeign) { 'reused, not created by the lab' } else { 'lab workspace' }))
} finally {
    Clear-LabTempFiles
}
exit 0
