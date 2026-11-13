<#
.SYNOPSIS
    Removes the VNet flow log and its storage account (idempotent; only resources with the lab tag).

.DESCRIPTION
    Deletes flow log 'fl-sangyshop-lab' when it carries the lab tag. The destination storage account
    is deleted only when it carries the lab tag AND component=flowlogs (i.e. the one this lab created).
    Use -KeepStorage to keep the collected flow-log blobs for analysis (they keep costing
    storage until removed). A missing flow log or account exits 0. Supports -WhatIf.

.EXAMPLE
    .\disable-flowlogs.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$FlowLogsStorageAccount,
    [switch]$KeepStorage
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$null = Get-LabSubscriptionId

try {
    $flowName = $script:LabFlowLogName
    $f = Invoke-LabAz -CliArgs @('network', 'watcher', 'flow-log', 'show', '--location', $script:LabRegion, '--name', $flowName, '--query', '{id:id,tags:tags}', '--output', 'json')
    if ($f.ExitCode -ne 0) {
        if (Test-LabNotFound -Text $f.Output) { Write-LabInfo "Flow log '$flowName' not found. Nothing to remove." }
        else { Stop-Lab -Code 1 -Message "Could not read flow log '$flowName'. $($f.Output)" }
    } else {
        $fl = ConvertFrom-LabJson -Text $f.Output
        if (-not (Test-LabTagged -Tags $fl.tags)) {
            Write-LabWarn "Flow log '$flowName' does not carry the lab tag. Left unchanged (untagged resource)."
        } else {
            $d = Invoke-LabAz -Mutating -CliArgs @('network', 'watcher', 'flow-log', 'delete', '--location', $script:LabRegion, '--name', $flowName)
            if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete flow log '$flowName'. $($d.Output)" }
            Write-LabInfo "Deleted flow log '$flowName'."
        }
    }

    $saName = if ($FlowLogsStorageAccount) { $FlowLogsStorageAccount } else { Get-LabFlowStorageName }
    if ($KeepStorage) {
        Write-LabInfo "Keeping storage account '$saName' (-KeepStorage). It keeps costing storage until removed."
    } else {
        $sa = Invoke-LabAz -CliArgs @('storage', 'account', 'show', '--resource-group', $ResourceGroup, '--name', $saName, '--query', 'tags', '--output', 'json')
        if ($sa.ExitCode -ne 0) {
            Write-LabInfo "Storage account '$saName' not found. Nothing to remove."
        } else {
            $tags = ConvertFrom-LabJson -Text $sa.Output
            $isFlow = ($tags -and "$($tags.component)" -eq 'flowlogs')
            if (-not (Test-LabTagged -Tags $tags) -or -not $isFlow) {
                Write-LabWarn "Storage account '$saName' was not created by this lab for flow logs (tags lab/component). Left unchanged (untagged resource)."
            } else {
                $d = Invoke-LabAz -Mutating -CliArgs @('storage', 'account', 'delete', '--resource-group', $ResourceGroup, '--name', $saName, '--yes')
                if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete storage account '$saName'. $($d.Output)" }
                Write-LabInfo "Deleted storage account '$saName'."
            }
        }
    }
} finally {
    Clear-LabTempFiles
}
exit 0
