<#
.SYNOPSIS
    Enables VNet flow logs to a storage account (idempotent, optional and billable).

.DESCRIPTION
    Uses VNet flow logs ONLY. NSG flow logs are not used in this lab: Microsoft blocked the
    creation of new NSG flow logs on 2025-06-30 and retires them on 2027-09-30 (see
    https://learn.microsoft.com/azure/network-watcher/nsg-flow-logs-migrate).
    Traffic Analytics is NOT enabled (no extra workspace ingestion); read the JSON blobs in the
    container insights-logs-flowlogflowevent. The first 5 GB per month are free.

    Steps:
      1. Finds the lab VNet (-VnetName, or the single VNet that carries the lab tag in the group).
      2. Finds or creates the destination storage account (-FlowLogsStorageAccount; default name
         is stflowlab<hash>, tagged lab + component=flowlogs, TLS 1.2, no public blob access).
      3. Creates flow log 'fl-sangyshop-lab' (Network Watcher of the region) with the lab tag.
    A same-named flow log without the lab tag is refused. Re-running creates nothing new.
    Supports -WhatIf.

.EXAMPLE
    .\enable-flowlogs.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$VnetName,
    [string]$FlowLogsStorageAccount,
    [int]$RetentionDays = 3
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $flowName = $script:LabFlowLogName

    # Already enabled?
    $f = Invoke-LabAz -CliArgs @('network', 'watcher', 'flow-log', 'show', '--location', $script:LabRegion, '--name', $flowName, '--query', '{id:id,tags:tags}', '--output', 'json')
    Stop-LabIfDenied -Result $f -Service 'network' -Action 'watcher flow-log show' -Step 'flow-log show'
    if ($f.ExitCode -eq 0) {
        $fl = ConvertFrom-LabJson -Text $f.Output
        if ($fl -and -not (Test-LabTagged -Tags $fl.tags)) { Confirm-LabUntaggedRefusal -Kind 'Flow log' -Name $flowName }
        Write-LabInfo "Flow log '$flowName' already exists with the lab tag. Nothing to create."
    } elseif (-not (Test-LabNotFound -Text $f.Output)) {
        Stop-Lab -Code 1 -Message "Could not read flow log '$flowName'. $($f.Output)"
    } else {
        # 1. VNet
        $vnetId = $null
        if (-not [string]::IsNullOrWhiteSpace($VnetName)) {
            $v = Invoke-LabAz -CliArgs @('network', 'vnet', 'show', '--resource-group', $ResourceGroup, '--name', $VnetName, '--query', 'id', '--output', 'tsv')
            if ($v.ExitCode -eq 0) { $vnetId = "$($v.Output)".Trim() }
        } else {
            $vnetId = Resolve-LabResourceId -ResourceGroup $ResourceGroup -ResourceType 'Microsoft.Network/virtualNetworks' -Name ''
        }
        if ([string]::IsNullOrWhiteSpace($vnetId)) {
            Stop-Lab -Code 2 -Message "Could not find the lab VNet in '$ResourceGroup' (none carries the lab tag). Pass -VnetName."
        }

        # 2. Destination storage account
        $saName = if ($FlowLogsStorageAccount) { $FlowLogsStorageAccount } else { Get-LabFlowStorageName }
        $sa = Invoke-LabAz -CliArgs @('storage', 'account', 'show', '--resource-group', $ResourceGroup, '--name', $saName, '--query', '{id:id,tags:tags}', '--output', 'json')
        $saId = $null
        if ($sa.ExitCode -eq 0) {
            $s = ConvertFrom-LabJson -Text $sa.Output
            if ($s -and -not (Test-LabTagged -Tags $s.tags)) { Confirm-LabUntaggedRefusal -Kind 'Storage account' -Name $saName }
            $saId = "$($s.id)"
            Write-LabInfo "Storage account '$saName' already exists with the lab tag."
        } else {
            $c = Invoke-LabAz -Mutating -CliArgs (@('storage', 'account', 'create', '--resource-group', $ResourceGroup, '--name', $saName, '--location', $script:LabRegion,
                    '--sku', 'Standard_LRS', '--kind', 'StorageV2', '--min-tls-version', 'TLS1_2', '--allow-blob-public-access', 'false', '--tags') + (Get-LabTagArgs -RunId $RunId -Component 'flowlogs'))
            Assert-LabAzOk -Result $c -Service 'storage' -Action 'account create' -Failure "Could not create storage account '$saName'."
            $saId = "/subscriptions/$(Get-LabSubscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$saName"
            Write-LabInfo "Created storage account '$saName' for flow logs."
        }

        # 3. Flow log (VNet target, no Traffic Analytics)
        $c = Invoke-LabAz -Mutating -CliArgs (@('network', 'watcher', 'flow-log', 'create', '--location', $script:LabRegion, '--name', $flowName,
                '--vnet', $vnetId, '--storage-account', $saId, '--enabled', 'true', '--retention', "$RetentionDays", '--tags') + (Get-LabTagArgs -RunId $RunId))
        Assert-LabAzOk -Result $c -Service 'network' -Action 'watcher flow-log create' -Failure 'Could not create the VNet flow log.'
        Write-LabInfo "VNet flow logs enabled -> $saName (retention $RetentionDays days; first 5 GB per month are free)."
    }
} finally {
    Clear-LabTempFiles
}
exit 0
