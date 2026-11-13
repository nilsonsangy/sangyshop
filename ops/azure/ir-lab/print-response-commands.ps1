<#
.SYNOPSIS
    Prints ready-to-run incident response commands for the Azure lab. Runs nothing.

.DESCRIPTION
    Prints native Azure CLI commands for the lab resources, with the real lab values filled
    in: VM name, resource group, subscription, region and, when the subscription is given,
    the OS disk name read from Azure. The commands cover the Activity Log, Defender for Cloud
    alerts, a snapshot of the OS disk, isolation of the VM network interface and removal of
    the leaked service principal credential.

    The commands are only printed. The snapshot, the network interface change and the
    credential removal modify the subscription, so review each command before you run it.

    Exit codes:
      0  commands printed
      3  a read was denied (the message names the built-in role to assign)
      4  no attack evidence file exists. Run the simulated attack first.
      2  configuration problem

    Only read calls are used (az vm show). Nothing is created, changed or deleted.

.PARAMETER Subscription
    Subscription id or name. Optional: without it the commands carry a <subscription-id>
    placeholder and the disk name is a placeholder too (no Azure call is made).
.PARAMETER ResourceGroup
    Lab resource group. Defaults to the group derived from the cloud config.
.PARAMETER Region
    Lab region. Defaults to the location in the cloud config.
.PARAMETER AttackEvidencePath
    Attack step log written by the simulated attack. Defaults to attack-simulation/out/attack-steps.jsonl.

.EXAMPLE
    .\print-response-commands.ps1 -Subscription 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$AttackEvidencePath
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
. (Join-Path $PSScriptRoot '..\..\lib\LabPermissions.ps1')
# The libraries turn strict mode on; this script reads optional CLI output.
Set-StrictMode -Off

# Gate: the response step needs the evidence of the attack step.
if ([string]::IsNullOrWhiteSpace($AttackEvidencePath)) {
    $AttackEvidencePath = Join-Path $PSScriptRoot '..\..\..\attack-simulation\out\attack-steps.jsonl'
}
if (-not (Test-Path -LiteralPath $AttackEvidencePath -PathType Leaf)) {
    [Console]::Error.WriteLine('BLOCKED: no attack evidence found. Run the simulated attack first (attack-simulation/attack.js).')
    exit 4
}

Assert-LabConfigLoaded
$names = Get-VmLabNames -Config $script:LabConfig
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$region = if ([string]::IsNullOrWhiteSpace($Region)) { $script:LabLocation } else { (($Region -replace '\s', '').ToLowerInvariant()) }
$vmName = $names['VmName']
$leakedSp = $names['LeakedSp']
$subText = '<subscription-id>'
$diskName = '<os-disk-name>'

if (-not [string]::IsNullOrWhiteSpace($Subscription)) {
    Initialize-Lab -Subscription $Subscription -Region $Region
    $subText = $script:LabSubscription
    # Read-only lookup of the real OS disk name of the lab VM.
    $r = Invoke-LabAz -CliArgs @('vm', 'show', '--resource-group', $ResourceGroup, '--name', $vmName, '--query', 'storageProfile.osDisk.name', '--output', 'tsv')
    if ($r.ExitCode -eq 0) {
        $d = "$($r.Output)".Trim()
        if ($d) { $diskName = $d }
    } elseif (Test-LabAccessDenied -Text $r.Output) {
        $hint = Get-LabPermissionHint -Cloud Azure -Service 'vm' -Action 'vm show'
        Stop-LabForPermission -Hint $hint -Step 'print-response-commands'
    } else {
        Write-LabWarn "Could not read VM '$vmName' in '$ResourceGroup' (not deployed yet?). The disk name stays a placeholder."
    }
}

$snapshotName = "$vmName-evidence-snapshot"

Write-Host ''
Write-Host "Lab tag     : $($script:LabTagKey)=$($script:LabTagValue)"
Write-Host "VM          : $vmName"
Write-Host "Group       : $ResourceGroup"
Write-Host "Region      : $region"
Write-Host ''
Write-Host '# 1. Collect the Activity Log for the attack window (fill in the UTC times from the attack step log)'
Write-Host "az monitor activity-log list --subscription '$subText' --resource-group '$ResourceGroup' --start-time '<start-utc>' --end-time '<end-utc>' --output json"
Write-Host ''
Write-Host '# 2. List the Defender for Cloud alerts'
Write-Host "az security alert list --subscription '$subText' --output json"
Write-Host ''
Write-Host '# 3. Snapshot the OS disk as evidence'
Write-Host "az snapshot create --subscription '$subText' --resource-group '$ResourceGroup' --location '$region' --name '$snapshotName' --source '$diskName' --tags $($script:LabTagKey)=$($script:LabTagValue)"
Write-Host ''
Write-Host '# 4. Isolate the VM: find its network interface, then attach a network security group that denies all traffic'
Write-Host "az vm show --subscription '$subText' --resource-group '$ResourceGroup' --name '$vmName' --query 'networkProfile.networkInterfaces[0].id' --output tsv"
Write-Host "az network nic update --ids '<nic-id>' --network-security-group '<quarantine-nsg-id>'"
Write-Host ''
Write-Host "# 5. Contain the leaked service principal '$leakedSp': find it, list its credentials, delete the leaked one"
Write-Host "az ad sp list --display-name '$leakedSp' --query '[0].appId' --output tsv"
Write-Host "az ad sp credential list --id '<app-id>' --output json"
Write-Host "az ad sp credential delete --id '<app-id>' --key-id '<key-id>'"
Write-Host ''
Write-Host 'Nothing was executed. Steps 3, 4 and 5 change the subscription. Review each command, then run it yourself.'
exit 0
