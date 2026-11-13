<#
.SYNOPSIS
    Prints ready-to-run incident response commands for the Azure lab. Runs nothing.

.DESCRIPTION
    Builds the commands of the generic NimbusDFIR Azure tools (VM isolation, disk snapshot,
    activity log collection) with the real lab values filled in: VM name, resource group,
    subscription, region and, when the subscription is given, the OS disk name read from
    Azure. The commands are only printed. Every NimbusDFIR tool is a dry-run unless you add
    -Execute, so review each command before you run it.

    The NimbusDFIR checkout is found with Resolve-NimbusDfirPath, in this order: -NimbusDfirPath,
    the NIMBUSDFIR_PATH environment variable, then Common.NimbusDfirPath in the cloud config.
    When no valid checkout is found the commands are still printed with a <NimbusDFIR> placeholder.

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
.PARAMETER NimbusDfirPath
    Path of the NimbusDFIR checkout (overrides NIMBUSDFIR_PATH and the cloud config).
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
    [string]$NimbusDfirPath,
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

# Locate the NimbusDFIR tools. A missing checkout is not fatal: the commands keep a placeholder.
$root = Resolve-NimbusDfirPath -Path $NimbusDfirPath -Config $script:LabConfig -Optional
$rootText = '<NimbusDFIR>'
if ($root) { $rootText = $root }
else { Write-LabWarn 'NimbusDFIR checkout not found. Set NIMBUSDFIR_PATH or pass -NimbusDfirPath, then run this script again.' }

function Format-ToolPath {
    param([string]$Relative)
    if ($root) {
        try { return (Get-NimbusToolPath -NimbusDfirPath $root -Relative $Relative) } catch { Write-LabWarn "$($_.Exception.Message)" }
    }
    return (Join-Path $rootText ($Relative -replace '/', '\'))
}

$isolate = Format-ToolPath -Relative 'azure/vm_isolate.ps1'
$snapshot = Format-ToolPath -Relative 'azure/disk_snapshot_hash.ps1'
$activity = Format-ToolPath -Relative 'azure/azure_activity_collect.ps1'

Write-Host ''
Write-Host "Lab tag     : $($script:LabTagKey)=$($script:LabTagValue)"
Write-Host "VM          : $vmName"
Write-Host "Group       : $ResourceGroup"
Write-Host "Region      : $region"
Write-Host ''
Write-Host '# 1. Isolate the VM (dry-run first, add -Execute to apply; use -Restore -Record <file> to undo)'
Write-Host "& '$isolate' -VmName '$vmName' -ResourceGroup '$ResourceGroup' -Subscription '$subText' -Region '$region'"
Write-Host ''
Write-Host '# 2. Snapshot and hash the OS disk (dry-run first, add -Execute to apply)'
Write-Host "& '$snapshot' -DiskName '$diskName' -ResourceGroup '$ResourceGroup' -Subscription '$subText' -Region '$region'"
Write-Host ''
Write-Host '# 3. Collect the activity log for the attack window (fill in the UTC times from the attack step log)'
Write-Host "& '$activity' -StartUtc '<start-utc>' -EndUtc '<end-utc>' -Subscription '$subText' -Region '$region'"
Write-Host ''
Write-Host 'Nothing was executed. Review each command, then run it yourself.'
exit 0
