<#
.SYNOPSIS
    Prints the generic incident response commands for this lab. Runs nothing.

.DESCRIPTION
    Prints ready-to-copy NimbusDFIR commands for the AWS lab: collect CloudTrail events,
    export GuardDuty findings, contain the leaked IAM user, isolate the instance and
    snapshot its volumes. Every command is dry-run by default in NimbusDFIR; the printed
    lines do not add -Execute, so you review the plan first.

    The script never executes a printed command and makes no AWS call. The NimbusDFIR
    checkout comes from -NimbusDfirPath, NIMBUSDFIR_PATH or Common.NimbusDfirPath in
    the config (Resolve-NimbusDfirPath). When none is set, the commands are printed
    with a placeholder for the checkout folder.

    Precondition: the attack simulation must have run, so its evidence file exists
    (attack-simulation/out/attack-steps.jsonl). Without it the script exits with code 4
    and names the attack step.

    Exit codes:
      0  commands printed
      2  configuration problem (no region, bad config)
      4  attack evidence file not found; run the attack simulation first

.PARAMETER Region
    AWS region. Defaults to Aws.Region of the config file.

.PARAMETER AttackEvidencePath
    Attack step log. Default: attack-simulation/out/attack-steps.jsonl in this repository.

.PARAMETER NimbusDfirPath
    Folder of a NimbusDFIR checkout. Overrides NIMBUSDFIR_PATH.

.PARAMETER InstanceId
    EC2 instance id to use in the isolation commands. Default: a placeholder.

.EXAMPLE
    .\print-response-commands.ps1 -Region us-east-1
#>
[CmdletBinding()]
param(
    [string]$Region,
    [string]$AttackEvidencePath,
    [string]$NimbusDfirPath,
    [string]$InstanceId
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
. "$PSScriptRoot\LabState-Common.ps1"
Initialize-Lab -Region $Region

# Precondition gate: the attack must have produced its evidence file.
if ([string]::IsNullOrWhiteSpace($AttackEvidencePath)) {
    $AttackEvidencePath = Join-Path $PSScriptRoot '..\..\..\attack-simulation\out\attack-steps.jsonl'
}
if (-not (Test-Path -LiteralPath $AttackEvidencePath -PathType Leaf)) {
    [Console]::Error.WriteLine("BLOCKED: the attack evidence file was not found: $AttackEvidencePath")
    [Console]::Error.WriteLine('  Cause : the attack simulation step has not run yet, so there is nothing to respond to.')
    [Console]::Error.WriteLine('  Fix   : run the attack simulation first (node attack-simulation/attack.js), then run this script again.')
    exit 4
}

$nimbus = Resolve-NimbusDfirPath -Path $NimbusDfirPath -Config $script:LabConfig -Optional
$placeholder = $false
if ($nimbus) {
    $aws = (Join-Path $nimbus 'aws')
} else {
    $placeholder = $true
    $aws = '<NimbusDFIR>\aws'
}
$tag = "lab=$($script:LabTagValue)"
$region = $script:LabRegion
$instance = if ([string]::IsNullOrWhiteSpace($InstanceId)) { '<instance-id>' } else { $InstanceId }
$leakedUser = [string]$script:LabNames['LeakedUser']

Write-Host ''
Write-LabInfo 'Response commands for the AWS lab. Nothing below is executed by this script.'
if ($placeholder) {
    Write-LabWarn 'NimbusDFIR was not found. Set NIMBUSDFIR_PATH or pass -NimbusDfirPath, then run this script again to print real paths.'
}
Write-Host "Attack evidence: $AttackEvidencePath"
# Local manifest read only: which trail holds the management events. A reused trail is never changed by the lab.
$trailTarget = Get-LabTrailTarget
Write-LabInfo ("CloudTrail source: trail '{0}' ({1}). The lab neither modifies nor removes a reused trail." -f $trailTarget.Name, $trailTarget.Ownership)
Write-Host ''
Write-Host '1. Collect CloudTrail management events (set the UTC range around the attack):'
Write-Host "   & '$aws\cloudtrail_collect.ps1' -StartTime <start-utc> -EndTime <end-utc> -Region $region -Identity $leakedUser"
Write-Host ''
Write-Host '2. Export GuardDuty findings:'
Write-Host "   & '$aws\guardduty_findings_export.ps1' -DetectorId <detector-id> -MinSeverity 4 -StartTime <start-utc> -EndTime <end-utc> -Region $region"
Write-Host ''
Write-Host '3. Contain the leaked IAM user (deactivates its keys, attaches a deny-all policy):'
Write-Host "   & '$aws\iam_credential_containment.ps1' -UserName $leakedUser -Region $region"
Write-Host ''
Write-Host '4. Isolate the instance (the tag marks the quarantine group as part of this lab):'
Write-Host "   & '$aws\ec2_evidence_preservation.ps1' isolate $instance -Region $region -Tag $tag"
Write-Host ''
Write-Host '5. Snapshot the instance volumes as evidence:'
Write-Host "   & '$aws\ec2_evidence_preservation.ps1' snapshot -Region $region -Tag $tag"
Write-Host ''
Write-Host 'Each tool runs as a dry run until you add -Execute. Review the plan, then add -Execute.'
Write-Host 'Next step: run the commands above one at a time, reviewing each dry run first.'
exit 0
