<#
.SYNOPSIS
    Prints the incident response commands for this lab. Runs nothing.

.DESCRIPTION
    Prints ready-to-copy native AWS CLI commands for the lab resources: query CloudTrail,
    list and read GuardDuty findings, snapshot the instance volume as evidence, move the
    instance to a quarantine security group, and contain the leaked IAM user (deactivate
    its access key and attach a deny-all inline policy).

    The script never executes a printed command and makes no AWS call. Values that depend
    on the live account (volume id, quarantine group id, access key id, time range) are
    printed as placeholders. Review each command before you run it: the snapshot, the
    group change and the IAM changes modify the account.

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

.PARAMETER InstanceId
    EC2 instance id to use in the isolation commands. Default: a placeholder.

.EXAMPLE
    .\print-response-commands.ps1 -Region us-east-1
#>
[CmdletBinding()]
param(
    [string]$Region,
    [string]$AttackEvidencePath,
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

$tagValue = [string]$script:LabTagValue
$region = $script:LabRegion
$instance = if ([string]::IsNullOrWhiteSpace($InstanceId)) { '<instance-id>' } else { $InstanceId }
$leakedUser = [string]$script:LabNames['LeakedUser']
$denyPolicyName = "$leakedUser-deny-all"

Write-Host ''
Write-LabInfo 'Response commands for the AWS lab. Nothing below is executed by this script.'
Write-Host "Attack evidence: $AttackEvidencePath"
# Local manifest read only: which trail holds the management events. A reused trail is never changed by the lab.
$trailTarget = Get-LabTrailTarget
Write-LabInfo ("CloudTrail source: trail '{0}' ({1}). The lab neither modifies nor removes a reused trail." -f $trailTarget.Name, $trailTarget.Ownership)
Write-Host ''
Write-Host '1. Query CloudTrail for the activity of the leaked IAM user (set the UTC range around the attack):'
Write-Host "   aws cloudtrail lookup-events --region $region --lookup-attributes AttributeKey=Username,AttributeValue=$leakedUser --start-time <start-utc> --end-time <end-utc>"
Write-Host ''
Write-Host '2. List the GuardDuty findings, then read the ones of interest:'
Write-Host "   aws guardduty list-findings --region $region --detector-id <detector-id> --finding-criteria '{`"Criterion`":{`"severity`":{`"Gte`":4}}}'"
Write-Host "   aws guardduty get-findings --region $region --detector-id <detector-id> --finding-ids <finding-id>"
Write-Host ''
Write-Host '3. Snapshot the instance volume as evidence (look up the volume id first):'
Write-Host "   aws ec2 describe-instances --region $region --instance-ids $instance --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' --output text"
Write-Host "   aws ec2 create-snapshot --region $region --volume-id <volume-id> --description 'evidence for $instance' --tag-specifications 'ResourceType=snapshot,Tags=[{Key=lab,Value=$tagValue}]'"
Write-Host ''
Write-Host '4. Quarantine the instance: replace its security groups with a group that has no inbound or outbound rules:'
Write-Host "   aws ec2 modify-instance-attribute --region $region --instance-id $instance --groups <quarantine-sg-id>"
Write-Host ''
Write-Host '5. Contain the leaked IAM user: deactivate its access key and attach a deny-all inline policy:'
Write-Host "   aws iam list-access-keys --user-name $leakedUser"
Write-Host "   aws iam update-access-key --user-name $leakedUser --access-key-id <access-key-id> --status Inactive"
Write-Host "   aws iam put-user-policy --user-name $leakedUser --policy-name $denyPolicyName --policy-document file://deny-all.json"
Write-Host ''
Write-Host 'deny-all.json holds: {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
Write-Host 'Steps 3, 4 and 5 change the account. Review each command before you run it.'
Write-Host 'Next step: run the commands above one at a time, reviewing the output of each.'
exit 0
