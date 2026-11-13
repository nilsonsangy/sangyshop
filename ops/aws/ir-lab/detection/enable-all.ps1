<#
.SYNOPSIS
    Enables the whole detection stack: SNS, CloudTrail, CloudWatch Logs, VPC Flow Logs, GuardDuty.

.DESCRIPTION
    Runs the individual enable-*.ps1 scripts with one shared run-id. A failure in one
    component does not stop the others; the exit code is 1 if any component failed.
    Optional or costly components can be skipped:
      -SkipFlowLogs    do not enable VPC Flow Logs
      -SkipGuardDuty   do not enable GuardDuty
      -SkipDataEvents  CloudTrail logs management events only (no S3 data events)
    All components are billable; see the README for the estimated cost. Supports -WhatIf.

    The script starts by reading the account (trail, log group, topic, detector) and printing
    one line per resource type, then checks that the application log group exists. Safe to run
    again after a failure: what exists is reused and only the missing part is created.
    Exit codes: 0 done, 1 a component failed, 2 invalid parameter or configuration,
    3 a permission is missing (the message names the policy to attach; fix it and run again),
    4 the application log group does not exist (run ops/aws/ec2/deploy.ps1 first) or a quota
    was reached.

    -Email is optional: if omitted, the alert e-mail comes from $env:LAB_ALERT_EMAIL (set it
    in a .env file at the repository root, copied from .env.example), or an interactive
    prompt. -NonInteractive turns a missing e-mail into exit code 2 instead of a prompt.

    -LabBucket is optional: when omitted it defaults to the app bucket that
    ops/aws/ec2/deploy.ps1 creates (Aws.Ec2.BucketBase + '-' + UniqueSuffix from the config),
    or to the s3-bucket entry of the deploy component in the lab manifest. The cloudtrail
    component fails with exit code 2 only when neither is available (and -SkipDataEvents is
    not set).


    Required IAM actions:
      cloudtrail:AddTags
      cloudtrail:CreateTrail
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      cloudtrail:PutEventSelectors
      cloudtrail:StartLogging
      cloudwatch:DescribeAlarms
      cloudwatch:ListTagsForResource
      cloudwatch:PutMetricAlarm
      cloudwatch:TagResource
      ec2:CreateFlowLogs
      ec2:CreateTags
      ec2:DescribeFlowLogs
      ec2:DescribeVpcs
      guardduty:CreateDetector
      guardduty:GetDetector
      guardduty:ListDetectors
      guardduty:ListTagsForResource
      guardduty:TagResource
      guardduty:UpdateDetector
      iam:CreateRole
      iam:GetRole
      iam:ListRoleTags
      iam:PassRole
      iam:PutRolePolicy
      iam:TagRole
      logs:CreateLogGroup
      logs:DescribeLogGroups
      logs:DescribeMetricFilters
      logs:ListTagsForResource
      logs:PutMetricFilter
      logs:PutRetentionPolicy
      logs:TagResource
      s3:CreateBucket
      s3:GetBucketTagging
      s3:ListBucket
      s3:PutBucketPolicy
      s3:PutBucketPublicAccessBlock
      s3:PutBucketTagging
      sns:CreateTopic
      sns:GetTopicAttributes
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics
      sns:Subscribe
      sns:TagResource

.EXAMPLE
    .\enable-all.ps1 -Region us-east-1 -Email user@example.com -LabBucket my-lab-bucket -WhatIf

.EXAMPLE
    # LAB_ALERT_EMAIL set in .env at the repository root; the bucket comes from the config:
    .\enable-all.ps1 -Region us-east-1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$Email,
    [string]$LabBucket,
    [string]$VpcId,
    [string]$RunId,
    [switch]$SkipFlowLogs,
    [switch]$SkipGuardDuty,
    [switch]$SkipDataEvents,
    [switch]$NonInteractive
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
$wi = [bool]$WhatIfPreference
$null = Get-LabAccountId

# Preflight: read what exists (read verbs only) and print one line per resource type, before any change.
$snapshot = Get-LabPreflightSnapshot
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'trail' -ExpectedName $script:LabTrailName
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'loggroup' -ExpectedName $script:LabAppLogGroup
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'topic' -ExpectedName $script:LabTopicName
if (-not $SkipGuardDuty) { $null = Resolve-LabDecision -Snapshot $snapshot -Type 'detector' -ExpectedName 'detector' -Singleton }

# Step gate: the application must be deployed first, because it creates the log group the alarm watches.
if (-not (Test-LabLogGroupExists -Name $script:LabAppLogGroup)) {
    Stop-Lab -Code 4 -Message "The application log group '$($script:LabAppLogGroup)' does not exist, so the application is not deployed yet. Run ops/aws/ec2/deploy.ps1 first, then run this script again."
}

# Resolved once here (not inside enable-sns.ps1) so an interactive prompt happens only once.
$Email = Resolve-LabAlertEmail -Email $Email -NonInteractive:$NonInteractive
Write-LabInfo "Enabling the detection stack in $($script:LabRegion) (run-id $RunId)."

$steps = New-Object System.Collections.ArrayList
[void]$steps.Add(@{ Name = 'sns'; Script = 'enable-sns.ps1'; Params = @{ Region = $Region; Email = $Email; RunId = $RunId; NonInteractive = $true } })
$ct = @{ Region = $Region; RunId = $RunId }
if ($SkipDataEvents) { $ct['SkipDataEvents'] = $true } else {
    # Default from the config or the manifest. An empty result still goes to enable-cloudtrail.ps1,
    # which fails that component with exit code 2 and a clear message; the other components run.
    $ct['LabBucket'] = Resolve-LabAppBucket -LabBucket $LabBucket
}
[void]$steps.Add(@{ Name = 'cloudtrail'; Script = 'enable-cloudtrail.ps1'; Params = $ct })
[void]$steps.Add(@{ Name = 'logs'; Script = 'enable-logs.ps1'; Params = @{ Region = $Region; RunId = $RunId } })
if ($SkipFlowLogs) { Write-LabInfo 'Skipping VPC Flow Logs (-SkipFlowLogs).' } else {
    $fp = @{ Region = $Region; RunId = $RunId }
    if ($VpcId) { $fp['VpcId'] = $VpcId }
    [void]$steps.Add(@{ Name = 'flowlogs'; Script = 'enable-flowlogs.ps1'; Params = $fp })
}
if ($SkipGuardDuty) { Write-LabInfo 'Skipping GuardDuty (-SkipGuardDuty).' } else {
    [void]$steps.Add(@{ Name = 'guardduty'; Script = 'enable-guardduty.ps1'; Params = @{ Region = $Region; RunId = $RunId } })
}

$failed = @()
$codes = @()
foreach ($s in $steps) {
    Write-Host ''
    Write-LabInfo "=== $($s.Name) ==="
    $p = $s.Params
    & (Join-Path $PSScriptRoot $s.Script) @p -WhatIf:$wi
    if ($LASTEXITCODE -ne 0) {
        $failed += $s.Name
        $codes += [int]$LASTEXITCODE
        [Console]::Error.WriteLine("Error: component '$($s.Name)' failed with exit code $LASTEXITCODE")
    }
}
Write-Host ''
if ($failed.Count -gt 0) {
    # Permission (3) and precondition (4) codes win over a plain failure, so the operator sees what to fix.
    $final = 1
    if ($codes -contains 3) { $final = 3 } elseif ($codes -contains 4) { $final = 4 }
    if ($final -eq 3) { Write-LabInfo 'Fix the permission named above and run this same script again. Resources already created are detected and reused.' }
    Stop-Lab -Code $final -Message "Detection stack incomplete. Failed components: $($failed -join ', ')"
}
Write-LabInfo 'Detection stack enabled. Remember: these services are billable; run disable-all.ps1 or the Full_Teardown when done.'
Write-Host ''
Write-Host 'Next steps (text only, nothing was run):'
Write-Host '  1. Open the AWS Notifications e-mail and confirm the subscription.'
Write-Host '  2. Run ops/aws/ir-lab/check-detection-ready.ps1 to confirm the stack is ready.'
exit 0
