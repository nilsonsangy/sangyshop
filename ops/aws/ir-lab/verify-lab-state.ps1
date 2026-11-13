<#
.SYNOPSIS
    Reports, read-only, which parts of the AWS detection stack exist.

.DESCRIPTION
    Prints one line per component: SNS topic, e-mail subscription, CloudTrail, app log
    group, login-failure metric filter, brute-force alarm, VPC flow logs and GuardDuty.
    A missing component is reported together with the script that creates it.

    Safety: only describe, get and list calls are made, never a mutating call, so it
    behaves the same with or without -WhatIf. Nothing is created, changed or removed.
    A denied read ends with exit code 3 and the exact managed policy to ask for.

    Exit codes:
      0  every checked component is present
      1  at least one component is missing or not usable
      2  configuration problem (no region, bad config)
      3  permission missing

    Required IAM actions:
      sts:GetCallerIdentity
      sns:GetTopicAttributes, sns:ListSubscriptionsByTopic
      cloudtrail:GetTrailStatus
      logs:DescribeLogGroups, logs:DescribeMetricFilters
      cloudwatch:DescribeAlarms
      ec2:DescribeFlowLogs
      guardduty:ListDetectors, guardduty:GetDetector

.PARAMETER Region
    AWS region. Defaults to Aws.Region of the config file.

.PARAMETER SkipFlowLogs
    Do not check VPC flow logs (matches enable-all.ps1 -SkipFlowLogs).

.PARAMETER SkipGuardDuty
    Do not check GuardDuty (matches enable-all.ps1 -SkipGuardDuty).

.EXAMPLE
    .\verify-lab-state.ps1 -Region us-east-1
#>
[CmdletBinding()]
param(
    [string]$Region,
    [switch]$SkipFlowLogs,
    [switch]$SkipGuardDuty
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
. "$PSScriptRoot\LabState-Common.ps1"
Initialize-Lab -Region $Region
$null = Get-LabAccountId

Write-LabInfo "Checking the detection stack in $($script:LabRegion) (read-only)."
$components = @(
    (Get-LabTopicState),
    (Get-LabSubscriptionState),
    (Get-LabTrailState),
    (Get-LabLogGroupState),
    (Get-LabMetricFilterState),
    (Get-LabAlarmState)
)
if ($SkipFlowLogs) { Write-LabInfo 'Skipping VPC flow logs (-SkipFlowLogs).' } else { $components += (Get-LabFlowLogState) }
if ($SkipGuardDuty) { Write-LabInfo 'Skipping GuardDuty (-SkipGuardDuty).' } else { $components += (Get-LabGuardDutyState) }

Write-Host ''
foreach ($c in $components) { Write-LabComponentLine -Component $c }
Write-Host ''

$bad = @($components | Where-Object { -not $_.Ok })
if ($bad.Count -gt 0) {
    $scripts = @($bad | ForEach-Object { $_.Script } | Where-Object { $_ } | Select-Object -Unique)
    Write-Host ("{0} of {1} components need attention. Run: {2}, or detection/enable-all.ps1." -f $bad.Count, $components.Count, ($scripts -join ', '))
    Write-Host 'Next step: run the script named above, then run verify-lab-state.ps1 again.'
    exit 1
}
Write-Host ("All {0} components are present." -f $components.Count)
Write-Host 'Next step: run check-detection-ready.ps1 before starting the attack simulation.'
exit 0
