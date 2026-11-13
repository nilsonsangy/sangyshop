<#
.SYNOPSIS
    Disables the whole detection stack in reverse dependency order.

.DESCRIPTION
    Runs the individual disable-*.ps1 scripts: GuardDuty, VPC Flow Logs, CloudWatch Logs,
    CloudTrail, SNS. A failure in one component does not stop the others; the exit code is
    1 if any component failed. Skip switches mirror enable-all.ps1:
      -SkipFlowLogs    leave VPC Flow Logs untouched
      -SkipGuardDuty   leave GuardDuty untouched
      -SkipDataEvents  accepted for symmetry (the CloudTrail trail is removed either way)
    Use -KeepLogs to keep the log groups and the trail bucket for analysis. Supports -WhatIf.


    Required IAM actions:
      cloudtrail:DeleteTrail
      cloudtrail:DescribeTrails
      cloudtrail:ListTags
      cloudtrail:StopLogging
      cloudwatch:DeleteAlarms
      cloudwatch:DescribeAlarms
      cloudwatch:ListTagsForResource
      ec2:DeleteFlowLogs
      ec2:DescribeFlowLogs
      guardduty:DeleteDetector
      guardduty:ListDetectors
      guardduty:ListTagsForResource
      iam:DeleteRole
      iam:DeleteRolePolicy
      iam:GetRole
      iam:ListRoleTags
      logs:DeleteLogGroup
      logs:DeleteMetricFilter
      logs:DescribeLogGroups
      logs:DescribeMetricFilters
      logs:ListTagsForResource
      s3:DeleteBucket
      s3:DeleteObject
      s3:GetBucketTagging
      s3:ListBucket
      sns:DeleteTopic
      sns:GetTopicAttributes
      sns:ListTagsForResource

.EXAMPLE
    .\disable-all.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [switch]$SkipFlowLogs,
    [switch]$SkipGuardDuty,
    [switch]$SkipDataEvents,
    [switch]$KeepLogs
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Region $Region
$wi = [bool]$WhatIfPreference
Write-LabInfo "Disabling the detection stack in $($script:LabRegion)."

$steps = New-Object System.Collections.ArrayList
if ($SkipGuardDuty) { Write-LabInfo 'Skipping GuardDuty (-SkipGuardDuty).' } else {
    [void]$steps.Add(@{ Name = 'guardduty'; Script = 'disable-guardduty.ps1'; Params = @{ Region = $Region } })
}
if ($SkipFlowLogs) { Write-LabInfo 'Skipping VPC Flow Logs (-SkipFlowLogs).' } else {
    $fp = @{ Region = $Region }
    if ($KeepLogs) { $fp['KeepLogGroup'] = $true }
    [void]$steps.Add(@{ Name = 'flowlogs'; Script = 'disable-flowlogs.ps1'; Params = $fp })
}
$lp = @{ Region = $Region }
if ($KeepLogs) { $lp['KeepLogGroup'] = $true }
[void]$steps.Add(@{ Name = 'logs'; Script = 'disable-logs.ps1'; Params = $lp })
$cp = @{ Region = $Region }
if ($KeepLogs) { $cp['KeepTrailBucket'] = $true }
[void]$steps.Add(@{ Name = 'cloudtrail'; Script = 'disable-cloudtrail.ps1'; Params = $cp })
[void]$steps.Add(@{ Name = 'sns'; Script = 'disable-sns.ps1'; Params = @{ Region = $Region } })

$failed = @()
foreach ($s in $steps) {
    Write-Host ''
    Write-LabInfo "=== $($s.Name) ==="
    $p = $s.Params
    & (Join-Path $PSScriptRoot $s.Script) @p -WhatIf:$wi
    if ($LASTEXITCODE -ne 0) {
        $failed += $s.Name
        [Console]::Error.WriteLine("Error: component '$($s.Name)' failed with exit code $LASTEXITCODE")
    }
}
Write-Host ''
if ($failed.Count -gt 0) {
    Stop-Lab -Code 1 -Message "Some components could not be removed: $($failed -join ', ')"
}
Write-LabInfo 'Detection stack disabled.'
exit 0
