<#
.SYNOPSIS
    Creates the app log group, the login-failure metric filter and the brute-force alarm (idempotent).

.DESCRIPTION
    1. Log group /sangyshop/app (tagged, short retention). The SangyShop container ships
       its structured JSON logs there through the Docker awslogs driver.
    2. Metric filter matching the accesslog.js schema:
           { $.event = "auth_login" && $.result = "failure" }
       published as SangyShopLab/LoginFailure. Metric filters cannot carry tags, so the
       filter is recorded in the lab manifest.
    3. Alarm 'sangyshop-lab-bruteforce': Sum >= 10 over 60 seconds. When the alert topic
       exists (or -TopicArn is given) it is used as the alarm action.
    Re-running creates nothing new. Supports -WhatIf.

    A log group with this name that the lab did not create is reused as it is (not tagged,
    retention untouched, recorded with ownership reused); only the lab metric filter and
    alarm are added. Exit codes: 0 done, 1 failure, 3 permission missing (fix it and run the
    script again), 4 quota reached.


    Required IAM actions:
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      cloudwatch:DescribeAlarms
      cloudwatch:ListTagsForResource
      cloudwatch:PutMetricAlarm
      cloudwatch:TagResource
      guardduty:GetDetector
      guardduty:ListDetectors
      logs:CreateLogGroup
      logs:DescribeLogGroups
      logs:DescribeMetricFilters
      logs:ListTagsForResource
      logs:PutMetricFilter
      logs:PutRetentionPolicy
      logs:TagResource
      sns:GetTopicAttributes
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics

.EXAMPLE
    .\enable-logs.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$RunId,
    [string]$LogGroup,
    [string]$TopicArn,
    [int]$RetentionDays = 7,
    [switch]$AdoptExisting
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $LogGroup) { $LogGroup = $script:LabAppLogGroup }
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabAccountId

# Preflight: read what exists (read verbs only) before any change.
$snapshot = Get-LabPreflightSnapshot -LogGroup $LogGroup
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'loggroup' -ExpectedName $LogGroup

try {
    # 1. Log group (a group the lab did not create is reused as it is)
    $null = Confirm-LabLogGroup -Name $LogGroup -RunId $RunId -RetentionDays $RetentionDays -Adopt:$AdoptExisting

    # 2. Metric filter (update only when the pattern differs)
    $f = Invoke-LabCli -CliArgs @('logs', 'describe-metric-filters', '--log-group-name', $LogGroup, '--filter-name-prefix', $script:LabFilterName, '--query', 'metricFilters[].{n:filterName,p:filterPattern}', '--output', 'json')
    $existing = @()
    if ($f.ExitCode -eq 0) { $existing = @(ConvertFrom-LabJson -Text $f.Output | Where-Object { $_.n -eq $script:LabFilterName }) }
    if ($existing.Count -gt 0 -and $existing[0].p -eq $script:LabFilterPattern) {
        Write-LabInfo "Metric filter '$($script:LabFilterName)' already exists. Nothing to create."
    } else {
        $put = Invoke-LabCli -Mutating -CliArgs @(
            'logs', 'put-metric-filter', '--log-group-name', $LogGroup,
            '--filter-name', $script:LabFilterName,
            '--filter-pattern', $script:LabFilterPattern,
            '--metric-transformations', "metricName=$($script:LabMetricName),metricNamespace=$($script:LabMetricNamespace),metricValue=1")
        if ($put.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the metric filter. $($put.Output)" }
        Write-LabInfo "Metric filter '$($script:LabFilterName)' is in place."
    }
    Add-LabResource -Type 'logs-metric-filter' -Id "$LogGroup|$($script:LabFilterName)" -RunId $RunId

    # 3. Alarm
    if (-not $TopicArn) {
        $candidate = Get-LabTopicArn -Name $script:LabTopicName
        $probe = Invoke-LabCli -CliArgs @('sns', 'get-topic-attributes', '--topic-arn', $candidate, '--query', 'Attributes.TopicArn', '--output', 'text')
        if ($probe.ExitCode -eq 0) { $TopicArn = $candidate }
    }
    $a = Invoke-LabCli -CliArgs @('cloudwatch', 'describe-alarms', '--alarm-names', $script:LabAlarmName, '--query', 'MetricAlarms[].AlarmArn', '--output', 'json')
    $alarmArns = @()
    if ($a.ExitCode -eq 0) { $alarmArns = @(ConvertFrom-LabJson -Text $a.Output) }
    if ($alarmArns.Count -gt 0) {
        $t = Invoke-LabCli -CliArgs @('cloudwatch', 'list-tags-for-resource', '--resource-arn', "$($alarmArns[0])", '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            if (-not (Test-LabManifestCreated -Type 'cloudwatch-alarm' -Id $script:LabAlarmName)) {
                Confirm-LabUntaggedRefusal -Kind 'CloudWatch alarm' -Name $script:LabAlarmName
            }
            $ta = Invoke-LabCli -Mutating -CliArgs (@('cloudwatch', 'tag-resource', '--resource-arn', "$($alarmArns[0])", '--tags') + (Get-LabTagPairs -RunId $RunId))
            if ($ta.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of the alarm. $($ta.Output)" }
            Write-LabInfo "Alarm '$($script:LabAlarmName)' was created by the lab without tags. Completed the tags."
        }
        Write-LabInfo "Alarm '$($script:LabAlarmName)' already exists with the lab tag. Nothing to create."
    } else {
        $alarmArgs = @(
            'cloudwatch', 'put-metric-alarm', '--alarm-name', $script:LabAlarmName,
            '--alarm-description', 'SangyShop lab: 10 or more failed logins in 60 seconds',
            '--namespace', $script:LabMetricNamespace, '--metric-name', $script:LabMetricName,
            '--statistic', 'Sum', '--period', '60', '--evaluation-periods', '1', '--datapoints-to-alarm', '1',
            '--threshold', '10', '--comparison-operator', 'GreaterThanOrEqualToThreshold',
            '--treat-missing-data', 'notBreaching')
        if ($TopicArn) { $alarmArgs += @('--alarm-actions', $TopicArn) } else { Write-LabWarn 'Alert topic not found: the alarm has no notification action. Run enable-sns.ps1 and re-create the alarm.' }
        $alarmArgs += @('--tags') + (Get-LabTagPairs -RunId $RunId)
        $c = Invoke-LabCli -Mutating -CliArgs $alarmArgs
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the alarm. $($c.Output)" }
        Add-LabResource -Type 'cloudwatch-alarm' -Id $script:LabAlarmName -RunId $RunId
        Write-LabInfo "Created alarm '$($script:LabAlarmName)' (Sum >= 10 in 60 s)."
    }
} finally {
    Clear-LabTempFiles
}
exit 0
