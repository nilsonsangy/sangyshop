<#
.SYNOPSIS
    Removes the brute-force alarm, the login-failure metric filter and the app log group (idempotent).

.DESCRIPTION
    The alarm and the log group are removed only when they carry lab tag. Use -KeepLogGroup
    to keep the collected application logs for analysis. Re-running when everything is
    gone exits 0. Supports -WhatIf.


    Required IAM actions:
      cloudwatch:DeleteAlarms
      cloudwatch:DescribeAlarms
      cloudwatch:ListTagsForResource
      logs:DeleteLogGroup
      logs:DeleteMetricFilter
      logs:DescribeLogGroups
      logs:DescribeMetricFilters
      logs:ListTagsForResource

.EXAMPLE
    .\disable-logs.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$LogGroup,
    [switch]$KeepLogGroup
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $LogGroup) { $LogGroup = $script:LabAppLogGroup }
Initialize-Lab -Region $Region
$null = Get-LabAccountId

try {
    # Alarm
    $a = Invoke-LabCli -CliArgs @('cloudwatch', 'describe-alarms', '--alarm-names', $script:LabAlarmName, '--query', 'MetricAlarms[].AlarmArn', '--output', 'json')
    $alarmArns = @()
    if ($a.ExitCode -eq 0) { $alarmArns = @(ConvertFrom-LabJson -Text $a.Output) }
    if ($alarmArns.Count -eq 0) {
        Write-LabInfo "Alarm '$($script:LabAlarmName)' not found. Nothing to remove."
    } else {
        $t = Invoke-LabCli -CliArgs @('cloudwatch', 'list-tags-for-resource', '--resource-arn', "$($alarmArns[0])", '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            Write-LabWarn "Alarm '$($script:LabAlarmName)' does not carry the lab tag: kept (not created by the lab). Left unchanged."
        } else {
            $d = Invoke-LabCli -Mutating -CliArgs @('cloudwatch', 'delete-alarms', '--alarm-names', $script:LabAlarmName)
            if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the alarm. $($d.Output)" }
            Write-LabInfo "Deleted alarm '$($script:LabAlarmName)'."
        }
    }

    # Metric filter (only if the log group exists and the filter is listed in the manifest or on the group)
    if (Test-LabLogGroupExists -Name $LogGroup) {
        $f = Invoke-LabCli -CliArgs @('logs', 'describe-metric-filters', '--log-group-name', $LogGroup, '--filter-name-prefix', $script:LabFilterName, '--query', 'metricFilters[].filterName', '--output', 'json')
        $names = @()
        if ($f.ExitCode -eq 0) { $names = @(ConvertFrom-LabJson -Text $f.Output) }
        if ($names -contains $script:LabFilterName) {
            $d = Invoke-LabCli -Mutating -CliArgs @('logs', 'delete-metric-filter', '--log-group-name', $LogGroup, '--filter-name', $script:LabFilterName)
            if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the metric filter. $($d.Output)" }
            Write-LabInfo "Deleted metric filter '$($script:LabFilterName)'."
        } else {
            Write-LabInfo "Metric filter '$($script:LabFilterName)' not found. Nothing to remove."
        }
    } else {
        Write-LabInfo "Log group '$LogGroup' not found, so there is no metric filter to remove."
    }
    Remove-LabManifestEntry -Type 'logs-metric-filter' -Id "$LogGroup|$($script:LabFilterName)"

    # Log group
    if ($KeepLogGroup) {
        Write-LabInfo "Keeping log group '$LogGroup' (-KeepLogGroup). It keeps costing storage until removed."
    } else {
        Remove-LabLogGroup -Name $LogGroup
    }
} finally {
    Clear-LabTempFiles
}
exit 0
