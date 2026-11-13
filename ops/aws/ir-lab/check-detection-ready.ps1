<#
.SYNOPSIS
    Checks, read-only, that detection will fire before the attack simulation starts.

.DESCRIPTION
    Four checks must all pass:
      1. the alert e-mail subscription is Confirmed (not PendingConfirmation)
      2. the brute-force alarm exists and has a notification action
      3. the application log group exists
      4. the trail (created by the lab or reused from the account) is logging

    On success (exit 0) it writes the readiness stamp readiness-<lab>.json next to the
    lab manifest (lab, region, UTC time and the four results; no e-mail address). On
    any other exit code no stamp is written and an older stamp is left as it was.

    Safety: only describe, get and list calls, never a mutating call. A denied read ends
    with exit code 3 and the exact managed policy to ask for.

    Exit codes:
      0  ready, stamp written
      1  a component is missing or not usable
      2  configuration problem (no region, bad config)
      3  permission missing
      4  the e-mail subscription is still PendingConfirmation

    Required IAM actions:
      sts:GetCallerIdentity
      sns:ListSubscriptionsByTopic
      cloudwatch:DescribeAlarms
      logs:DescribeLogGroups
      cloudtrail:GetTrailStatus

.PARAMETER Region
    AWS region. Defaults to Aws.Region of the config file.

.PARAMETER StampPath
    Where to write the readiness stamp. Default: next to the lab manifest.

.EXAMPLE
    .\check-detection-ready.ps1 -Region us-east-1
#>
[CmdletBinding()]
param(
    [string]$Region,
    [string]$StampPath
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
. "$PSScriptRoot\LabState-Common.ps1"
Initialize-Lab -Region $Region
$null = Get-LabAccountId

Write-LabInfo "Checking detection readiness in $($script:LabRegion) (read-only)."
$sub = Get-LabSubscriptionState
$alarm = Get-LabAlarmState
$logGroup = Get-LabLogGroupState
$trail = Get-LabTrailState

Write-Host ''
Write-LabInfo "Trail checked: '$($trail.TrailName)' ($($trail.TrailOwnership))."
foreach ($c in @($sub, $alarm, $logGroup, $trail)) { Write-LabComponentLine -Component $c }
Write-Host ''

if ($sub.Status -eq 'PendingConfirmation') {
    Write-Host 'The alert e-mail is not confirmed yet, so no alert would reach you.'
    Write-Host 'Open the AWS Notifications e-mail (check spam) and choose Confirm subscription.'
    $others = @(@($alarm, $logGroup, $trail) | Where-Object { -not $_.Ok })
    if ($others.Count -gt 0) {
        $fixes = @($others | ForEach-Object { $_.Script } | Select-Object -Unique)
        Write-Host ("Also run: {0}" -f ($fixes -join ', '))
    }
    Write-Host 'Next step: confirm the e-mail subscription, then run check-detection-ready.ps1 again.'
    exit 4
}

$bad = @(@($sub, $alarm, $logGroup, $trail) | Where-Object { -not $_.Ok })
if ($bad.Count -gt 0) {
    $fixes = @($bad | ForEach-Object { $_.Script } | Select-Object -Unique)
    Write-Host ("Detection is not ready. Run: {0}, or detection/enable-all.ps1." -f ($fixes -join ', '))
    Write-Host 'Next step: run the script named above, then run check-detection-ready.ps1 again.'
    exit 1
}

$checks = @{
    subscription_confirmed = $sub.Ok
    alarm_has_action       = $alarm.Ok
    log_group_exists       = $logGroup.Ok
    trail_logging          = $trail.Ok
}
$written = Write-LabReadinessStamp -Checks $checks -Path $StampPath -TrailName $trail.TrailName -TrailOwnership $trail.TrailOwnership
Write-LabInfo "Detection is ready. Readiness stamp written to $written"
Write-Host 'Next step: start the attack simulation (attack-simulation/attack.js).'
exit 0
