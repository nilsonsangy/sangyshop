<#
.SYNOPSIS
    Read-only state checks shared by verify-lab-state.ps1 and check-detection-ready.ps1.

.DESCRIPTION
    Dot-source it after Detection-Common.ps1:
        . "$PSScriptRoot\detection\Detection-Common.ps1"
        . "$PSScriptRoot\LabState-Common.ps1"

    Every AWS call goes through Invoke-LabCli without -Mutating, and only with
    describe, get and list verbs. Nothing here creates, changes, tags or removes a
    resource, and no IAM verb is called. A read that is denied stops the script with
    exit code 3 and the exact managed policy to ask for (Stop-LabForPermission).

    Windows PowerShell 5.1 compatible.
#>

Set-StrictMode -Version Latest

function Invoke-LabRead {
    <#
    .SYNOPSIS
        One read-only AWS CLI call. Returns Ok, Data (parsed JSON or $null) and Text.
    .DESCRIPTION
        Access denied ends the script with exit code 3. Any other failure returns
        Ok = $false so the caller reports the component as missing or unreadable.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][string]$Operation,
        [string[]]$Extra = @()
    )
    $cliArgs = @($Service, $Operation) + @($Extra) + @('--output', 'json')
    $r = Invoke-LabCli -CliArgs $cliArgs
    $text = if ($null -ne $r -and $null -ne $r.PSObject.Properties['Output']) { "$($r.Output)" } else { '' }
    $code = if ($null -ne $r -and $null -ne $r.PSObject.Properties['ExitCode']) { [int]$r.ExitCode } else { 0 }
    if ($code -ne 0) {
        if (Test-LabAccessDenied -Text $text) {
            $hint = Get-LabPermissionHint -Cloud Aws -Service $Service -Action $Operation
            Stop-LabForPermission -Hint $hint -Step "$Service $Operation"
        }
        return [pscustomobject]@{ Ok = $false; Data = $null; Text = (Protect-LabText -Text $text).Trim() }
    }
    return [pscustomobject]@{ Ok = $true; Data = (ConvertFrom-LabJson -Text $text); Text = $text }
}

function Get-LabStateProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function New-LabComponent {
    param([string]$Name, [bool]$Ok, [string]$Detail, [string]$Script, [string]$Status = '')
    if (-not $Status) { $Status = if ($Ok) { 'ok' } else { 'missing' } }
    return [pscustomobject]@{ Name = $Name; Ok = $Ok; Status = $Status; Detail = $Detail; Script = $Script }
}

$script:LabTrailManifestType = 'cloudtrail-trail'

function Get-LabTrailManifestEntries {
    <#
    Entries of type cloudtrail-trail (the type enable-cloudtrail.ps1 writes, created or reused).
    Reads the manifest at Get-LabManifestPath (default $HOME/.sangyshop-lab/manifest-<lab>.json,
    LAB_MANIFEST_PATH overrides) and, when that has none, the older lab-manifest.json in the same folder.
    #>
    $primary = Get-LabManifestPath -Lab $script:LabTagValue
    $paths = @($primary)
    if ([string]::IsNullOrWhiteSpace($env:LAB_MANIFEST_PATH)) { $paths += (Join-Path (Split-Path -Parent $primary) 'lab-manifest.json') }
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $doc = $null
        try { $doc = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($p)) } catch { $doc = $null }
        if ($null -eq $doc -or $null -eq (Get-LabStateProp $doc 'resources')) { continue }
        $found = @(@(Get-LabStateProp $doc 'resources') | Where-Object {
                $null -ne $_ -and "$(Get-LabStateProp $_ 'type')" -ieq $script:LabTrailManifestType -and -not [string]::IsNullOrWhiteSpace("$(Get-LabStateProp $_ 'id')")
            })
        if ($found.Count -gt 0) { return $found }
    }
    return @()
}

function Get-LabTrailTarget {
    <#
    The trail to inspect: the newest trail entry of the lab manifest (created or reused),
    else the lab trail name. Returns Name, Ownership (created, reused or default) and Source.
    #>
    $entries = @(Get-LabTrailManifestEntries)
    if ($entries.Count -gt 0) {
        $e = $entries[$entries.Count - 1]
        $own = "$(Get-LabStateProp $e 'ownership')"
        if ([string]::IsNullOrWhiteSpace($own)) { $own = 'created' }
        return [pscustomobject]@{ Name = "$(Get-LabStateProp $e 'id')"; Ownership = $own; Source = 'manifest' }
    }
    return [pscustomobject]@{ Name = $script:LabTrailName; Ownership = 'default'; Source = 'lab trail name' }
}

function Get-LabTrailIdentifier {
    <# The name of the trail to inspect (see Get-LabTrailTarget). #>
    return (Get-LabTrailTarget).Name
}

function Get-LabTopicState {
    $r = Invoke-LabRead -Service 'sns' -Operation 'get-topic-attributes' -Extra @('--topic-arn', (Get-LabTopicArn -Name $script:LabTopicName))
    return (New-LabComponent -Name 'sns-topic' -Ok $r.Ok -Detail $(if ($r.Ok) { "topic '$($script:LabTopicName)' exists" } else { "topic '$($script:LabTopicName)' not found" }) -Script 'detection/enable-sns.ps1')
}

function Get-LabSubscriptionState {
    # Status: Confirmed, PendingConfirmation or missing.
    $r = Invoke-LabRead -Service 'sns' -Operation 'list-subscriptions-by-topic' -Extra @('--topic-arn', (Get-LabTopicArn -Name $script:LabTopicName))
    $fixScript = 'detection/enable-sns.ps1'
    if (-not $r.Ok) { return (New-LabComponent -Name 'sns-subscription' -Ok $false -Detail 'subscriptions could not be read' -Script $fixScript) }
    $subs = @(Get-LabStateProp $r.Data 'Subscriptions') | Where-Object { $null -ne $_ -and (Get-LabStateProp $_ 'Protocol') -eq 'email' }
    $subs = @($subs)
    if ($subs.Count -eq 0) { return (New-LabComponent -Name 'sns-subscription' -Ok $false -Detail 'no e-mail subscription on the alert topic' -Script $fixScript) }
    foreach ($s in $subs) {
        $arn = "$(Get-LabStateProp $s 'SubscriptionArn')"
        if ($arn -like 'arn:*') { return (New-LabComponent -Name 'sns-subscription' -Ok $true -Detail 'e-mail subscription is confirmed' -Script $fixScript -Status 'Confirmed') }
    }
    return (New-LabComponent -Name 'sns-subscription' -Ok $false -Detail 'e-mail subscription is waiting for confirmation (PendingConfirmation)' -Script $fixScript -Status 'PendingConfirmation')
}

function Get-LabTrailState {
    $target = Get-LabTrailTarget
    $id = $target.Name
    $how = switch ($target.Ownership) {
        'reused' { 'reused from the account, per lab manifest' }
        'created' { 'created by the lab, per lab manifest' }
        default { 'lab trail name, no trail in the lab manifest' }
    }
    $label = "trail '$id' ($how)"
    $fixScript = 'detection/enable-cloudtrail.ps1'
    $r = Invoke-LabRead -Service 'cloudtrail' -Operation 'get-trail-status' -Extra @('--name', $id)
    $c = $null
    if (-not $r.Ok) {
        $c = New-LabComponent -Name 'cloudtrail' -Ok $false -Detail "$label not found" -Script $fixScript
    } elseif ((Get-LabStateProp $r.Data 'IsLogging') -eq $true) {
        $c = New-LabComponent -Name 'cloudtrail' -Ok $true -Detail "$label is logging" -Script $fixScript
    } else {
        $c = New-LabComponent -Name 'cloudtrail' -Ok $false -Detail "$label exists but is not logging" -Script $fixScript -Status 'not-logging'
    }
    $c | Add-Member -NotePropertyName TrailName -NotePropertyValue $id
    $c | Add-Member -NotePropertyName TrailOwnership -NotePropertyValue $target.Ownership
    return $c
}

function Get-LabLogGroupState {
    $fixScript = 'detection/enable-logs.ps1'
    $r = Invoke-LabRead -Service 'logs' -Operation 'describe-log-groups' -Extra @('--log-group-name-prefix', $script:LabAppLogGroup)
    $found = $false
    if ($r.Ok) {
        foreach ($g in @(Get-LabStateProp $r.Data 'logGroups')) {
            if ($null -ne $g -and "$(Get-LabStateProp $g 'logGroupName')" -ceq $script:LabAppLogGroup) { $found = $true }
        }
    }
    return (New-LabComponent -Name 'app-log-group' -Ok $found -Detail $(if ($found) { "log group '$($script:LabAppLogGroup)' exists" } else { "log group '$($script:LabAppLogGroup)' not found" }) -Script $fixScript)
}

function Get-LabMetricFilterState {
    $fixScript = 'detection/enable-logs.ps1'
    $r = Invoke-LabRead -Service 'logs' -Operation 'describe-metric-filters' -Extra @('--log-group-name', $script:LabAppLogGroup, '--filter-name-prefix', $script:LabFilterName)
    $found = $false
    if ($r.Ok) {
        foreach ($f in @(Get-LabStateProp $r.Data 'metricFilters')) {
            if ($null -ne $f -and "$(Get-LabStateProp $f 'filterName')" -ceq $script:LabFilterName) { $found = $true }
        }
    }
    return (New-LabComponent -Name 'metric-filter' -Ok $found -Detail $(if ($found) { "metric filter '$($script:LabFilterName)' exists" } else { "metric filter '$($script:LabFilterName)' not found" }) -Script $fixScript)
}

function Get-LabAlarmState {
    # Ok only when the alarm exists and has at least one alarm action.
    $fixScript = 'detection/enable-logs.ps1'
    $r = Invoke-LabRead -Service 'cloudwatch' -Operation 'describe-alarms' -Extra @('--alarm-names', $script:LabAlarmName)
    $alarm = $null
    if ($r.Ok) {
        $alarm = @(Get-LabStateProp $r.Data 'MetricAlarms') | Where-Object { $null -ne $_ } | Select-Object -First 1
    }
    if ($null -eq $alarm) { return (New-LabComponent -Name 'alarm' -Ok $false -Detail "alarm '$($script:LabAlarmName)' not found" -Script $fixScript) }
    $actions = @(Get-LabStateProp $alarm 'AlarmActions') | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }
    if (@($actions).Count -eq 0) {
        return (New-LabComponent -Name 'alarm' -Ok $false -Detail "alarm '$($script:LabAlarmName)' exists but has no notification action" -Script $fixScript -Status 'no-action')
    }
    return (New-LabComponent -Name 'alarm' -Ok $true -Detail "alarm '$($script:LabAlarmName)' exists with a notification action" -Script $fixScript)
}

function Get-LabFlowLogState {
    $fixScript = 'detection/enable-flowlogs.ps1'
    $r = Invoke-LabRead -Service 'ec2' -Operation 'describe-flow-logs' -Extra @('--filter', "Name=tag:$($script:LabTagKey),Values=$($script:LabTagValue)")
    $n = 0
    if ($r.Ok) { $n = @(@(Get-LabStateProp $r.Data 'FlowLogs') | Where-Object { $null -ne $_ }).Count }
    return (New-LabComponent -Name 'vpc-flow-logs' -Ok ($n -gt 0) -Detail $(if ($n -gt 0) { 'VPC flow logs are enabled' } else { 'no lab-tagged VPC flow log found' }) -Script $fixScript)
}

function Get-LabGuardDutyState {
    $fixScript = 'detection/enable-guardduty.ps1'
    $r = Invoke-LabRead -Service 'guardduty' -Operation 'list-detectors'
    $ids = @()
    if ($r.Ok) { $ids = @(@(Get-LabStateProp $r.Data 'DetectorIds') | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }) }
    if ($ids.Count -eq 0) { return (New-LabComponent -Name 'guardduty' -Ok $false -Detail 'no GuardDuty detector in this region' -Script $fixScript) }
    $g = Invoke-LabRead -Service 'guardduty' -Operation 'get-detector' -Extra @('--detector-id', "$($ids[0])")
    $enabled = $g.Ok -and ("$(Get-LabStateProp $g.Data 'Status')" -eq 'ENABLED')
    return (New-LabComponent -Name 'guardduty' -Ok $enabled -Detail $(if ($enabled) { 'GuardDuty detector is enabled' } else { 'GuardDuty detector exists but is not enabled' }) -Script $fixScript -Status $(if ($enabled) { 'ok' } else { 'disabled' }))
}

function Write-LabComponentLine {
    param($Component)
    $mark = if ($Component.Ok) { 'OK     ' } else { 'MISSING' }
    $line = '{0} {1,-17} {2}' -f $mark, $Component.Name, $Component.Detail
    if (-not $Component.Ok -and $Component.Script) { $line += " (created by $($Component.Script))" }
    Write-Host $line
}

function Get-LabReadinessStampPath {
    <# readiness-<lab>.json next to the lab manifest (same folder, so LAB_MANIFEST_PATH moves both). #>
    $dir = Split-Path -Parent (Get-LabManifestPath -Lab $script:LabTagValue)
    return (Join-Path $dir ("readiness-$($script:LabTagValue).json"))
}

function Write-LabReadinessStamp {
    <#
    .SYNOPSIS
        Writes the readiness stamp: lab, region, UTC time and the four check results. No e-mail, no ids.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Checks, [string]$Path, [string]$TrailName, [string]$TrailOwnership)
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-LabReadinessStampPath }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $doc = [ordered]@{
        schema      = 1
        lab         = $script:LabTagValue
        region      = $script:LabRegion
        checked_utc = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        ok          = $true
        checks      = [ordered]@{
            subscription_confirmed = [bool]$Checks['subscription_confirmed']
            alarm_has_action       = [bool]$Checks['alarm_has_action']
            log_group_exists       = [bool]$Checks['log_group_exists']
            trail_logging          = [bool]$Checks['trail_logging']
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($TrailName)) {
        $doc['trail'] = [ordered]@{ name = $TrailName; ownership = $(if ($TrailOwnership) { $TrailOwnership } else { 'default' }) }
    }
    $tmp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [System.IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $doc -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $Path
}
