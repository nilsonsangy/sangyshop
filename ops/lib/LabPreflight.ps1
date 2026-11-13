<#
.SYNOPSIS
    Read-only discovery of what already exists in the account, before any lab change.

.DESCRIPTION
    Dot-sourced by the lab scripts under ops/. Provides:

      Get-LabAccountSnapshot   Reads the current state of the detection resources
                               (AWS: trails, log groups, topics, subscriptions,
                               GuardDuty detectors. Azure: Log Analytics workspaces,
                               action groups, alert rules).
      Find-ReusableTrail       Picks an existing trail that already records management
                               events in every region, so the lab does not create a
                               second one.
      Resolve-ResourceDecision Turns the snapshot into one decision per resource type:
                               Create, ReuseLabOwned, ReuseForeign or Blocked. Prints
                               one line per resource type.

    Safety rules:
      * Only read verbs are used (describe, get, list). The -Mutating switch of the CLI
        seam is never passed, so even a -WhatIf run reads the real state.
      * A read that is denied or fails is never treated as "does not exist". The type
        becomes Blocked, so no caller can create a duplicate because of a missing
        permission.
      * Nothing here changes, tags or removes a resource, and nothing calls an IAM verb.

    Seams: AWS reads go through Invoke-LabCli (honors $global:LabCliHandler) and Azure
    reads go through Invoke-LabAz (honors $global:LabAzHandler). Both come from the
    detection helper of the matching cloud, which the calling script dot-sources first.
    The lab-ownership tag is lab=<LabTag>.

    Windows PowerShell 5.1 compatible (no newer syntax).
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Small helpers (private by convention, prefixed Pf)
# ---------------------------------------------------------------------------

function Get-PfProp {
    # Reads a property or dictionary key without failing under strict mode.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertFrom-PfJson {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return (ConvertFrom-Json -InputObject $Text) } catch { return $null }
}

function Test-PfLabTagged {
    # True when a tag list ([{Key,Value}]) or a tag map ({lab: value}) carries lab=<LabTag>.
    param($Tags, [string]$LabTag)
    if ($null -eq $Tags) { return $false }
    foreach ($t in @($Tags)) {
        if ($null -eq $t) { continue }
        $key = Get-PfProp $t 'Key'
        $val = Get-PfProp $t 'Value'
        if ($null -ne $key -and $null -ne $val) {
            if ("$key" -ceq 'lab' -and "$val" -ceq $LabTag) { return $true }
            continue
        }
        $direct = Get-PfProp $t 'lab'
        if ($null -ne $direct -and "$direct" -ceq $LabTag) { return $true }
    }
    return $false
}

function Invoke-PfRead {
    # One read-only CLI call through the seam of the cloud. Never passes -Mutating.
    # Returns Ok, Denied, Data (parsed JSON or $null) and Text (raw output).
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Aws', 'Azure')][string]$Cloud,
        [Parameter(Mandatory = $true)][string[]]$CliArgs
    )
    $args2 = @($CliArgs) + @('--output', 'json')
    $r = $null
    try {
        if ($Cloud -eq 'Aws') {
            if (-not (Get-Command Invoke-LabCli -ErrorAction SilentlyContinue)) {
                return [pscustomobject]@{ Ok = $false; Denied = $false; Data = $null; Text = 'Invoke-LabCli is not available. Dot-source the AWS detection helper first.' }
            }
            $r = Invoke-LabCli -CliArgs $args2
        }
        else {
            if (-not (Get-Command Invoke-LabAz -ErrorAction SilentlyContinue)) {
                return [pscustomobject]@{ Ok = $false; Denied = $false; Data = $null; Text = 'Invoke-LabAz is not available. Dot-source the Azure detection helper first.' }
            }
            $r = Invoke-LabAz -CliArgs $args2
        }
    }
    catch {
        $msg = "$($_.Exception.Message)"
        return [pscustomobject]@{ Ok = $false; Denied = (Test-PfDenied $msg); Data = $null; Text = $msg }
    }

    $text = if ($null -ne $r -and $null -ne (Get-PfProp $r 'Output')) { "$($r.Output)" } else { '' }
    $code = if ($null -ne $r -and $null -ne (Get-PfProp $r 'ExitCode')) { [int]$r.ExitCode } else { 0 }
    if ($code -ne 0) {
        return [pscustomobject]@{ Ok = $false; Denied = (Test-PfDenied $text); Data = $null; Text = $text }
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{ Ok = $true; Denied = $false; Data = $null; Text = $text }
    }
    $data = ConvertFrom-PfJson $text
    # An empty JSON list ("[]") parses to nothing: that is a valid, empty answer.
    if ($null -eq $data -and $text.Trim() -match '^\[\s*\]$') {
        return [pscustomobject]@{ Ok = $true; Denied = $false; Data = $null; Text = $text }
    }
    if ($null -eq $data) {
        # Exit code 0 but unreadable output: do not guess, report it as an error.
        return [pscustomobject]@{ Ok = $false; Denied = $false; Data = $null; Text = "Unreadable output: $text" }
    }
    return [pscustomobject]@{ Ok = $true; Denied = $false; Data = $data; Text = $text }
}

function Test-PfDenied {
    param([string]$Text)
    if (Get-Command Test-LabAccessDenied -ErrorAction SilentlyContinue) {
        return [bool](Test-LabAccessDenied -Text $Text)
    }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return [bool]($Text -match '(?i)AccessDenied|UnauthorizedOperation|AuthorizationError|AuthorizationFailed|not\s+authorized|\b403\b')
}

function New-PfTypeResult {
    param([string]$Status = 'Ok', $Items = @(), [string]$Error = '', [string]$Service = '', [string]$Action = '')
    return [pscustomobject]@{
        Status  = $Status          # Ok, Denied or Error
        Items   = @($Items)
        Error   = $Error
        Service = $Service         # CLI service of the failed read (for permission hints)
        Action  = $Action          # CLI operation of the failed read
    }
}

function New-PfFailure {
    param($Read, [string]$Service, [string]$Action)
    $status = if ($Read.Denied) { 'Denied' } else { 'Error' }
    return New-PfTypeResult -Status $status -Error "$($Read.Text)".Trim() -Service $Service -Action $Action
}

function ConvertTo-PfManagementScope {
    # Normalizes trail event selectors to All, ReadOnly, WriteOnly, None.
    param($Selectors)
    $read = $false; $write = $false
    $basic = Get-PfProp $Selectors 'EventSelectors'
    foreach ($s in @($basic)) {
        if ($null -eq $s) { continue }
        if ((Get-PfProp $s 'IncludeManagementEvents') -ne $true) { continue }
        switch ("$(Get-PfProp $s 'ReadWriteType')") {
            'ReadOnly'  { $read = $true }
            'WriteOnly' { $write = $true }
            default     { $read = $true; $write = $true }
        }
    }
    $advanced = Get-PfProp $Selectors 'AdvancedEventSelectors'
    foreach ($s in @($advanced)) {
        if ($null -eq $s) { continue }
        $isManagement = $false
        $ro = $null
        foreach ($f in @(Get-PfProp $s 'FieldSelectors')) {
            if ($null -eq $f) { continue }
            $field = "$(Get-PfProp $f 'Field')"
            $eq = @(Get-PfProp $f 'Equals')
            if ($field -eq 'eventCategory' -and ($eq -contains 'Management')) { $isManagement = $true }
            if ($field -eq 'readOnly') { $ro = $eq }
        }
        if (-not $isManagement) { continue }
        if ($null -eq $ro) { $read = $true; $write = $true }
        elseif ($ro -contains 'true') { $read = $true }
        elseif ($ro -contains 'false') { $write = $true }
    }
    if ($read -and $write) { return 'All' }
    if ($read) { return 'ReadOnly' }
    if ($write) { return 'WriteOnly' }
    return 'None'
}

# ---------------------------------------------------------------------------
# AWS readers
# ---------------------------------------------------------------------------

function Get-PfAwsTrails {
    param([string]$LabTag)
    $d = Invoke-PfRead -Cloud Aws -CliArgs @('cloudtrail', 'describe-trails')
    if (-not $d.Ok) { return New-PfFailure $d 'cloudtrail' 'describe-trails' }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-PfProp $d.Data 'trailList')) {
        if ($null -eq $t) { continue }
        $arn = "$(Get-PfProp $t 'TrailARN')"
        $name = "$(Get-PfProp $t 'Name')"
        $ident = if ($arn) { $arn } else { $name }

        $st = Invoke-PfRead -Cloud Aws -CliArgs @('cloudtrail', 'get-trail-status', '--name', $ident)
        if (-not $st.Ok) { return New-PfFailure $st 'cloudtrail' 'get-trail-status' }
        $sel = Invoke-PfRead -Cloud Aws -CliArgs @('cloudtrail', 'get-event-selectors', '--trail-name', $ident)
        if (-not $sel.Ok) { return New-PfFailure $sel 'cloudtrail' 'get-event-selectors' }
        $tg = Invoke-PfRead -Cloud Aws -CliArgs @('cloudtrail', 'list-tags', '--resource-id-list', $ident)
        if (-not $tg.Ok) { return New-PfFailure $tg 'cloudtrail' 'list-tags' }

        $tagList = @()
        $rt = @(Get-PfProp $tg.Data 'ResourceTagList')
        if ($rt.Count -gt 0 -and $null -ne $rt[0]) { $tagList = @(Get-PfProp $rt[0] 'TagsList') }

        $items.Add([pscustomobject]@{
            Name              = $name
            Id                = $ident
            Tagged            = (Test-PfLabTagged $tagList $LabTag)
            IsMultiRegion     = ((Get-PfProp $t 'IsMultiRegionTrail') -eq $true)
            IsOrganization    = ((Get-PfProp $t 'IsOrganizationTrail') -eq $true)
            IsLogging         = ((Get-PfProp $st.Data 'IsLogging') -eq $true)
            ManagementEvents  = (ConvertTo-PfManagementScope $sel.Data)
        })
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

function Get-PfAwsLogGroups {
    param([string]$LabTag, [string]$Name)
    $args2 = @('logs', 'describe-log-groups')
    if (-not [string]::IsNullOrWhiteSpace($Name)) { $args2 += @('--log-group-name-prefix', $Name) }
    $d = Invoke-PfRead -Cloud Aws -CliArgs $args2
    if (-not $d.Ok) { return New-PfFailure $d 'logs' 'describe-log-groups' }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($g in @(Get-PfProp $d.Data 'logGroups')) {
        if ($null -eq $g) { continue }
        $gname = "$(Get-PfProp $g 'logGroupName')"
        $arn = ("$(Get-PfProp $g 'arn')") -replace ':\*$', ''
        $tagged = $false
        if ($arn) {
            $tg = Invoke-PfRead -Cloud Aws -CliArgs @('logs', 'list-tags-for-resource', '--resource-arn', $arn)
            if (-not $tg.Ok) { return New-PfFailure $tg 'logs' 'list-tags-for-resource' }
            $tagged = Test-PfLabTagged (Get-PfProp $tg.Data 'tags') $LabTag
        }
        $items.Add([pscustomobject]@{ Name = $gname; Id = $gname; Tagged = $tagged })
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

function Get-PfAwsTopics {
    param([string]$LabTag)
    $d = Invoke-PfRead -Cloud Aws -CliArgs @('sns', 'list-topics')
    if (-not $d.Ok) { return New-PfFailure $d 'sns' 'list-topics' }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($t in @(Get-PfProp $d.Data 'Topics')) {
        if ($null -eq $t) { continue }
        $arn = "$(Get-PfProp $t 'TopicArn')"
        if (-not $arn) { continue }
        $tg = Invoke-PfRead -Cloud Aws -CliArgs @('sns', 'list-tags-for-resource', '--resource-arn', $arn)
        if (-not $tg.Ok) { return New-PfFailure $tg 'sns' 'list-tags-for-resource' }
        $items.Add([pscustomobject]@{
            Name   = ($arn -split ':')[-1]
            Id     = $arn
            Tagged = (Test-PfLabTagged (Get-PfProp $tg.Data 'Tags') $LabTag)
        })
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

function Get-PfAwsSubscriptions {
    # Reads subscriptions only for the topic the lab would use (matched by name).
    param($TopicResult, [string]$TopicName)
    if ($TopicResult.Status -ne 'Ok') {
        return New-PfTypeResult -Status $TopicResult.Status -Error $TopicResult.Error -Service $TopicResult.Service -Action $TopicResult.Action
    }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($topic in @($TopicResult.Items)) {
        if ($null -eq $topic -or [string]::IsNullOrWhiteSpace($TopicName) -or $topic.Name -cne $TopicName) { continue }
        $d = Invoke-PfRead -Cloud Aws -CliArgs @('sns', 'list-subscriptions-by-topic', '--topic-arn', $topic.Id)
        if (-not $d.Ok) { return New-PfFailure $d 'sns' 'list-subscriptions-by-topic' }
        foreach ($s in @(Get-PfProp $d.Data 'Subscriptions')) {
            if ($null -eq $s) { continue }
            $arn = "$(Get-PfProp $s 'SubscriptionArn')"
            $endpoint = "$(Get-PfProp $s 'Endpoint')"
            $items.Add([pscustomobject]@{
                Name      = $endpoint
                Id        = $arn
                Protocol  = "$(Get-PfProp $s 'Protocol')"
                Confirmed = ($arn -ne 'PendingConfirmation' -and $arn -ne 'Deleted' -and $arn -like 'arn:*')
                # A subscription cannot carry tags: it follows the ownership of its topic.
                Tagged    = [bool]$topic.Tagged
            })
        }
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

function Get-PfAwsDetectors {
    param([string]$LabTag)
    $d = Invoke-PfRead -Cloud Aws -CliArgs @('guardduty', 'list-detectors')
    if (-not $d.Ok) { return New-PfFailure $d 'guardduty' 'list-detectors' }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($id in @(Get-PfProp $d.Data 'DetectorIds')) {
        if ([string]::IsNullOrWhiteSpace("$id")) { continue }
        $g = Invoke-PfRead -Cloud Aws -CliArgs @('guardduty', 'get-detector', '--detector-id', "$id")
        if (-not $g.Ok) { return New-PfFailure $g 'guardduty' 'get-detector' }
        $items.Add([pscustomobject]@{
            Name   = "$id"
            Id     = "$id"
            Status = "$(Get-PfProp $g.Data 'Status')"
            Tagged = (Test-PfLabTagged (Get-PfProp $g.Data 'Tags') $LabTag)
        })
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

# ---------------------------------------------------------------------------
# Azure readers
# ---------------------------------------------------------------------------

function Get-PfAzureList {
    param([string[]]$CliArgs, [string]$LabTag, [string]$Service, [string]$Action)
    $d = Invoke-PfRead -Cloud Azure -CliArgs $CliArgs
    if (-not $d.Ok) { return New-PfFailure $d $Service $Action }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($d.Data)) {
        if ($null -eq $r) { continue }
        $items.Add([pscustomobject]@{
            Name   = "$(Get-PfProp $r 'name')"
            Id     = "$(Get-PfProp $r 'id')"
            Tagged = (Test-PfLabTagged (Get-PfProp $r 'tags') $LabTag)
        })
    }
    return New-PfTypeResult -Status 'Ok' -Items $items.ToArray()
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Get-LabAccountSnapshot {
    <#
    .SYNOPSIS
        Reads, without changing anything, which detection resources already exist.
    .DESCRIPTION
        Returns an object with Cloud, LabTag and Types, a hashtable keyed by resource type.
        Each type has Status (Ok, Denied or Error), Items (Name, Id, Tagged and type
        specific fields), Error, Service and Action of a failed read.

        AWS types: trail, loggroup, topic, subscription, detector.
        Azure types: workspace, actiongroup, alertrule.

        Only describe, get and list verbs are issued, and -Mutating is never passed.
        -LabNames carries the names the lab would create (keys LogGroup and Topic for
        AWS), used to narrow the log group read and to pick which topic to read
        subscriptions for.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Aws', 'Azure')][string]$Cloud,
        [string]$LabTag,
        [hashtable]$LabNames = @{}
    )

    if ([string]::IsNullOrWhiteSpace($LabTag)) {
        $LabTag = if ($Cloud -eq 'Aws') { 'sangyshop-lab-aws' } else { 'sangyshop-lab-azure' }
    }
    $types = [ordered]@{}

    if ($Cloud -eq 'Aws') {
        $types['trail']        = Get-PfAwsTrails -LabTag $LabTag
        $types['loggroup']     = Get-PfAwsLogGroups -LabTag $LabTag -Name ($(if ($LabNames.ContainsKey('LogGroup')) { [string]$LabNames['LogGroup'] } else { '' }))
        $types['topic']        = Get-PfAwsTopics -LabTag $LabTag
        $topicName = if ($LabNames.ContainsKey('Topic')) { [string]$LabNames['Topic'] } else { '' }
        $types['subscription'] = Get-PfAwsSubscriptions -TopicResult $types['topic'] -TopicName $topicName
        $types['detector']     = Get-PfAwsDetectors -LabTag $LabTag
    }
    else {
        $types['workspace']   = Get-PfAzureList -CliArgs @('monitor', 'log-analytics', 'workspace', 'list') -LabTag $LabTag -Service 'monitor' -Action 'log-analytics workspace list'
        $types['actiongroup'] = Get-PfAzureList -CliArgs @('monitor', 'action-group', 'list') -LabTag $LabTag -Service 'monitor' -Action 'action-group list'
        $types['alertrule']   = Get-PfAzureList -CliArgs @('monitor', 'scheduled-query', 'list') -LabTag $LabTag -Service 'monitor' -Action 'scheduled-query list'
    }

    return [pscustomobject]@{ Cloud = $Cloud; LabTag = $LabTag; Types = $types }
}

function Find-ReusableTrail {
    <#
    .SYNOPSIS
        Picks an existing trail the lab can reuse instead of creating a new one.
    .DESCRIPTION
        A trail qualifies when it is multi-region, is currently logging, and records
        management events for both reads and writes. Tie-break: the trail with the lab
        trail name first, then ascending ordinal order of the name. Returns $null when
        none qualifies. Pure function: no CLI call.
    .PARAMETER Trails
        Trail items as returned in the snapshot (Name, IsMultiRegion, IsLogging,
        ManagementEvents).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Trails,
        [string]$LabTrailName
    )

    $best = $null
    foreach ($t in @($Trails)) {
        if ($null -eq $t) { continue }
        if ((Get-PfProp $t 'IsMultiRegion') -ne $true) { continue }
        if ((Get-PfProp $t 'IsLogging') -ne $true) { continue }
        if ("$(Get-PfProp $t 'ManagementEvents')" -ne 'All') { continue }

        if ($null -eq $best) { $best = $t; continue }
        $tIsLab = (-not [string]::IsNullOrEmpty($LabTrailName)) -and ("$($t.Name)" -ceq $LabTrailName)
        $bIsLab = (-not [string]::IsNullOrEmpty($LabTrailName)) -and ("$($best.Name)" -ceq $LabTrailName)
        if ($tIsLab -and -not $bIsLab) { $best = $t; continue }
        if ($bIsLab -and -not $tIsLab) { continue }
        if ([string]::CompareOrdinal("$($t.Name)", "$($best.Name)") -lt 0) { $best = $t }
    }
    return $best
}

function Get-PfTrailReasons {
    param($Trail)
    $r = @('multi-region', 'logging', 'management events for reads and writes')
    if ((Get-PfProp $Trail 'IsOrganization') -eq $true) { $r += 'organization trail' }
    return $r
}

function Resolve-ResourceDecision {
    <#
    .SYNOPSIS
        Decides what to do for one resource type: Create, ReuseLabOwned, ReuseForeign or Blocked.
    .DESCRIPTION
        Blocked: the read of that type was denied or failed. Never Create.
        ReuseLabOwned: the resource carries the lab tag, or has the lab name but lacks
          the tag (the caller completes the tags, never recreates it).
        ReuseForeign: a resource the lab did not create satisfies the need (a qualified
          trail, a GuardDuty detector, a same-named topic or log group without the lab
          tag). The caller uses it as is and must not tag, change or remove it.
        Create: nothing suitable exists and every read succeeded.

        Classification is Absent, LabOwned, LabNamedUntagged, Foreign or Unreadable.
        Prints one line per call. Returns an object with Type, Decision, Classification,
        Name, Reasons, Item, Error, Service and Action.
    .PARAMETER Type
        trail, loggroup, topic, subscription, detector (AWS) or workspace, actiongroup,
        alertrule (Azure).
    .PARAMETER ExpectedName
        The name the lab would create (for a subscription: the endpoint e-mail).
    .PARAMETER Singleton
        Any existing item counts (one GuardDuty detector per region).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Type,
        [string]$ExpectedName,
        [switch]$Singleton,
        [switch]$Quiet
    )

    $result = {
        param($Decision, $Class, $Name, $Reasons, $Item, $Res)
        $err = ''; $svc = ''; $act = ''
        if ($null -ne $Res) { $err = $Res.Error; $svc = $Res.Service; $act = $Res.Action }
        return [pscustomobject]@{
            Type = $Type; Decision = $Decision; Classification = $Class; Name = $Name
            Reasons = @($Reasons); Item = $Item; Error = $err; Service = $svc; Action = $act
        }
    }
    $print = {
        param($d, $count)
        if ($Quiet) { return }
        $label = if ($d.Name) { " '$($d.Name)'" } else { '' }
        $why = if ($d.Reasons.Count -gt 0) { ' (' + ($d.Reasons -join '; ') + ')' } else { '' }
        Write-Host ("Preflight {0,-12}: found {1}, class {2}{3}, decision {4}{5}" -f $d.Type, $count, $d.Classification, $label, $d.Decision, $why)
    }

    $res = $null
    if ($Snapshot.Types.Contains($Type)) { $res = $Snapshot.Types[$Type] }
    if ($null -eq $res) {
        $d = & $result 'Blocked' 'Unreadable' $ExpectedName @("resource type '$Type' was not read") $null $null
        & $print $d 0
        return $d
    }
    if ($res.Status -ne 'Ok') {
        $why = if ($res.Status -eq 'Denied') { 'read denied' } else { 'read failed' }
        $d = & $result 'Blocked' 'Unreadable' $ExpectedName @($why) $null $res
        & $print $d 0
        return $d
    }

    $items = @($res.Items | Where-Object { $null -ne $_ })
    $count = $items.Count

    # Trail: a lab trail by name, otherwise a qualified trail of the account.
    if ($Type -eq 'trail') {
        $named = $items | Where-Object { $_.Name -ceq $ExpectedName } | Select-Object -First 1
        if ($named) {
            $class = if ($named.Tagged) { 'LabOwned' } else { 'LabNamedUntagged' }
            $d = & $result 'ReuseLabOwned' $class $named.Name @() $named $res
            & $print $d $count
            return $d
        }
        $pick = Find-ReusableTrail -Trails $items -LabTrailName $ExpectedName
        if ($pick) {
            $d = & $result 'ReuseForeign' 'Foreign' $pick.Name (Get-PfTrailReasons $pick) $pick $res
            & $print $d $count
            return $d
        }
        $reasons = @()
        if ($count -gt 0) { $reasons = @('no existing trail is multi-region, logging and recording read and write management events') }
        $d = & $result 'Create' 'Absent' $ExpectedName $reasons $null $res
        & $print $d $count
        return $d
    }

    # Singleton types (detector): any existing item satisfies the need.
    if ($Singleton) {
        $owned = $items | Where-Object { $_.Tagged } | Select-Object -First 1
        if ($owned) {
            $d = & $result 'ReuseLabOwned' 'LabOwned' $owned.Name @() $owned $res
        }
        elseif ($count -gt 0) {
            $first = $items | Select-Object -First 1
            $d = & $result 'ReuseForeign' 'Foreign' $first.Name @('only one is allowed per region') $first $res
        }
        else {
            $d = & $result 'Create' 'Absent' $ExpectedName @() $null $res
        }
        & $print $d $count
        return $d
    }

    # Named types: match by expected name.
    $match = $null
    if (-not [string]::IsNullOrEmpty($ExpectedName)) {
        $match = $items | Where-Object { $_.Name -ceq $ExpectedName } | Select-Object -First 1
    }
    if ($match) {
        if ($match.Tagged) {
            $d = & $result 'ReuseLabOwned' 'LabOwned' $match.Name @() $match $res
        }
        elseif ($Type -eq 'subscription') {
            # Follows the ownership of its topic, which is not the lab's.
            $d = & $result 'ReuseForeign' 'Foreign' $match.Name @('attached to a topic the lab did not create') $match $res
        }
        else {
            # Same name as the lab resource, without tags: complete the tags, never recreate.
            $d = & $result 'ReuseLabOwned' 'LabNamedUntagged' $match.Name @('has the lab name but no lab tag') $match $res
        }
    }
    else {
        $d = & $result 'Create' 'Absent' $ExpectedName @() $null $res
    }
    & $print $d $count
    return $d
}
