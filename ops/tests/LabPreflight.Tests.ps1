<#
.SYNOPSIS
    Pester 5.x property tests for the read-only account discovery (lib/LabPreflight.ps1).

.DESCRIPTION
    An in-memory account simulator answers every read through the same seams the lab
    scripts use ($global:LabCliHandler for AWS, $global:LabAzHandler for Azure). No cloud
    CLI is ever invoked and no real account is touched.

    Properties checked over seeded random accounts (a failure is reproducible):

      * Classification and decision: for every resource type, the decision follows the
        state of the account. Nothing suitable and every read fine gives Create. A lab
        tagged resource gives ReuseLabOwned. A lab named resource without the tag is
        completed, never recreated (ReuseLabOwned, LabNamedUntagged). A resource the lab
        did not create gives ReuseForeign. A denied or failed read gives Blocked and never
        Create, whichever read failed.
      * Read only: every call the discovery issues uses a describe, get or list verb,
        never passes -Mutating and never touches IAM.
      * Trail selection: a trail is reusable only when it is multi-region, logging and
        records management events for reads and writes. The lab trail wins a tie, then the
        ascending ordinal order of the name. A qualified foreign trail is reused as is and
        no creation is proposed.

    Run with:
        Invoke-Pester -Path ops/tests/LabPreflight.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'lib' 'LabPreflight.ps1')

    $script:LabTag       = 'sangyshop-lab-aws'
    $script:AzureTag     = 'sangyshop-lab-azure'
    $script:LabTrailName = 'sangyshop-lab-trail'
    $script:LabLogGroup  = '/sangyshop/lab/detection'
    $script:LabTopic     = 'sangyshop-lab-alerts'
    $script:LabEmail     = 'user@example.com'

    # Stand-ins for the detection helpers: same contract as the real seams.
    function Invoke-LabCli {
        param([string[]]$CliArgs, [switch]$Mutating)
        if ($Mutating) { $global:LabSimMutating = $true }
        if ($global:LabCliHandler) { return (& $global:LabCliHandler @($CliArgs)) }
        throw 'The simulator handler is not installed. No real CLI is allowed in this test.'
    }
    function Invoke-LabAz {
        param([string[]]$CliArgs, [switch]$Mutating)
        if ($Mutating) { $global:LabSimMutating = $true }
        if ($global:LabAzHandler) { return (& $global:LabAzHandler @($CliArgs)) }
        throw 'The simulator handler is not installed. No real CLI is allowed in this test.'
    }

    function ConvertTo-SimJson { param($Value) return (ConvertTo-Json -InputObject $Value -Depth 10 -Compress) }

    function ConvertTo-SimTagList {
        param([hashtable]$Tags)
        $l = @()
        foreach ($k in $Tags.Keys) { $l += , @{ Key = $k; Value = $Tags[$k] } }
        return , $l
    }

    function Get-SimOwned {
        param([hashtable]$Tags, [string]$Tag)
        return ($Tags.ContainsKey('lab') -and ([string]$Tags['lab'] -ceq $Tag))
    }

    # The AWS handler: reads the account from $global:LabSimAccount, records every call.
    $global:LabSimAwsHandler = {
        param($full)
        $a = @($full)
        $global:LabSimCalls.Add(($a -join ' '))
        $acct = $global:LabSimAccount
        $key = "$($a[0]) $($a[1])"
        $opt = {
            param($n)
            $i = [array]::IndexOf($a, $n)
            if ($i -ge 0 -and ($i + 1) -lt $a.Count) { return $a[$i + 1] }
            return $null
        }
        if ($acct.Deny -contains $key) {
            return [pscustomobject]@{ ExitCode = 254; Output = "An error occurred (AccessDeniedException) when calling the $($a[1]) operation: User is not authorized to perform: $key" }
        }
        if ($acct.Fail -contains $key) {
            return [pscustomobject]@{ ExitCode = 1; Output = 'Could not connect to the endpoint URL' }
        }
        $ok = { param($o) return [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-SimJson $o) } }

        switch ($key) {
            'cloudtrail describe-trails' {
                $l = @()
                foreach ($t in $acct.Trails) {
                    $l += , @{
                        Name = $t.Name; TrailARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/$($t.Name)"
                        IsMultiRegionTrail = $t.Multi; IsOrganizationTrail = $t.Org
                    }
                }
                return (& $ok @{ trailList = $l })
            }
            'cloudtrail get-trail-status' {
                $n = ([string](& $opt '--name') -split '/')[-1]
                $t = $acct.Trails | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
                return (& $ok @{ IsLogging = [bool]$t.Logging })
            }
            'cloudtrail get-event-selectors' {
                $n = ([string](& $opt '--trail-name') -split '/')[-1]
                $t = $acct.Trails | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
                $out = @{}
                $mgmt = @{ All = $true; ReadOnly = $true; WriteOnly = $true; None = $false }
                if ($t.Adv -and $t.Scope -in @('All', 'ReadOnly', 'WriteOnly')) {
                    $fs = @(@{ Field = 'eventCategory'; Equals = @('Management') })
                    if ($t.Scope -eq 'ReadOnly') { $fs += , @{ Field = 'readOnly'; Equals = @('true') } }
                    if ($t.Scope -eq 'WriteOnly') { $fs += , @{ Field = 'readOnly'; Equals = @('false') } }
                    $out['AdvancedEventSelectors'] = @(, @{ Name = 'mgmt'; FieldSelectors = $fs })
                }
                else {
                    $out['EventSelectors'] = @(, @{ IncludeManagementEvents = $mgmt[$t.Scope]; ReadWriteType = $(if ($t.Scope -eq 'None') { 'All' } else { $t.Scope }) })
                }
                return (& $ok $out)
            }
            'cloudtrail list-tags' {
                $n = ([string](& $opt '--resource-id-list') -split '/')[-1]
                $t = $acct.Trails | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
                return (& $ok @{ ResourceTagList = @(, @{ ResourceId = $n; TagsList = (ConvertTo-SimTagList $t.Tags) }) })
            }
            'logs describe-log-groups' {
                $p = [string](& $opt '--log-group-name-prefix')
                $l = @()
                foreach ($g in $acct.LogGroups) {
                    if ($p -and -not $g.Name.StartsWith($p, [System.StringComparison]::Ordinal)) { continue }
                    $l += , @{ logGroupName = $g.Name; arn = "arn:aws:logs:us-east-1:123456789012:log-group:$($g.Name):*" }
                }
                return (& $ok @{ logGroups = $l })
            }
            'logs list-tags-for-resource' {
                $arn = [string](& $opt '--resource-arn')
                $g = $acct.LogGroups | Where-Object { $arn -ceq "arn:aws:logs:us-east-1:123456789012:log-group:$($_.Name)" } | Select-Object -First 1
                return (& $ok @{ tags = $g.Tags })
            }
            'sns list-topics' {
                $l = @()
                foreach ($t in $acct.Topics) { $l += , @{ TopicArn = "arn:aws:sns:us-east-1:123456789012:$($t.Name)" } }
                return (& $ok @{ Topics = $l })
            }
            'sns list-tags-for-resource' {
                $n = ([string](& $opt '--resource-arn') -split ':')[-1]
                $t = $acct.Topics | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
                return (& $ok @{ Tags = (ConvertTo-SimTagList $t.Tags) })
            }
            'sns list-subscriptions-by-topic' {
                $n = ([string](& $opt '--topic-arn') -split ':')[-1]
                $t = $acct.Topics | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
                $l = @()
                foreach ($s in $t.Subs) {
                    $sa = if ($s.Confirmed) { "arn:aws:sns:us-east-1:123456789012:$($t.Name):$($s.Id)" } else { 'PendingConfirmation' }
                    $l += , @{ SubscriptionArn = $sa; Endpoint = $s.Endpoint; Protocol = 'email'; TopicArn = [string](& $opt '--topic-arn') }
                }
                return (& $ok @{ Subscriptions = $l })
            }
            'guardduty list-detectors' {
                $l = @(); foreach ($d in $acct.Detectors) { $l += $d.Id }
                return (& $ok @{ DetectorIds = $l })
            }
            'guardduty get-detector' {
                $id = [string](& $opt '--detector-id')
                $d = $acct.Detectors | Where-Object { $_.Id -ceq $id } | Select-Object -First 1
                return (& $ok @{ Status = 'ENABLED'; Tags = $d.Tags })
            }
            default {
                return [pscustomobject]@{ ExitCode = 2; Output = "Unexpected call in the simulator: $key" }
            }
        }
    }

    $global:LabSimAzHandler = {
        param($full)
        $a = @($full)
        $global:LabSimCalls.Add(($a -join ' '))
        $acct = $global:LabSimAccount
        $key = ($a | Select-Object -First 3) -join ' '
        $kind = switch -Wildcard ($key) {
            'monitor log-analytics workspace' { 'Workspaces' }
            'monitor action-group list'       { 'ActionGroups' }
            'monitor scheduled-query list'    { 'AlertRules' }
            default                           { $null }
        }
        if ($null -eq $kind) { return [pscustomobject]@{ ExitCode = 2; Output = "Unexpected call in the simulator: $key" } }
        if ($acct.Deny -contains $kind) {
            return [pscustomobject]@{ ExitCode = 1; Output = "ERROR: (AuthorizationFailed) The client does not have authorization to perform action for $kind" }
        }
        if ($acct.Fail -contains $kind) {
            return [pscustomobject]@{ ExitCode = 1; Output = 'ERROR: connection reset' }
        }
        $l = @()
        foreach ($r in $acct[$kind]) { $l += , @{ name = $r.Name; id = "/subscriptions/s/resourceGroups/rg/providers/x/$($r.Name)"; tags = $r.Tags } }
        return [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-SimJson $l) }
    }

    # ---- random account generation (seeded by the caller) ----------------------

    function Get-SimTags {
        param($Rng, [string]$Tag)
        switch ($Rng.Next(4)) {
            0 { return @{ lab = $Tag } }
            1 { return @{} }
            2 { return @{ lab = 'someone-elses-lab' } }
            default { return @{ team = 'platform'; env = 'prod' } }
        }
    }

    function New-SimAwsAccount {
        param($Rng)
        $acct = @{ Trails = @(); LogGroups = @(); Topics = @(); Detectors = @(); Deny = @(); Fail = @() }

        $pool = @('Alpha-trail', 'zeta-trail', 'mgmt-events', 'Org-Audit', 'audit', 'Audit', 'central', 'b-trail', $script:LabTrailName)
        $names = $pool | Sort-Object { $Rng.Next() } | Select-Object -First $Rng.Next(0, 6)
        $scopes = @('All', 'ReadOnly', 'WriteOnly', 'None')
        foreach ($n in $names) {
            $acct.Trails += , @{
                Name = $n; Multi = ($Rng.Next(3) -ne 0); Org = ($Rng.Next(4) -eq 0); Logging = ($Rng.Next(4) -ne 0)
                Scope = $scopes[$(if ($Rng.Next(2) -eq 0) { 0 } else { $Rng.Next(4) })]; Adv = ($Rng.Next(2) -eq 0)
                Tags = (Get-SimTags $Rng $script:LabTag)
            }
        }

        $gpool = @($script:LabLogGroup, "$($script:LabLogGroup)-old", '/aws/lambda/other', '/sangyshop/lab', '/app/prod')
        foreach ($n in ($gpool | Sort-Object { $Rng.Next() } | Select-Object -First $Rng.Next(0, 5))) {
            $acct.LogGroups += , @{ Name = $n; Tags = (Get-SimTags $Rng $script:LabTag) }
        }

        $tpool = @($script:LabTopic, 'prod-alerts', 'billing', "$($script:LabTopic)-2")
        foreach ($n in ($tpool | Sort-Object { $Rng.Next() } | Select-Object -First $Rng.Next(0, 4))) {
            $subs = @()
            $emails = @($script:LabEmail, 'ops@example.org', 'other@example.net') | Sort-Object { $Rng.Next() } | Select-Object -First $Rng.Next(0, 3)
            $i = 0
            foreach ($e in $emails) { $i++; $subs += , @{ Endpoint = $e; Confirmed = ($Rng.Next(2) -eq 0); Id = "sub$i" } }
            $acct.Topics += , @{ Name = $n; Tags = (Get-SimTags $Rng $script:LabTag); Subs = $subs }
        }

        $dcount = $Rng.Next(0, 3)
        for ($i = 0; $i -lt $dcount; $i++) {
            $acct.Detectors += , @{ Id = ('d{0:x31}' -f $Rng.Next(1, 100000) + $i); Tags = (Get-SimTags $Rng $script:LabTag) }
        }
        return $acct
    }

    function Start-SimAws {
        param($Account)
        $global:LabSimAccount = $Account
        $global:LabSimCalls = New-Object System.Collections.Generic.List[string]
        $global:LabSimMutating = $false
        $global:LabCliHandler = $global:LabSimAwsHandler
    }
    function Start-SimAzure {
        param($Account)
        $global:LabSimAccount = $Account
        $global:LabSimCalls = New-Object System.Collections.Generic.List[string]
        $global:LabSimMutating = $false
        $global:LabAzHandler = $global:LabSimAzHandler
    }

    function Get-SimTrailQualified {
        param($T) return ($T.Multi -and $T.Logging -and $T.Scope -eq 'All')
    }

    function Get-SimExpectedTrailPick {
        param($Trails, [string]$LabName)
        $q = @($Trails | Where-Object { $_.Name -ceq $LabName -or $true } | Where-Object { Get-SimTrailQualified $_ })
        if ($q.Count -eq 0) { return $null }
        $lab = @($q | Where-Object { $_.Name -ceq $LabName })
        if ($lab.Count -gt 0) { return $lab[0].Name }
        $arr = [string[]]@($q | ForEach-Object { $_.Name })
        [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
        return $arr[0]
    }

    # Expected decision for a named type. Returns @{Decision; Class; Name}.
    function Get-SimExpectedNamed {
        param($Items, [string]$Name, [string]$Tag)
        $m = @($Items | Where-Object { $_.Name -ceq $Name }) | Select-Object -First 1
        if (-not $m) { return @{ Decision = 'Create'; Class = 'Absent' } }
        if (Get-SimOwned $m.Tags $Tag) { return @{ Decision = 'ReuseLabOwned'; Class = 'LabOwned' } }
        return @{ Decision = 'ReuseLabOwned'; Class = 'LabNamedUntagged' }
    }

    function Assert-SimReadOnly {
        foreach ($c in $global:LabSimCalls) {
            $parts = $c -split ' '
            $parts[1] | Should -Match '^(describe|get|list)-' -Because "call '$c' must be a read"
            $parts[0] | Should -Not -Be 'iam' -Because "call '$c' must not touch IAM"
            $c | Should -Not -Match '(?i)\b(create|put|delete|tag|untag|update|attach|detach|start|stop|enable|disable)-'
        }
        $global:LabSimMutating | Should -BeFalse
    }
}

Describe 'Account discovery decisions on random AWS accounts' {

    AfterEach {
        $global:LabCliHandler = $null
        $global:LabAzHandler = $null
    }

    It 'decides every type from the account state and only issues read calls' {
        $rng = [System.Random]::new(2501)
        for ($n = 0; $n -lt 80; $n++) {
            $acct = New-SimAwsAccount $rng
            Start-SimAws $acct
            $snap = Get-LabAccountSnapshot -Cloud Aws -LabNames @{ LogGroup = $script:LabLogGroup; Topic = $script:LabTopic } 6>$null
            Assert-SimReadOnly

            foreach ($type in @('trail', 'loggroup', 'topic', 'subscription', 'detector')) {
                $snap.Types[$type].Status | Should -Be 'Ok'
            }

            # Trail: lab named first, else a qualified trail of the account, else Create.
            $d = Resolve-ResourceDecision -Snapshot $snap -Type trail -ExpectedName $script:LabTrailName -Quiet
            $named = @($acct.Trails | Where-Object { $_.Name -ceq $script:LabTrailName }) | Select-Object -First 1
            $pick = Get-SimExpectedTrailPick $acct.Trails $script:LabTrailName
            if ($named) {
                $d.Decision | Should -Be 'ReuseLabOwned'
                $d.Classification | Should -Be $(if (Get-SimOwned $named.Tags $script:LabTag) { 'LabOwned' } else { 'LabNamedUntagged' })
            }
            elseif ($pick) {
                $d.Decision | Should -Be 'ReuseForeign'
                $d.Name | Should -BeExactly $pick
            }
            else {
                $d.Decision | Should -Be 'Create'
                $d.Classification | Should -Be 'Absent'
            }

            # Log group and topic: the name decides, the tag only picks the class.
            $exp = Get-SimExpectedNamed $acct.LogGroups $script:LabLogGroup $script:LabTag
            $d = Resolve-ResourceDecision -Snapshot $snap -Type loggroup -ExpectedName $script:LabLogGroup -Quiet
            $d.Decision | Should -Be $exp.Decision
            $d.Classification | Should -Be $exp.Class

            $exp = Get-SimExpectedNamed $acct.Topics $script:LabTopic $script:LabTag
            $d = Resolve-ResourceDecision -Snapshot $snap -Type topic -ExpectedName $script:LabTopic -Quiet
            $d.Decision | Should -Be $exp.Decision
            $d.Classification | Should -Be $exp.Class

            # Detector: one per region, so any existing one is reused.
            $d = Resolve-ResourceDecision -Snapshot $snap -Type detector -Singleton -Quiet
            if ($acct.Detectors.Count -eq 0) { $d.Decision | Should -Be 'Create' }
            elseif (@($acct.Detectors | Where-Object { Get-SimOwned $_.Tags $script:LabTag }).Count -gt 0) {
                $d.Decision | Should -Be 'ReuseLabOwned'
            }
            else { $d.Decision | Should -Be 'ReuseForeign' }

            # Subscription: only on the lab topic, matched by e-mail endpoint.
            $d = Resolve-ResourceDecision -Snapshot $snap -Type subscription -ExpectedName $script:LabEmail -Quiet
            $topic = @($acct.Topics | Where-Object { $_.Name -ceq $script:LabTopic }) | Select-Object -First 1
            $sub = $null
            if ($topic) { $sub = @($topic.Subs | Where-Object { $_.Endpoint -ceq $script:LabEmail }) | Select-Object -First 1 }
            if (-not $sub) { $d.Decision | Should -Be 'Create' }
            elseif (Get-SimOwned $topic.Tags $script:LabTag) { $d.Decision | Should -Be 'ReuseLabOwned' }
            else { $d.Decision | Should -Be 'ReuseForeign' }
        }
    }

    It 'never classifies a resource without the lab tag as lab owned unless it has the lab name' {
        $rng = [System.Random]::new(2502)
        for ($n = 0; $n -lt 60; $n++) {
            $acct = New-SimAwsAccount $rng
            Start-SimAws $acct
            $snap = Get-LabAccountSnapshot -Cloud Aws -LabNames @{ LogGroup = $script:LabLogGroup; Topic = $script:LabTopic } 6>$null
            foreach ($t in $snap.Types['trail'].Items) {
                $t.Tagged | Should -Be (Get-SimOwned (@($acct.Trails | Where-Object { $_.Name -ceq $t.Name })[0].Tags) $script:LabTag)
            }
            # A differently named, untagged resource is never taken as the lab's own.
            $d = Resolve-ResourceDecision -Snapshot $snap -Type loggroup -ExpectedName '/never/used/name' -Quiet
            $d.Decision | Should -Be 'Create'
            $d = Resolve-ResourceDecision -Snapshot $snap -Type topic -ExpectedName 'never-used-topic' -Quiet
            $d.Decision | Should -Be 'Create'
        }
    }

    It 'blocks the affected types and never proposes Create when any read is denied or fails' {
        $rng = [System.Random]::new(2503)
        $reads = @(
            @{ Key = 'cloudtrail describe-trails';          Types = @('trail');                  Needs = { $true } },
            @{ Key = 'cloudtrail get-trail-status';         Types = @('trail');                  Needs = { $a = $args[0]; $a.Trails.Count -gt 0 } },
            @{ Key = 'cloudtrail get-event-selectors';      Types = @('trail');                  Needs = { $a = $args[0]; $a.Trails.Count -gt 0 } },
            @{ Key = 'cloudtrail list-tags';                Types = @('trail');                  Needs = { $a = $args[0]; $a.Trails.Count -gt 0 } },
            @{ Key = 'logs describe-log-groups';            Types = @('loggroup');               Needs = { $true } },
            @{ Key = 'logs list-tags-for-resource';         Types = @('loggroup');               Needs = { $a = $args[0]; @($a.LogGroups | Where-Object { $_.Name.StartsWith($script:LabLogGroup, [System.StringComparison]::Ordinal) }).Count -gt 0 } },
            @{ Key = 'sns list-topics';                     Types = @('topic', 'subscription');  Needs = { $true } },
            @{ Key = 'sns list-subscriptions-by-topic';     Types = @('subscription');           Needs = { $a = $args[0]; @($a.Topics | Where-Object { $_.Name -ceq $script:LabTopic }).Count -gt 0 } },
            @{ Key = 'guardduty list-detectors';            Types = @('detector');               Needs = { $true } },
            @{ Key = 'guardduty get-detector';              Types = @('detector');               Needs = { $a = $args[0]; $a.Detectors.Count -gt 0 } }
        )
        $nameOf = @{ trail = $script:LabTrailName; loggroup = $script:LabLogGroup; topic = $script:LabTopic; subscription = $script:LabEmail; detector = '' }

        for ($n = 0; $n -lt 120; $n++) {
            $acct = New-SimAwsAccount $rng
            $read = $reads[$rng.Next($reads.Count)]
            $mode = if ($rng.Next(2) -eq 0) { 'Deny' } else { 'Fail' }
            # sns list-tags-for-resource also blocks topics and subscriptions when a topic exists.
            $acct[$mode] = @($read.Key)
            Start-SimAws $acct
            $snap = Get-LabAccountSnapshot -Cloud Aws -LabNames @{ LogGroup = $script:LabLogGroup; Topic = $script:LabTopic } 6>$null
            Assert-SimReadOnly

            $applies = [bool](& $read.Needs $acct)
            foreach ($type in @('trail', 'loggroup', 'topic', 'subscription', 'detector')) {
                $d = Resolve-ResourceDecision -Snapshot $snap -Type $type -ExpectedName $nameOf[$type] -Singleton:($type -eq 'detector') -Quiet
                if ($applies -and ($read.Types -contains $type)) {
                    $d.Decision | Should -Be 'Blocked' -Because "$($read.Key) $mode must block $type"
                    $d.Classification | Should -Be 'Unreadable'
                    $snap.Types[$type].Status | Should -Be $(if ($mode -eq 'Deny') { 'Denied' } else { 'Error' })
                    $snap.Types[$type].Service | Should -Not -BeNullOrEmpty
                }
                else {
                    $d.Decision | Should -Not -Be 'Blocked' -Because "$($read.Key) must not block $type"
                }
            }
        }
    }

    It 'blocks a type whose read was never performed' {
        $snap = [pscustomobject]@{ Cloud = 'Aws'; LabTag = $script:LabTag; Types = ([ordered]@{}) }
        $d = Resolve-ResourceDecision -Snapshot $snap -Type topic -ExpectedName $script:LabTopic -Quiet
        $d.Decision | Should -Be 'Blocked'
    }

    It 'prints one line per call with the type, the class and the decision' {
        $acct = @{ Trails = @(); LogGroups = @(); Topics = @(); Detectors = @(); Deny = @(); Fail = @() }
        Start-SimAws $acct
        $snap = Get-LabAccountSnapshot -Cloud Aws -LabNames @{ LogGroup = $script:LabLogGroup; Topic = $script:LabTopic } 6>$null
        $out = Resolve-ResourceDecision -Snapshot $snap -Type topic -ExpectedName $script:LabTopic 6>&1 | Out-String
        $out | Should -Match 'Preflight topic'
        $out | Should -Match 'class Absent'
        $out | Should -Match 'decision Create'
    }
}

Describe 'Account discovery decisions on random Azure accounts' {

    AfterEach {
        $global:LabCliHandler = $null
        $global:LabAzHandler = $null
    }

    It 'decides each Azure type from the account state and only lists' {
        $rng = [System.Random]::new(2504)
        $kinds = @{ workspace = 'Workspaces'; actiongroup = 'ActionGroups'; alertrule = 'AlertRules' }
        $labNames = @{ workspace = 'sangyshop-lab-law'; actiongroup = 'sangyshop-lab-ag'; alertrule = 'sangyshop-lab-rule' }
        for ($n = 0; $n -lt 60; $n++) {
            $acct = @{ Workspaces = @(); ActionGroups = @(); AlertRules = @(); Deny = @(); Fail = @() }
            foreach ($type in $kinds.Keys) {
                $pool = @($labNames[$type], 'prod-monitor', 'shared-rules', "$($labNames[$type])-2")
                foreach ($nm in ($pool | Sort-Object { $rng.Next() } | Select-Object -First $rng.Next(0, 4))) {
                    $acct[$kinds[$type]] += , @{ Name = $nm; Tags = (Get-SimTags $rng $script:AzureTag) }
                }
            }
            # One denied listing at random on half of the accounts.
            $blockedKind = $null
            if ($rng.Next(2) -eq 0) {
                $blockedKind = @($kinds.Values)[$rng.Next(3)]
                $mode = if ($rng.Next(2) -eq 0) { 'Deny' } else { 'Fail' }
                $acct[$mode] = @($blockedKind)
            }
            Start-SimAzure $acct
            $snap = Get-LabAccountSnapshot -Cloud Azure 6>$null
            $global:LabSimMutating | Should -BeFalse
            foreach ($c in $global:LabSimCalls) { $c | Should -Match '\b(list)\b' }

            foreach ($type in $kinds.Keys) {
                $d = Resolve-ResourceDecision -Snapshot $snap -Type $type -ExpectedName $labNames[$type] -Quiet
                if ($kinds[$type] -eq $blockedKind) {
                    $d.Decision | Should -Be 'Blocked'
                    continue
                }
                $exp = Get-SimExpectedNamed $acct[$kinds[$type]] $labNames[$type] $script:AzureTag
                $d.Decision | Should -Be $exp.Decision
                $d.Classification | Should -Be $exp.Class
            }
        }
    }
}

Describe 'Trail selection and reuse' {

    AfterEach {
        $global:LabCliHandler = $null
        $global:LabAzHandler = $null
    }

    It 'picks the qualified trail by lab name first, then ascending ordinal name' {
        $rng = [System.Random]::new(2601)
        $pool = @('Zulu', 'alpha', 'Alpha', 'beta', '_first', '0-trail', 'mgmt', 'Mgmt', $script:LabTrailName)
        for ($n = 0; $n -lt 200; $n++) {
            $names = @($pool | Sort-Object { $rng.Next() } | Select-Object -First $rng.Next(1, 8))
            $trails = @()
            foreach ($nm in $names) {
                $trails += , @{
                    Name = $nm; Multi = ($rng.Next(3) -ne 0); Logging = ($rng.Next(3) -ne 0)
                    Scope = @('All', 'All', 'ReadOnly', 'WriteOnly', 'None')[$rng.Next(5)]
                }
            }
            $input = $trails | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; IsMultiRegion = $_.Multi; IsLogging = $_.Logging; ManagementEvents = $_.Scope }
            }
            $pick = Find-ReusableTrail -Trails $input -LabTrailName $script:LabTrailName
            $expected = Get-SimExpectedTrailPick $trails $script:LabTrailName
            if ($null -eq $expected) { $pick | Should -BeNullOrEmpty }
            else {
                $pick.Name | Should -BeExactly $expected
                $pick.IsMultiRegion | Should -BeTrue
                $pick.IsLogging | Should -BeTrue
                $pick.ManagementEvents | Should -Be 'All'
            }
        }
    }

    It 'does not depend on the order the trails are listed in' {
        $trails = @('b', 'A', 'a', 'C') | ForEach-Object {
            [pscustomobject]@{ Name = $_; IsMultiRegion = $true; IsLogging = $true; ManagementEvents = 'All' }
        }
        $fwd = Find-ReusableTrail -Trails $trails
        $rev = Find-ReusableTrail -Trails @($trails[3..0])
        $fwd.Name | Should -BeExactly 'A'
        $rev.Name | Should -BeExactly 'A'
    }

    It 'returns nothing for null, empty or only unqualified trails' {
        Find-ReusableTrail -Trails $null | Should -BeNullOrEmpty
        Find-ReusableTrail -Trails @() | Should -BeNullOrEmpty
        $bad = @(
            [pscustomobject]@{ Name = 'single'; IsMultiRegion = $false; IsLogging = $true; ManagementEvents = 'All' },
            [pscustomobject]@{ Name = 'stopped'; IsMultiRegion = $true; IsLogging = $false; ManagementEvents = 'All' },
            [pscustomobject]@{ Name = 'reads'; IsMultiRegion = $true; IsLogging = $true; ManagementEvents = 'ReadOnly' },
            [pscustomobject]@{ Name = 'writes'; IsMultiRegion = $true; IsLogging = $true; ManagementEvents = 'WriteOnly' },
            [pscustomobject]@{ Name = 'data-only'; IsMultiRegion = $true; IsLogging = $true; ManagementEvents = 'None' }
        )
        Find-ReusableTrail -Trails $bad | Should -BeNullOrEmpty
    }

    It 'reuses a qualified foreign trail as is and proposes no trail creation' {
        $rng = [System.Random]::new(2602)
        for ($n = 0; $n -lt 60; $n++) {
            $acct = New-SimAwsAccount $rng
            # Force exactly one qualified foreign trail with a name that is not the lab's.
            $acct.Trails = @($acct.Trails | Where-Object { $_.Name -cne $script:LabTrailName -and -not (Get-SimTrailQualified $_) })
            $acct.Trails += , @{ Name = 'central-audit'; Multi = $true; Org = ($rng.Next(2) -eq 0); Logging = $true; Scope = 'All'; Adv = ($rng.Next(2) -eq 0); Tags = @{} }
            Start-SimAws $acct
            $snap = Get-LabAccountSnapshot -Cloud Aws -LabNames @{ LogGroup = $script:LabLogGroup; Topic = $script:LabTopic } 6>$null
            $d = Resolve-ResourceDecision -Snapshot $snap -Type trail -ExpectedName $script:LabTrailName -Quiet
            $d.Decision | Should -Be 'ReuseForeign'
            $d.Decision | Should -Not -Be 'Create'
            $d.Name | Should -BeExactly 'central-audit'
            ($d.Reasons -join ' ') | Should -Match 'multi-region'
            ($d.Reasons -join ' ') | Should -Match 'logging'
            ($d.Reasons -join ' ') | Should -Match 'reads and writes'
            Assert-SimReadOnly
        }
    }

    It 'explains why no existing trail serves when only unqualified trails exist' {
        $acct = @{ Trails = @(); LogGroups = @(); Topics = @(); Detectors = @(); Deny = @(); Fail = @() }
        $acct.Trails += , @{ Name = 'reads-only'; Multi = $true; Org = $false; Logging = $true; Scope = 'ReadOnly'; Adv = $false; Tags = @{} }
        Start-SimAws $acct
        $snap = Get-LabAccountSnapshot -Cloud Aws 6>$null
        $d = Resolve-ResourceDecision -Snapshot $snap -Type trail -ExpectedName $script:LabTrailName -Quiet
        $d.Decision | Should -Be 'Create'
        ($d.Reasons -join ' ') | Should -Match 'no existing trail'
    }
}
