<#
.SYNOPSIS
    Pester tests: the AWS detection scripts survive permission and limit errors, converge on
    re-run and never touch resources the lab did not create.

.DESCRIPTION
    Every AWS call of the enable-*.ps1 scripts goes through Invoke-LabCli, so the tests set
    $global:LabCliHandler to a small stateful fake of AWS. No real AWS call is ever made.

    A clean run of enable-all.ps1 is recorded first. Then, for every call of that run (each
    mutating call, and the first occurrence of each distinct read), a fresh account is built
    and that one call is made to fail:
      * an access denied error must stop the stack with exit code 3;
      * a LimitExceeded error must stop the stack with exit code 4 (exit 3 for IAM policy calls,
        which have their own quota message);
      * running the same script again with no fault must exit 0, create exactly what a clean
        run creates, and never create anything twice;
      * every resource created before the fault must already be in the lab manifest.

    Other cases cover trail reuse (no create-trail when a qualified trail exists, no change to
    it, quota of trails reached) and additive reuse of a foreign topic, log group and detector
    (only the e-mail subscription and the metric filter are added).

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.Resilience.Tests.ps1
#>

BeforeAll {
    $script:DetectionDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab\detection')).Path
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-resil-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

    # Self-contained config so the test does not depend on a local cloud.config.ps1.
    $script:ConfigFile = Join-Path $script:WorkDir 'cloud.config.ps1'
    Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = 'labtest01'
    Common = @{ AppName = 'sangyshop'; DbName = 'sangyshop'; DbUser = 'sangyshop'; ImageTag = 'hardened' }
    Aws = @{
        Region = 'us-east-1'; AccountId = '123456789012'
        Ec2 = @{ InstanceType = 't3.small'; DbInstanceClass = 'db.t4g.micro'; BucketBase = 'sangyshop-lab'; VolumeGb = 20 }
    }
}
'@
    $env:LAB_CONFIG_PATH = $script:ConfigFile

    # Avoid the real 10 s IAM propagation wait in enable-flowlogs.ps1.
    function global:Start-Sleep { param($Seconds, $Milliseconds) }

    $global:ResCreateVerbs = '^(sns create-topic|sns subscribe|s3api create-bucket|cloudtrail create-trail|logs create-log-group|logs put-metric-filter|cloudwatch put-metric-alarm|ec2 create-flow-logs|iam create-role|guardduty create-detector)$'
    # Calls that legitimately mention a resource the lab reuses without owning it.
    $global:ResAllowedOnForeign = '^(sns subscribe|logs put-metric-filter|cloudwatch put-metric-alarm|ec2 create-flow-logs)$'

    # Stateful fake of the AWS CLI with fault injection (FailAt = index of the call to fail).
    $global:ResHandler = {
        param($a)
        $s = $global:ResState
        $svc = $a[2]; $cmd = $a[3]; $key = "$svc $cmd"
        $joined = $a -join ' '
        $q = $a -contains '--query'
        $isMut = $cmd -match '^(create|put|subscribe|tag|add-tags|start|stop|update|set|delete|attach|remove|enable)'
        $idx = $s.Seq.Count
        [void]$s.Seq.Add([pscustomobject]@{ Key = $key; Mutating = $isMut })

        $json = { param($o) ConvertTo-Json -InputObject $o -Compress -Depth 8 }
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'NotFound' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }
        $dup = { param($what) [void]$s.Dups.Add($what); [pscustomobject]@{ ExitCode = 254; Output = "AlreadyExists: $what" } }
        $tagList = { param($t) if ($t) { '[{"Key":"lab","Value":"sangyshop-lab-aws"},{"Key":"run-id","Value":"x"}]' } else { '[]' } }
        $tagMap = { param($t) if ($t) { '{"lab":"sangyshop-lab-aws"}' } else { '{}' } }
        $trailArn = { param($n) "arn:aws:cloudtrail:us-east-1:123456789012:trail/$n" }
        $topicName = 'sangyshop-lab-alerts'
        $topicArn = "arn:aws:sns:us-east-1:123456789012:$topicName"

        if ($idx -eq $s.FailAt) {
            $s.Failed = $key
            if ($s.FailKind -eq 'deny') {
                return [pscustomobject]@{ ExitCode = 254; Output = "An error occurred (AccessDeniedException) when calling the $cmd operation: User: arn:aws:iam::123456789012:user/user is not authorized to perform: ${svc}:$cmd" }
            }
            return [pscustomobject]@{ ExitCode = 254; Output = "An error occurred (LimitExceededException) when calling the $cmd operation: limit reached" }
        }

        if ($key -match $global:ResCreateVerbs) { [void]$s.Creates.Add($key) }
        if ($isMut -and $key -notmatch $global:ResAllowedOnForeign) {
            foreach ($f in $s.Foreign) { if ($joined.Contains($f)) { [void]$s.Alien.Add("$key touches $f") } }
        }

        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }

            'sns list-topics' {
                if ($s.Topic) { return (& $ok (& $json @{ Topics = @(@{ TopicArn = $topicArn }) })) }
                return (& $ok '{"Topics":[]}')
            }
            'sns get-topic-attributes' { if ($s.Topic) { return (& $ok $topicArn) } else { return $no } }
            'sns list-tags-for-resource' {
                $t = & $tagList $s.TopicTagged
                if ($q) { return (& $ok $t) } else { return (& $ok ('{"Tags":' + $t + '}')) }
            }
            'sns create-topic' {
                if ($s.Topic) { return (& $dup 'sns topic') }
                $s.Topic = $true; $s.TopicTagged = $true; [void]$s.CreatedNames.Add($topicName); return (& $ok $topicArn)
            }
            'sns tag-resource' { $s.TopicTagged = $true; return (& $ok '') }
            'sns list-subscriptions-by-topic' {
                if ($q) { return (& $ok (& $json @($s.Subs))) }
                $subs = @($s.Subs | ForEach-Object { @{ SubscriptionArn = 'PendingConfirmation'; Endpoint = $_; Protocol = 'email' } })
                return (& $ok (& $json @{ Subscriptions = $subs }))
            }
            'sns subscribe' {
                $e = & $opt '--notification-endpoint'
                if ($s.Subs -contains $e) { return (& $dup "subscription $e") }
                [void]$s.Subs.Add($e); return (& $ok 'pending')
            }

            's3api head-bucket' { if ($s.Buckets.Contains((& $opt '--bucket'))) { return (& $ok '') } else { return $no } }
            's3api get-bucket-tagging' { return (& $ok (& $tagList $true)) }
            's3api create-bucket' {
                $b = & $opt '--bucket'
                if ($s.Buckets.Contains($b)) { return (& $dup "bucket $b") }
                [void]$s.Buckets.Add($b); [void]$s.CreatedNames.Add($b); return (& $ok '')
            }

            'cloudtrail describe-trails' {
                $names = @($s.Trails.Keys | Sort-Object)
                if ($a -contains '--trail-name-list') {
                    $n = & $opt '--trail-name-list'
                    if ($s.Trails.Contains($n)) { return (& $ok (& $json @(, (& $trailArn $n)))) }
                    return (& $ok '[]')
                }
                if ($q) { return (& $ok (& $json @($names))) }
                $list = @($names | ForEach-Object { $t = $s.Trails[$_]; @{ Name = $_; TrailARN = (& $trailArn $_); IsMultiRegionTrail = [bool]$t.Multi; IsOrganizationTrail = $false } })
                return (& $ok (& $json @{ trailList = $list }))
            }
            'cloudtrail get-trail-status' {
                $n = ((& $opt '--name') -split '/')[-1]
                return (& $ok (& $json @{ IsLogging = [bool]$s.Trails[$n].Logging }))
            }
            'cloudtrail get-event-selectors' {
                $n = ((& $opt '--trail-name') -split '/')[-1]
                return (& $ok (& $json @{ EventSelectors = @(@{ ReadWriteType = $s.Trails[$n].Mgmt; IncludeManagementEvents = $true }) }))
            }
            'cloudtrail list-tags' {
                $n = ((& $opt '--resource-id-list') -split '/')[-1]
                $t = & $tagList $s.Trails[$n].Tagged
                if ($q) { return (& $ok $t) } else { return (& $ok ('{"ResourceTagList":[{"TagsList":' + $t + '}]}')) }
            }
            'cloudtrail create-trail' {
                $n = & $opt '--name'
                if ($s.Trails.Contains($n)) { return (& $dup "trail $n") }
                $s.Trails[$n] = @{ Multi = $false; Logging = $false; Mgmt = 'All'; Tagged = $true }
                [void]$s.CreatedNames.Add($n); return (& $ok '')
            }
            'cloudtrail start-logging' { $s.Trails[(& $opt '--name')].Logging = $true; return (& $ok '') }

            'logs describe-log-groups' {
                $prefix = & $opt '--log-group-name-prefix'
                $names = @($s.Groups.Keys | Where-Object { $_ -like "$prefix*" } | Sort-Object)
                if ($q) { return (& $ok (& $json @($names))) }
                $list = @($names | ForEach-Object { @{ logGroupName = $_; arn = "arn:aws:logs:us-east-1:123456789012:log-group:${_}:*" } })
                return (& $ok (& $json @{ logGroups = $list }))
            }
            'logs list-tags-for-resource' {
                $n = ((& $opt '--resource-arn') -replace '^.*log-group:', '') -replace ':\*$', ''
                $t = & $tagMap $s.Groups[$n]
                if ($q) { return (& $ok $t) } else { return (& $ok ('{"tags":' + $t + '}')) }
            }
            'logs create-log-group' {
                $n = & $opt '--log-group-name'
                if ($s.Groups.Contains($n)) { return (& $dup "log group $n") }
                $s.Groups[$n] = $true; [void]$s.CreatedNames.Add($n); return (& $ok '')
            }
            'logs tag-resource' {
                $n = ((& $opt '--resource-arn') -replace '^.*log-group:', '') -replace ':\*$', ''
                $s.Groups[$n] = $true; return (& $ok '')
            }
            'logs describe-metric-filters' {
                if ($s.FilterPattern) { return (& $ok (& $json @(, @{ n = 'sangyshop-auth-login-failure'; p = $s.FilterPattern }))) }
                return (& $ok '[]')
            }
            'logs put-metric-filter' {
                $s.FilterPattern = & $opt '--filter-pattern'; return (& $ok '')
            }

            'cloudwatch describe-alarms' {
                if ($s.Alarm) { return (& $ok '["arn:aws:cloudwatch:us-east-1:123456789012:alarm:sangyshop-lab-bruteforce"]') } else { return (& $ok '[]') }
            }
            'cloudwatch list-tags-for-resource' { return (& $ok (& $tagList $true)) }
            'cloudwatch put-metric-alarm' {
                if ($s.Alarm) { return (& $dup 'alarm') }
                $s.Alarm = $true; [void]$s.CreatedNames.Add('sangyshop-lab-bruteforce'); return (& $ok '')
            }

            'ec2 describe-flow-logs' { if ($s.FlowLog) { return (& $ok '["fl-0123456789abcdef0"]') } else { return (& $ok '[]') } }
            'ec2 create-flow-logs' { if ($s.FlowLog) { return (& $dup 'flow log') }; $s.FlowLog = $true; return (& $ok '') }

            'iam get-role' { if ($s.Role) { return (& $ok 'arn') } else { return $no } }
            'iam list-role-tags' { return (& $ok (& $tagList $true)) }
            'iam create-role' {
                if ($s.Role) { return (& $dup 'iam role') }
                $s.Role = $true; [void]$s.CreatedNames.Add((& $opt '--role-name')); return (& $ok '')
            }

            'guardduty list-detectors' {
                if ($q) { if ($s.Detector) { return (& $ok (& $json @(, $s.Detector))) } else { return (& $ok '[]') } }
                if ($s.Detector) { return (& $ok (& $json @{ DetectorIds = @($s.Detector) })) } else { return (& $ok '{"DetectorIds":[]}') }
            }
            'guardduty list-tags-for-resource' { return (& $ok (& $tagMap $s.DetectorTagged)) }
            'guardduty get-detector' {
                if ($q) { return (& $ok 'ENABLED') }
                return (& $ok ('{"Status":"ENABLED","Tags":' + (& $tagMap $s.DetectorTagged) + '}'))
            }
            'guardduty create-detector' {
                if ($s.Detector) { return (& $dup 'guardduty detector') }
                $s.Detector = 'abcdef0123456789abcdef0123456789'; $s.DetectorTagged = $true
                [void]$s.CreatedNames.Add($s.Detector); return (& $ok $s.Detector)
            }
            default { return (& $ok '') }   # idempotent puts, tag calls, etc.
        }
    }

    function script:New-ResState {
        # Scenario keys: AppGroupTagged, ForeignTopic, ForeignDetector, ForeignTrail (qualified), OtherTrails (count of single-region trails).
        param([hashtable]$Scenario = @{})
        $tagged = if ($Scenario.ContainsKey('AppGroupTagged')) { [bool]$Scenario.AppGroupTagged } else { $true }
        $s = @{
            Seq = New-Object System.Collections.ArrayList
            Creates = New-Object System.Collections.ArrayList
            CreatedNames = New-Object System.Collections.ArrayList
            Dups = New-Object System.Collections.ArrayList
            Alien = New-Object System.Collections.ArrayList
            Subs = New-Object System.Collections.ArrayList
            Buckets = New-Object System.Collections.ArrayList
            Groups = @{}
            Trails = @{}
            Foreign = New-Object System.Collections.ArrayList
            FailAt = -1; FailKind = ''; Failed = ''
            Topic = $false; TopicTagged = $false
            Alarm = $false; FlowLog = $false; Role = $false
            Detector = $null; DetectorTagged = $false
            FilterPattern = $null
        }
        # The application is deployed first: its log group exists.
        $s.Groups['/sangyshop/app'] = $tagged
        if (-not $tagged) { [void]$s.Foreign.Add('/sangyshop/app') }
        if ($Scenario.ForeignTopic) {
            $s.Topic = $true; $s.TopicTagged = $false
            [void]$s.Foreign.Add('sangyshop-lab-alerts')
        }
        if ($Scenario.ForeignDetector) {
            $s.Detector = 'abcdef0123456789abcdef0123456789'; $s.DetectorTagged = $false
            [void]$s.Foreign.Add($s.Detector)
        }
        if ($Scenario.ForeignTrail) {
            $s.Trails['org-security-trail'] = @{ Multi = $true; Logging = $true; Mgmt = 'All'; Tagged = $false }
            [void]$s.Foreign.Add('org-security-trail')
        }
        for ($i = 0; $i -lt [int]$Scenario.OtherTrails; $i++) {
            $n = "team-trail-$i"
            $s.Trails[$n] = @{ Multi = $false; Logging = $true; Mgmt = 'ReadOnly'; Tagged = $false }
            [void]$s.Foreign.Add($n)
        }
        return $s
    }

    $script:RunParams = @{
        Region = 'us-east-1'; RunId = '20260101T000000Z-0a0a'; Email = 'user@example.com'
        VpcId = 'vpc-0123abcd'; SkipDataEvents = $true; NonInteractive = $true
    }
    $script:CaseNo = 0

    function script:Invoke-Script {
        param([string]$Name, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        & (Join-Path $script:DetectionDir $Name) @Params *> $null
        return [int]$LASTEXITCODE
    }

    function script:New-Account {
        # Fresh fake account and manifest file for one case.
        param([hashtable]$Scenario = @{})
        $script:CaseNo++
        $env:LAB_MANIFEST_PATH = Join-Path $script:WorkDir ("manifest-$($script:CaseNo).json")
        $global:ResState = New-ResState -Scenario $Scenario
        $global:LabCliHandler = $global:ResHandler
    }

    function script:Get-ManifestText {
        if (Test-Path -LiteralPath $env:LAB_MANIFEST_PATH) { return [System.IO.File]::ReadAllText($env:LAB_MANIFEST_PATH) }
        return ''
    }

    # One clean enable-all run: the reference for what a complete run creates, and the list of call points.
    New-Account
    $script:BaselineExit = Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams
    $script:Baseline = @{
        Creates = @($global:ResState.Creates | Sort-Object)
        Names   = @($global:ResState.CreatedNames | Sort-Object)
        Seq     = @($global:ResState.Seq)
        Dups    = $global:ResState.Dups.Count
    }
    # Fault points, kept few so the run stays short (each point costs two full stack runs):
    # the first occurrence of every creating call (one per resource kind), the IAM policy call
    # (which has its own quota message) and two reads.
    $script:AllMutCount = @(0..($script:Baseline.Seq.Count - 1) | Where-Object { $script:Baseline.Seq[$_].Mutating }).Count
    $seenMut = @{}
    $createPoints = New-Object System.Collections.ArrayList
    $readPoints = New-Object System.Collections.ArrayList
    $policyPoint = $null
    for ($i = 0; $i -lt $script:Baseline.Seq.Count; $i++) {
        $c = $script:Baseline.Seq[$i]
        if ($c.Mutating -and $c.Key -match $global:ResCreateVerbs -and -not $seenMut.ContainsKey($c.Key)) { $seenMut[$c.Key] = $true; [void]$createPoints.Add($i) }
        if ($c.Mutating -and $c.Key -eq 'iam put-role-policy' -and $null -eq $policyPoint) { $policyPoint = $i }
        if ($c.Key -in @('sts get-caller-identity', 'guardduty list-detectors') -and -not $seenMut.ContainsKey($c.Key)) { $seenMut[$c.Key] = $true; [void]$readPoints.Add($i) }
    }
    $script:MutPoints = $createPoints.ToArray()
    $script:ReadPoints = $readPoints.ToArray()
    $script:LimitPoints = @(@($script:MutPoints | Where-Object { $script:MutPoints.IndexOf($_) % 2 -eq 0 }) + $policyPoint)
    $script:DenyPoints = @($script:MutPoints + $script:ReadPoints + $policyPoint)

    function script:Test-FaultPoints {
        # Fails each point in turn, then re-runs without fault. Returns a list of problems (empty = all good).
        param([ValidateSet('deny', 'limit')][string]$Kind, [int[]]$Points)
        $problems = New-Object System.Collections.ArrayList
        foreach ($p in $Points) {
            New-Account
            $global:ResState.FailAt = $p; $global:ResState.FailKind = $Kind
            $key = $script:Baseline.Seq[$p].Key
            $exit1 = Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams
            $expected = if ($Kind -eq 'deny') { 3 } elseif ($key -match '^iam .*policy') { 3 } else { 4 }
            # A denied read of a type the running script does not need (for example the trail read
            # in the logs preflight) is not an error for that script, so exit 0 is also correct there.
            $allowed = @($expected)
            if (-not $script:Baseline.Seq[$p].Mutating) { $allowed += 0 }
            if ($allowed -notcontains $exit1) { [void]$problems.Add("fault on '$key' (call $p): exit $exit1, expected $expected") }
            if ($global:ResState.Failed -ne $key) { [void]$problems.Add("fault on call $p was not injected at '$key' (got '$($global:ResState.Failed)')") }

            # Everything created before the stop is already in the manifest.
            $manifest = Get-ManifestText
            foreach ($n in $global:ResState.CreatedNames) {
                if (-not $manifest.Contains([string]$n)) { [void]$problems.Add("fault on '$key': '$n' was created but is not in the manifest") }
            }

            # Same script again, fault gone: converges to the clean result without duplicates.
            $global:ResState.FailAt = -1
            $exit2 = Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams
            if ($exit2 -ne 0) { [void]$problems.Add("re-run after fault on '$key': exit $exit2, expected 0") }
            if ($global:ResState.Dups.Count -ne 0) { [void]$problems.Add("re-run after fault on '$key': duplicate create ($($global:ResState.Dups -join ', '))") }
            $created = @($global:ResState.Creates | Sort-Object)
            if (($created -join '|') -ne ($script:Baseline.Creates -join '|')) { [void]$problems.Add("re-run after fault on '$key': creations differ from a clean run ($($created -join ', '))") }
        }
        return , $problems
    }
}

AfterAll {
    Remove-Item -LiteralPath 'Function:\global:Start-Sleep' -ErrorAction SilentlyContinue
    $global:LabCliHandler = $null
    $global:ResHandler = $null
    $global:ResState = $null
    $global:ResCreateVerbs = $null
    $global:ResAllowedOnForeign = $null
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Clean run of the whole detection stack (reference for the fault cases)' {
    It 'exits 0, creates the stack once and makes no duplicate call' {
        $script:BaselineExit | Should -Be 0
        $script:Baseline.Dups | Should -Be 0
        $script:Baseline.Creates.Count | Should -BeGreaterThan 8
        $script:AllMutCount | Should -BeGreaterThan 15
        $script:MutPoints.Count | Should -BeGreaterThan 6
    }

    It 'records every resource it created in the manifest' {
        New-Account
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        $manifest = Get-ManifestText
        foreach ($n in $global:ResState.CreatedNames) { $manifest | Should -BeLike "*$n*" }
    }
}

Describe 'A permission error in the stack stops with exit 3 and a re-run converges' {
    It 'stops with exit 3 at each resource creation, the IAM policy call and key reads, then a clean re-run finishes without duplicates' {
        $problems = Test-FaultPoints -Kind deny -Points $script:DenyPoints
        $problems.Count | Should -Be 0 -Because ($problems -join '; ')
    }
}

Describe 'A limit error in the stack stops with exit 4 and a re-run converges' {
    It 'stops with exit 4 (exit 3 for IAM policy calls), then a clean re-run finishes without duplicates' {
        $problems = Test-FaultPoints -Kind limit -Points $script:LimitPoints
        $problems.Count | Should -Be 0 -Because ($problems -join '; ')
    }
}

Describe 'Re-running the stack' {
    It 'creates nothing the second and the third time' {
        New-Account
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        foreach ($round in 1..2) {
            $before = $global:ResState.Creates.Count
            (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
            $global:ResState.Creates.Count | Should -Be $before
            $global:ResState.Dups.Count | Should -Be 0
        }
    }
}

Describe 'CloudTrail reuse and quota' {
    It 'does not create a trail or a bucket when a qualified trail exists, and leaves it unchanged' {
        New-Account -Scenario @{ ForeignTrail = $true }
        (Invoke-Script -Name 'enable-cloudtrail.ps1' -Params @{ Region = 'us-east-1'; RunId = '20260101T000000Z-0a0a'; SkipDataEvents = $true }) | Should -Be 0
        $global:ResState.Creates | Should -Not -Contain 'cloudtrail create-trail'
        $global:ResState.Creates | Should -Not -Contain 's3api create-bucket'
        $global:ResState.Alien.Count | Should -Be 0 -Because ($global:ResState.Alien -join '; ')
        $global:ResState.Trails.Keys.Count | Should -Be 1
        Get-ManifestText | Should -BeLike '*org-security-trail*'
        Get-ManifestText | Should -BeLike '*reused*'
    }

    It 'reuses the qualified trail inside the whole stack too, on every run' {
        New-Account -Scenario @{ ForeignTrail = $true }
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        $global:ResState.Creates | Should -Not -Contain 'cloudtrail create-trail'
        $global:ResState.Alien.Count | Should -Be 0 -Because ($global:ResState.Alien -join '; ')
        $global:ResState.Dups.Count | Should -Be 0
    }

    It 'creates the lab trail next to trails that do not qualify, without touching them' {
        New-Account -Scenario @{ OtherTrails = 2 }
        (Invoke-Script -Name 'enable-cloudtrail.ps1' -Params @{ Region = 'us-east-1'; RunId = '20260101T000000Z-0a0a'; SkipDataEvents = $true }) | Should -Be 0
        @($global:ResState.Creates | Where-Object { $_ -eq 'cloudtrail create-trail' }).Count | Should -Be 1
        $global:ResState.Alien.Count | Should -Be 0 -Because ($global:ResState.Alien -join '; ')
    }

    It 'stops with exit 4 and creates nothing when the region already holds five trails' {
        New-Account -Scenario @{ OtherTrails = 5 }
        (Invoke-Script -Name 'enable-cloudtrail.ps1' -Params @{ Region = 'us-east-1'; RunId = '20260101T000000Z-0a0a'; SkipDataEvents = $true }) | Should -Be 4
        $global:ResState.Creates.Count | Should -Be 0
        $global:ResState.Alien.Count | Should -Be 0 -Because ($global:ResState.Alien -join '; ')
    }
}

Describe 'Resources the lab did not create are reused and never changed' {
    It 'adds only the subscription and the metric filter to a foreign topic, log group and detector' {
        New-Account -Scenario @{ ForeignTopic = $true; ForeignDetector = $true; AppGroupTagged = $false }
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        $s = $global:ResState
        $s.Creates | Should -Not -Contain 'sns create-topic'
        $s.Creates | Should -Not -Contain 'guardduty create-detector'
        $s.CreatedNames | Should -Not -Contain '/sangyshop/app'
        $s.CreatedNames | Should -Contain '/sangyshop/vpcflow'
        $s.Subs | Should -Contain 'user@example.com'
        $s.FilterPattern | Should -Not -BeNullOrEmpty
        $s.TopicTagged | Should -BeFalse
        $s.DetectorTagged | Should -BeFalse
        $s.Groups['/sangyshop/app'] | Should -BeFalse
        $s.Alien.Count | Should -Be 0 -Because ($s.Alien -join '; ')
        $s.Dups.Count | Should -Be 0
    }

    It 'converges when re-run over foreign resources' {
        New-Account -Scenario @{ ForeignTopic = $true; ForeignDetector = $true; AppGroupTagged = $false }
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        $before = $global:ResState.Creates.Count
        (Invoke-Script -Name 'enable-all.ps1' -Params $script:RunParams) | Should -Be 0
        $global:ResState.Creates.Count | Should -Be $before
        $global:ResState.Alien.Count | Should -Be 0 -Because ($global:ResState.Alien -join '; ')
        $global:ResState.Dups.Count | Should -Be 0
    }

    It 'completes the tags of a lab topic left untagged by an interrupted run instead of recreating it' {
        New-Account
        $global:ResState.Topic = $true
        $global:ResState.TopicTagged = $false
        # The manifest says the lab created it.
        Add-Content -LiteralPath $env:LAB_MANIFEST_PATH -Value '' -ErrorAction SilentlyContinue
        $manifest = @{ lab = 'sangyshop-lab-aws'; resources = @(@{ type = 'sns-topic'; id = 'sangyshop-lab-alerts'; region = 'us-east-1'; runId = 'x'; component = 'detection'; ownership = 'created' }) }
        [System.IO.File]::WriteAllText($env:LAB_MANIFEST_PATH, (ConvertTo-Json -InputObject $manifest -Depth 6))
        (Invoke-Script -Name 'enable-sns.ps1' -Params @{ Region = 'us-east-1'; RunId = '20260101T000000Z-0a0a'; Email = 'user@example.com'; NonInteractive = $true }) | Should -Be 0
        $global:ResState.Creates | Should -Not -Contain 'sns create-topic'
        $global:ResState.TopicTagged | Should -BeTrue
        $global:ResState.Dups.Count | Should -Be 0
    }
}
