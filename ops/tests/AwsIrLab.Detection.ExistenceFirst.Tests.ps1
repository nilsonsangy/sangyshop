<#
.SYNOPSIS
    Pester tests: the detection enable scripts read the account before they create anything.

.DESCRIPTION
    PowerShell has no native property-based testing library, so this file generates
    36 cases with a FIXED SEED (declared project limitation). Each case starts from a
    random simulated account (a random subset of the lab resources already exists, some of
    them without the lab tag) and runs one enable script through the Invoke-LabCli /
    $global:LabCliHandler seam. Two things must hold for every case:
      - Read before create: every creation call is preceded by the read call that
        looks for that same kind of resource.
      - No create for what exists: a resource that already exists is never created again.
    No AWS call is ever made.

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.Detection.ExistenceFirst.Tests.ps1
#>

BeforeDiscovery {
    $rng = [System.Random]::new(15410)   # fixed seed: reproducible cases
    $targets = @('sns', 'cloudtrail', 'logs', 'flowlogs', 'guardduty', 'all')
    $resources = @('topic', 'subscription', 'bucket', 'trail', 'appGroup', 'flowGroup', 'metricFilter', 'alarm', 'role', 'flowLog', 'detector')
    $foreignable = @('topic', 'appGroup', 'detector')

    $cases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 36; $i++) {
        $target = $targets[$i % $targets.Count]
        $run = '202602{0:D2}T0000{1:D2}Z-{2:x4}' -f $rng.Next(1, 29), $rng.Next(60), $rng.Next(65536)
        $email = 'user{0}@example.com' -f $rng.Next(1000)
        $bucket = 'sangyshop-lab-app-{0}' -f $rng.Next(100000, 999999)
        $vpc = 'vpc-' + (('{0:x8}' -f $rng.Next()) + ('{0:x8}' -f $rng.Next()))
        $skipData = ($rng.Next(2) -eq 1)

        $pre = @{}
        foreach ($r in $resources) { $pre[$r] = ($rng.Next(2) -eq 0) }
        $pre['subscription'] = $pre['subscription'] -and $pre['topic']
        # Some existing resources were not created by the lab (no lab tag).
        $foreign = @{}
        foreach ($r in $foreignable) { $foreign[$r] = $pre[$r] -and ($rng.Next(3) -eq 0) }

        switch ($target) {
            'sns' { $p = @{ Region = 'us-east-1'; Email = $email; RunId = $run } }
            'cloudtrail' {
                $p = @{ Region = 'us-east-1'; RunId = $run }
                if ($skipData) { $p['SkipDataEvents'] = $true } else { $p['LabBucket'] = $bucket }
            }
            'logs' { $p = @{ Region = 'us-east-1'; RunId = $run } }
            'flowlogs' { $p = @{ Region = 'us-east-1'; RunId = $run; VpcId = $vpc } }
            'guardduty' { $p = @{ Region = 'us-east-1'; RunId = $run } }
            'all' {
                $p = @{ Region = 'us-east-1'; RunId = $run; Email = $email; VpcId = $vpc }
                if ($skipData) { $p['SkipDataEvents'] = $true } else { $p['LabBucket'] = $bucket }
            }
        }
        [void]$cases.Add(@{ Index = $i; Target = $target; Params = $p; Pre = $pre; Foreign = $foreign; Email = $email })
    }
    $script:Cases = $cases.ToArray()
}

BeforeAll {
    $script:DetectionDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab\detection')).Path
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-exist-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

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

    # Avoid the real IAM propagation wait in enable-flowlogs.ps1.
    function global:Start-Sleep { param($Seconds, $Milliseconds) }

    # Creation verb -> the read verb that looks for the same kind of resource.
    $script:ReadFor = @{
        'sns create-topic'           = 'sns get-topic-attributes'
        'sns subscribe'              = 'sns list-subscriptions-by-topic'
        's3api create-bucket'        = 's3api head-bucket'
        'cloudtrail create-trail'    = 'cloudtrail describe-trails'
        'logs create-log-group'      = 'logs describe-log-groups'
        'logs put-metric-filter'     = 'logs describe-metric-filters'
        'cloudwatch put-metric-alarm' = 'cloudwatch describe-alarms'
        'ec2 create-flow-logs'       = 'ec2 describe-flow-logs'
        'iam create-role'            = 'iam get-role'
        'guardduty create-detector'  = 'guardduty list-detectors'
    }
    # Creation verb -> the key of the simulated resource it would create.
    $script:ResourceFor = @{
        'sns create-topic' = 'topic'; 'sns subscribe' = 'subscription'; 's3api create-bucket' = 'bucket'
        'cloudtrail create-trail' = 'trail'; 'logs put-metric-filter' = 'metricFilter'; 'cloudwatch put-metric-alarm' = 'alarm'
        'ec2 create-flow-logs' = 'flowLog'; 'iam create-role' = 'role'; 'guardduty create-detector' = 'detector'
    }

    # Stateful fake of the AWS CLI that logs every call in order.
    $global:LabFakeHandler = {
        param($a)
        $s = $global:LabFakeAws
        $svc = $a[2]; $cmd = $a[3]; $key = "$svc $cmd"
        [void]$s.Calls.Add($key)
        $tagsOk = '[{"Key":"lab","Value":"sangyshop-lab-aws"},{"Key":"run-id","Value":"x"}]'
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'NotFound' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }
        $tagsFor = { param($res) if ($s.Foreign[$res]) { & $ok '[]' } else { & $ok $tagsOk } }

        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'sns get-topic-attributes' { if ($s.topic) { return (& $ok 'arn') } else { return $no } }
            'sns list-tags-for-resource' { return (& $tagsFor 'topic') }
            'sns create-topic' { $s.topic = $true; return (& $ok 'arn') }
            'sns list-subscriptions-by-topic' { return (& $ok (ConvertTo-Json -InputObject @($s.Subs) -Compress)) }
            'sns subscribe' { [void]$s.Subs.Add((& $opt '--notification-endpoint')); return (& $ok 'pending') }
            's3api head-bucket' { if ($s.bucket) { return (& $ok '') } else { return $no } }
            's3api get-bucket-tagging' { return (& $ok $tagsOk) }
            's3api create-bucket' { $s.bucket = $true; return (& $ok '') }
            'cloudtrail describe-trails' {
                if ($s.trail) { return (& $ok '["arn:aws:cloudtrail:r:123456789012:trail/sangyshop-lab-trail"]') } else { return (& $ok '[]') }
            }
            'cloudtrail list-tags' { return (& $ok $tagsOk) }
            'cloudtrail create-trail' { $s.trail = $true; return (& $ok '') }
            'logs describe-log-groups' {
                $prefix = & $opt '--log-group-name-prefix'
                $names = @($s.Groups.Keys | Where-Object { $_ -like "$prefix*" })
                return (& $ok (ConvertTo-Json -InputObject $names -Compress))
            }
            'logs list-tags-for-resource' {
                if ((& $opt '--resource-arn') -like '*:/sangyshop/app') { return (& $tagsFor 'appGroup') }
                return (& $ok $tagsOk)
            }
            'logs create-log-group' { $s.Groups[(& $opt '--log-group-name')] = $true; return (& $ok '') }
            'logs describe-metric-filters' {
                if ($s.metricFilter) {
                    $o = ConvertTo-Json -InputObject @(@{ n = 'sangyshop-auth-login-failure'; p = $s.FilterPattern }) -Compress
                    return (& $ok $o)
                }
                return (& $ok '[]')
            }
            'logs put-metric-filter' { $s.metricFilter = $true; $s.FilterPattern = & $opt '--filter-pattern'; return (& $ok '') }
            'cloudwatch describe-alarms' {
                if ($s.alarm) { return (& $ok '["arn:aws:cloudwatch:r:123456789012:alarm:sangyshop-lab-bruteforce"]') } else { return (& $ok '[]') }
            }
            'cloudwatch list-tags-for-resource' { return (& $ok $tagsOk) }
            'cloudwatch put-metric-alarm' { $s.alarm = $true; return (& $ok '') }
            'ec2 describe-flow-logs' { if ($s.flowLog) { return (& $ok '["fl-0123456789abcdef0"]') } else { return (& $ok '[]') } }
            'ec2 create-flow-logs' { $s.flowLog = $true; return (& $ok '') }
            'iam get-role' { if ($s.role) { return (& $ok 'arn') } else { return $no } }
            'iam list-role-tags' { return (& $ok $tagsOk) }
            'iam create-role' { $s.role = $true; return (& $ok '') }
            'guardduty list-detectors' { if ($s.detector) { return (& $ok '["abcdef0123456789abcdef0123456789"]') } else { return (& $ok '[]') } }
            'guardduty list-tags-for-resource' { return (& $tagsFor 'detector') }
            'guardduty get-detector' { return (& $ok 'ENABLED') }
            'guardduty create-detector' { $s.detector = $true; return (& $ok 'abcdef0123456789abcdef0123456789') }
            default { return (& $ok '') }
        }
    }

    function script:New-FakeAws {
        param([hashtable]$Pre, [hashtable]$Foreign, [string]$Email)
        $s = @{
            Calls = New-Object System.Collections.ArrayList
            Subs = New-Object System.Collections.ArrayList
            Groups = @{}
            Foreign = $Foreign
            FilterPattern = '{ $.event = "auth_login" && $.result = "failure" }'
            topic = [bool]$Pre['topic']; bucket = [bool]$Pre['bucket']; trail = [bool]$Pre['trail']
            alarm = [bool]$Pre['alarm']; role = [bool]$Pre['role']; flowLog = [bool]$Pre['flowLog']
            detector = [bool]$Pre['detector']; metricFilter = [bool]$Pre['metricFilter']
        }
        if ($Pre['subscription']) { [void]$s.Subs.Add($Email) }
        if ($Pre['appGroup']) { $s.Groups['/sangyshop/app'] = $true }
        if ($Pre['flowGroup']) { $s.Groups['/sangyshop/vpcflow'] = $true }
        return $s
    }

    function script:Invoke-EnableScript {
        param([string]$Target, [hashtable]$Params)
        $name = if ($Target -eq 'all') { 'enable-all.ps1' } else { "enable-$Target.ps1" }
        $global:LASTEXITCODE = $null
        & (Join-Path $script:DetectionDir $name) @Params *> $null
        return $LASTEXITCODE
    }
}

AfterAll {
    Remove-Item -LiteralPath 'Function:\global:Start-Sleep' -ErrorAction SilentlyContinue
    $global:LabCliHandler = $null
    $global:LabFakeHandler = $null
    $global:LabFakeAws = $null
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Detection enable scripts look before they create (fixed seed, 36 cases)' {

    It 'case <Index> (<Target>): every create is preceded by its read and nothing existing is created' -ForEach $script:Cases {
        $env:LAB_MANIFEST_PATH = Join-Path $script:WorkDir ("manifest-$Index.json")
        $global:LabFakeAws = New-FakeAws -Pre $Pre -Foreign $Foreign -Email $Email
        # enable-all refuses to start until the application is deployed (its log group exists).
        if ($Target -eq 'all') { $global:LabFakeAws.Groups['/sangyshop/app'] = $true; $Pre['appGroup'] = $true }
        $global:LabCliHandler = $global:LabFakeHandler

        $code = Invoke-EnableScript -Target $Target -Params $Params
        $code | Should -Be 0

        $calls = @($global:LabFakeAws.Calls)
        for ($n = 0; $n -lt $calls.Count; $n++) {
            $verb = $calls[$n]
            if (-not $script:ReadFor.ContainsKey($verb)) { continue }
            $before = @($calls[0..($n - 1)])
            if ($n -eq 0) { $before = @() }
            $before | Should -Contain $script:ReadFor[$verb] -Because "'$verb' (call $n) ran without '$($script:ReadFor[$verb])' first"
            if ($script:ResourceFor.ContainsKey($verb) -and $Pre[$script:ResourceFor[$verb]]) {
                throw "'$verb' was called although the resource '$($script:ResourceFor[$verb])' already existed"
            }
        }
        # Log groups: a group that existed must not be created again.
        $createdGroups = @($calls | Where-Object { $_ -eq 'logs create-log-group' }).Count
        $existingGroups = @('appGroup', 'flowGroup' | Where-Object { $Pre[$_] }).Count
        $createdGroups + $existingGroups | Should -BeLessOrEqual 2
    }

    It 'quota check lists trails with the boolean --no-include-shadow-trails flag and no stray value' {
        $env:LAB_MANIFEST_PATH = Join-Path $script:WorkDir 'manifest-quota.json'
        $global:LabFakeAws = New-FakeAws -Pre @{} -Foreign @{} -Email 'a@example.com'
        $global:QuotaCalls = New-Object System.Collections.ArrayList
        $global:LabCliHandler = {
            param($a)
            if ($a[2] -eq 'cloudtrail' -and $a[3] -eq 'describe-trails' -and ($a -contains '--query') -and ($a -contains 'trailList[].Name')) {
                [void]$global:QuotaCalls.Add(@($a))
            }
            & $global:LabFakeHandler $a
        }
        $p = @{ Region = 'us-east-1'; RunId = '20260201T000000Z-0000'; SkipDataEvents = $true }
        (Invoke-EnableScript -Target 'cloudtrail' -Params $p) | Should -Be 0
        $calls = @($global:QuotaCalls)
        $global:QuotaCalls = $null
        $calls.Count | Should -Be 1
        (@($calls[0])[2..(@($calls[0]).Count - 1)] -join ' ') | Should -Be 'cloudtrail describe-trails --no-include-shadow-trails --query trailList[].Name --output json'
        (@($calls[0]) -contains 'false') | Should -BeFalse
    }

    It 'sanity: from an empty account the same scripts do create resources (the check is not vacuous)' {
        $env:LAB_MANIFEST_PATH = Join-Path $script:WorkDir 'manifest-sanity.json'
        $global:LabFakeAws = New-FakeAws -Pre @{} -Foreign @{} -Email 'a@example.com'
        $global:LabFakeAws.Groups['/sangyshop/app'] = $true
        $global:LabCliHandler = $global:LabFakeHandler
        $p = @{ Region = 'us-east-1'; RunId = '20260201T000000Z-0000'; Email = 'a@example.com'; VpcId = 'vpc-0123abcd'; SkipDataEvents = $true }
        (Invoke-EnableScript -Target 'all' -Params $p) | Should -Be 0
        @($global:LabFakeAws.Calls | Where-Object { $script:ReadFor.ContainsKey($_) }).Count | Should -BeGreaterThan 5
    }
}
