<#
.SYNOPSIS
    Pester tests: the detection enable scripts are idempotent.

.DESCRIPTION
    PowerShell has no native property-based testing library, so this file generates
    100 cases with a FIXED SEED (declared project limitation). Each case runs an
    enable script twice through the Invoke-LabCli / $global:LabCliHandler seam, against
    a small stateful fake of AWS. The first run may start from a random set of already
    tagged resources. The second run must issue zero creation calls (no duplicates) and
    exit 0. No AWS call is ever made.

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.Detection.Idempotent.Tests.ps1
#>

BeforeDiscovery {
    $rng = [System.Random]::new(24250)   # fixed seed: reproducible cases
    $regions = @('us-east-1', 'us-west-2', 'eu-west-1', 'sa-east-1', 'ap-southeast-2')
    $targets = @('sns', 'cloudtrail', 'logs', 'flowlogs', 'guardduty', 'all')
    $resources = @('topic', 'subscription', 'bucket', 'trail', 'appGroup', 'flowGroup', 'metricFilter', 'alarm', 'role', 'flowLog', 'detector')

    $cases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 100; $i++) {
        $target = $targets[$i % $targets.Count]
        $region = $regions[$rng.Next($regions.Count)]
        $run = '202601{0:D2}T0000{1:D2}Z-{2:x4}' -f $rng.Next(1, 29), $rng.Next(60), $rng.Next(65536)
        $email = 'user{0}@example.com' -f $rng.Next(1000)
        $bucket = 'sangyshop-lab-app-{0}' -f $rng.Next(100000, 999999)
        $vpc = 'vpc-' + (('{0:x8}' -f $rng.Next()) + ('{0:x8}' -f $rng.Next()))
        $skipData = ($rng.Next(2) -eq 1)

        # Random subset of resources that already exist (tagged) before the first run.
        $pre = @{}
        foreach ($r in $resources) { $pre[$r] = ($i % 4 -ne 0) -and ($rng.Next(3) -eq 0) }

        switch ($target) {
            'sns' { $p = @{ Region = $region; Email = $email; RunId = $run } }
            'cloudtrail' {
                $p = @{ Region = $region; RunId = $run }
                if ($skipData) { $p['SkipDataEvents'] = $true } else { $p['LabBucket'] = $bucket }
            }
            'logs' { $p = @{ Region = $region; RunId = $run } }
            'flowlogs' { $p = @{ Region = $region; RunId = $run; VpcId = $vpc } }
            'guardduty' { $p = @{ Region = $region; RunId = $run } }
            'all' {
                $p = @{ Region = $region; RunId = $run; Email = $email; VpcId = $vpc }
                if ($skipData) { $p['SkipDataEvents'] = $true } else { $p['LabBucket'] = $bucket }
                if ($rng.Next(4) -eq 0) { $p['SkipFlowLogs'] = $true }
                if ($rng.Next(4) -eq 0) { $p['SkipGuardDuty'] = $true }
            }
        }
        [void]$cases.Add(@{ Index = $i; Target = $target; Params = $p; Pre = $pre; Email = $email })
    }
    $script:Cases = $cases.ToArray()
}

BeforeAll {
    $script:DetectionDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab\detection')).Path
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:ManifestDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-idem-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:ManifestDir -Force | Out-Null

    # Self-contained config so the test does not depend on a local cloud.config.ps1.
    $script:ConfigFile = Join-Path $script:ManifestDir 'cloud.config.ps1'
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

    $global:LabCreateVerbs = '^(sns create-topic|sns subscribe|s3api create-bucket|cloudtrail create-trail|logs create-log-group|logs put-metric-filter|cloudwatch put-metric-alarm|ec2 create-flow-logs|iam create-role|guardduty create-detector)$'

    # Stateful fake of the AWS CLI. Records creation calls and flags duplicates.
    $global:LabFakeHandler = {
        param($a)
        $s = $global:LabFakeAws
        $svc = $a[2]; $cmd = $a[3]; $key = "$svc $cmd"
        $tags = '[{"Key":"lab","Value":"sangyshop-lab-aws"},{"Key":"run-id","Value":"x"}]'
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'NotFound' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }

        if ($key -match $global:LabCreateVerbs) { [void]$s.Creates.Add($key) }
        $dup = { param($what) [void]$s.Dups.Add($what); [pscustomobject]@{ ExitCode = 254; Output = "AlreadyExists: $what" } }

        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'sns get-topic-attributes' { if ($s.topic) { return (& $ok 'arn') } else { return $no } }
            'sns list-tags-for-resource' { return (& $ok $tags) }
            'sns create-topic' { if ($s.topic) { return (& $dup 'sns topic') }; $s.topic = $true; return (& $ok 'arn') }
            'sns list-subscriptions-by-topic' { return (& $ok (ConvertTo-Json -InputObject @($s.Subs) -Compress)) }
            'sns subscribe' {
                $e = & $opt '--notification-endpoint'
                if ($s.Subs -contains $e) { return (& $dup "subscription $e") }
                [void]$s.Subs.Add($e); return (& $ok 'pending')
            }
            's3api head-bucket' { if ($s.bucket) { return (& $ok '') } else { return $no } }
            's3api get-bucket-tagging' { return (& $ok $tags) }
            's3api create-bucket' { if ($s.bucket) { return (& $dup 's3 bucket') }; $s.bucket = $true; return (& $ok '') }
            'cloudtrail describe-trails' {
                if ($s.trail) { return (& $ok '["arn:aws:cloudtrail:r:123456789012:trail/sangyshop-lab-trail"]') } else { return (& $ok '[]') }
            }
            'cloudtrail list-tags' { return (& $ok $tags) }
            'cloudtrail create-trail' { if ($s.trail) { return (& $dup 'trail') }; $s.trail = $true; return (& $ok '') }
            'logs describe-log-groups' {
                $prefix = & $opt '--log-group-name-prefix'
                $names = @($s.Groups.Keys | Where-Object { $_ -like "$prefix*" })
                return (& $ok (ConvertTo-Json -InputObject $names -Compress))
            }
            'logs list-tags-for-resource' { return (& $ok $tags) }
            'logs create-log-group' {
                $n = & $opt '--log-group-name'
                if ($s.Groups.ContainsKey($n)) { return (& $dup "log group $n") }
                $s.Groups[$n] = $true; return (& $ok '')
            }
            'logs describe-metric-filters' {
                if ($s.metricFilterPattern) {
                    $o = ConvertTo-Json -InputObject @(@{ n = 'sangyshop-auth-login-failure'; p = $s.metricFilterPattern }) -Compress
                    return (& $ok $o)
                }
                return (& $ok '[]')
            }
            'logs put-metric-filter' {
                if ($s.metricFilterPattern) { [void]$s.Dups.Add('metric filter') }
                $s.metricFilterPattern = & $opt '--filter-pattern'; return (& $ok '')
            }
            'cloudwatch describe-alarms' {
                if ($s.alarm) { return (& $ok '["arn:aws:cloudwatch:r:123456789012:alarm:sangyshop-lab-bruteforce"]') } else { return (& $ok '[]') }
            }
            'cloudwatch list-tags-for-resource' { return (& $ok $tags) }
            'cloudwatch put-metric-alarm' { if ($s.alarm) { return (& $dup 'alarm') }; $s.alarm = $true; return (& $ok '') }
            'ec2 describe-flow-logs' { if ($s.flowLog) { return (& $ok '["fl-0123456789abcdef0"]') } else { return (& $ok '[]') } }
            'ec2 create-flow-logs' { if ($s.flowLog) { return (& $dup 'flow log') }; $s.flowLog = $true; return (& $ok '') }
            'iam get-role' { if ($s.role) { return (& $ok 'arn') } else { return $no } }
            'iam list-role-tags' { return (& $ok $tags) }
            'iam create-role' { if ($s.role) { return (& $dup 'iam role') }; $s.role = $true; return (& $ok '') }
            'guardduty list-detectors' { if ($s.detector) { return (& $ok '["abcdef0123456789abcdef0123456789"]') } else { return (& $ok '[]') } }
            'guardduty list-tags-for-resource' { return (& $ok $tags) }
            'guardduty get-detector' { return (& $ok 'ENABLED') }
            'guardduty create-detector' { if ($s.detector) { return (& $dup 'guardduty detector') }; $s.detector = $true; return (& $ok 'abcdef0123456789abcdef0123456789') }
            default { return (& $ok '') }   # idempotent puts, tag calls, etc.
        }
    }

    function script:New-FakeAws {
        param([hashtable]$Pre)
        $s = @{
            Creates = New-Object System.Collections.ArrayList
            Dups = New-Object System.Collections.ArrayList
            Subs = New-Object System.Collections.ArrayList
            Groups = @{}
            topic = [bool]$Pre.topic
            bucket = [bool]$Pre.bucket
            trail = [bool]$Pre.trail
            alarm = [bool]$Pre.alarm
            role = [bool]$Pre.role
            flowLog = [bool]$Pre.flowLog
            detector = [bool]$Pre.detector
            metricFilterPattern = $null
        }
        if ($Pre.appGroup) { $s.Groups['/sangyshop/app'] = $true }
        if ($Pre.flowGroup) { $s.Groups['/sangyshop/vpcflow'] = $true }
        if ($Pre.metricFilter) { $s.metricFilterPattern = '{ $.event = "auth_login" && $.result = "failure" }' }
        return $s
    }

    function script:Invoke-EnableScript {
        param([string]$Target, [hashtable]$Params)
        $name = if ($Target -eq 'all') { 'enable-all.ps1' } else { "enable-$Target.ps1" }
        $path = Join-Path $script:DetectionDir $name
        $before = $global:LabFakeAws.Creates.Count
        $global:LASTEXITCODE = $null
        & $path @Params *> $null
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Creates  = @($global:LabFakeAws.Creates | Select-Object -Skip $before)
        }
    }
}

AfterAll {
    Remove-Item -LiteralPath 'Function:\global:Start-Sleep' -ErrorAction SilentlyContinue
    $global:LabCliHandler = $null
    $global:LabFakeHandler = $null
    $global:LabCreateVerbs = $null
    $global:LabFakeAws = $null
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    if ($script:ManifestDir -and (Test-Path -LiteralPath $script:ManifestDir)) {
        Remove-Item -LiteralPath $script:ManifestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Detection enable scripts are idempotent (fixed seed, 100 cases)' {

    It 'case <Index> (<Target>): second run makes zero creation calls' -ForEach $script:Cases {
        $env:LAB_MANIFEST_PATH = Join-Path $script:ManifestDir ("manifest-$Index.json")
        $global:LabFakeAws = New-FakeAws -Pre $Pre
        # enable-all refuses to start until the application is deployed (its log group exists).
        if ($Target -eq 'all') { $global:LabFakeAws.Groups['/sangyshop/app'] = $true }
        $global:LabCliHandler = $global:LabFakeHandler

        $first = Invoke-EnableScript -Target $Target -Params $Params
        $first.ExitCode | Should -Be 0
        $global:LabFakeAws.Dups.Count | Should -Be 0

        $second = Invoke-EnableScript -Target $Target -Params $Params
        $second.ExitCode | Should -Be 0
        $second.Creates.Count | Should -Be 0 -Because "second run created: $($second.Creates -join ', ')"
        $global:LabFakeAws.Dups.Count | Should -Be 0
    }

    It 'sanity: a run from an empty account does create resources (the check is not vacuous)' {
        $env:LAB_MANIFEST_PATH = Join-Path $script:ManifestDir 'manifest-sanity.json'
        $none = @{}
        $global:LabFakeAws = New-FakeAws -Pre $none
        $global:LabFakeAws.Groups['/sangyshop/app'] = $true   # the application is deployed first
        $global:LabCliHandler = $global:LabFakeHandler
        $p = @{ Region = 'us-east-1'; RunId = '20260101T000000Z-0000'; Email = 'a@example.com'; VpcId = 'vpc-0123abcd'; SkipDataEvents = $true }
        $first = Invoke-EnableScript -Target 'all' -Params $p
        $first.ExitCode | Should -Be 0
        $first.Creates.Count | Should -BeGreaterThan 5
    }
}
