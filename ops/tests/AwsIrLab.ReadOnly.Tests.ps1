<#
.SYNOPSIS
    Pester tests: the read-only AWS lab tools (verify-lab-state, check-detection-ready,
    print-response-commands).

.DESCRIPTION
    PowerShell has no native property-based testing library, so this file generates
    cases with a FIXED SEED (declared project limitation). Each case runs a script
    in-process through the Invoke-LabCli / $global:LabCliHandler seam, against a fake
    AWS account whose state is drawn at random. No AWS call is ever made.

    Properties checked:
      * read-only tools only issue describe, get and list verbs (and none for print)
      * verify-lab-state: one line per component, exit 0 only when all are present,
        exit 1 otherwise, exit 3 on a denied read
      * check-detection-ready: exit 0 only when the four checks pass, exit 4 for a
        pending e-mail subscription, exit 1 for other gaps, exit 3 on a denied read;
        the stamp exists only after exit 0 and never contains the e-mail address
      * print-response-commands: no AWS call, nothing executed, exit 4 without the
        attack evidence file

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.ReadOnly.Tests.ps1
#>

BeforeDiscovery {
    $rng = [System.Random]::new(24317)   # fixed seed: reproducible cases
    $regions = @('us-east-1', 'us-west-2', 'eu-west-1', 'sa-east-1', 'ap-southeast-2')
    $denyPool = @(
        'sns get-topic-attributes', 'sns list-subscriptions-by-topic', 'cloudtrail get-trail-status',
        'logs describe-log-groups', 'logs describe-metric-filters', 'cloudwatch describe-alarms',
        'ec2 describe-flow-logs', 'guardduty list-detectors', 'guardduty get-detector'
    )
    $subModes = @('none', 'pending', 'confirmed')
    $trailModes = @('none', 'notlogging', 'logging')
    $alarmModes = @('none', 'noaction', 'ok')
    $detModes = @('none', 'disabled', 'enabled')

    $mk = {
        param($i, $forceHealthy)
        $s = @{
            Sub      = $subModes[$rng.Next(3)]
            Trail    = $trailModes[$rng.Next(3)]
            Alarm    = $alarmModes[$rng.Next(3)]
            Detector = $detModes[$rng.Next(3)]
            Topic    = ($rng.Next(4) -ne 0)
            Group    = ($rng.Next(4) -ne 0)
            Filter   = ($rng.Next(4) -ne 0)
            Flow     = ($rng.Next(4) -ne 0)
            Deny     = $null
        }
        # Bias a share of the cases to a fully healthy account so the exit 0 path is exercised.
        if ($forceHealthy) {
            $s.Sub = 'confirmed'; $s.Trail = 'logging'; $s.Alarm = 'ok'; $s.Detector = 'enabled'
            $s.Topic = $true; $s.Group = $true; $s.Filter = $true; $s.Flow = $true
        }
        if (-not $forceHealthy -and $rng.Next(8) -eq 0) { $s.Deny = $denyPool[$rng.Next($denyPool.Count)] }
        $s
    }

    $verifyCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 60; $i++) {
        $healthy = ($i % 5 -eq 0)
        [void]$verifyCases.Add(@{
                Index = $i; State = (& $mk $i $healthy); Region = $regions[$rng.Next($regions.Count)]
                SkipFlow = ($rng.Next(3) -eq 0); SkipGd = ($rng.Next(3) -eq 0)
                Email = ('user{0}@example.com' -f $rng.Next(100000))
            })
    }
    $script:VerifyCases = $verifyCases.ToArray()

    $readyCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 60; $i++) {
        $healthy = ($i % 3 -eq 0)
        [void]$readyCases.Add(@{
                Index = $i; State = (& $mk $i $healthy); Region = $regions[$rng.Next($regions.Count)]
                Email = ('user{0}@example.com' -f $rng.Next(100000))
                OldStamp = ($rng.Next(2) -eq 1)
            })
    }
    $script:ReadyCases = $readyCases.ToArray()

    $printCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 20; $i++) {
        [void]$printCases.Add(@{
                Index = $i; Region = $regions[$rng.Next($regions.Count)]
                Evidence = ($i % 2 -eq 0)
                Instance = $(if ($rng.Next(2) -eq 1) { 'i-' + ('{0:x8}' -f $rng.Next()) } else { '' })
            })
    }
    $script:PrintCases = $printCases.ToArray()
}

BeforeAll {
    $script:LabDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab')).Path
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-ro-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    # Self-contained config so the test does not depend on a local cloud.config.ps1.
    $script:ConfigFile = Join-Path $script:Work 'cloud.config.ps1'
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

    $global:LabReadOnlyVerbs = '^(describe|get|list)-'

    # Fake of the AWS CLI driven by $global:LabReadState. Records every call.
    $global:LabReadHandler = {
        param($a)
        $s = $global:LabReadState
        $svc = [string]$a[2]; $op = [string]$a[3]; $key = "$svc $op"
        [void]$global:LabReadCalls.Add($key)
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'An error occurred (ResourceNotFoundException): not found' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }
        $json = { param($o) ConvertTo-Json -InputObject $o -Depth 6 -Compress }

        if ($s.Deny -and $s.Deny -eq $key) {
            $s.Denied = $true
            return [pscustomobject]@{ ExitCode = 254; Output = "An error occurred (AccessDeniedException) when calling the $op operation: User is not authorized to perform: ${svc}:$op" }
        }
        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'sns get-topic-attributes' { if ($s.Topic) { return (& $ok '{"Attributes":{}}') } else { return $no } }
            'sns list-subscriptions-by-topic' {
                $subs = @()
                if ($s.Sub -eq 'pending') { $subs = @(@{ Protocol = 'email'; Endpoint = $s.Email; SubscriptionArn = 'PendingConfirmation' }) }
                if ($s.Sub -eq 'confirmed') { $subs = @(@{ Protocol = 'email'; Endpoint = $s.Email; SubscriptionArn = 'arn:aws:sns:us-east-1:123456789012:t:abc' }) }
                return (& $ok (& $json @{ Subscriptions = $subs }))
            }
            'cloudtrail get-trail-status' {
                if ($s.Trail -eq 'none') { return $no }
                return (& $ok (& $json @{ IsLogging = ($s.Trail -eq 'logging') }))
            }
            'logs describe-log-groups' {
                $groups = @(); if ($s.Group) { $groups = @(@{ logGroupName = (& $opt '--log-group-name-prefix') }) }
                return (& $ok (& $json @{ logGroups = $groups }))
            }
            'logs describe-metric-filters' {
                $f = @(); if ($s.Filter) { $f = @(@{ filterName = (& $opt '--filter-name-prefix') }) }
                return (& $ok (& $json @{ metricFilters = $f }))
            }
            'cloudwatch describe-alarms' {
                $al = @()
                if ($s.Alarm -eq 'noaction') { $al = @(@{ AlarmName = (& $opt '--alarm-names'); AlarmActions = @() }) }
                if ($s.Alarm -eq 'ok') { $al = @(@{ AlarmName = (& $opt '--alarm-names'); AlarmActions = @('arn:aws:sns:us-east-1:123456789012:t') }) }
                return (& $ok (& $json @{ MetricAlarms = $al }))
            }
            'ec2 describe-flow-logs' {
                $fl = @(); if ($s.Flow) { $fl = @(@{ FlowLogId = 'fl-0123456789abcdef0' }) }
                return (& $ok (& $json @{ FlowLogs = $fl }))
            }
            'guardduty list-detectors' {
                $d = @(); if ($s.Detector -ne 'none') { $d = @('abcdef0123456789abcdef0123456789') }
                return (& $ok (& $json @{ DetectorIds = $d }))
            }
            'guardduty get-detector' {
                return (& $ok (& $json @{ Status = $(if ($s.Detector -eq 'enabled') { 'ENABLED' } else { 'DISABLED' }) }))
            }
            default { [void]$global:LabMutating.Add($key); return (& $ok '{}') }
        }
    }

    function script:Initialize-Case {
        param([hashtable]$State, [string]$Email, [string]$Name)
        $State['Email'] = $Email
        $State['Denied'] = $false
        $global:LabReadState = $State
        $global:LabReadCalls = New-Object System.Collections.ArrayList
        $global:LabMutating = New-Object System.Collections.ArrayList
        $global:LabCliHandler = $global:LabReadHandler
        $dir = Join-Path $script:Work $Name
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $env:LAB_MANIFEST_PATH = Join-Path $dir 'manifest.json'
        return $dir
    }

    function script:Invoke-Tool {
        param([string]$Script, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        # A fixed width keeps long command lines unwrapped whatever the host console width is.
        $text = (& (Join-Path $script:LabDir $Script) @Params *>&1 | Out-String -Width 4096)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
    }

    function script:Assert-ReadOnlyCalls {
        $bad = @($global:LabReadCalls | Where-Object { ($_ -split ' ')[1] -notmatch $global:LabReadOnlyVerbs -and $_ -ne 'sts get-caller-identity' })
        $bad.Count | Should -Be 0 -Because "non-read calls: $($bad -join ', ')"
        @($global:LabReadCalls | Where-Object { $_ -match '^iam ' }).Count | Should -Be 0
        $global:LabMutating.Count | Should -Be 0 -Because "unexpected calls: $($global:LabMutating -join ', ')"
    }
}

AfterAll {
    $global:LabCliHandler = $null
    $global:LabReadHandler = $null
    $global:LabReadState = $null
    $global:LabReadCalls = $null
    $global:LabMutating = $null
    $global:LabReadOnlyVerbs = $null
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'verify-lab-state.ps1 (fixed seed, 60 cases)' {

    It 'case <Index>: reads only, one line per component, exit code follows the account state' -ForEach $script:VerifyCases {
        $null = Initialize-Case -State $State -Email $Email -Name "verify-$Index"
        $p = @{ Region = $Region }
        if ($SkipFlow) { $p['SkipFlowLogs'] = $true }
        if ($SkipGd) { $p['SkipGuardDuty'] = $true }

        $r = Invoke-Tool -Script 'verify-lab-state.ps1' -Params $p

        Assert-ReadOnlyCalls
        $r.Text | Should -Not -Match ([regex]::Escape($Email))

        if ($State.Denied) {
            $r.ExitCode | Should -Be 3
            return
        }

        $expectedCount = 6 + $(if ($SkipFlow) { 0 } else { 1 }) + $(if ($SkipGd) { 0 } else { 1 })
        $lines = @($r.Text -split "`r?`n" | Where-Object { $_ -match '^(OK     |MISSING) ' })
        $lines.Count | Should -Be $expectedCount

        $missing = @($lines | Where-Object { $_ -like 'MISSING*' })
        $ready = ($State.Topic -and $State.Sub -eq 'confirmed' -and $State.Trail -eq 'logging' -and $State.Group -and
            $State.Filter -and $State.Alarm -eq 'ok' -and ($SkipFlow -or $State.Flow) -and ($SkipGd -or $State.Detector -eq 'enabled'))
        if ($ready) {
            $r.ExitCode | Should -Be 0
            $missing.Count | Should -Be 0
        } else {
            $r.ExitCode | Should -Be 1
            $missing.Count | Should -BeGreaterThan 0
            # Every missing component names the script that creates it.
            @($missing | Where-Object { $_ -notmatch 'created by \S+\.ps1' }).Count | Should -Be 0
        }
        $r.Text | Should -Match 'Next step:'
    }
}

Describe 'check-detection-ready.ps1 (fixed seed, 60 cases)' {

    It 'case <Index>: reads only, exit code and stamp follow the four checks' -ForEach $script:ReadyCases {
        $dir = Initialize-Case -State $State -Email $Email -Name "ready-$Index"
        $stamp = Join-Path $dir 'readiness-sangyshop-lab-aws.json'
        if ($OldStamp) { Set-Content -LiteralPath $stamp -Value '{"old":true}' -Encoding UTF8 }
        $before = if ($OldStamp) { Get-Content -LiteralPath $stamp -Raw } else { $null }

        $r = Invoke-Tool -Script 'check-detection-ready.ps1' -Params @{ Region = $Region; StampPath = $stamp }

        Assert-ReadOnlyCalls
        $r.Text | Should -Not -Match ([regex]::Escape($Email))

        $allOk = ($State.Sub -eq 'confirmed' -and $State.Alarm -eq 'ok' -and $State.Group -and $State.Trail -eq 'logging')
        if ($State.Denied) { $expected = 3 }
        elseif ($State.Sub -eq 'pending') { $expected = 4 }
        elseif ($allOk) { $expected = 0 }
        else { $expected = 1 }
        $r.ExitCode | Should -Be $expected

        if ($expected -eq 0) {
            Test-Path -LiteralPath $stamp | Should -BeTrue
            $raw = Get-Content -LiteralPath $stamp -Raw
            $raw | Should -Not -Match ([regex]::Escape($Email))
            $doc = $raw | ConvertFrom-Json
            $doc.region | Should -Be $Region
            $doc.lab | Should -Not -BeNullOrEmpty
            $raw | Should -Match '"checked_utc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
            foreach ($k in 'subscription_confirmed', 'alarm_has_action', 'log_group_exists', 'trail_logging') {
                $doc.checks.$k | Should -BeTrue
            }
        } elseif ($OldStamp) {
            # An older stamp is left exactly as it was.
            (Get-Content -LiteralPath $stamp -Raw) | Should -Be $before
        } else {
            Test-Path -LiteralPath $stamp | Should -BeFalse
        }
        if ($expected -eq 4) { $r.Text | Should -Match '(?i)confirm' }
    }
}

Describe 'print-response-commands.ps1 (fixed seed, 20 cases)' {

    It 'case <Index>: makes no AWS call, prints only native aws commands, exit 4 without attack evidence' -ForEach $script:PrintCases {
        $dir = Initialize-Case -State @{ Deny = $null } -Email 'x@example.com' -Name "print-$Index"
        $evidence = Join-Path $dir 'attack-steps.jsonl'
        if ($Evidence) { Set-Content -LiteralPath $evidence -Value '{"step":1}' -Encoding UTF8 }

        $p = @{ Region = $Region; AttackEvidencePath = $evidence }
        if ($Instance) { $p['InstanceId'] = $Instance }

        $r = Invoke-Tool -Script 'print-response-commands.ps1' -Params $p

        # Printing is not executing: no AWS call reaches the fake CLI.
        $global:LabReadCalls.Count | Should -Be 0 -Because "calls: $($global:LabReadCalls -join ', ')"
        $global:LabMutating.Count | Should -Be 0

        if (-not $Evidence) {
            $r.ExitCode | Should -Be 4
            $r.Text | Should -Match 'attack simulation'
            $r.Text | Should -Not -Match '(?m)^\s+aws\s'
            return
        }
        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match 'Next step:'
        $commandLines = @($r.Text -split "`r?`n" | Where-Object { $_ -match '^\s+aws\s' })
        $commandLines.Count | Should -Be 9
        # Every printed command is a native aws command, with no other tool or path.
        @($commandLines | Where-Object { $_ -notmatch '^\s+aws (cloudtrail|guardduty|ec2|iam) ' }).Count | Should -Be 0
        $r.Text | Should -Not -Match '-Execute'
        $r.Text | Should -Not -Match '(?m)^\s+&\s'
        foreach ($needle in 'cloudtrail lookup-events', 'guardduty list-findings', 'guardduty get-findings',
            'ec2 create-snapshot', 'ec2 modify-instance-attribute', 'iam update-access-key', 'iam put-user-policy') {
            $r.Text | Should -Match ([regex]::Escape($needle))
        }
        $r.Text | Should -Match '--status Inactive'
        $r.Text | Should -Match ([regex]::Escape("--region $Region"))
        if ($Instance) { $r.Text | Should -Match ([regex]::Escape($Instance)) } else { $r.Text | Should -Match '<instance-id>' }
    }
}
