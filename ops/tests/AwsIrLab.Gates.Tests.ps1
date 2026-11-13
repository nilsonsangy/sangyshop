<#
.SYNOPSIS
    Pester tests: the precondition gates and the readiness stamp on the PowerShell side.

.DESCRIPTION
    PowerShell has no native property-based testing library, so this file generates
    cases with a FIXED SEED (declared project limitation). Every script runs in-process
    through a fake CLI seam ($global:LabCliHandler for AWS, $global:LabAzHandler for
    Azure). No cloud call is ever made. The stamp is written in a temporary directory.

    Properties checked:
      * enable-all.ps1 (AWS) exits 4 and issues no mutating call when the application
        log group does not exist, and the message names ops/aws/ec2/deploy.ps1
      * print-response-commands.ps1 (AWS) exits 4 without the attack evidence file,
        names the attack step and prints no command
      * check-detection-ready.ps1 (AWS and Azure) writes the readiness stamp only on
        exit 0; the stamp has the schema fields (lab, region, UTC time, the four
        results) and never holds the alert e-mail address; for any other exit code an
        older stamp is left byte for byte as it was and no new stamp appears

    The attack.js gate is covered by the Node tests, not here.

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.Gates.Tests.ps1
#>

BeforeDiscovery {
    $rng = [System.Random]::new(31107)   # fixed seed: reproducible cases
    $regions = @('us-east-1', 'us-west-2', 'eu-west-1', 'sa-east-1')

    $gateCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 12; $i++) {
        [void]$gateCases.Add(@{ Index = $i; Region = $regions[$rng.Next($regions.Count)]; Email = ('user{0}@example.com' -f $rng.Next(100000)) })
    }
    $script:GateCases = $gateCases.ToArray()

    $printCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 8; $i++) {
        [void]$printCases.Add(@{ Index = $i; Region = $regions[$rng.Next($regions.Count)]; Instance = $(if ($rng.Next(2) -eq 1) { 'i-' + ('{0:x8}' -f $rng.Next()) } else { '' }) })
    }
    $script:PrintCases = $printCases.ToArray()

    $subModes = @('none', 'pending', 'confirmed')
    $trailModes = @('none', 'notlogging', 'logging')
    $alarmModes = @('none', 'noaction', 'ok')
    $awsCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 40; $i++) {
        $healthy = ($i % 3 -eq 0)
        $st = @{
            Sub   = $(if ($healthy) { 'confirmed' } else { $subModes[$rng.Next(3)] })
            Trail = $(if ($healthy) { 'logging' } else { $trailModes[$rng.Next(3)] })
            Alarm = $(if ($healthy) { 'ok' } else { $alarmModes[$rng.Next(3)] })
            Group = $(if ($healthy) { $true } else { $rng.Next(4) -ne 0 })
        }
        [void]$awsCases.Add(@{
                Index = $i; State = $st; Region = $regions[$rng.Next($regions.Count)]
                Email = ('user{0}@example.com' -f $rng.Next(100000)); OldStamp = ($rng.Next(2) -eq 1)
                Deny = $(if (-not $healthy -and $rng.Next(6) -eq 0) { 'cloudtrail get-trail-status' } else { $null })
            })
    }
    $script:AwsReadyCases = $awsCases.ToArray()

    $agModes = @('none', 'noreceiver', 'ok')
    $ruleModes = @('none', 'disabled', 'nolink', 'ok')
    $denyPool = @('monitor log-analytics workspace show', 'monitor action-group show', 'monitor scheduled-query show')
    $azCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 40; $i++) {
        $healthy = ($i % 3 -eq 0)
        $st = @{
            Workspace = $(if ($healthy) { $true } else { $rng.Next(4) -ne 0 })
            Ag        = $(if ($healthy) { 'ok' } else { $agModes[$rng.Next(3)] })
            Rule      = $(if ($healthy) { 'ok' } else { $ruleModes[$rng.Next(4)] })
        }
        [void]$azCases.Add(@{
                Index = $i; State = $st; Region = $regions[$rng.Next($regions.Count)]
                Email = ('user{0}@example.com' -f $rng.Next(100000)); OldStamp = ($rng.Next(2) -eq 1)
                Deny = $(if (-not $healthy -and $rng.Next(6) -eq 0) { $denyPool[$rng.Next($denyPool.Count)] } else { $null })
            })
    }
    $script:AzReadyCases = $azCases.ToArray()
}

BeforeAll {
    $script:AwsDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab')).Path
    $script:AzDir = (Resolve-Path (Join-Path $PSScriptRoot '..\azure\ir-lab')).Path
    $script:Saved = @{}
    foreach ($n in 'LAB_MANIFEST_PATH', 'LAB_CONFIG_PATH', 'LAB_CLOUD_CONFIG_PATH', 'LAB_ALERT_EMAIL') {
        $script:Saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-gates-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    $script:AwsConfig = Join-Path $script:Work 'aws.config.ps1'
    Set-Content -LiteralPath $script:AwsConfig -Encoding UTF8 -Value @'
@{
    UniqueSuffix = 'labtest01'
    Common = @{ AppName = 'sangyshop'; DbName = 'sangyshop'; DbUser = 'sangyshop'; ImageTag = 'hardened' }
    Aws = @{
        Region = 'us-east-1'; AccountId = '123456789012'
        Ec2 = @{ InstanceType = 't3.small'; DbInstanceClass = 'db.t4g.micro'; BucketBase = 'sangyshop-lab'; VolumeGb = 20 }
    }
}
'@
    $script:AzConfig = Join-Path $script:Work 'azure.config.ps1'
    Set-Content -LiteralPath $script:AzConfig -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "abc12345"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Azure = @{
        Location = "eastus"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "sangyshop-lab"; EvidenceGroupBase = "sangyshop-evidence" }
    }
}
'@
    $env:LAB_CONFIG_PATH = $script:AwsConfig
    $env:LAB_CLOUD_CONFIG_PATH = $script:AzConfig
    $env:LAB_ALERT_EMAIL = $null
    $script:AzSubId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:AzAgId = '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag-sangyshop-lab'

    # Fake AWS for the check-detection-ready cases and for the enable-all gate.
    $global:GateAwsHandler = {
        param($a)
        $s = $global:GateState
        $svc = [string]$a[2]; $op = [string]$a[3]; $key = "$svc $op"
        [void]$s.Calls.Add($key)
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'An error occurred (ResourceNotFoundException): not found' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }
        $json = { param($o) ConvertTo-Json -InputObject $o -Depth 6 -Compress }
        if ($op -match '^(create|put|subscribe|tag|add|start|stop|update|set|delete|attach|remove|enable)') { [void]$s.Mutating.Add($key) }
        if ($s.Deny -and $s.Deny -eq $key) {
            return [pscustomobject]@{ ExitCode = 254; Output = "An error occurred (AccessDeniedException) when calling the $op operation: User is not authorized to perform: ${svc}:$op" }
        }
        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'sns get-topic-attributes' { return $no }
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
                if ($a -contains '--query') { return (& $ok (& $json @($groups | ForEach-Object { $_.logGroupName }))) }
                return (& $ok (& $json @{ logGroups = $groups }))
            }
            'cloudwatch describe-alarms' {
                $al = @()
                if ($s.Alarm -eq 'noaction') { $al = @(@{ AlarmName = (& $opt '--alarm-names'); AlarmActions = @() }) }
                if ($s.Alarm -eq 'ok') { $al = @(@{ AlarmName = (& $opt '--alarm-names'); AlarmActions = @('arn:aws:sns:us-east-1:123456789012:t') }) }
                return (& $ok (& $json @{ MetricAlarms = $al }))
            }
            default { return (& $ok '{}') }
        }
    }

    # Fake Azure CLI for the Azure check-detection-ready cases.
    $global:GateAzHandler = {
        param($a)
        $s = $global:GateState
        $words = New-Object System.Collections.ArrayList
        foreach ($t in $a) { if ("$t".StartsWith('-')) { break }; [void]$words.Add("$t") }
        $call = $words -join ' '
        [void]$s.Calls.Add($call)
        if ($call -match '(^| )(create|update|delete|set)$') { [void]$s.Mutating.Add($call) }
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $nf = [pscustomobject]@{ ExitCode = 3; Output = 'ERROR: (ResourceNotFound) The Resource was not found.' }
        if ($s.Deny -and $s.Deny -eq $call) {
            return [pscustomobject]@{ ExitCode = 1; Output = 'ERROR: (AuthorizationFailed) The client does not have authorization to perform action.' }
        }
        switch ($call) {
            'account show' { return (& $ok $s.SubId) }
            'monitor log-analytics workspace show' {
                if ($s.Workspace) { return (& $ok '{"id":"/subscriptions/x/workspaces/w"}') } else { return $nf }
            }
            'monitor action-group show' {
                if ($s.Ag -eq 'none') { return $nf }
                $status = if ($s.Ag -eq 'ok') { 'Enabled' } else { 'Disabled' }
                return (& $ok (ConvertTo-Json -Compress -InputObject @{ id = $s.AgId; enabled = $true; receivers = @($status) }))
            }
            'monitor scheduled-query show' {
                if ($s.Rule -eq 'none') { return $nf }
                $groups = @(); if ($s.Rule -in 'ok', 'disabled') { $groups = @($s.AgId) }
                return (& $ok (ConvertTo-Json -Compress -InputObject @{ id = '/subscriptions/x/rules/r'; enabled = ($s.Rule -ne 'disabled'); groups = $groups }))
            }
            default { return (& $ok '{}') }
        }
    }

    function script:New-CaseDir {
        param([string]$Name)
        $dir = Join-Path $script:Work $Name
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $env:LAB_MANIFEST_PATH = Join-Path $dir 'manifest.json'
        return $dir
    }

    function script:Invoke-Tool {
        param([string]$Path, [hashtable]$Params)
        # Scripts print their errors with [Console]::Error, so capture that stream as well.
        $global:LASTEXITCODE = $null
        $oldErr = [Console]::Error
        $errWriter = New-Object System.IO.StringWriter
        [Console]::SetError($errWriter)
        try { $text = (& $Path @Params *>&1 | Out-String -Width 4096) } finally { [Console]::SetError($oldErr) }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = ($text + $errWriter.ToString()) }
    }

    function script:Assert-Stamp {
        # Shared stamp rules for both clouds. Expected = the exit code the case must produce.
        param($Result, [int]$Expected, [string]$Dir, [string]$StampFile, [bool]$OldStamp, [string]$Email, [string[]]$CheckNames)
        $Result.ExitCode | Should -Be $Expected
        $Result.Text | Should -Not -Match ([regex]::Escape($Email))
        $stamps = @(Get-ChildItem -LiteralPath $Dir -Filter 'readiness-*.json' -ErrorAction SilentlyContinue)
        if ($Expected -eq 0) {
            $stamps.Count | Should -Be 1
            $raw = Get-Content -LiteralPath $stamps[0].FullName -Raw
            $raw | Should -Not -Match ([regex]::Escape($Email))
            $raw | Should -Not -Match '@'
            $doc = $raw | ConvertFrom-Json
            $doc.lab | Should -Not -BeNullOrEmpty
            $doc.region | Should -Not -BeNullOrEmpty
            $raw | Should -Match '"checked_utc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
            foreach ($k in $CheckNames) { $doc.checks.$k | Should -BeTrue }
            @($doc.checks.PSObject.Properties).Count | Should -Be 4
            @(Get-ChildItem -LiteralPath $Dir -Filter '*.tmp' -ErrorAction SilentlyContinue).Count | Should -Be 0
        } elseif ($OldStamp) {
            $stamps.Count | Should -Be 1
            (Get-Content -LiteralPath $StampFile -Raw) | Should -Be '{"old":true}'
        } else {
            $stamps.Count | Should -Be 0
        }
    }
}

AfterAll {
    foreach ($n in $script:Saved.Keys) { [Environment]::SetEnvironmentVariable($n, $script:Saved[$n], 'Process') }
    $global:LabCliHandler = $null
    $global:LabAzHandler = $null
    $global:GateAwsHandler = $null
    $global:GateAzHandler = $null
    $global:GateState = $null
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'enable-all.ps1 log group gate (fixed seed, 12 cases)' {

    It 'case <Index>: exits 4 naming deploy.ps1 and issues no mutating call when the app log group is missing' -ForEach $script:GateCases {
        $null = New-CaseDir -Name "gate-$Index"
        $global:GateState = @{
            Group = $false; Sub = 'none'; Trail = 'none'; Alarm = 'none'; Email = $Email; Deny = $null
            Calls = (New-Object System.Collections.ArrayList); Mutating = (New-Object System.Collections.ArrayList)
        }
        $global:LabCliHandler = $global:GateAwsHandler
        $global:LabAzHandler = $null

        $r = Invoke-Tool -Path (Join-Path $script:AwsDir 'detection\enable-all.ps1') -Params @{ Region = $Region; Email = $Email; NonInteractive = $true }

        $r.ExitCode | Should -Be 4
        $r.Text | Should -Match 'ops/aws/ec2/deploy\.ps1'
        $global:GateState.Mutating.Count | Should -Be 0 -Because "mutating calls: $($global:GateState.Mutating -join ', ')"
        $global:GateState.Calls | Should -Contain 'logs describe-log-groups'
        $r.Text | Should -Not -Match ([regex]::Escape($Email))
    }

    It 'does not stop at the gate when the app log group exists' {
        $null = New-CaseDir -Name 'gate-present'
        $global:GateState = @{
            Group = $true; Sub = 'none'; Trail = 'none'; Alarm = 'none'; Email = 'user@example.com'; Deny = $null
            Calls = (New-Object System.Collections.ArrayList); Mutating = (New-Object System.Collections.ArrayList)
        }
        $global:LabCliHandler = $global:GateAwsHandler

        # No e-mail and -NonInteractive: the run passes the gate and then stops with a configuration error (2).
        $r = Invoke-Tool -Path (Join-Path $script:AwsDir 'detection\enable-all.ps1') -Params @{ Region = 'us-east-1'; NonInteractive = $true }

        $r.ExitCode | Should -Be 2
        $r.Text | Should -Not -Match 'is not deployed yet'
        $global:GateState.Mutating.Count | Should -Be 0
    }
}

Describe 'print-response-commands.ps1 attack evidence gate (fixed seed, 8 cases)' {

    It 'case <Index>: exits 4 naming the attack step, prints no command and makes no call' -ForEach $script:PrintCases {
        $dir = New-CaseDir -Name "print-$Index"
        $global:GateState = @{
            Calls = (New-Object System.Collections.ArrayList); Mutating = (New-Object System.Collections.ArrayList); Deny = $null
        }
        $global:LabCliHandler = $global:GateAwsHandler
        $p = @{ Region = $Region; AttackEvidencePath = (Join-Path $dir 'attack-steps.jsonl') }
        if ($Instance) { $p['InstanceId'] = $Instance }

        $r = Invoke-Tool -Path (Join-Path $script:AwsDir 'print-response-commands.ps1') -Params $p

        $r.ExitCode | Should -Be 4
        $r.Text | Should -Match 'attack simulation'
        $r.Text | Should -Not -Match '(?m)^\s+aws\s'
        $global:GateState.Calls.Count | Should -Be 0

        # With the evidence file the same call succeeds, so the file is the only gate.
        Set-Content -LiteralPath $p['AttackEvidencePath'] -Value '{"step":1}' -Encoding UTF8
        $r2 = Invoke-Tool -Path (Join-Path $script:AwsDir 'print-response-commands.ps1') -Params $p
        $r2.ExitCode | Should -Be 0
    }
}

Describe 'AWS check-detection-ready.ps1 readiness stamp (fixed seed, 40 cases)' {

    It 'case <Index>: stamp only on exit 0, schema fields, no e-mail, older stamp untouched otherwise' -ForEach $script:AwsReadyCases {
        $dir = New-CaseDir -Name "aws-ready-$Index"
        $stamp = Join-Path $dir 'readiness-sangyshop-lab-aws.json'
        if ($OldStamp) { Set-Content -LiteralPath $stamp -Value '{"old":true}' -NoNewline -Encoding UTF8 }
        $State['Email'] = $Email; $State['Deny'] = $Deny
        $State['Calls'] = New-Object System.Collections.ArrayList; $State['Mutating'] = New-Object System.Collections.ArrayList
        $global:GateState = $State
        $global:LabCliHandler = $global:GateAwsHandler
        $global:LabAzHandler = $null

        $r = Invoke-Tool -Path (Join-Path $script:AwsDir 'check-detection-ready.ps1') -Params @{ Region = $Region }

        $allOk = ($State.Sub -eq 'confirmed' -and $State.Alarm -eq 'ok' -and $State.Group -and $State.Trail -eq 'logging')
        if ($Deny) { $expected = 3 }
        elseif ($State.Sub -eq 'pending') { $expected = 4 }
        elseif ($allOk) { $expected = 0 }
        else { $expected = 1 }
        # The deny hits a read the script always makes, so a denied case ends with 3.
        Assert-Stamp -Result $r -Expected $expected -Dir $dir -StampFile $stamp -OldStamp ([bool]$OldStamp) -Email $Email `
            -CheckNames @('subscription_confirmed', 'alarm_has_action', 'log_group_exists', 'trail_logging')
        if ($expected -eq 0) { ((Get-Content -LiteralPath (Get-ChildItem -LiteralPath $dir -Filter 'readiness-*.json')[0].FullName -Raw) | ConvertFrom-Json).region | Should -Be $Region }
        $State.Mutating.Count | Should -Be 0
    }
}

Describe 'Azure check-detection-ready.ps1 readiness stamp (fixed seed, 40 cases)' {

    It 'case <Index>: stamp only on exit 0, schema fields, no e-mail, older stamp untouched otherwise' -ForEach $script:AzReadyCases {
        $dir = New-CaseDir -Name "az-ready-$Index"
        $stamp = Join-Path $dir 'readiness-sangyshop-lab-azure.json'
        if ($OldStamp) { Set-Content -LiteralPath $stamp -Value '{"old":true}' -NoNewline -Encoding UTF8 }
        $State['Email'] = $Email; $State['Deny'] = $Deny; $State['SubId'] = $script:AzSubId; $State['AgId'] = $script:AzAgId
        $State['Calls'] = New-Object System.Collections.ArrayList; $State['Mutating'] = New-Object System.Collections.ArrayList
        $global:GateState = $State
        $global:LabAzHandler = $global:GateAzHandler
        $global:LabCliHandler = $null

        $r = Invoke-Tool -Path (Join-Path $script:AzDir 'check-detection-ready.ps1') -Params @{ Subscription = $script:AzSubId; Region = $Region }

        $allOk = ($State.Workspace -and $State.Ag -eq 'ok' -and $State.Rule -eq 'ok')
        if ($Deny) { $expected = 3 } elseif ($allOk) { $expected = 0 } else { $expected = 4 }
        Assert-Stamp -Result $r -Expected $expected -Dir $dir -StampFile $stamp -OldStamp ([bool]$OldStamp) -Email $Email `
            -CheckNames @('workspace', 'action_group', 'alert_rule', 'alert_action')
        if ($expected -eq 0) {
            $doc = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $dir -Filter 'readiness-*.json')[0].FullName -Raw | ConvertFrom-Json
            $doc.region | Should -Be ($Region -replace '\s', '').ToLowerInvariant()
            $doc.schema | Should -Be 1
        }
        $State.Mutating.Count | Should -Be 0
    }
}
