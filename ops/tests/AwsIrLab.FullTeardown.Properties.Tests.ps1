<#
.SYNOPSIS
    Pester tests: generated-case properties for full-teardown.ps1 and verify-zero-cost.ps1 (AWS).

.DESCRIPTION
    PowerShell has no mature property-based testing library, so each property below is
    checked on 100 generated cases drawn from a System.Random with a FIXED SEED per property
    (declared project limitation). Every case is a random universe of lab resources:
    which types exist, which carry lab tag, which carry a different 'lab' tag value, which carry
    no tag, which are listed only in the lab manifest, which are already gone while the tag
    index still lists them (ghosts), which snapshots are evidence=preserved, and the run-id.

    The scripts run in-process through the Invoke-LabCli seam ($global:LabCliHandler) against a
    small STATEFUL fake of AWS. No AWS call is ever made, and the sangyshop teardown is
    intercepted by $global:LabDeployTeardownHandler.

      -WhatIf runs zero mutating calls, never delegates, exits 0.
      running twice converges; the second run removes nothing and exits 0.
      the removed set is exactly lab tag union lab manifest (within the run scope);
                  every other billable resource stays and is reported as unmarked.
                  Removal also follows the reverse dependency order.
      preserved evidence goes only with both confirmations.
      verify-zero-cost says 'nothing billable remaining' and exits 0 if and only if
                  nothing billable remains, tagged or not; it never mutates.

    Run: Invoke-Pester ops/tests/AwsIrLab.FullTeardown.Properties.Tests.ps1
#>

BeforeDiscovery {
    $script:Regions = @('us-east-1', 'us-west-2', 'eu-west-1', 'sa-east-1')
    $script:Billable = @('ec2-instance', 'ebs-volume', 'ebs-snapshot', 's3-bucket', 'secret', 'log-group', 'sns-topic', 'lambda-function', 'vpc')

    function New-Universe {
        param([System.Random]$Rng, [int]$Index, [switch]$ForcePreserved, [double]$CleanProb = 0)
        $prefix = @{
            'ec2-instance' = 'i-'; 'ebs-volume' = 'vol-'; 'ebs-snapshot' = 'snap-'; 's3-bucket' = 'lab-app-'
            'secret' = 'lab/secret-'; 'log-group' = '/lab/group-'; 'sns-topic' = 'lab-topic-'
            'lambda-function' = 'lab-fn-'; 'vpc' = 'vpc-'; 'subnet' = 'subnet-'; 'security-group' = 'sg-'
        }
        $items = New-Object System.Collections.ArrayList
        $n = 0
        foreach ($type in $prefix.Keys) {
            $count = @(0, 0, 1, 1, 2)[$Rng.Next(5)]
            for ($k = 0; $k -lt $count; $k++) {
                $n++
                $kind = 'none'
                $d = $Rng.Next(100)
                if ($d -lt 58) { $kind = 'lab' } elseif ($d -lt 70) { $kind = 'wrong' }
                $ev = ''
                if ($type -eq 'ebs-snapshot' -and $kind -eq 'lab' -and $Rng.Next(2) -eq 0) { $ev = 'preserved' }
                $inMan = $false
                if ($kind -ne 'lab' -and $Rng.Next(4) -eq 0) { $inMan = $true }
                if ($kind -eq 'lab' -and $Rng.Next(6) -eq 0) { $inMan = $true }
                [void]$items.Add(@{
                        Type = $type; Id = ('{0}{1:x6}{2:D2}' -f $prefix[$type], $Rng.Next(0x1000000), $n); TagKind = $kind
                        RunId = @('run-a', 'run-b')[$Rng.Next(2)]; Evidence = $ev; InManifest = $inMan
                        Deleted = ($Rng.Next(100) -lt 8); Vpc = ''
                    })
            }
        }
        if ($ForcePreserved) {
            $n++
            [void]$items.Add(@{ Type = 'ebs-snapshot'; Id = ('snap-forced{0:x4}{1:D2}' -f $Rng.Next(0x10000), $n); TagKind = 'lab'; RunId = 'run-a'; Evidence = 'preserved'; InManifest = $false; Deleted = $false; Vpc = '' })
        }
        $vpcs = @($items | Where-Object { $_.Type -eq 'vpc' } | ForEach-Object { $_.Id })
        if ($vpcs.Count -gt 0) {
            foreach ($it in $items) {
                if ($it.Type -in @('ec2-instance', 'subnet', 'security-group')) { $it.Vpc = $vpcs[$Rng.Next($vpcs.Count)] }
            }
        }
        if ($Rng.NextDouble() -lt $CleanProb) {
            foreach ($it in $items) {
                if ($it.TagKind -eq 'lab' -or $it.InManifest -or ($script:Billable -contains $it.Type)) { $it.Deleted = $true }
            }
        }
        $stale = New-Object System.Collections.ArrayList
        for ($k = 0; $k -lt $Rng.Next(3); $k++) { [void]$stale.Add(@{ Type = 'secret'; Id = ('lab/stale-{0:x6}' -f $Rng.Next(0x1000000)); RunId = 'run-a' }) }
        return @{
            Index = $Index; Region = $script:Regions[$Rng.Next($script:Regions.Count)]
            Items = $items.ToArray(); Stale = $stale.ToArray(); RunPick = $Rng.Next(3); Pick = $Rng.Next(1000)
        }
    }

    function New-Cases {
        param([int]$Seed, [switch]$ForcePreserved, [double]$CleanProb = 0)
        $rng = [System.Random]::new($Seed)   # fixed seed: reproducible cases
        $list = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 100; $i++) { [void]$list.Add((New-Universe -Rng $rng -Index $i -ForcePreserved:$ForcePreserved -CleanProb $CleanProb)) }
        return $list.ToArray()
    }

    $script:P2Cases = New-Cases -Seed 24402
    $script:P3Cases = New-Cases -Seed 24403
    $script:P4Cases = New-Cases -Seed 24404
    $script:OrderCases = New-Cases -Seed 24407
    $script:P5Cases = New-Cases -Seed 24405 -ForcePreserved
    $script:P6Cases = New-Cases -Seed 24406 -CleanProb 0.35
}

BeforeAll {
    $script:AwsDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab')).Path
    $script:TeardownScript = Join-Path $script:AwsDir 'full-teardown.ps1'
    $script:VerifyScript = Join-Path $script:AwsDir 'verify-zero-cost.ps1'
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-ftp-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    # Minimal config the scripts read to derive every lab name (no cloud call is involved).
    $script:ConfigPath = Join-Path $script:WorkDir 'cloud.config.ps1'
    $cfgText = @'
@{
    UniqueSuffix = 'labtest'
    Common       = @{ AppName = 'sangyshop' }
    Aws          = @{
        Region    = 'us-east-1'
        AccountId = '123456789012'
        Ec2       = @{ InstanceType = 't3.micro'; DbInstanceClass = 'db.t3.micro'; BucketBase = 'app'; VolumeGb = 20 }
    }
}
'@
    [System.IO.File]::WriteAllText($script:ConfigPath, $cfgText, (New-Object System.Text.UTF8Encoding($false)))
    $script:PreviousConfigPath = $env:LAB_CONFIG_PATH
    $env:LAB_CONFIG_PATH = $script:ConfigPath
    $script:Billable = @('ec2-instance', 'ebs-volume', 'ebs-snapshot', 's3-bucket', 'secret', 'log-group', 'sns-topic', 'lambda-function', 'vpc')
    $script:Phase = @{
        'lambda-function' = 21; 'log-group' = 33; 'sns-topic' = 39; 'ec2-instance' = 40; 'ebs-volume' = 43; 'secret' = 55
        's3-bucket' = 60; 'security-group' = 80; 'subnet' = 81; 'vpc' = 85; 'ebs-snapshot' = 90
    }
    $global:LabFakeMutatingPattern = '^(terminate|delete|create|put|release|revoke|detach|attach|remove|update|add|stop|start|schedule|unsubscribe|subscribe|tag|untag|wait)'

    function global:New-FakeArn {
        param($r, [string]$Region)
        $acct = '123456789012'
        switch ($r.Type) {
            'ec2-instance' { return "arn:aws:ec2:${Region}:${acct}:instance/$($r.Id)" }
            'ebs-volume' { return "arn:aws:ec2:${Region}:${acct}:volume/$($r.Id)" }
            'ebs-snapshot' { return "arn:aws:ec2:${Region}:${acct}:snapshot/$($r.Id)" }
            'vpc' { return "arn:aws:ec2:${Region}:${acct}:vpc/$($r.Id)" }
            'subnet' { return "arn:aws:ec2:${Region}:${acct}:subnet/$($r.Id)" }
            'security-group' { return "arn:aws:ec2:${Region}:${acct}:security-group/$($r.Id)" }
            's3-bucket' { return "arn:aws:s3:::$($r.Id)" }
            'secret' { return "arn:aws:secretsmanager:${Region}:${acct}:secret:$($r.Id)-AbC123" }
            'log-group' { return "arn:aws:logs:${Region}:${acct}:log-group:$($r.Id):*" }
            'sns-topic' { return "arn:aws:sns:${Region}:${acct}:$($r.Id)" }
            'lambda-function' { return "arn:aws:lambda:${Region}:${acct}:function:$($r.Id)" }
        }
    }

    # Stateful fake of the AWS CLI (receives ['--region', R, service, command, ...]).
    $global:LabFakeHandler = {
        param($a)
        $st = $global:LabFake
        $svc = $a[2]; $cmd = $a[3]; $call = "$svc $cmd"
        $arg = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { [string]$a[$i + 1] } else { $null } }
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $nf = [pscustomobject]@{ ExitCode = 254; Output = 'An error occurred (NotFound) when calling the operation: does not exist' }
        $json = { param($o) [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-Json -InputObject @($o) -Compress -Depth 8) } }
        $live = { param($t) @($st.Res.Values | Where-Object { $_.Type -eq $t -and -not $_.Deleted }) }
        $find = { param($t, $id) $k = "$t|$id"; if ($st.Res.Contains($k)) { $st.Res[$k] } else { $null } }
        $tagsOf = {
            param($r)
            if ($r.TagKind -eq 'lab') {
                $l = @(@{ Key = 'lab'; Value = 'sangyshop-lab-aws' }, @{ Key = 'run-id'; Value = $r.RunId })
                if ($r.Evidence) { $l += @{ Key = 'evidence'; Value = $r.Evidence } }
                return , $l
            }
            if ($r.TagKind -eq 'wrong') { return , @(@{ Key = 'lab'; Value = 'other-lab' }) }
            return $null
        }
        $exist = { param($t, $id) $r = & $find $t $id; if ($r -and -not $r.Deleted) { & $ok $id } else { $nf } }
        $scan = {
            param($t, [bool]$withTags)
            $rows = @(foreach ($r in (& $live $t)) {
                    $row = [ordered]@{ id = $r.Id }
                    if ($withTags) { $row['tags'] = (& $tagsOf $r) }
                    [pscustomobject]$row
                })
            & $json $rows
        }

        [void]$st.Calls.Add($call)
        if ($st.FailOn -and $call -eq $st.FailOn) { return [pscustomobject]@{ ExitCode = 254; Output = 'AccessDenied: injected failure' } }
        if ($cmd -match $global:LabFakeMutatingPattern) { [void]$st.Mutating.Add($call) }

        if ($st.MutMap.ContainsKey($call)) {
            $m = $st.MutMap[$call]
            $id = & $arg $m[1]
            if ($m[0] -eq 'sns-topic') { $id = ($id -split ':')[-1] }
            $k = "$($m[0])|$id"
            [void]$st.Attempts.Add($k)
            $r = & $find $m[0] $id
            if ($null -eq $r -or $r.Deleted) { return $nf }
            $r.Deleted = $true
            [void]$st.Removals.Add($k)
            return (& $ok '')
        }

        switch -Exact ($call) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'resourcegroupstaggingapi get-resources' {
                if ($a[1] -ne $st.Region) { return (& $json @()) }
                $rows = @(foreach ($r in $st.Res.Values) {
                        if ($r.TagKind -eq 'lab') { [pscustomobject]@{ a = (New-FakeArn $r $st.Region); t = (& $tagsOf $r) } }
                    })
                return (& $json $rows)
            }
            'ec2 describe-instances' {
                if (& $arg '--instance-ids') { $r = & $find 'ec2-instance' (& $arg '--instance-ids'); if ($r -and -not $r.Deleted) { return (& $ok $r.Id) } else { return (& $ok '') } }
                return (& $scan 'ec2-instance' $true)
            }
            'ec2 describe-volumes' {
                if (& $arg '--volume-ids') { return (& $exist 'ebs-volume' (& $arg '--volume-ids')) }
                return (& $scan 'ebs-volume' $true)
            }
            'ec2 describe-snapshots' {
                if (& $arg '--snapshot-ids') {
                    if ((& $arg '--query') -match 'VolumeSize') { return (& $ok '8') }
                    return (& $exist 'ebs-snapshot' (& $arg '--snapshot-ids'))
                }
                return (& $scan 'ebs-snapshot' $true)
            }
            'ec2 describe-vpcs' {
                if (& $arg '--vpc-ids') { return (& $exist 'vpc' (& $arg '--vpc-ids')) }
                return (& $scan 'vpc' $true)
            }
            'ec2 describe-subnets' { return (& $exist 'subnet' (& $arg '--subnet-ids')) }
            'ec2 describe-security-groups' {
                if ((& $arg '--query') -match 'IpPermissions') { return (& $json @()) }
                return (& $exist 'security-group' (& $arg '--group-ids'))
            }
            'ec2 wait' { return (& $ok '') }
            'logs describe-log-groups' {
                if (& $arg '--log-group-name-prefix') { return (& $exist 'log-group' (& $arg '--log-group-name-prefix')) }
                return (& $scan 'log-group' $false)
            }
            'secretsmanager describe-secret' { return (& $exist 'secret' (& $arg '--secret-id')) }
            'secretsmanager list-secrets' { return (& $scan 'secret' $true) }
            'sns get-topic-attributes' { return (& $exist 'sns-topic' ((& $arg '--topic-arn') -split ':')[-1]) }
            'sns list-topics' { return (& $json @(foreach ($r in (& $live 'sns-topic')) { New-FakeArn $r $st.Region })) }
            'lambda get-function' { return (& $exist 'lambda-function' (& $arg '--function-name')) }
            'lambda list-functions' { return (& $scan 'lambda-function' $false) }
            's3api head-bucket' { return (& $exist 's3-bucket' (& $arg '--bucket')) }
            's3api list-buckets' { return (& $json @(foreach ($r in (& $live 's3-bucket')) { $r.Id })) }
            's3api get-bucket-location' { if ($st.Region -eq 'us-east-1') { return (& $ok 'None') } else { return (& $ok $st.Region) } }
            's3api get-object-lock-configuration' { return [pscustomobject]@{ ExitCode = 254; Output = 'ObjectLockConfigurationNotFoundError' } }
            's3api list-object-versions' { return (& $ok '{"v":null,"m":null}') }
            default { return (& $json @()) }
        }
    }

    function global:New-FakeState {
        param([string]$Region, $Items, [string]$FailOn = '')
        $res = [ordered]@{}
        foreach ($it in $Items) { $c = @{} + $it; $res["$($it.Type)|$($it.Id)"] = $c }
        return @{
            Region = $Region; Res = $res; FailOn = $FailOn
            Calls = (New-Object System.Collections.ArrayList); Mutating = (New-Object System.Collections.ArrayList)
            Attempts = (New-Object System.Collections.ArrayList); Removals = (New-Object System.Collections.ArrayList)
            Sangy = (New-Object System.Collections.ArrayList); Prompts = (New-Object System.Collections.ArrayList)
            Answers = @(); PromptIdx = 0
            MutMap = @{
                'ec2 terminate-instances' = @('ec2-instance', '--instance-ids'); 'ec2 delete-volume' = @('ebs-volume', '--volume-id')
                'ec2 delete-snapshot' = @('ebs-snapshot', '--snapshot-id'); 'ec2 delete-vpc' = @('vpc', '--vpc-id')
                'ec2 delete-subnet' = @('subnet', '--subnet-id'); 'ec2 delete-security-group' = @('security-group', '--group-id')
                's3api delete-bucket' = @('s3-bucket', '--bucket'); 'secretsmanager delete-secret' = @('secret', '--secret-id')
                'logs delete-log-group' = @('log-group', '--log-group-name'); 'sns delete-topic' = @('sns-topic', '--topic-arn')
                'lambda delete-function' = @('lambda-function', '--function-name')
            }
        }
    }

    function New-FakeManifest {
        param([string]$Region, $Items, $Stale, [int]$Index)
        $entries = New-Object System.Collections.ArrayList
        foreach ($it in $Items) { if ($it.InManifest) { [void]$entries.Add([ordered]@{ type = $it.Type; id = $it.Id; region = $Region; 'run-id' = $it.RunId }) } }
        foreach ($s in $Stale) { [void]$entries.Add([ordered]@{ type = $s.Type; id = $s.Id; region = $Region; 'run-id' = $s.RunId }) }
        $path = Join-Path $script:WorkDir ("manifest-$Index-$([guid]::NewGuid().ToString('N')).json")
        $json = ([ordered]@{ resources = $entries.ToArray() }) | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
        return $path
    }

    function Start-FakeAws {
        param([string]$Region, $Items, [string]$FailOn = '', $Answers = @())
        $global:LabFake = New-FakeState -Region $Region -Items $Items -FailOn $FailOn
        $global:LabFake.Answers = @($Answers)
        $global:LabCliHandler = $global:LabFakeHandler
        $global:LabDeployTeardownHandler = { param($p) [void]$global:LabFake.Sangy.Add($p); return 0 }
        $global:LabConfirmHandler = {
            param($p)
            $s = $global:LabFake
            [void]$s.Prompts.Add($p)
            $ans = ''
            if ($s.PromptIdx -lt $s.Answers.Count) { $ans = $s.Answers[$s.PromptIdx] }
            $s.PromptIdx++
            return $ans
        }
    }

    function Invoke-LabScript {
        param([string]$Script, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        $out = & $Script @Params *>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }

    function Reset-FakeCounters {
        $s = $global:LabFake
        foreach ($n in @('Calls', 'Mutating', 'Attempts', 'Removals', 'Sangy', 'Prompts')) { $s[$n].Clear() }
        $s.PromptIdx = 0
    }

    function Get-DeletedKeys { return @($global:LabFake.Res.Keys | Where-Object { $global:LabFake.Res[$_].Deleted } | Sort-Object) }

    function Get-Oracle {
        param($Items, [string]$RunFilter, [bool]$ConfirmPreserved)
        $removed = New-Object System.Collections.ArrayList
        $kept = New-Object System.Collections.ArrayList
        $unmarked = New-Object System.Collections.ArrayList
        foreach ($i in $Items) {
            if ($i.Deleted) { continue }
            $key = "$($i.Type)|$($i.Id)"
            $inScope = ($i.TagKind -eq 'lab') -or $i.InManifest
            if (-not $inScope) { if ($script:Billable -contains $i.Type) { [void]$unmarked.Add($key) }; continue }
            if ($RunFilter -and $i.RunId -ne $RunFilter) { continue }
            if ($i.Type -eq 'ebs-snapshot' -and $i.TagKind -eq 'lab' -and $i.Evidence -eq 'preserved' -and -not $ConfirmPreserved) { [void]$kept.Add($key); continue }
            [void]$removed.Add($key)
        }
        return @{ Removed = @($removed | Sort-Object); Kept = @($kept | Sort-Object); Unmarked = @($unmarked | Sort-Object) }
    }

    function Get-RunFilter { param([int]$Pick) return @('', 'run-a', 'run-b')[$Pick] }

    function Get-UnmarkedFromOutput {
        param([string]$Text)
        $found = New-Object System.Collections.ArrayList
        foreach ($m in [regex]::Matches($Text, '(?m)^\s+- (\S+) (\S+)\s+region=\S+\s+class=')) { [void]$found.Add("$($m.Groups[1].Value)|$($m.Groups[2].Value)") }
        return @($found | Sort-Object -Unique)
    }
}

AfterAll {
    $env:LAB_CONFIG_PATH = $script:PreviousConfigPath
    $global:LabCliHandler = $null
    $global:LabFake = $null
    $global:LabFakeHandler = $null
    $global:LabDeployTeardownHandler = $null
    $global:LabConfirmHandler = $null
    $global:LabFakeMutatingPattern = $null
    Remove-Item -LiteralPath 'Function:\global:New-FakeArn' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Function:\global:New-FakeState' -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'simulation runs no external command (full-teardown.ps1 -WhatIf)' {
    It 'case <Index>: -WhatIf makes zero mutating calls, never delegates, changes nothing and exits 0' -ForEach $script:P2Cases {
        $runFilter = Get-RunFilter $RunPick
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        Start-FakeAws -Region $Region -Items $Items
        $p = @{ Region = $Region; ManifestPath = $manifest; WhatIf = $true }
        if ($runFilter) { $p['RunId'] = $runFilter } elseif ($Pick % 2 -eq 0) { $p['AllRuns'] = $true }
        $confirm = ($Pick % 5 -eq 0)
        if ($confirm) { $p['ConfirmPreservedEvidenceRemoval'] = $true }
        if ($Pick % 3 -eq 0) { $p['NonInteractive'] = $true }
        $before = Get-DeletedKeys

        $r = Invoke-LabScript -Script $script:TeardownScript -Params $p
        $expected = Get-Oracle -Items $Items -RunFilter $runFilter -ConfirmPreserved $confirm

        $r.Code | Should -Be 0
        $global:LabFake.Mutating.Count | Should -Be 0
        $global:LabFake.Attempts.Count | Should -Be 0
        $global:LabFake.Sangy.Count | Should -Be 0
        $global:LabFake.Prompts.Count | Should -Be 0
        (Get-DeletedKeys) -join ',' | Should -Be ($before -join ',')
        if ($expected.Removed.Count -gt 0) {
            $r.Output | Should -Match ("What if: {0} resource\(s\) would be removed" -f $expected.Removed.Count)
            $r.Output | Should -Match 'No changes were made to the account'
        } else {
            $r.Output | Should -Match 'No lab resources'
        }
    }
}

Describe 'teardown is idempotent and converges' {
    It 'case <Index>: the second run removes nothing, changes nothing and exits 0' -ForEach $script:P3Cases {
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        Start-FakeAws -Region $Region -Items $Items
        $confirm = ($Pick % 2 -eq 0)
        $p = @{ Region = $Region; ManifestPath = $manifest; NonInteractive = $true }
        if ($confirm) { $p['ConfirmPreservedEvidenceRemoval'] = $true }
        $expected = Get-Oracle -Items $Items -RunFilter '' -ConfirmPreserved $confirm

        $first = Invoke-LabScript -Script $script:TeardownScript -Params $p
        $first.Code | Should -Be 0
        @($global:LabFake.Removals | Sort-Object) -join ',' | Should -Be ($expected.Removed -join ',')
        $afterFirst = Get-DeletedKeys

        Reset-FakeCounters
        $second = Invoke-LabScript -Script $script:TeardownScript -Params $p
        $second.Code | Should -Be 0
        $global:LabFake.Mutating.Count | Should -Be 0
        $global:LabFake.Removals.Count | Should -Be 0
        $global:LabFake.Sangy.Count | Should -Be 0
        (Get-DeletedKeys) -join ',' | Should -Be ($afterFirst -join ',')
        $second.Output | Should -Match 'No lab resources'
    }
}

Describe 'removal is restricted to lab resources' {
    It 'case <Index>: the removed set is exactly lab tag union manifest; everything else stays and is reported as unmarked' -ForEach $script:P4Cases {
        $runFilter = Get-RunFilter $RunPick
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        Start-FakeAws -Region $Region -Items $Items
        $p = @{ Region = $Region; ManifestPath = $manifest; NonInteractive = $true }
        if ($runFilter) { $p['RunId'] = $runFilter }
        $expected = Get-Oracle -Items $Items -RunFilter $runFilter -ConfirmPreserved $false

        $r = Invoke-LabScript -Script $script:TeardownScript -Params $p

        $r.Code | Should -Be 0
        @($global:LabFake.Removals | Sort-Object) -join ',' | Should -Be ($expected.Removed -join ',')
        # No delete call was even attempted against anything outside the expected set.
        @($global:LabFake.Attempts | Sort-Object -Unique) -join ',' | Should -Be ($expected.Removed -join ',')
        # Every present resource that is not expected to go is still there.
        foreach ($it in $Items) {
            $k = "$($it.Type)|$($it.Id)"
            if (-not $it.Deleted -and ($expected.Removed -notcontains $k)) { $global:LabFake.Res[$k].Deleted | Should -BeFalse -Because "$k must stay" }
        }
        (Get-UnmarkedFromOutput $r.Output) -join ',' | Should -Be ($expected.Unmarked -join ',')
        if ($expected.Unmarked.Count -gt 0) { $r.Output | Should -Match 'Unmarked resources' }
    }
}

Describe 'removal follows the reverse dependency order' {
    It 'case <Index>: phases never decrease and children go before their VPC' -ForEach $script:OrderCases {
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        Start-FakeAws -Region $Region -Items $Items
        $p = @{ Region = $Region; ManifestPath = $manifest; NonInteractive = $true }

        $r = Invoke-LabScript -Script $script:TeardownScript -Params $p
        $r.Code | Should -Be 0
        $seq = @($global:LabFake.Removals)
        $phases = @($seq | ForEach-Object { $script:Phase[($_ -split '\|')[0]] })
        for ($i = 1; $i -lt $phases.Count; $i++) {
            $phases[$i] | Should -BeGreaterOrEqual $phases[$i - 1] -Because "removal order: $($seq -join ' -> ')"
        }
        foreach ($it in $Items) {
            if ($it.Vpc) {
                $child = $seq.IndexOf("$($it.Type)|$($it.Id)")
                $parent = $seq.IndexOf("vpc|$($it.Vpc)")
                if ($child -ge 0 -and $parent -ge 0) { $child | Should -BeLessThan $parent -Because "$($it.Type) $($it.Id) must go before $($it.Vpc)" }
            }
        }
    }
}

Describe 'preserved evidence gate' {
    It 'case <Index>: preserved evidence is removed only when both confirmations are given' -ForEach $script:P5Cases {
        $modes = @('none', 'noninteractive-flag', 'interactive-both', 'interactive-wrong-extra', 'interactive-cancel')
        $mode = $modes[$Index % $modes.Count]
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        $answers = @()
        $p = @{ Region = $Region; ManifestPath = $manifest }
        switch ($mode) {
            'none' { $p['NonInteractive'] = $true }
            'noninteractive-flag' { $p['NonInteractive'] = $true; $p['ConfirmPreservedEvidenceRemoval'] = $true }
            'interactive-both' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('yes', 'remove preserved evidence') }
            'interactive-wrong-extra' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('yes', 'maybe') }
            'interactive-cancel' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('no') }
        }
        Start-FakeAws -Region $Region -Items $Items -Answers $answers
        $granted = $mode -in @('noninteractive-flag', 'interactive-both')
        $preserved = @($Items | Where-Object { -not $_.Deleted -and $_.TagKind -eq 'lab' -and $_.Evidence -eq 'preserved' } | ForEach-Object { "$($_.Type)|$($_.Id)" })
        $preserved.Count | Should -BeGreaterThan 0

        $r = Invoke-LabScript -Script $script:TeardownScript -Params $p

        if ($mode -in @('interactive-wrong-extra', 'interactive-cancel')) {
            $r.Code | Should -Be 5
            $global:LabFake.Mutating.Count | Should -Be 0
            $global:LabFake.Removals.Count | Should -Be 0
            $global:LabFake.Prompts.Count | Should -Be $(if ($mode -eq 'interactive-cancel') { 1 } else { 2 })
        } else {
            $r.Code | Should -Be 0
            $expected = Get-Oracle -Items $Items -RunFilter '' -ConfirmPreserved $granted
            @($global:LabFake.Removals | Sort-Object) -join ',' | Should -Be ($expected.Removed -join ',')
            foreach ($k in $preserved) {
                $global:LabFake.Res[$k].Deleted | Should -Be $granted -Because "$k with mode $mode"
            }
            if (-not $granted) {
                $r.Output | Should -Match 'US\$'
                $r.Output | Should -Match 'R\$'
                $r.Output | Should -Match 'evidence=preserved'
            }
            if ($mode -eq 'interactive-both') { $global:LabFake.Prompts.Count | Should -Be 2 }
        }
    }
}

Describe 'zero-cost report (verify-zero-cost.ps1)' {
    It 'case <Index>: says nothing billable remaining and exits 0 iff nothing billable remains, tagged or not' -ForEach $script:P6Cases {
        $manifest = New-FakeManifest -Region $Region -Items $Items -Stale $Stale -Index $Index
        $allow = ($Pick % 3 -eq 0)
        $inject = ($Pick % 10 -eq 0)
        Start-FakeAws -Region $Region -Items $Items -FailOn $(if ($inject) { 'lambda list-functions' } else { '' })
        $p = @{ Region = $Region; ManifestPath = $manifest }
        if ($allow) { $p['AllowPreserved'] = $true }
        $before = Get-DeletedKeys

        $pending = New-Object System.Collections.ArrayList
        $preservedList = New-Object System.Collections.ArrayList
        foreach ($i in $Items) {
            if ($i.Deleted) { continue }
            $inScope = ($i.TagKind -eq 'lab') -or $i.InManifest
            if ($inScope -and $i.Type -eq 'ebs-snapshot' -and $i.Evidence -eq 'preserved') { [void]$preservedList.Add($i); continue }
            if ($inScope) { [void]$pending.Add(@{ Item = $i; Marking = 'tagged' }) }
            elseif ($script:Billable -contains $i.Type) { [void]$pending.Add(@{ Item = $i; Marking = 'unmarked' }) }
        }
        $failing = $pending.Count + $(if ($allow) { 0 } else { $preservedList.Count })
        $clean = ($failing -eq 0) -and (-not $inject)

        $r = Invoke-LabScript -Script $script:VerifyScript -Params $p

        $global:LabFake.Mutating.Count | Should -Be 0
        (Get-DeletedKeys) -join ',' | Should -Be ($before -join ',')
        if ($clean) {
            $r.Code | Should -Be 0
            $r.Output | Should -Match 'nothing billable remaining'
        } else {
            $r.Code | Should -Not -Be 0
            $r.Output | Should -Not -Match 'nothing billable remaining'
            foreach ($e in $pending) {
                # The injected failure hides the Lambda listing, so unmarked functions cannot be listed (the run is inconclusive instead).
                if ($inject -and $e.Marking -eq 'unmarked' -and $e.Item.Type -eq 'lambda-function') { continue }
                $r.Output | Should -Match ('\[{0}\] {1} {2}\s' -f $e.Marking, [regex]::Escape($e.Item.Type), [regex]::Escape($e.Item.Id))
            }
            if (-not $allow) {
                foreach ($i in $preservedList) { $r.Output | Should -Match ('- {0} {1}\s+region=' -f [regex]::Escape($i.Type), [regex]::Escape($i.Id)) }
            }
            if ($inject) { $r.Output | Should -Match 'INCONCLUSIVE' }
        }
    }
}
