<#
.SYNOPSIS
    Pester 5.x property tests for the safety of ops/aws/iam/ensure-lab-group.ps1.

.DESCRIPTION
    An in-memory IAM simulator answers every call through $global:LabCliHandler, so no AWS
    CLI is ever invoked and no real account is touched. The simulator holds the lab group
    (sometimes already there, sometimes not), a foreign group with its own policies and
    members, foreign managed policies and foreign users. Each property runs over seeded
    random accounts (a failure is reproducible from the seed).

    Properties checked:

      * Additive only: after a real run, everything that was attached to the group is still
        attached, every member is still a member, no policy was deleted, and the foreign
        group, the foreign policies and the foreign users are exactly as they were.
      * No destructive verb: the script never issues a detach, remove, delete-group,
        delete-policy or delete-user call. The only delete it may issue is the oldest
        non-default version of one of its own sangyshop-* policies.
      * Scope: every call that names a group names the guarded lab group, and the only user
        it names is one passed with -AddUser.
      * -WhatIf and -Describe make zero mutating calls and leave the account unchanged.
      * Confirmation: the confirmation prompt (ShouldProcess, high impact) sits in the
        script before the first mutating call, and in every run all reads happen before the
        first mutating call.

    Run with:
        Import-Module Pester -MinimumVersion 5
        Invoke-Pester -Path ops/tests/LabGroup.Safety.Tests.ps1
#>

BeforeAll {
    $script:IamDir     = Join-Path $PSScriptRoot '..' 'aws' 'iam'
    $script:EnsureFile = Join-Path $script:IamDir 'ensure-lab-group.ps1'
    $script:PolicyDir  = Join-Path $script:IamDir 'policies'
    . (Join-Path $script:IamDir 'LabGroup-Common.ps1')

    $script:AccountId  = '123456789012'
    $script:Region     = 'us-east-1'
    $script:LabGroup   = 'sangyshop-lab-group'
    $script:ForeignGrp = 'other-team-admins'
    $script:Templates  = @(Get-ChildItem -Path $script:PolicyDir -Filter '*.json' | Sort-Object Name)

    $script:MutatingVerbs = '^(create|attach|add|delete|put|detach|remove|update|set|tag|untag|upload|enable|disable)-'

    $global:SimAccountId     = $script:AccountId
    $global:SimMutatingVerbs = $script:MutatingVerbs

    function Get-SimArg {
        param([string[]]$CliArgs, [string]$Name)
        for ($i = 0; $i -lt $CliArgs.Count - 1; $i++) { if ($CliArgs[$i] -eq $Name) { return $CliArgs[$i + 1] } }
        return $null
    }

    function New-SimResult {
        param([int]$ExitCode = 0, $Output = '')
        if ($Output -isnot [string]) { $Output = ConvertTo-Json -InputObject $Output -Depth 12 -Compress }
        return [pscustomobject]@{ ExitCode = $ExitCode; Output = $Output }
    }

    function New-SimState {
        param([int]$Seed)
        $rng = [System.Random]::new($Seed)
        $s = @{
            Groups   = @{}   # name -> @{ Attached = list of arn; Members = list of user }
            Policies = @{}   # arn -> @{ Versions = list of @{Id;Doc;Created}; Default = id }
            Calls    = New-Object System.Collections.Generic.List[object]
            Rng      = $rng
        }
        $foreignArns = @()
        $nForeign = $rng.Next(0, 6)
        for ($i = 0; $i -lt $nForeign; $i++) {
            $arn = "arn:aws:iam::$($script:AccountId):policy/foreign-$i"
            $foreignArns += $arn
            $s.Policies[$arn] = @{ Default = 'v1'; Versions = @(, @{ Id = 'v1'; Doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'; Created = '2024-01-01T00:00:00Z' }) }
        }
        $s.Groups[$script:ForeignGrp] = @{
            Attached = @($foreignArns + 'arn:aws:iam::aws:policy/AdministratorAccess')
            Members  = @('alice', 'bob')
        }
        if ($rng.Next(0, 2) -eq 1) {
            $members = @('carol', 'dave') | Where-Object { $rng.Next(0, 2) -eq 1 }
            $s.Groups[$script:LabGroup] = @{ Attached = @($foreignArns); Members = @($members) }
        }
        foreach ($t in $script:Templates) {
            $name = "sangyshop-$([System.IO.Path]::GetFileNameWithoutExtension($t.Name))"
            $arn = "arn:aws:iam::$($script:AccountId):policy/$name"
            $mode = $rng.Next(0, 3)   # 0 missing, 1 identical, 2 different
            if ($mode -eq 0) { continue }
            $doc = Expand-LabPolicyTemplate -Path $t.FullName -AccountId $script:AccountId -Region $script:Region
            if ($mode -eq 2) { $doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}' }
            $count = if ($mode -eq 2) { $rng.Next(1, 6) } else { 1 }
            $versions = @()
            for ($v = 1; $v -le $count; $v++) {
                $versions += , @{ Id = "v$v"; Doc = $doc; Created = ('2024-02-{0:d2}T00:00:00Z' -f $v) }
            }
            $s.Policies[$arn] = @{ Default = "v$count"; Versions = $versions }
            if ($s.Groups.ContainsKey($script:LabGroup) -and $rng.Next(0, 2) -eq 1) {
                $s.Groups[$script:LabGroup].Attached = @($s.Groups[$script:LabGroup].Attached + $arn)
            }
        }
        return $s
    }

    function Get-SimSnapshot {
        param($State)
        $copy = @{ Groups = @{}; Policies = @{} }
        foreach ($k in $State.Groups.Keys) {
            $copy.Groups[$k] = @{ Attached = @($State.Groups[$k].Attached); Members = @($State.Groups[$k].Members) }
        }
        foreach ($k in $State.Policies.Keys) {
            $p = $State.Policies[$k]
            $copy.Policies[$k] = @{ Default = $p.Default; Versions = @($p.Versions | ForEach-Object { @{ Id = $_.Id; Doc = $_.Doc; Created = $_.Created } }) }
        }
        return $copy
    }

    function Invoke-SimCall {
        param([string[]]$Full)
        $s = $global:LabSim
        $a = @($Full)
        if ($a.Count -ge 2 -and $a[0] -eq '--region') { $a = @($a | Select-Object -Skip 2) }
        $svc = $a[0]; $op = $a[1]
        $mutating = ($op -match $global:SimMutatingVerbs)
        $s.Calls.Add([pscustomobject]@{ Svc = $svc; Op = $op; Args = $a; Mutating = $mutating })

        if ($svc -eq 'sts') { return (New-SimResult 0 $global:SimAccountId) }
        $group = Get-SimArg $a '--group-name'
        $arn   = Get-SimArg $a '--policy-arn'
        switch ($op) {
            'get-group' {
                if (-not $s.Groups.ContainsKey($group)) { return (New-SimResult 254 'An error occurred (NoSuchEntity) when calling the GetGroup operation') }
                return (New-SimResult 0 @{ Group = @{ GroupName = $group }; Users = @($s.Groups[$group].Members | ForEach-Object { @{ UserName = $_ } }) })
            }
            'list-attached-group-policies' {
                if (-not $s.Groups.ContainsKey($group)) { return (New-SimResult 254 'NoSuchEntity') }
                return (New-SimResult 0 @{ AttachedPolicies = @($s.Groups[$group].Attached | ForEach-Object { @{ PolicyArn = $_; PolicyName = ($_ -split '/')[-1] } }) })
            }
            'get-policy' {
                if (-not $s.Policies.ContainsKey($arn)) { return (New-SimResult 254 'NoSuchEntity') }
                return (New-SimResult 0 @{ Policy = @{ DefaultVersionId = $s.Policies[$arn].Default } })
            }
            'get-policy-version' {
                $vid = Get-SimArg $a '--version-id'
                $v = $s.Policies[$arn].Versions | Where-Object { $_.Id -eq $vid }
                return (New-SimResult 0 @{ PolicyVersion = @{ VersionId = $vid; Document = ($v.Doc | ConvertFrom-Json) } })
            }
            'list-policy-versions' {
                $p = $s.Policies[$arn]
                return (New-SimResult 0 @{ Versions = @($p.Versions | ForEach-Object { @{ VersionId = $_.Id; IsDefaultVersion = ($_.Id -eq $p.Default); CreateDate = $_.Created } }) })
            }
            'create-group' { $s.Groups[$group] = @{ Attached = @(); Members = @() }; return (New-SimResult 0) }
            'create-policy' {
                $name = Get-SimArg $a '--policy-name'
                $newArn = "arn:aws:iam::$($global:SimAccountId):policy/$name"
                $s.Policies[$newArn] = @{ Default = 'v1'; Versions = @(, @{ Id = 'v1'; Doc = (Get-SimArg $a '--policy-document'); Created = '2025-01-01T00:00:00Z' }) }
                return (New-SimResult 0)
            }
            'create-policy-version' {
                $p = $s.Policies[$arn]
                if ($p.Versions.Count -ge 5) { return (New-SimResult 254 'LimitExceeded: versions') }
                $n = 1 + ($p.Versions | ForEach-Object { [int]($_.Id -replace '\D', '') } | Measure-Object -Maximum).Maximum
                $p.Versions = @($p.Versions + , @{ Id = "v$n"; Doc = (Get-SimArg $a '--policy-document'); Created = ('2025-01-{0:d2}T00:00:00Z' -f [int]$n) })
                $p.Default = "v$n"
                return (New-SimResult 0)
            }
            'delete-policy-version' {
                $vid = Get-SimArg $a '--version-id'
                $p = $s.Policies[$arn]
                if ($p.Default -eq $vid) { return (New-SimResult 254 'DeleteConflict: default version') }
                $p.Versions = @($p.Versions | Where-Object { $_.Id -ne $vid })
                return (New-SimResult 0)
            }
            'attach-group-policy' {
                $s.Groups[$group].Attached = @($s.Groups[$group].Attached + $arn)
                if ($s.Groups[$group].Attached.Count -gt 10) { return (New-SimResult 254 'LimitExceeded') }
                return (New-SimResult 0)
            }
            'add-user-to-group' {
                $s.Groups[$group].Members = @($s.Groups[$group].Members + (Get-SimArg $a '--user-name'))
                return (New-SimResult 0)
            }
            default { return (New-SimResult 255 "Unsupported simulator operation $op") }
        }
    }

    # Runs the script against a fresh seeded account. Returns the outcome and both snapshots.
    function Invoke-Ensure {
        param([int]$Seed, [hashtable]$Params = @{})
        $global:LabSim = New-SimState -Seed $Seed
        $global:LabCliHandler = { param($Full) Invoke-SimCall -Full $Full }
        $before = Get-SimSnapshot -State $global:LabSim
        $all = @{ Region = $script:Region } + $Params
        $null = & $script:EnsureFile @all *>&1
        $code = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $code
            Calls    = $global:LabSim.Calls.ToArray()
            Before   = $before
            After    = (Get-SimSnapshot -State $global:LabSim)
        }
    }
}

AfterAll {
    Remove-Variable -Name LabCliHandler -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LabSim, SimAccountId, SimMutatingVerbs -Scope Global -ErrorAction SilentlyContinue
}

Describe 'ensure-lab-group safety' {

    Context 'a real run only adds and stays inside the lab group' -ForEach @(1..30 | ForEach-Object { @{ Seed = $_ } }) {
        BeforeAll {
            $params = @{ Confirm = $false }
            if ($Seed % 2 -eq 0) { $params.AddUser = @('user-one') }
            $script:Run = Invoke-Ensure -Seed $Seed -Params $params
        }

        It 'finishes successfully' {
            $Run.ExitCode | Should -Be 0
        }

        It 'keeps everything already attached to the lab group and every member' {
            if ($Run.Before.Groups.ContainsKey($script:LabGroup)) {
                foreach ($arn in $Run.Before.Groups[$script:LabGroup].Attached) {
                    $Run.After.Groups[$script:LabGroup].Attached | Should -Contain $arn
                }
                foreach ($m in $Run.Before.Groups[$script:LabGroup].Members) {
                    $Run.After.Groups[$script:LabGroup].Members | Should -Contain $m
                }
            }
        }

        It 'does not delete any policy and does not change foreign policies' {
            foreach ($arn in $Run.Before.Policies.Keys) {
                $Run.After.Policies.ContainsKey($arn) | Should -BeTrue
                if ($arn -match '/foreign-') {
                    ($Run.After.Policies[$arn].Versions | ForEach-Object { $_.Id }) -join ',' |
                        Should -Be (($Run.Before.Policies[$arn].Versions | ForEach-Object { $_.Id }) -join ',')
                    $Run.After.Policies[$arn].Default | Should -Be $Run.Before.Policies[$arn].Default
                }
            }
        }

        It 'leaves the foreign group exactly as it was' {
            ($Run.After.Groups[$script:ForeignGrp].Attached -join ',') | Should -Be ($Run.Before.Groups[$script:ForeignGrp].Attached -join ',')
            ($Run.After.Groups[$script:ForeignGrp].Members -join ',') | Should -Be ($Run.Before.Groups[$script:ForeignGrp].Members -join ',')
        }

        It 'issues no detach, remove or delete of groups, policies or users' {
            $bad = @($Run.Calls | Where-Object { $_.Op -match '^(detach|remove|delete-group|delete-policy$|delete-user|delete-role|put-|update-)' })
            $bad.Count | Should -Be 0
        }

        It 'deletes only a non-default version of its own sangyshop policy' {
            foreach ($c in @($Run.Calls | Where-Object { $_.Op -eq 'delete-policy-version' })) {
                $arn = Get-SimArg $c.Args '--policy-arn'
                $arn | Should -Match '/sangyshop-'
                $Run.Before.Policies[$arn].Default | Should -Not -Be (Get-SimArg $c.Args '--version-id')
            }
        }

        It 'names only the guarded group and only the user given with -AddUser' {
            foreach ($c in $Run.Calls) {
                $g = Get-SimArg $c.Args '--group-name'
                if ($g) { $g | Should -Be $script:LabGroup }
                $u = Get-SimArg $c.Args '--user-name'
                if ($u) { $u | Should -Be 'user-one' }
            }
            if ($Seed % 2 -ne 0) {
                @($Run.Calls | Where-Object { $_.Op -eq 'add-user-to-group' }).Count | Should -Be 0
            }
        }

        It 'does only reads before the first mutating call' {
            $first = -1
            for ($i = 0; $i -lt $Run.Calls.Count; $i++) { if ($Run.Calls[$i].Mutating) { $first = $i; break } }
            if ($first -ge 0) {
                @($Run.Calls | Select-Object -Skip $first | Where-Object { -not $_.Mutating -and $_.Op -match '^(get|list)-' }).Count | Should -Be 0
            }
        }

        It 'is idempotent: a second run makes no mutating call' {
            $global:LabSim.Calls.Clear()
            $again = @{ Region = $script:Region; Confirm = $false }
            if ($Seed % 2 -eq 0) { $again.AddUser = @('user-one') }
            $null = & $script:EnsureFile @again *>&1
            @($global:LabSim.Calls.ToArray() | Where-Object { $_.Mutating }).Count | Should -Be 0
        }
    }

    Context '-WhatIf and -Describe change nothing' -ForEach @(1..30 | ForEach-Object { @{ Seed = $_ } }) {
        It '-WhatIf makes zero mutating calls and leaves the account unchanged' {
            $r = Invoke-Ensure -Seed $Seed -Params @{ WhatIf = $true; AddUser = @('user-one') }
            @($r.Calls | Where-Object { $_.Mutating }).Count | Should -Be 0
            $r.ExitCode | Should -Be 0
            (ConvertTo-Json $r.After -Depth 10) | Should -Be (ConvertTo-Json $r.Before -Depth 10)
        }

        It '-Describe makes zero mutating calls and leaves the account unchanged' {
            $r = Invoke-Ensure -Seed $Seed -Params @{ Describe = $true; AddUser = @('user-one') }
            @($r.Calls | Where-Object { $_.Mutating }).Count | Should -Be 0
            $r.ExitCode | Should -Be 0
            (ConvertTo-Json $r.After -Depth 10) | Should -Be (ConvertTo-Json $r.Before -Depth 10)
        }
    }

    Context 'confirmation comes before the first mutating call' {
        BeforeAll {
            $script:Text = Get-Content -LiteralPath $script:EnsureFile -Raw
        }

        It 'declares high impact confirmation' {
            $Text | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
            $Text | Should -Match "ConfirmImpact\s*=\s*'High'"
        }

        It 'asks ShouldProcess before the apply loop that issues mutating calls' {
            $ask = $Text.IndexOf('$PSCmdlet.ShouldProcess(')
            $firstMutating = $Text.IndexOf('-Mutating')
            # The first textual use of -Mutating is the helper definition; the apply call is the last one.
            $apply = $Text.LastIndexOf('Invoke-GroupCli -CliArgs $p.Args -Mutating')
            $ask | Should -BeGreaterThan 0
            $apply | Should -BeGreaterThan $ask
            $Text.IndexOf('Invoke-GroupCli -CliArgs $p.Args -Mutating') | Should -Be $apply
        }

        It 'never calls a mutating operation outside the apply loop' {
            $Text | Should -Not -Match "Invoke-GroupCli[^\r\n]*'(create|attach|add|delete)-[^\r\n]*-Mutating"
            ([regex]::Matches($Text, 'Invoke-GroupCli[^\r\n]*-Mutating')).Count | Should -Be 1
        }

        It 'does not require a prompt answer when nothing needs to change' {
            $global:LabSim = New-SimState -Seed 1
            $global:LabCliHandler = { param($Full) Invoke-SimCall -Full $Full }
            # Converge first, then run again with the default confirmation preference.
            $null = & $script:EnsureFile -Region $script:Region -Confirm:$false *>&1
            $global:LabSim.Calls.Clear()
            $null = & $script:EnsureFile -Region $script:Region *>&1
            $LASTEXITCODE | Should -Be 0
            @($global:LabSim.Calls.ToArray() | Where-Object { $_.Mutating }).Count | Should -Be 0
        }
    }
}
