<#
.SYNOPSIS
    Pester 5.x property tests for the policy versions handling of ensure-lab-group.ps1.

.DESCRIPTION
    An in-memory IAM simulator answers every call through $global:LabCliHandler, the
    seam used by Invoke-LabCli. No AWS CLI is ever invoked and no real account is
    touched.

    Properties:
      * Idempotence: when the default version of a policy is equivalent to the rendered
        template after normalization (any key order, any order of Action and Resource
        entries, one-element lists written as scalars), the script makes no mutating
        call. After a run that changed something, a second run makes none either.
      * Rotation: when a policy differs from the template and already has five versions,
        the oldest non-default version is deleted first, the default version is never
        deleted, and only then is the new default version created. With fewer than five
        versions nothing is deleted.

    Inputs are generated from a fixed seed so a failure is reproducible.

    Run with:
        Invoke-Pester -Path ops/tests/LabGroup.PolicyVersions.Tests.ps1
#>

BeforeAll {
    $script:IamDir = Join-Path $PSScriptRoot '..' 'aws' 'iam'
    $script:Script = Join-Path $script:IamDir 'ensure-lab-group.ps1'
    . (Join-Path $script:IamDir 'LabGroup-Common.ps1')

    $script:AccountId = '123456789012'
    $script:RegionName = 'us-east-1'
    $script:GroupName = 'sangyshop-lab-group'
    $script:TemplateFiles = @(Get-LabPolicyTemplatePath -TemplateDir (Join-Path $script:IamDir 'policies'))

    function Get-Rendered {
        param([string] $Path)
        Expand-LabPolicyTemplate -Path $Path -AccountId $script:AccountId -Region $script:RegionName
    }

    # Same meaning, different shape: shuffled keys, shuffled Action/Resource lists,
    # one-element lists written as scalars. Statement order is kept.
    function Convert-ToEquivalent {
        param($Node, [System.Random] $Rng, [string] $Key = '')
        if ($Node -is [System.Array]) {
            $items = @($Node | ForEach-Object { Convert-ToEquivalent -Node $_ -Rng $Rng })
            if ($Key -in @('Action', 'Resource')) {
                $items = @($items | Sort-Object { $Rng.Next() })
                if ($items.Count -eq 1 -and $Rng.Next(2) -eq 0) { return $items[0] }
            }
            return , $items
        }
        if ($Node -is [pscustomobject]) {
            $out = [ordered]@{}
            $names = @($Node.PSObject.Properties.Name | Sort-Object { $Rng.Next() })
            foreach ($n in $names) { $out[$n] = Convert-ToEquivalent -Node $Node.$n -Rng $Rng -Key $n }
            return [pscustomobject]$out
        }
        return $Node
    }

    # Simulator state --------------------------------------------------------------

    function New-SimVersion {
        param([string] $Id, [bool] $IsDefault, [string] $Date, $Document)
        [pscustomobject]@{ VersionId = $Id; IsDefaultVersion = $IsDefault; CreateDate = $Date; Document = $Document }
    }

    function Reset-Sim {
        $global:LabSim = @{
            Policies = @{}
            Calls    = New-Object System.Collections.Generic.List[string]
            Ops      = New-Object System.Collections.Generic.List[object]
            Clock    = [datetime]'2030-01-01T00:00:00Z'
        }
        $global:LabCliHandler = {
            param($CliArgs)
            $a = @($CliArgs)
            $sim = $global:LabSim
            $op = "$($a[2]) $($a[3])"
            $opt = {
                param([string] $Name)
                for ($i = 0; $i -lt $a.Count - 1; $i++) { if ($a[$i] -eq $Name) { return $a[$i + 1] } }
                return $null
            }
            $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = $o } }
            $fail = { param($code, $msg) [pscustomobject]@{ ExitCode = 254; Output = "An error occurred ($code) when calling the operation: $msg" } }
            $sim.Calls.Add($op)
            $arn = & $opt '--policy-arn'
            $pol = $null
            if ($arn) {
                $pname = ($arn -split '/')[-1]
                if ($sim.Policies.ContainsKey($pname)) { $pol = $sim.Policies[$pname] }
            }

            switch ($op) {
                'sts get-caller-identity' { return (& $ok '123456789012') }
                'iam get-group' {
                    return (& $ok (@{ Group = @{ GroupName = 'sangyshop-lab-group' }; Users = @() } | ConvertTo-Json -Depth 8 -Compress))
                }
                'iam list-attached-group-policies' {
                    $att = @($sim.Policies.Keys | ForEach-Object { @{ PolicyName = $_; PolicyArn = "arn:aws:iam::123456789012:policy/$_" } })
                    return (& $ok (@{ AttachedPolicies = $att } | ConvertTo-Json -Depth 8 -Compress))
                }
                'iam get-policy' {
                    if ($null -eq $pol) { return (& $fail 'NoSuchEntity' 'Policy not found') }
                    $def = @($pol | Where-Object { $_.IsDefaultVersion })[0]
                    return (& $ok (@{ Policy = @{ DefaultVersionId = $def.VersionId } } | ConvertTo-Json -Depth 8 -Compress))
                }
                'iam get-policy-version' {
                    $vid = & $opt '--version-id'
                    $v = @($pol | Where-Object { $_.VersionId -eq $vid })[0]
                    return (& $ok (@{ PolicyVersion = @{ VersionId = $vid; Document = $v.Document } } | ConvertTo-Json -Depth 32 -Compress))
                }
                'iam list-policy-versions' {
                    $vs = @($pol | ForEach-Object {
                            @{ VersionId = $_.VersionId; IsDefaultVersion = $_.IsDefaultVersion; CreateDate = $_.CreateDate }
                        })
                    return (& $ok (@{ Versions = $vs } | ConvertTo-Json -Depth 8 -Compress))
                }
                'iam delete-policy-version' {
                    $vid = & $opt '--version-id'
                    $sim.Ops.Add([pscustomobject]@{ Op = 'delete'; Policy = $pname; VersionId = $vid; Default = [bool](@($pol | Where-Object { $_.VersionId -eq $vid })[0].IsDefaultVersion) })
                    $v = @($pol | Where-Object { $_.VersionId -eq $vid })[0]
                    if ($v.IsDefaultVersion) { return (& $fail 'DeleteConflict' 'Cannot delete the default version') }
                    $sim.Policies[$pname] = @($pol | Where-Object { $_.VersionId -ne $vid })
                    return (& $ok '')
                }
                'iam create-policy-version' {
                    $sim.Ops.Add([pscustomobject]@{ Op = 'create-version'; Policy = $pname; VersionId = $null; Default = $true })
                    if ($pol.Count -ge 5) { return (& $fail 'LimitExceeded' 'A managed policy can have up to 5 versions') }
                    $sim.Clock = $sim.Clock.AddMinutes(1)
                    $doc = (& $opt '--policy-document') | ConvertFrom-Json
                    $nextId = 'v' + ((@($pol | ForEach-Object { [int]($_.VersionId -replace '\D', '') }) | Measure-Object -Maximum).Maximum + 1)
                    foreach ($v in $pol) { $v.IsDefaultVersion = $false }
                    $new = [pscustomobject]@{ VersionId = $nextId; IsDefaultVersion = $true; CreateDate = $sim.Clock.ToString('yyyy-MM-ddTHH:mm:ssZ'); Document = $doc }
                    $sim.Policies[$pname] = @($pol) + $new
                    return (& $ok '')
                }
                default {
                    # create-policy, attach-group-policy, create-group, add-user-to-group
                    $sim.Ops.Add([pscustomobject]@{ Op = $a[3]; Policy = $null; VersionId = $null; Default = $false })
                    return (& $ok '')
                }
            }
        }
    }

    # One default version per policy that matches (in shape-shifted form) the template.
    function Add-SimPolicy {
        param([string] $Name, $Document, [System.Random] $Rng, [int] $Count = 1, [int] $DefaultIndex = 0, [string[]] $Dates)
        $versions = for ($i = 0; $i -lt $Count; $i++) {
            $date = if ($Dates) { $Dates[$i] } else { '2024-01-01T00:00:00Z' }
            New-SimVersion -Id ('v' + ($i + 1)) -IsDefault ($i -eq $DefaultIndex) -Date $date -Document $Document
        }
        $global:LabSim.Policies[$Name] = @($versions)
    }

    function Invoke-Ensure {
        & $script:Script -GroupName $script:GroupName -Region $script:RegionName -Confirm:$false *>$null
        return $LASTEXITCODE
    }

    function Get-MutatingCalls {
        @($global:LabSim.Calls | Where-Object { $_ -match '^iam (create|delete|attach|add)-' })
    }

    function Get-DefaultDocument {
        param([string] $Name)
        $v = @($global:LabSim.Policies[$Name] | Where-Object { $_.IsDefaultVersion })[0]
        return $v.Document
    }
}

AfterAll {
    $global:LabCliHandler = $null
    $global:LabSim = $null
}

Describe 'ensure-lab-group.ps1 policy versions' {

    AfterEach {
        $global:LabCliHandler = $null
        $global:LabSim = $null
    }

    It 'finds the policy templates to test against' {
        $script:TemplateFiles.Count | Should -BeGreaterThan 0
    }

    Context 'idempotence by normalized comparison' {

        It 'makes no mutating call when every default version is equivalent to its template' {
            $rng = [System.Random]::new(2101)
            for ($iter = 0; $iter -lt 25; $iter++) {
                Reset-Sim
                foreach ($tpl in $script:TemplateFiles) {
                    $name = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($tpl)
                    $obj = (Get-Rendered -Path $tpl) | ConvertFrom-Json
                    $equiv = Convert-ToEquivalent -Node $obj -Rng $rng
                    Add-SimPolicy -Name $name -Document $equiv -Rng $rng
                }
                $code = Invoke-Ensure
                $code | Should -Be 0 -Because "iteration $iter (seed 2101)"
                @(Get-MutatingCalls).Count | Should -Be 0 -Because "iteration $iter (seed 2101)"
            }
        }

        It 'makes no mutating call on a second run after a run that changed policies' {
            $rng = [System.Random]::new(2102)
            for ($iter = 0; $iter -lt 15; $iter++) {
                Reset-Sim
                foreach ($tpl in $script:TemplateFiles) {
                    $name = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($tpl)
                    $obj = (Get-Rendered -Path $tpl) | ConvertFrom-Json
                    # About half of the policies are out of date.
                    if ($rng.Next(2) -eq 0) {
                        $obj.Statement[0].Action = @($obj.Statement[0].Action) + "iam:Stale$($rng.Next(1000))"
                    }
                    Add-SimPolicy -Name $name -Document $obj -Rng $rng -Count ($rng.Next(1, 6)) -DefaultIndex 0 `
                        -Dates @('2020-01-01T00:00:00Z', '2021-01-01T00:00:00Z', '2022-01-01T00:00:00Z', '2023-01-01T00:00:00Z', '2024-01-01T00:00:00Z')
                }
                (Invoke-Ensure) | Should -Be 0 -Because "first run, iteration $iter"
                $global:LabSim.Calls.Clear()
                (Invoke-Ensure) | Should -Be 0 -Because "second run, iteration $iter"
                @(Get-MutatingCalls).Count | Should -Be 0 -Because "second run, iteration $iter (seed 2102)"
            }
        }

        It 'creates a new default version when the document really differs' {
            Reset-Sim
            $tpl = $script:TemplateFiles[0]
            $name = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($tpl)
            $obj = (Get-Rendered -Path $tpl) | ConvertFrom-Json
            $obj.Statement[0].Action = @($obj.Statement[0].Action) + 'iam:Stale'
            Add-SimPolicy -Name $name -Document $obj -Rng ([System.Random]::new(1))
            (Invoke-Ensure) | Should -Be 0
            @($global:LabSim.Ops | Where-Object { $_.Op -eq 'create-version' -and $_.Policy -eq $name }).Count | Should -Be 1
        }
    }

    Context 'rotation at five versions' {

        It 'deletes the oldest non-default version first, never the default, then creates the new default' {
            $rng = [System.Random]::new(2103)
            for ($iter = 0; $iter -lt 30; $iter++) {
                Reset-Sim
                $tpl = $script:TemplateFiles[0]
                $name = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($tpl)
                $wanted = Get-Rendered -Path $tpl
                $stale = $wanted | ConvertFrom-Json
                $stale.Statement[0].Action = @($stale.Statement[0].Action) + "iam:Stale$iter"

                # Five distinct dates over several years, assigned in random order so that
                # version ids and creation dates disagree.
                $years = @(2019..2025 | Sort-Object { $rng.Next() } | Select-Object -First 5)
                $dates = @($years | ForEach-Object { '{0}-{1:00}-{2:00}T10:00:00Z' -f $_, $rng.Next(1, 13), $rng.Next(1, 29) })
                $defaultIndex = $rng.Next(0, 5)
                Add-SimPolicy -Name $name -Document $stale -Rng $rng -Count 5 -DefaultIndex $defaultIndex -Dates $dates

                $expectedOldest = $null
                $oldestDate = $null
                for ($i = 0; $i -lt 5; $i++) {
                    if ($i -eq $defaultIndex) { continue }
                    $d = [datetime]::Parse($dates[$i], [cultureinfo]::InvariantCulture, 'AdjustToUniversal')
                    if ($null -eq $oldestDate -or $d -lt $oldestDate) { $oldestDate = $d; $expectedOldest = 'v' + ($i + 1) }
                }

                # The other policies are already current, so only this one changes.
                foreach ($other in $script:TemplateFiles | Select-Object -Skip 1) {
                    $oname = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($other)
                    Add-SimPolicy -Name $oname -Document ((Get-Rendered -Path $other) | ConvertFrom-Json) -Rng $rng
                }

                (Invoke-Ensure) | Should -Be 0 -Because "iteration $iter (seed 2103)"

                $ops = @($global:LabSim.Ops | Where-Object { $_.Policy -eq $name })
                $deletes = @($ops | Where-Object { $_.Op -eq 'delete' })
                $creates = @($ops | Where-Object { $_.Op -eq 'create-version' })
                $deletes.Count | Should -Be 1 -Because "iteration $iter"
                $deletes[0].VersionId | Should -Be $expectedOldest -Because "iteration $iter, dates $($dates -join ',')"
                $deletes[0].Default | Should -BeFalse -Because "iteration $iter"
                $creates.Count | Should -Be 1 -Because "iteration $iter"
                [array]::IndexOf(@($ops), $deletes[0]) | Should -BeLessThan ([array]::IndexOf(@($ops), $creates[0])) -Because "iteration $iter"

                $final = @($global:LabSim.Policies[$name])
                $final.Count | Should -BeLessOrEqual 5
                @($final | Where-Object { $_.IsDefaultVersion }).Count | Should -Be 1
                $expectedNormalized = (ConvertTo-Json -InputObject ($wanted | ConvertFrom-Json) -Depth 32 -Compress)
                (ConvertTo-Json -InputObject (Get-DefaultDocument -Name $name) -Depth 32 -Compress) | Should -Be $expectedNormalized -Because "iteration $iter"
            }
        }

        It 'deletes nothing when the policy has fewer than five versions' {
            $rng = [System.Random]::new(2104)
            for ($iter = 0; $iter -lt 20; $iter++) {
                Reset-Sim
                $tpl = $script:TemplateFiles[0]
                $name = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($tpl)
                $stale = (Get-Rendered -Path $tpl) | ConvertFrom-Json
                $stale.Statement[0].Action = @($stale.Statement[0].Action) + "iam:Stale$iter"
                $count = $rng.Next(1, 5)
                Add-SimPolicy -Name $name -Document $stale -Rng $rng -Count $count -DefaultIndex ($rng.Next(0, $count)) `
                    -Dates @('2020-01-01T00:00:00Z', '2021-01-01T00:00:00Z', '2022-01-01T00:00:00Z', '2023-01-01T00:00:00Z')
                foreach ($other in $script:TemplateFiles | Select-Object -Skip 1) {
                    $oname = 'sangyshop-' + [System.IO.Path]::GetFileNameWithoutExtension($other)
                    Add-SimPolicy -Name $oname -Document ((Get-Rendered -Path $other) | ConvertFrom-Json) -Rng $rng
                }

                (Invoke-Ensure) | Should -Be 0 -Because "iteration $iter (seed 2104)"
                @($global:LabSim.Ops | Where-Object { $_.Op -eq 'delete' }).Count | Should -Be 0 -Because "iteration $iter, $count versions"
                @($global:LabSim.Ops | Where-Object { $_.Op -eq 'create-version' -and $_.Policy -eq $name }).Count | Should -Be 1
                @($global:LabSim.Policies[$name]).Count | Should -Be ($count + 1)
            }
        }
    }
}
