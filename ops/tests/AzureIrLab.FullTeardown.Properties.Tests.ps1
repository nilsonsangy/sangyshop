<#
.SYNOPSIS
    Pester tests for ops/azure/ir-lab/full-teardown.ps1 and verify-zero-cost.ps1.

.DESCRIPTION
    PowerShell has no mature property-based testing library, so each check below runs on
    100 generated cases drawn from a System.Random with a FIXED SEED. Every case is a random
    subscription: resource groups with or without the lab tag (lab=sangyshop-lab-azure),
    evidence groups (evidence=true|preserved), resources with the lab tag, a different 'lab'
    tag value or no tag, resources that are already gone, run-ids, and subscription
    diagnostic settings that are (or are not) listed in the lab manifest.

    The scripts run in-process through the Invoke-LabAz seam ($global:LabAzHandler) against a
    small STATEFUL fake of Azure. No Azure call is ever made, and the VM deploy teardown is
    intercepted by $global:LabChildHandler.

      Simulation: -WhatIf runs zero mutating calls, never delegates, exits 0.
      Idempotence: running twice converges; the second run removes nothing and exits 0.
      Scope: the removed set is exactly lab tag union lab manifest (within the run scope);
             every other billable resource stays and is reported as unmarked.
             Removal also follows the documented step order.
      Evidence: preserved evidence goes only with both confirmations.
      Zero cost: verify-zero-cost says 'nothing billable remaining' and exits 0 if and only if
             nothing billable remains, tagged or not; it never mutates.
      Reuse: manifest entries marked as reused are reported and never removed.

    Run: Invoke-Pester -Path ops/tests/AzureIrLab.FullTeardown.Properties.Tests.ps1
#>

BeforeDiscovery {
    $script:Regions = @('eastus', 'westeurope', 'brazilsouth', 'centralus')
    $script:AzTypes = @(
        'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/disks', 'Microsoft.Network/publicIPAddresses',
        'Microsoft.Storage/storageAccounts', 'Microsoft.Insights/actionGroups',
        'Microsoft.Network/networkSecurityGroups', 'Microsoft.Network/virtualNetworks'
    )
    # Types that belong to a billable risk class (the last two do not).
    $script:AzBillable = @($script:AzTypes[0..4])

    function New-AzUniverse {
        param([System.Random]$Rng, [int]$Index, [switch]$ForceEvidence, [double]$CleanProb = 0)
        $groups = New-Object System.Collections.ArrayList
        $nG = 2 + $Rng.Next(3)
        for ($g = 0; $g -lt $nG; $g++) {
            $kind = 'none'
            if ($Rng.Next(100) -lt 62) { $kind = 'lab' }
            $ev = ''
            if ($kind -eq 'lab') { $d = $Rng.Next(100); if ($d -ge 85) { $ev = 'preserved' } elseif ($d -ge 70) { $ev = 'true' } }
            [void]$groups.Add(@{
                    Name = ('rg-{0}-{1}-{2:x4}' -f $(if ($kind -eq 'lab') { 'lab' } else { 'other' }), $g, $Rng.Next(0x10000))
                    TagKind = $kind; RunId = @('run-a', 'run-b')[$Rng.Next(2)]; Evidence = $ev; Deleted = ($Rng.Next(100) -lt 8)
                })
        }
        $resources = New-Object System.Collections.ArrayList
        $nR = 3 + $Rng.Next(9)
        for ($k = 0; $k -lt $nR; $k++) {
            $grp = $groups[$Rng.Next($groups.Count)]
            $type = $script:AzTypes[$Rng.Next($script:AzTypes.Count)]
            $tk = 'lab'
            if ($grp.TagKind -eq 'lab') {
                # Inside a lab group only billable resources may lack the tag (they make the group be refused).
                if ($script:AzBillable -contains $type -and $Rng.Next(100) -lt 20) { $tk = @('none', 'wrong')[$Rng.Next(2)] }
            } else {
                $d = $Rng.Next(100)
                if ($d -ge 50) { $tk = 'wrong' } ; if ($d -ge 70) { $tk = 'none' }
            }
            $run = if ($grp.TagKind -eq 'lab') { $grp.RunId } else { @('run-a', 'run-b')[$Rng.Next(2)] }
            $short = ($type -split '/')[-1]
            [void]$resources.Add(@{
                    Name = ('{0}-{1}-{2:x4}' -f $short.ToLowerInvariant(), $k, $Rng.Next(0x10000)); Type = $type; Group = $grp.Name
                    TagKind = $tk; RunId = $run; Evidence = ''; Deleted = ($grp.Deleted -or ($Rng.Next(100) -lt 6))
                })
        }
        if ($ForceEvidence) {
            $gname = ('rg-lab-evidence-{0:x4}' -f $Rng.Next(0x10000))
            [void]$groups.Add(@{ Name = $gname; TagKind = 'lab'; RunId = 'run-a'; Evidence = 'preserved'; Deleted = $false })
            [void]$resources.Add(@{ Name = ('storageaccounts-ev-{0:x4}' -f $Rng.Next(0x10000)); Type = 'Microsoft.Storage/storageAccounts'; Group = $gname; TagKind = 'lab'; RunId = 'run-a'; Evidence = ''; Deleted = $false })
        }
        $diags = New-Object System.Collections.ArrayList
        $nD = $Rng.Next(4)
        for ($k = 0; $k -lt $nD; $k++) {
            [void]$diags.Add(@{ Name = ('diag-{0}-{1:x4}' -f $k, $Rng.Next(0x10000)); InManifest = ($Rng.Next(100) -lt 70); RunId = @('run-a', 'run-b')[$Rng.Next(2)]; Deleted = ($Rng.Next(100) -lt 10) })
        }
        $stale = New-Object System.Collections.ArrayList
        if ($Rng.Next(3) -eq 0) { [void]$stale.Add(@{ Name = ('diag-stale-{0:x4}' -f $Rng.Next(0x10000)); RunId = 'run-a' }) }
        if ($Rng.NextDouble() -lt $CleanProb) {
            foreach ($g in $groups) { if ($g.TagKind -eq 'lab') { $g.Deleted = $true } }
            foreach ($r in $resources) {
                $grp = $groups | Where-Object { $_.Name -eq $r.Group }
                if ($grp.Deleted -or $r.TagKind -eq 'lab' -or ($script:AzBillable -contains $r.Type)) { $r.Deleted = $true }
            }
        }
        return @{
            Index = $Index; Region = $script:Regions[$Rng.Next($script:Regions.Count)]
            Groups = $groups.ToArray(); Resources = $resources.ToArray(); Diags = $diags.ToArray(); Stale = $stale.ToArray()
            RunPick = $Rng.Next(3); Pick = $Rng.Next(1000)
        }
    }

    function New-AzCases {
        param([int]$Seed, [switch]$ForceEvidence, [double]$CleanProb = 0)
        $rng = [System.Random]::new($Seed)   # fixed seed: reproducible cases
        $list = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 100; $i++) { [void]$list.Add((New-AzUniverse -Rng $rng -Index $i -ForceEvidence:$ForceEvidence -CleanProb $CleanProb)) }
        return $list.ToArray()
    }

    $script:P2Cases = New-AzCases -Seed 25502
    $script:P3Cases = New-AzCases -Seed 25503
    $script:P4Cases = New-AzCases -Seed 25504
    $script:OrderCases = New-AzCases -Seed 25507
    $script:P5Cases = New-AzCases -Seed 25505 -ForceEvidence
    $script:P6Cases = New-AzCases -Seed 25506 -CleanProb 0.35
}

BeforeAll {
    $script:AzDir = (Resolve-Path (Join-Path $PSScriptRoot '..\azure\ir-lab')).Path
    $script:TeardownScript = Join-Path $script:AzDir 'full-teardown.ps1'
    $script:VerifyScript = Join-Path $script:AzDir 'verify-zero-cost.ps1'
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-aztd-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    # The lab helpers derive their names from a cloud config; give them a throwaway one.
    $script:PrevCloudConfigPath = $env:LAB_CLOUD_CONFIG_PATH
    $cfgFile = Join-Path $script:WorkDir 'cloud.config.ps1'
    Set-Content -LiteralPath $cfgFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "abc12345"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Azure = @{
        Location = "eastus"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "sangyshop-lab"; EvidenceGroupBase = "sangyshop-evidence" }
    }
}
'@
    $env:LAB_CLOUD_CONFIG_PATH = $cfgFile
    $script:SubId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:AzBillable = @('Microsoft.Compute/virtualMachines', 'Microsoft.Compute/disks', 'Microsoft.Network/publicIPAddresses', 'Microsoft.Storage/storageAccounts', 'Microsoft.Insights/actionGroups')
    $script:TypeRank = @{
        'Microsoft.Compute/virtualMachines' = 0; 'Microsoft.Network/publicIPAddresses' = 3; 'Microsoft.Compute/disks' = 4
        'Microsoft.Storage/storageAccounts' = 5; 'Microsoft.Network/networkSecurityGroups' = 8; 'Microsoft.Network/virtualNetworks' = 8
    }

    function global:Get-AzFakeResourceId { param($r) return "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/$($r.Group)/providers/$($r.Type)/$($r.Name)" }

    # Stateful fake of the Azure CLI (receives the full argument list incl. --subscription and --only-show-errors).
    $global:LabAzFakeHandler = {
        param($a)
        $st = $global:LabAzFake
        $words = New-Object System.Collections.ArrayList
        foreach ($t in $a) { if ("$t".StartsWith('-')) { break }; [void]$words.Add("$t") }
        $call = $words -join ' '
        $arg = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { [string]$a[$i + 1] } else { $null } }
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $nf = [pscustomobject]@{ ExitCode = 3; Output = 'ERROR: (ResourceNotFound) The Resource was not found.' }
        $json = { param($o) [pscustomobject]@{ ExitCode = 0; Output = (ConvertTo-Json -InputObject @($o) -Compress -Depth 8) } }
        $tagsOf = {
            param($r)
            if ($r.TagKind -eq 'lab') {
                $t = [ordered]@{ lab = 'sangyshop-lab-azure'; 'run-id' = $r.RunId }
                if ($r.Evidence) { $t['evidence'] = $r.Evidence }
                return [pscustomobject]$t
            }
            if ($r.TagKind -eq 'wrong') { return [pscustomobject]@{ lab = 'other-lab' } }
            return $null
        }
        $groupRow = { param($g) [pscustomobject]@{ id = "/subscriptions/$($st.SubId)/resourceGroups/$($g.Name)"; name = $g.Name; location = $st.Region; tags = (& $tagsOf $g) } }
        $resRow = { param($r) [pscustomobject]@{ id = (Get-AzFakeResourceId $r); name = $r.Name; type = $r.Type; location = $st.Region; rg = $r.Group; tags = (& $tagsOf $r); managedBy = $null } }

        [void]$st.Calls.Add($call)
        if ($st.FailOn -and $call -eq $st.FailOn) { return [pscustomobject]@{ ExitCode = 1; Output = 'ERROR: AuthorizationFailed injected failure' } }
        $mutating = ($call -match '(^| )(delete|create|update|purge|recover)$')
        if ($call -eq 'rest' -and (& $arg '--method') -and (& $arg '--method') -ne 'get') { $mutating = $true }
        if ($mutating) { [void]$st.Mutating.Add($call) }

        switch -Exact ($call) {
            'account show' {
                if ((& $arg '--query') -eq 'id') { return (& $ok $st.SubId) }
                return (& $ok 'operator@example.com')
            }
            'group list' { return (& $json @(foreach ($g in $st.Groups.Values) { if (-not $g.Deleted -and $g.TagKind -eq 'lab') { & $groupRow $g } })) }
            'resource list' {
                $tagged = [bool](& $arg '--tag')
                return (& $json @(foreach ($r in $st.Res.Values) { if (-not $r.Deleted -and (-not $tagged -or $r.TagKind -eq 'lab')) { & $resRow $r } }))
            }
            'group delete' {
                $name = & $arg '--name'
                [void]$st.Attempts.Add("group|$name")
                if (-not $st.Groups.Contains($name) -or $st.Groups[$name].Deleted) { return $nf }
                $st.Groups[$name].Deleted = $true
                foreach ($r in $st.Res.Values) { if ($r.Group -eq $name) { $r.Deleted = $true } }
                [void]$st.Removals.Add("group|$name")
                [void]$st.Events.Add("group|$name")
                return (& $ok '')
            }
            'resource delete' {
                $id = & $arg '--ids'
                [void]$st.Attempts.Add("resource|$id")
                $hit = $st.Res.Values | Where-Object { (Get-AzFakeResourceId $_) -eq $id } | Select-Object -First 1
                if ($null -eq $hit -or $hit.Deleted) { return $nf }
                $hit.Deleted = $true
                [void]$st.Removals.Add("resource|$id")
                [void]$st.Events.Add("resource|$id")
                return (& $ok '')
            }
            'tag update' {
                $id = & $arg '--resource-id'
                foreach ($g in $st.Groups.Values) { if ("/subscriptions/$($st.SubId)/resourceGroups/$($g.Name)" -eq $id) { $g.Evidence = 'preserved' } }
                foreach ($r in $st.Res.Values) { if ((Get-AzFakeResourceId $r) -eq $id) { $r.Evidence = 'preserved' } }
                return (& $ok '')
            }
            'monitor diagnostic-settings subscription show' {
                $n = & $arg '--name'
                if ($st.Diags.Contains($n) -and -not $st.Diags[$n].Deleted) { return (& $ok $n) }
                return $nf
            }
            'monitor diagnostic-settings subscription delete' {
                $n = & $arg '--name'
                [void]$st.Attempts.Add("diag|$n")
                if (-not $st.Diags.Contains($n) -or $st.Diags[$n].Deleted) { return $nf }
                $st.Diags[$n].Deleted = $true
                [void]$st.Removals.Add("diag|$n")
                [void]$st.Events.Add("diag|$n")
                return (& $ok '')
            }
            default { return (& $json @()) }
        }
    }

    function global:New-AzFakeState {
        param([string]$Region, $Groups, $Resources, $Diags, [string]$FailOn = '')
        $g = [ordered]@{}; foreach ($x in $Groups) { $g[$x.Name] = @{} + $x }
        $r = [ordered]@{}; foreach ($x in $Resources) { $c = @{} + $x; $r["$($x.Group)/$($x.Name)"] = $c }
        $d = [ordered]@{}; foreach ($x in $Diags) { $d[$x.Name] = @{} + $x }
        return @{
            Region = $Region; SubId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; Groups = $g; Res = $r; Diags = $d; FailOn = $FailOn
            Calls = (New-Object System.Collections.ArrayList); Mutating = (New-Object System.Collections.ArrayList)
            Attempts = (New-Object System.Collections.ArrayList); Removals = (New-Object System.Collections.ArrayList)
            Events = (New-Object System.Collections.ArrayList); Child = (New-Object System.Collections.ArrayList)
            Prompts = (New-Object System.Collections.ArrayList); Answers = @(); PromptIdx = 0
        }
    }

    function New-AzFakeManifest {
        param($Diags, $Stale, [int]$Index)
        $entries = New-Object System.Collections.ArrayList
        foreach ($d in $Diags) { if ($d.InManifest) { [void]$entries.Add([ordered]@{ type = 'diagnostic-setting-subscription'; id = $d.Name; 'run-id' = $d.RunId }) } }
        foreach ($s in $Stale) { [void]$entries.Add([ordered]@{ type = 'diagnostic-setting-subscription'; id = $s.Name; 'run-id' = $s.RunId }) }
        $path = Join-Path $script:WorkDir ("manifest-$Index-$([guid]::NewGuid().ToString('N')).json")
        $json = ([ordered]@{ schema = 1; lab = 'sangyshop-lab-azure'; resources = $entries.ToArray() }) | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
        return $path
    }

    function Start-AzFake {
        param($Case, [string]$FailOn = '', $Answers = @())
        $global:LabAzFake = New-AzFakeState -Region $Case.Region -Groups $Case.Groups -Resources $Case.Resources -Diags $Case.Diags -FailOn $FailOn
        $global:LabAzFake.Answers = @($Answers)
        $global:LabAzHandler = $global:LabAzFakeHandler
        $global:LabChildHandler = { param($p, $rid) [void]$global:LabAzFake.Child.Add($p); [void]$global:LabAzFake.Events.Add('child'); return 0 }
        $global:LabConfirmHandler = {
            param($p)
            $s = $global:LabAzFake
            [void]$s.Prompts.Add($p)
            $ans = ''
            if ($s.PromptIdx -lt $s.Answers.Count) { $ans = $s.Answers[$s.PromptIdx] }
            $s.PromptIdx++
            return $ans
        }
    }

    function Invoke-AzScript {
        param([string]$Script, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        $out = & $Script @Params *>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }

    function Reset-AzCounters {
        $s = $global:LabAzFake
        foreach ($n in @('Calls', 'Mutating', 'Attempts', 'Removals', 'Events', 'Child', 'Prompts')) { $s[$n].Clear() }
        $s.PromptIdx = 0
    }

    function Get-AzState {
        $s = $global:LabAzFake
        $keys = @()
        $keys += @($s.Groups.Keys | Where-Object { $s.Groups[$_].Deleted } | ForEach-Object { "group|$_" })
        $keys += @($s.Res.Keys | Where-Object { $s.Res[$_].Deleted } | ForEach-Object { "res|$_" })
        $keys += @($s.Diags.Keys | Where-Object { $s.Diags[$_].Deleted } | ForEach-Object { "diag|$_" })
        return (@($keys | Sort-Object) -join ',')
    }

    function Get-AzOracle {
        param($Groups, $Resources, $Diags, [string]$Run, [bool]$Preserve)
        $present = @($Resources | Where-Object { -not $_.Deleted })
        $unmarked = @($present | Where-Object { $_.TagKind -ne 'lab' -and $script:AzBillable -contains $_.Type })
        $removedGroups = New-Object System.Collections.ArrayList
        $kept = New-Object System.Collections.ArrayList
        $needConfirm = New-Object System.Collections.ArrayList
        $removedRes = New-Object System.Collections.ArrayList
        $deletable = @{}
        foreach ($g in $Groups) {
            if ($g.Deleted -or $g.TagKind -ne 'lab') { continue }
            if ($Run -and $g.RunId -ne $Run) { continue }
            if (@($unmarked | Where-Object { $_.Group -eq $g.Name }).Count -gt 0) { continue }   # refused: not deleted as a whole
            if ($g.Evidence -and $Preserve) { [void]$kept.Add($g.Name); continue }
            if ($g.Evidence -eq 'preserved') { [void]$needConfirm.Add($g.Name) }
            $deletable[$g.Name] = $true
            [void]$removedGroups.Add("group|$($g.Name)")
        }
        foreach ($r in $present) {
            $k = "res|$($r.Group)/$($r.Name)"
            if ($deletable.ContainsKey($r.Group)) { [void]$removedRes.Add($k); continue }      # goes with its group
            if ($r.TagKind -ne 'lab') { continue }
            if ($Run -and $r.RunId -ne $Run) { continue }
            if ($kept -contains $r.Group) { continue }
            [void]$removedRes.Add($k)
        }
        $removedDiags = @($Diags | Where-Object { -not $_.Deleted -and $_.InManifest -and (-not $Run -or $_.RunId -eq $Run) } | ForEach-Object { "diag|$($_.Name)" })
        return @{
            Removed = @(@($removedGroups) + @($removedRes) + $removedDiags | Sort-Object)
            Kept = @($kept); NeedConfirm = @($needConfirm)
            Unmarked = @($unmarked | ForEach-Object { Get-AzFakeResourceId $_ } | Sort-Object)
        }
    }

    function Get-AzRunFilter { param([int]$Pick) return @('', 'run-a', 'run-b')[$Pick] }

    function Get-AzUnmarkedFromOutput {
        param([string]$Text)
        $i = $Text.IndexOf('Unmarked_Resource')
        if ($i -lt 0) { return @() }
        $found = New-Object System.Collections.ArrayList
        foreach ($m in [regex]::Matches($Text.Substring($i), '(?m)^\s+- (\S+)\s{2}(\S+)\s{2}\(scope: [^;)]*\)\s*$')) { [void]$found.Add($m.Groups[2].Value) }
        return @($found | Sort-Object -Unique)
    }

    function Get-AzEventRank {
        param([string]$Event, $State)
        if ($Event -eq 'child') { return 100 }
        $kind, $rest = $Event -split '\|', 2
        if ($kind -eq 'diag') { return 60 }
        if ($kind -eq 'group') { if ($State.Groups[$rest].Evidence) { return 150 } else { return 110 } }
        $type = ($rest -split '/providers/')[1]
        $type = ($type -split '/')[0..1] -join '/'
        if ($type -eq 'Microsoft.Insights/actionGroups') { return 80 }
        return 120
    }
}

AfterAll {
    $env:LAB_CLOUD_CONFIG_PATH = $script:PrevCloudConfigPath
    $global:LabAzHandler = $null
    $global:LabAzFake = $null
    $global:LabAzFakeHandler = $null
    $global:LabChildHandler = $null
    $global:LabConfirmHandler = $null
    Remove-Item -LiteralPath 'Function:\global:Get-AzFakeResourceId' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Function:\global:New-AzFakeState' -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'full-teardown.ps1 -WhatIf: the simulation runs no external command' {
    It 'case <Index>: -WhatIf makes zero mutating calls, never delegates, changes nothing and exits 0' -ForEach $script:P2Cases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $run = Get-AzRunFilter $RunPick
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        Start-AzFake -Case $case
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest; WhatIf = $true }
        if ($run) { $p['RunId'] = $run } elseif ($Pick % 2 -eq 0) { $p['AllRuns'] = $true }
        $preserve = ($Pick % 4 -eq 1)
        if ($preserve) { $p['PreserveEvidence'] = $true } elseif ($Pick % 5 -eq 0) { $p['ConfirmPreservedEvidenceRemoval'] = $true }
        if ($Pick % 3 -eq 0) { $p['NonInteractive'] = $true }
        $before = Get-AzState

        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $expected = Get-AzOracle -Groups $Groups -Resources $Resources -Diags $Diags -Run $run -Preserve $preserve

        $r.Code | Should -Be 0
        $global:LabAzFake.Mutating.Count | Should -Be 0
        $global:LabAzFake.Attempts.Count | Should -Be 0
        $global:LabAzFake.Child.Count | Should -Be 0
        $global:LabAzFake.Prompts.Count | Should -Be 0
        Get-AzState | Should -Be $before
        $r.Output | Should -Match 'Simulation complete: 0 changes made'
        # Every group and resource that a real run would remove is listed in the plan.
        foreach ($k in $expected.Removed) {
            $kind, $name = $k -split '\|', 2
            if ($kind -eq 'group') { $r.Output | Should -Match ([regex]::Escape($name)) }
            if ($kind -eq 'diag') { $r.Output | Should -Match ([regex]::Escape($name)) }
            if ($kind -eq 'res') { $r.Output | Should -Match ([regex]::Escape((($name -split '/')[1]))) }
        }
        # (Kept evidence may still produce a "tag evidence=preserved" action, so the empty-plan message only applies without it.)
        if ($expected.Removed.Count -eq 0 -and $expected.Kept.Count -eq 0) { $r.Output | Should -Match 'No lab resources remain' }
    }
}

Describe 'full-teardown.ps1: teardown is idempotent and converges' {
    It 'case <Index>: the second run removes nothing, changes nothing and exits 0' -ForEach $script:P3Cases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        Start-AzFake -Case $case
        $preserve = ($Pick % 2 -eq 1)
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest; NonInteractive = $true }
        if ($preserve) { $p['PreserveEvidence'] = $true } else { $p['ConfirmPreservedEvidenceRemoval'] = $true }
        $expected = Get-AzOracle -Groups $Groups -Resources $Resources -Diags $Diags -Run '' -Preserve $preserve

        $first = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $first.Code | Should -Be 0
        $afterFirst = Get-AzState

        Reset-AzCounters
        $second = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $second.Code | Should -Be 0
        $global:LabAzFake.Mutating.Count | Should -Be 0
        $global:LabAzFake.Removals.Count | Should -Be 0
        $global:LabAzFake.Child.Count | Should -Be 0
        Get-AzState | Should -Be $afterFirst
        $second.Output | Should -Match 'No lab resources remain'

        # The converged state is exactly what the oracle predicts: everything lab-owned (except kept evidence) is gone.
        foreach ($k in $expected.Removed) {
            $kind, $name = $k -split '\|', 2
            $deleted = switch ($kind) { 'group' { $global:LabAzFake.Groups[$name].Deleted } 'res' { $global:LabAzFake.Res[$name].Deleted } 'diag' { $global:LabAzFake.Diags[$name].Deleted } }
            $deleted | Should -BeTrue -Because "$k must be gone after the first run"
        }
    }
}

Describe 'full-teardown.ps1: removal is restricted to lab resources' {
    It 'case <Index>: the removed set is exactly lab tag union manifest; everything else stays and is reported as unmarked' -ForEach $script:P4Cases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $run = Get-AzRunFilter $RunPick
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        Start-AzFake -Case $case
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest; NonInteractive = $true; ConfirmPreservedEvidenceRemoval = $true }
        if ($run) { $p['RunId'] = $run }
        $initial = @{}
        foreach ($k in $global:LabAzFake.Res.Keys) { $initial["res|$k"] = $global:LabAzFake.Res[$k].Deleted }
        foreach ($k in $global:LabAzFake.Groups.Keys) { $initial["group|$k"] = $global:LabAzFake.Groups[$k].Deleted }
        foreach ($k in $global:LabAzFake.Diags.Keys) { $initial["diag|$k"] = $global:LabAzFake.Diags[$k].Deleted }
        $expected = Get-AzOracle -Groups $Groups -Resources $Resources -Diags $Diags -Run $run -Preserve $false

        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p

        $r.Code | Should -Be 0
        # State change = exactly the expected set.
        $now = @{}
        foreach ($k in $global:LabAzFake.Res.Keys) { $now["res|$k"] = $global:LabAzFake.Res[$k].Deleted }
        foreach ($k in $global:LabAzFake.Groups.Keys) { $now["group|$k"] = $global:LabAzFake.Groups[$k].Deleted }
        foreach ($k in $global:LabAzFake.Diags.Keys) { $now["diag|$k"] = $global:LabAzFake.Diags[$k].Deleted }
        $newlyGone = @($now.Keys | Where-Object { $now[$_] -and -not $initial[$_] } | Sort-Object)
        $newlyGone -join ',' | Should -Be ($expected.Removed -join ',')
        # No delete call was even attempted against anything outside the expected set.
        foreach ($att in @($global:LabAzFake.Attempts | Sort-Object -Unique)) {
            $kind, $name = $att -split '\|', 2
            if ($kind -eq 'resource') {
                $hit = $global:LabAzFake.Res.Values | Where-Object { (Get-AzFakeResourceId $_) -eq $name } | Select-Object -First 1
                $key = "res|$($hit.Group)/$($hit.Name)"
            } else { $key = $att }
            $expected.Removed | Should -Contain $key -Because "attempted removal of $att"
        }
        # Untagged billable resources are untouched and reported as unmarked.
        foreach ($res in ($Resources | Where-Object { -not $_.Deleted -and $_.TagKind -ne 'lab' -and ($script:AzBillable -contains $_.Type) })) {
            $global:LabAzFake.Res["$($res.Group)/$($res.Name)"].Deleted | Should -BeFalse -Because "unmarked $($res.Name) must stay"
        }
        (Get-AzUnmarkedFromOutput $r.Output) -join ',' | Should -Be ($expected.Unmarked -join ',')
        if ($expected.Unmarked.Count -gt 0) { $r.Output | Should -Match 'Unmarked_Resource' }
    }
}

Describe 'full-teardown.ps1: removal follows the documented step order' {
    It 'case <Index>: diagnostics, alerts, deploy, lab group, resources and evidence group never go out of order' -ForEach $script:OrderCases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        Start-AzFake -Case $case
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest; NonInteractive = $true; ConfirmPreservedEvidenceRemoval = $true }

        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $r.Code | Should -Be 0
        $events = @($global:LabAzFake.Events)
        $ranks = @($events | ForEach-Object { Get-AzEventRank -Event $_ -State $global:LabAzFake })
        for ($i = 1; $i -lt $ranks.Count; $i++) {
            $ranks[$i] | Should -BeGreaterOrEqual $ranks[$i - 1] -Because "order: $($events -join ' -> ')"
        }
        # Inside the individual-resources step, VMs go before public IPs, disks, storage and the network.
        $typeRanks = @($events | Where-Object { $_ -like 'resource|*' -and (Get-AzEventRank -Event $_ -State $global:LabAzFake) -eq 120 } | ForEach-Object {
                $t = (($_ -split '\|', 2)[1] -split '/providers/')[1]
                $script:TypeRank[(($t -split '/')[0..1] -join '/')]
            })
        for ($i = 1; $i -lt $typeRanks.Count; $i++) { $typeRanks[$i] | Should -BeGreaterOrEqual $typeRanks[$i - 1] }
    }
}

Describe 'full-teardown.ps1: preserved evidence gate' {
    It 'case <Index>: preserved evidence is removed only when both confirmations are given' -ForEach $script:P5Cases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $modes = @('none', 'preserve', 'noninteractive-flag', 'interactive-both', 'interactive-wrong-extra', 'interactive-cancel')
        $mode = $modes[$Index % $modes.Count]
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        $answers = @()
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest }
        switch ($mode) {
            'none' { $p['NonInteractive'] = $true }
            'preserve' { $p['NonInteractive'] = $true; $p['PreserveEvidence'] = $true }
            'noninteractive-flag' { $p['NonInteractive'] = $true; $p['ConfirmPreservedEvidenceRemoval'] = $true }
            'interactive-both' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('yes', 'delete preserved evidence') }
            'interactive-wrong-extra' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('yes', 'maybe') }
            'interactive-cancel' { $p['ConfirmPreservedEvidenceRemoval'] = $true; $answers = @('no') }
        }
        Start-AzFake -Case $case -Answers $answers
        $keep = ($mode -eq 'preserve')
        $granted = $mode -in @('noninteractive-flag', 'interactive-both')
        $expected = Get-AzOracle -Groups $Groups -Resources $Resources -Diags $Diags -Run '' -Preserve $keep
        $forced = @($Groups | Where-Object { $_.Name -like 'rg-lab-evidence-*' })[0].Name
        $forcedKey = "$forced"
        # Every case has a deletable evidence=preserved group, unless -PreserveEvidence keeps it.
        if ($keep) { $expected.Kept | Should -Contain $forcedKey } else { $expected.NeedConfirm | Should -Contain $forcedKey }

        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p

        if ($mode -in @('none', 'interactive-wrong-extra', 'interactive-cancel')) {
            $r.Code | Should -Be 5
            $global:LabAzFake.Mutating.Count | Should -Be 0
            $global:LabAzFake.Removals.Count | Should -Be 0
            $global:LabAzFake.Child.Count | Should -Be 0
            $global:LabAzFake.Groups[$forcedKey].Deleted | Should -BeFalse
            $expectedPrompts = @{ 'none' = 0; 'interactive-cancel' = 1; 'interactive-wrong-extra' = 2 }[$mode]
            $global:LabAzFake.Prompts.Count | Should -Be $expectedPrompts
        } else {
            $r.Code | Should -Be 0
            $global:LabAzFake.Groups[$forcedKey].Deleted | Should -Be $granted -Because "evidence group with mode $mode"
            $removedNow = @($global:LabAzFake.Removals | Where-Object { $_ -like 'group|*' } | ForEach-Object { $_ })
            if ($keep) {
                $removedNow | Should -Not -Contain "group|$forcedKey"
                $r.Output | Should -Match 'USD'
                $r.Output | Should -Match 'BRL'
                $r.Output | Should -Match 'KEPT'
            } else {
                $removedNow | Should -Contain "group|$forcedKey"
            }
            if ($mode -eq 'interactive-both') { $global:LabAzFake.Prompts.Count | Should -Be 2 }
            # Everything else follows the normal rules.
            foreach ($k in ($expected.Removed | Where-Object { $_ -like 'group|*' })) {
                $name = ($k -split '\|', 2)[1]
                $global:LabAzFake.Groups[$name].Deleted | Should -BeTrue
            }
        }
    }
}

Describe 'verify-zero-cost.ps1: zero-cost report' {
    It 'case <Index>: says nothing billable remaining and exits 0 iff nothing billable remains, tagged or not' -ForEach $script:P6Cases {
        $case = @{ Index = $Index; Region = $Region; Groups = $Groups; Resources = $Resources; Diags = $Diags; Stale = $Stale }
        $manifest = New-AzFakeManifest -Diags $Diags -Stale $Stale -Index $Index
        $inject = ($Pick % 10 -eq 0)
        Start-AzFake -Case $case -FailOn $(if ($inject) { 'ad sp list' } else { '' })
        $p = @{ Subscription = $script:SubId; Region = $Region; ManifestPath = $manifest }
        $before = Get-AzState

        $pending = New-Object System.Collections.ArrayList
        foreach ($g in $Groups) {
            if (-not $g.Deleted -and $g.TagKind -eq 'lab') {
                [void]$pending.Add(@{ Type = 'Microsoft.Resources/resourceGroups'; Id = "/subscriptions/$($script:SubId)/resourceGroups/$($g.Name)"; Marking = 'tagged' })
            }
        }
        foreach ($rs in $Resources) {
            if ($rs.Deleted) { continue }
            $id = "/subscriptions/$($script:SubId)/resourceGroups/$($rs.Group)/providers/$($rs.Type)/$($rs.Name)"
            $billable = ($script:AzBillable -contains $rs.Type)
            if ($rs.TagKind -eq 'lab' -and $billable) { [void]$pending.Add(@{ Type = $rs.Type; Id = $id; Marking = 'tagged' }) }
            elseif ($rs.TagKind -ne 'lab' -and $billable) { [void]$pending.Add(@{ Type = $rs.Type; Id = $id; Marking = 'unmarked' }) }
        }
        $clean = ($pending.Count -eq 0) -and (-not $inject)

        $r = Invoke-AzScript -Script $script:VerifyScript -Params $p

        $global:LabAzFake.Mutating.Count | Should -Be 0
        Get-AzState | Should -Be $before
        if ($clean) {
            $r.Code | Should -Be 0
            $r.Output | Should -Match 'nothing billable remaining'
        } else {
            $r.Code | Should -Not -Be 0
            $r.Output | Should -Not -Match 'nothing billable remaining'
            foreach ($e in $pending) {
                $r.Output | Should -Match ('- {0}\s+{1}\s+region=\S+\s+\[{2}\]' -f [regex]::Escape($e.Type), [regex]::Escape($e.Id), $e.Marking)
            }
            if ($inject -and $pending.Count -eq 0) { $r.Output | Should -Match 'Could not verify' }
        }
    }
}

Describe 'full-teardown.ps1: manifest ownership' {
    BeforeEach {
        $script:Case = @{
            Index = 900; Region = 'eastus'; Groups = @(); Resources = @(); Stale = @()
            Diags = @(
                @{ Name = 'diag-reused'; InManifest = $false; RunId = 'run-a'; Deleted = $false },
                @{ Name = 'diag-created'; InManifest = $false; RunId = 'run-a'; Deleted = $false },
                @{ Name = 'diag-legacy'; InManifest = $false; RunId = 'run-a'; Deleted = $false }
            )
        }
        $script:OwnPath = Join-Path $script:WorkDir ("own-$([guid]::NewGuid().ToString('N')).json")
        $doc = [ordered]@{
            schema = 1; lab = 'sangyshop-lab-azure'; run_id = 'run-a'; region = 'eastus'; created_utc = '2025-01-01T00:00:00Z'
            resources = @(
                [ordered]@{ type = 'diagnostic-setting-subscription'; id = 'diag-reused'; run_id = 'run-a'; ownership = 'reused' },
                [ordered]@{ type = 'diagnostic-setting-subscription'; id = 'diag-created'; run_id = 'run-a'; ownership = 'created' },
                [ordered]@{ type = 'diagnostic-setting-subscription'; id = 'diag-legacy'; 'run-id' = 'run-a' }
            )
        }
        [System.IO.File]::WriteAllText($script:OwnPath, ($doc | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
        Start-AzFake -Case $script:Case
    }

    It 'removes created and legacy entries, keeps the reused one and says so' {
        $p = @{ Subscription = $script:SubId; Region = 'eastus'; ManifestPath = $script:OwnPath; NonInteractive = $true }
        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $r.Code | Should -Be 0
        $global:LabAzFake.Diags['diag-created'].Deleted | Should -BeTrue
        $global:LabAzFake.Diags['diag-legacy'].Deleted | Should -BeTrue
        $global:LabAzFake.Diags['diag-reused'].Deleted | Should -BeFalse
        $global:LabAzFake.Attempts | Should -Not -Contain 'diag|diag-reused'
        $r.Output | Should -Match 'diag-reused.*kept \(not created by the lab\)'
    }

    It 'keeps the manifest header and the reused record after the removal' {
        $p = @{ Subscription = $script:SubId; Region = 'eastus'; ManifestPath = $script:OwnPath; NonInteractive = $true }
        $null = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $after = Get-Content -LiteralPath $script:OwnPath -Raw | ConvertFrom-Json
        $after.region | Should -Be 'eastus'
        ([datetime]$after.created_utc).ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2025-01-01'
        (Get-Content -LiteralPath $script:OwnPath -Raw) | Should -Match '"created_utc":\s*"2025-01-01T00:00:00Z"'
        @($after.resources).Count | Should -Be 1
        $after.resources[0].id | Should -Be 'diag-reused'
        $after.resources[0].ownership | Should -Be 'reused'
    }

    It 'simulation lists the reused record and changes nothing' {
        $p = @{ Subscription = $script:SubId; Region = 'eastus'; ManifestPath = $script:OwnPath; WhatIf = $true }
        $r = Invoke-AzScript -Script $script:TeardownScript -Params $p
        $r.Code | Should -Be 0
        $global:LabAzFake.Mutating.Count | Should -Be 0
        $r.Output | Should -Match 'kept \(not created by the lab\)'
    }
}