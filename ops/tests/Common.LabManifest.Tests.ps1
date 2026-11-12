<#
.SYNOPSIS
    Pester 5.x tests for Get-LabTags / Add-LabManifestEntry (lib/Common.ps1, task 9.3).

.DESCRIPTION
    Property 7: Etiquetas e Manifesto de todo recurso criado.
    Validates: Requirements 46.1, 46.2, 48.1, 48.2

    Pester has no native property-based engine, so each property is exercised by a
    loop of >= 100 generated cases driven by a fixed-seed System.Random (reproducible).
    Every test uses a temp manifest path; the real $HOME/.sangyshop-lab is never touched.

    Run with:
        Invoke-Pester -Path ops/tests/Common.LabManifest.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1')

    $script:Seed = 20240924
    $script:Components = @('deploy', 'detection', 'blocker', 'evidence', 'credential')
    $script:Types = @('iam-access-key', 'sns-subscription', 'nacl-entry', 'service-principal', 'sg-rule', 'role-assignment')

    function New-TestDir {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('labmanifest-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        return $d
    }

    function New-RandomToken {
        param([System.Random] $Rng, [int] $Min = 3, [int] $Max = 20)
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789-_/:.'
        $len = $Rng.Next($Min, $Max + 1)
        $sb = [System.Text.StringBuilder]::new()
        for ($i = 0; $i -lt $len; $i++) { [void]$sb.Append($chars[$Rng.Next(0, $chars.Length)]) }
        return $sb.ToString()
    }

    function New-RandomRunId {
        param([System.Random] $Rng)
        $dt = [DateTime]::new(2020, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($Rng.Next(0, 300000000))
        $hex = '{0:x4}' -f $Rng.Next(0, 65536)
        return ($dt.ToString('yyyyMMdd\THHmmss\Z', [System.Globalization.CultureInfo]::InvariantCulture) + '-' + $hex)
    }

    function Read-Manifest {
        param([string] $Path)
        return ([System.IO.File]::ReadAllText($Path) | ConvertFrom-Json)
    }
}

Describe 'Get-LabTags (Req 46.1, 46.2)' {
    It 'always returns lab, run-id and component for 100+ generated RunIds' {
        $rng = [System.Random]::new($script:Seed)
        for ($i = 0; $i -lt 120; $i++) {
            $runId = New-RandomRunId -Rng $rng
            $lab = 'lab-' + (New-RandomToken -Rng $rng)
            $comp = $script:Components[$rng.Next(0, $script:Components.Count)]
            $tags = Get-LabTags -Lab $lab -RunId $runId -Component $comp
            $tags.Keys | Should -Contain 'lab'
            $tags.Keys | Should -Contain 'run-id'
            $tags.Keys | Should -Contain 'component'
            $tags['lab'] | Should -BeExactly $lab
            $tags['run-id'] | Should -BeExactly $runId
            $tags['component'] | Should -BeExactly $comp
            $tags.Keys | Should -Not -Contain 'evidence'
        }
    }

    It 'adds evidence=true only with -Evidence' {
        $tags = Get-LabTags -Lab 'x' -RunId (New-RunId) -Component evidence -Evidence
        $tags['evidence'] | Should -BeExactly 'true'
    }

    It 'accepts every RunId produced by New-RunId' {
        for ($i = 0; $i -lt 100; $i++) {
            $runId = New-RunId
            (Get-LabTags -Lab 'sangyshop-lab-aws' -RunId $runId)['run-id'] | Should -BeExactly $runId
        }
    }

    It 'rejects malformed RunIds' -ForEach @(
        @{ Bad = '' }, @{ Bad = 'abc' }, @{ Bad = '20240101T000000Z-ZZZZ' }, @{ Bad = '20240101T000000-abcd' }
    ) {
        { Get-LabTags -Lab 'x' -RunId $Bad } | Should -Throw
    }
}

Describe 'Add-LabManifestEntry (Req 48.1, 48.2)' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Mf = Join-Path $script:Dir 'manifest.json'
    }
    AfterEach {
        Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'is idempotent by (type,id) over 100+ generated cases and updates fields in place' {
        $rng = [System.Random]::new($script:Seed)
        $expected = @{}
        for ($i = 0; $i -lt 120; $i++) {
            $type = $script:Types[$rng.Next(0, $script:Types.Count)]
            $id = New-RandomToken -Rng $rng
            $runId = New-RandomRunId -Rng $rng
            $comp = $script:Components[$rng.Next(0, $script:Components.Count)]

            Add-LabManifestEntry -Type $type -Id $id -Region 'us-east-1' -RunId $runId -Component $comp -ManifestPath $script:Mf
            # Same key again with updated fields.
            $runId2 = New-RandomRunId -Rng $rng
            $comp2 = $script:Components[$rng.Next(0, $script:Components.Count)]
            Add-LabManifestEntry -Type $type -Id $id -Region 'eu-west-1' -RunId $runId2 -Component $comp2 `
                -DeleteHint @{ cmd = "delete $id" } -ManifestPath $script:Mf
            $expected["$type|$id"] = @{ Region = 'eu-west-1'; RunId = $runId2; Component = $comp2; Hint = "delete $id" }
        }

        $m = Read-Manifest -Path $script:Mf
        $res = @($m.resources)
        $res.Count | Should -Be $expected.Count
        ($res | ForEach-Object { "$($_.type)|$($_.id)" } | Select-Object -Unique).Count | Should -Be $res.Count
        foreach ($r in $res) {
            $e = $expected["$($r.type)|$($r.id)"]
            $r.region | Should -BeExactly $e.Region
            $r.run_id | Should -BeExactly $e.RunId
            $r.component | Should -BeExactly $e.Component
            $r.delete.cmd | Should -BeExactly $e.Hint
        }
    }

    It 'adding the same (type,id) twice yields exactly one entry' {
        Add-LabManifestEntry -Type 'sg-rule' -Id 'sg-1' -Region 'r1' -RunId '20240101T000000Z-abcd' -Component deploy -ManifestPath $script:Mf
        Add-LabManifestEntry -Type 'sg-rule' -Id 'sg-1' -Region 'r2' -RunId '20240101T000000Z-abcd' -Component blocker -ManifestPath $script:Mf
        $res = @((Read-Manifest -Path $script:Mf).resources)
        $res.Count | Should -Be 1
        $res[0].region | Should -BeExactly 'r2'
        $res[0].component | Should -BeExactly 'blocker'
    }

    It 'keeps the file valid JSON after every write and leaves no temp/bak files' {
        $rng = [System.Random]::new($script:Seed)
        for ($i = 0; $i -lt 100; $i++) {
            Add-LabManifestEntry -Type $script:Types[$rng.Next(0, $script:Types.Count)] -Id (New-RandomToken -Rng $rng) `
                -Region 'us-east-1' -RunId (New-RandomRunId -Rng $rng) -Component deploy -ManifestPath $script:Mf
            { Read-Manifest -Path $script:Mf } | Should -Not -Throw
            @(Get-ChildItem -LiteralPath $script:Dir -Filter '*.tmp*').Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $script:Dir -Filter '*.bak').Count | Should -Be 0
        }
        @(Get-ChildItem -LiteralPath $script:Dir).Count | Should -Be 1
    }

    It 'interrupted write: a failing replace leaves the previous manifest intact and no partial file' {
        Add-LabManifestEntry -Type 'sg-rule' -Id 'keep' -Region 'r1' -RunId '20240101T000000Z-abcd' -Component deploy -ManifestPath $script:Mf
        $before = [System.IO.File]::ReadAllText($script:Mf)

        # Hold the destination open exclusively so the replace step fails mid-write.
        $fs = [System.IO.File]::Open($script:Mf, 'Open', 'Read', 'None')
        try {
            { Add-LabManifestEntry -Type 'sg-rule' -Id 'new' -Region 'r1' -RunId '20240101T000000Z-abcd' -Component deploy -ManifestPath $script:Mf } |
                Should -Throw
        }
        finally { $fs.Dispose() }

        [System.IO.File]::ReadAllText($script:Mf) | Should -BeExactly $before
        { Read-Manifest -Path $script:Mf } | Should -Not -Throw
        @(Get-ChildItem -LiteralPath $script:Dir -Filter '*.tmp*').Count | Should -Be 0
    }

    It 'refuses to overwrite a corrupt manifest and leaves it untouched' {
        [System.IO.File]::WriteAllText($script:Mf, '{ "resources": [ { "type": ')
        $before = [System.IO.File]::ReadAllText($script:Mf)
        { Add-LabManifestEntry -Type 'sg-rule' -Id 'x' -Region 'r1' -RunId '20240101T000000Z-abcd' -Component deploy -ManifestPath $script:Mf } |
            Should -Throw
        [System.IO.File]::ReadAllText($script:Mf) | Should -BeExactly $before
        @(Get-ChildItem -LiteralPath $script:Dir -Filter '*.tmp*').Count | Should -Be 0
    }

    It 'concurrent writers from separate processes keep valid JSON and lose no entries' {
        $common = (Resolve-Path (Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1')).Path
        $jobs = 1..3 | ForEach-Object {
            $w = $_
            Start-Job -ArgumentList $common, $script:Mf, $w -ScriptBlock {
                param($common, $mf, $w)
                . $common
                1..5 | ForEach-Object {
                    Add-LabManifestEntry -Type 'sg-rule' -Id "w$w-$_" -Region 'r1' -RunId '20240101T000000Z-abcd' -Component deploy -ManifestPath $mf
                }
            }
        }
        $jobs | Wait-Job -Timeout 300 | Out-Null
        $jobs | Receive-Job -ErrorAction SilentlyContinue | Out-Null
        $jobs | Remove-Job -Force

        $res = @((Read-Manifest -Path $script:Mf).resources)
        $res.Count | Should -Be 15
        @(Get-ChildItem -LiteralPath $script:Dir -Filter '*.tmp*').Count | Should -Be 0
    }
}
