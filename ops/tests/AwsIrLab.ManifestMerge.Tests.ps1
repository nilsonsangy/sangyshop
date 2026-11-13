<#
.SYNOPSIS
    Pester 5.x property test: reading the lab manifest merges every candidate file without losing anything.

.DESCRIPTION
    Read-LabManifestEntries (aws/ir-lab/LabTeardown-Common.ps1) reads the file named by LAB_MANIFEST_PATH
    plus the standard files under the home folder (legacy lab-manifest.json and the current
    manifest-<lab>.json). For generated sets of manifests in both on-disk shapes, the merge must be:
      - additive: every (type, id, region) of every file is in the result, exactly once;
      - ownership-safe: a resource is reused when ANY file marks it reused, and entries without the
        ownership field are read as created;
      - legacy-aware: the legacy "run-id" spelling and the current "run_id" spelling both give RunId;
      - independent of which file holds which entries.

    Cases come from a fixed-seed System.Random (reproducible). The home folder is redirected to a temp
    folder for the test, so the real ~/.sangyshop-lab is never read. No AWS call is made.

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.ManifestMerge.Tests.ps1
#>

BeforeAll {
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-merge-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

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
    $script:PreviousManifestPath = $env:LAB_MANIFEST_PATH
    $env:LAB_CONFIG_PATH = $script:ConfigPath

    . (Join-Path $PSScriptRoot '..' 'aws' 'ir-lab' 'LabTeardown-Common.ps1')

    # Redirect the home folder so the standard candidate files live in the temp folder.
    $script:PreviousHome = $HOME
    $script:FakeHome = Join-Path $script:WorkDir 'home'
    New-Item -ItemType Directory -Path (Join-Path $script:FakeHome '.sangyshop-lab') -Force | Out-Null
    Set-Variable -Name HOME -Value $script:FakeHome -Force -Scope Global

    $script:Seed = 20240611
    $script:Types = @('secret', 'iam-access-key', 'sns-subscription', 'nacl-entry', 'log-group', 'trail')
    $script:Regions = @('us-east-1', 'eu-west-1', 'global')

    function New-GenEntries {
        # A pool of unique keys, each with a ground-truth ownership.
        param([System.Random] $Rng, [int] $Count)
        $pool = @{}
        while ($pool.Count -lt $Count) {
            $t = $script:Types[$Rng.Next(0, $script:Types.Count)]
            $r = $script:Regions[$Rng.Next(0, $script:Regions.Count)]
            $id = 'res-' + $Rng.Next(0, 100000)
            $pool["$t|$id|$r"] = [pscustomobject]@{ Type = $t; Id = $id; Region = $r; RunId = ('run-' + $Rng.Next(0, 50)) }
        }
        return @($pool.Values)
    }

    function Write-ManifestFile {
        # Shape 'legacy': {resources:[{type,id,region,"run-id"}]} (no ownership at all).
        # Shape 'current': {schema,lab,run_id,region,resources:[{...,run_id,component,ownership}]}.
        param([string] $Path, [string] $Shape, $Items)
        $rows = foreach ($i in $Items) {
            if ($Shape -eq 'legacy') {
                $o = [ordered]@{ type = $i.Entry.Type; id = $i.Entry.Id; region = $i.Entry.Region }
                $o['run-id'] = $i.Entry.RunId
                $o
            }
            else {
                [ordered]@{
                    type = $i.Entry.Type; id = $i.Entry.Id; region = $i.Entry.Region; run_id = $i.Entry.RunId
                    component = 'detection'; ownership = $i.Ownership
                }
            }
        }
        $doc = if ($Shape -eq 'legacy') { [ordered]@{ resources = @($rows) } }
        else { [ordered]@{ schema = 1; lab = $script:LabTagValue; run_id = 'run-x'; region = 'us-east-1'; resources = @($rows) } }
        $json = $doc | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
    }
}

AfterAll {
    Set-Variable -Name HOME -Value $script:PreviousHome -Force -Scope Global
    $env:LAB_CONFIG_PATH = $script:PreviousConfigPath
    $env:LAB_MANIFEST_PATH = $script:PreviousManifestPath
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Lab manifest merge' {
    BeforeEach {
        $script:Dir = Join-Path $script:WorkDir ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        $script:EnvFile = Join-Path $script:Dir 'env-manifest.json'
        $script:LegacyFile = Join-Path $script:FakeHome '.sangyshop-lab' 'lab-manifest.json'
        $script:CurrentFile = Join-Path $script:FakeHome '.sangyshop-lab' "manifest-$($script:LabTagValue).json"
        Remove-Item -LiteralPath $script:LegacyFile, $script:CurrentFile -Force -ErrorAction SilentlyContinue
        $env:LAB_MANIFEST_PATH = $script:EnvFile
    }

    It 'keeps every entry of every file once, reused wins, no ownership means created (120 generated cases)' {
        $rng = [System.Random]::new($script:Seed)
        for ($n = 0; $n -lt 120; $n++) {
            $pool = New-GenEntries -Rng $rng -Count $rng.Next(1, 13)

            # Spread the pool over the three files; an entry may appear in several files with different ownership.
            $files = @{ Env = @(); Legacy = @(); Current = @() }
            $expectReused = @{}
            foreach ($e in $pool) {
                $key = "$($e.Type)|$($e.Id)|$($e.Region)"
                $expectReused[$key] = $false
                $placed = 0
                foreach ($f in @('Env', 'Legacy', 'Current')) {
                    if ($rng.Next(0, 2) -eq 0 -and $placed -gt 0) { continue }
                    $own = if ($rng.Next(0, 3) -eq 0) { 'reused' } else { 'created' }
                    $files[$f] += [pscustomobject]@{ Entry = $e; Ownership = $own }
                    $placed++
                    # Legacy files carry no ownership: they can never mark a resource as reused.
                    $isLegacyShape = ($f -eq 'Legacy') -or ($f -eq 'Env' -and ($n % 2 -eq 0))
                    if ($own -eq 'reused' -and -not $isLegacyShape) { $expectReused[$key] = $true }
                }
            }

            # The env file alternates between the legacy and the current shape across cases.
            $envShape = if ($n % 2 -eq 0) { 'legacy' } else { 'current' }
            Write-ManifestFile -Path $script:EnvFile -Shape $envShape -Items $files.Env
            Write-ManifestFile -Path $script:LegacyFile -Shape 'legacy' -Items $files.Legacy
            Write-ManifestFile -Path $script:CurrentFile -Shape 'current' -Items $files.Current

            $merged = @(Read-LabManifestEntries)

            # Additive and de-duplicated: exactly the union of keys.
            $keys = @($merged | ForEach-Object { "$($_.Type)|$($_.Id)|$($_.Region)" })
            ($keys | Select-Object -Unique).Count | Should -Be $keys.Count
            $keys.Count | Should -Be $expectReused.Count
            foreach ($k in $expectReused.Keys) { $keys | Should -Contain $k }

            # Ownership: reused if any current-shape file says so; everything else is created.
            foreach ($m in $merged) {
                $m.Reused | Should -Be $expectReused["$($m.Type)|$($m.Id)|$($m.Region)"]
            }

            # Both run id spellings are understood.
            foreach ($m in $merged) { $m.RunId | Should -Match '^run-\d+$' }
        }
    }

    It 'reads legacy entries without ownership as created and keeps their run-id' {
        $e = [pscustomobject]@{ Type = 'secret'; Id = 'app/old'; Region = 'us-east-1'; RunId = 'run-7' }
        Write-ManifestFile -Path $script:EnvFile -Shape 'legacy' -Items @([pscustomobject]@{ Entry = $e; Ownership = 'created' })
        $merged = @(Read-LabManifestEntries)
        $merged.Count | Should -Be 1
        $merged[0].Reused | Should -BeFalse
        $merged[0].RunId | Should -BeExactly 'run-7'
    }

    It 'an unreadable candidate file does not drop the entries of the readable ones' {
        $e = [pscustomobject]@{ Type = 'trail'; Id = 'lab-trail'; Region = 'us-east-1'; RunId = 'run-1' }
        Write-ManifestFile -Path $script:CurrentFile -Shape 'current' -Items @([pscustomobject]@{ Entry = $e; Ownership = 'reused' })
        [System.IO.File]::WriteAllText($script:EnvFile, '{ "resources": [ { "type": ')
        $merged = @(Read-LabManifestEntries 3>$null)
        $merged.Count | Should -Be 1
        $merged[0].Reused | Should -BeTrue
    }
}
