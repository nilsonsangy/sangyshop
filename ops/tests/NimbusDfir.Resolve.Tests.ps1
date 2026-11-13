<#
.SYNOPSIS
    Pester 5.x property tests for Resolve-NimbusDfirPath (lib/NimbusDfir.ps1).

.DESCRIPTION
    The checkout location of NimbusDFIR is never guessed. It comes only from an
    explicit parameter, the NIMBUSDFIR_PATH environment variable, or the
    Common.NimbusDfirPath key of the cloud config, in that order, and the first
    source that points to a valid checkout wins. A directory is valid only when
    it contains ir_lab_core\__init__.py and aws\ec2_evidence_preservation.py.

    Covered here:
      * Across 100 seeded random combinations of the three sources (absent,
        valid, or invalid), the result is the first valid source in order.
      * With no valid source, the call throws a message that explains how to set
        the path, or returns $null with -Optional.
      * A valid checkout sitting next to the working directory (a sibling
        directory) or inside it is never used when no source points to it.
      * Get-NimbusToolPath returns existing tools and throws for missing ones.

    Every directory lives under $TestDrive. NIMBUSDFIR_PATH and the working
    directory are restored after each test. No cloud CLI is invoked.
    Windows PowerShell 5.1 compatible.

    Run with:
        Invoke-Pester -Path ops/tests/NimbusDfir.Resolve.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'lib' 'NimbusDfir.ps1')

    # Creates a directory with both marker files and returns its full path.
    function New-Checkout {
        param([Parameter(Mandatory)][string] $Path)
        New-Item -ItemType Directory -Force -Path (Join-Path $Path 'ir_lab_core') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $Path 'aws') | Out-Null
        Set-Content -LiteralPath (Join-Path $Path 'ir_lab_core\__init__.py') -Value '' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $Path 'aws\ec2_evidence_preservation.py') -Value '' -Encoding UTF8
        return (Resolve-Path -LiteralPath $Path).ProviderPath
    }

    # Creates a directory that is missing one marker file (or both).
    function New-InvalidDir {
        param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][int] $Variant)
        New-Item -ItemType Directory -Force -Path (Join-Path $Path 'ir_lab_core') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $Path 'aws') | Out-Null
        if ($Variant -eq 1) {
            Set-Content -LiteralPath (Join-Path $Path 'ir_lab_core\__init__.py') -Value '' -Encoding UTF8
        }
        elseif ($Variant -eq 2) {
            Set-Content -LiteralPath (Join-Path $Path 'aws\ec2_evidence_preservation.py') -Value '' -Encoding UTF8
        }
        return $Path
    }
}

Describe 'Resolve-NimbusDfirPath' {
    BeforeEach {
        $script:SavedEnv = [Environment]::GetEnvironmentVariable('NIMBUSDFIR_PATH')
        $script:SavedCwd = (Get-Location).ProviderPath
        [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $null)
    }
    AfterEach {
        [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $script:SavedEnv)
        Set-Location -LiteralPath $script:SavedCwd
    }

    It 'returns the first valid source in order (parameter, environment, config) across 100 seeded combinations' {
        $rng = New-Object System.Random 4242
        $valid = New-Checkout (Join-Path $TestDrive 'pool\valid-a')
        $valid2 = New-Checkout (Join-Path $TestDrive 'pool\valid-b')
        $valid3 = New-Checkout (Join-Path $TestDrive 'pool\valid-c')
        $validByIndex = @($valid, $valid2, $valid3)
        $invalidDirs = @(
            (New-InvalidDir (Join-Path $TestDrive 'pool\bad-none') 0),
            (New-InvalidDir (Join-Path $TestDrive 'pool\bad-init-only') 1),
            (New-InvalidDir (Join-Path $TestDrive 'pool\bad-tool-only') 2),
            (Join-Path $TestDrive 'pool\does-not-exist')
        )

        for ($i = 0; $i -lt 100; $i++) {
            $values = @($null, $null, $null)
            $expected = $null
            for ($s = 0; $s -lt 3; $s++) {
                switch ($rng.Next(0, 3)) {
                    0 { $values[$s] = $null }
                    1 { $values[$s] = $validByIndex[$s]; if ($null -eq $expected) { $expected = $validByIndex[$s] } }
                    2 { $values[$s] = $invalidDirs[$rng.Next(0, $invalidDirs.Count)] }
                }
            }

            [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $values[1])
            $params = @{ Optional = $true }
            if ($null -ne $values[0]) { $params.Path = $values[0] }
            if ($null -ne $values[2]) { $params.Config = @{ Common = @{ NimbusDfirPath = $values[2] } } }

            $actual = Resolve-NimbusDfirPath @params
            $actual | Should -Be $expected -Because "case $i with sources [$($values -join ' | ')]"

            # Without -Optional the same inputs must resolve to the same path,
            # or throw when no source is valid.
            $strictParams = @{}
            if ($params.ContainsKey('Path')) { $strictParams.Path = $params.Path }
            if ($params.ContainsKey('Config')) { $strictParams.Config = $params.Config }
            if ($null -ne $expected) {
                (Resolve-NimbusDfirPath @strictParams) | Should -Be $expected
            }
            else {
                { Resolve-NimbusDfirPath @strictParams } | Should -Throw
            }
        }
    }

    It 'falls through an invalid parameter to a valid environment variable' {
        $valid = New-Checkout (Join-Path $TestDrive 'env-valid')
        $bad = New-InvalidDir (Join-Path $TestDrive 'param-bad') 1
        [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $valid)
        Resolve-NimbusDfirPath -Path $bad | Should -Be $valid
    }

    It 'prefers the environment variable over the config value when both are valid' {
        $envDir = New-Checkout (Join-Path $TestDrive 'env-first')
        $cfgDir = New-Checkout (Join-Path $TestDrive 'cfg-second')
        [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $envDir)
        Resolve-NimbusDfirPath -Config @{ Common = @{ NimbusDfirPath = $cfgDir } } | Should -Be $envDir
    }

    It 'reads the config value when it is the only source' {
        $cfgDir = New-Checkout (Join-Path $TestDrive 'cfg-only')
        Resolve-NimbusDfirPath -Config @{ Common = @{ NimbusDfirPath = $cfgDir } } | Should -Be $cfgDir
    }

    It 'throws with setup guidance when no source is set' {
        $err = $null
        try { Resolve-NimbusDfirPath | Out-Null } catch { $err = $_.Exception.Message }
        $err | Should -Not -BeNullOrEmpty
        $err | Should -Match 'NIMBUSDFIR_PATH'
        $err | Should -Match 'cloud\.config\.ps1'
        $err | Should -Match 'ir_lab_core'
    }

    It 'names each source that was tried when every source is invalid' {
        $bad = New-InvalidDir (Join-Path $TestDrive 'all-bad') 2
        [Environment]::SetEnvironmentVariable('NIMBUSDFIR_PATH', $bad)
        $err = $null
        try { Resolve-NimbusDfirPath -Path $bad | Out-Null } catch { $err = $_.Exception.Message }
        $err | Should -Match '-Path'
        $err | Should -Match 'NIMBUSDFIR_PATH'
    }

    It 'returns null instead of throwing with -Optional when nothing is set' {
        Resolve-NimbusDfirPath -Optional | Should -BeNullOrEmpty
    }

    It 'never uses a valid sibling directory named NimbusDFIR when no source is set' {
        $work = Join-Path $TestDrive 'work'
        $repo = Join-Path $work 'sangyshop'
        New-Item -ItemType Directory -Force -Path $repo | Out-Null
        New-Checkout (Join-Path $work 'NimbusDFIR') | Out-Null
        Set-Location -LiteralPath $repo

        { Resolve-NimbusDfirPath } | Should -Throw
        Resolve-NimbusDfirPath -Optional | Should -BeNullOrEmpty
    }

    It 'never uses a valid checkout found inside the working directory or its parent when no source is set' {
        $work = Join-Path $TestDrive 'work2'
        $repo = Join-Path $work 'sangyshop'
        New-Item -ItemType Directory -Force -Path $repo | Out-Null
        New-Checkout (Join-Path $repo 'NimbusDFIR') | Out-Null
        New-Checkout $work | Out-Null
        Set-Location -LiteralPath $repo

        Resolve-NimbusDfirPath -Optional | Should -BeNullOrEmpty
    }

    It 'ignores the sibling directory even when an invalid source is given' {
        $work = Join-Path $TestDrive 'work3'
        $repo = Join-Path $work 'sangyshop'
        New-Item -ItemType Directory -Force -Path $repo | Out-Null
        New-Checkout (Join-Path $work 'NimbusDFIR') | Out-Null
        $bad = New-InvalidDir (Join-Path $TestDrive 'explicit-bad') 0
        Set-Location -LiteralPath $repo

        Resolve-NimbusDfirPath -Path $bad -Optional | Should -BeNullOrEmpty
    }

    It 'restores NIMBUSDFIR_PATH between tests (guard against leakage)' {
        [Environment]::GetEnvironmentVariable('NIMBUSDFIR_PATH') | Should -BeNullOrEmpty
    }
}

Describe 'Get-NimbusToolPath' {
    It 'returns the full path of an existing tool using forward slashes' {
        $root = New-Checkout (Join-Path $TestDrive 'tools')
        $tool = Get-NimbusToolPath -NimbusDfirPath $root -Relative 'aws/ec2_evidence_preservation.py'
        $tool | Should -Be (Join-Path $root 'aws\ec2_evidence_preservation.py')
    }

    It 'throws when the tool does not exist' {
        $root = New-Checkout (Join-Path $TestDrive 'tools2')
        { Get-NimbusToolPath -NimbusDfirPath $root -Relative 'aws/missing.py' } | Should -Throw '*tool not found*'
    }
}
