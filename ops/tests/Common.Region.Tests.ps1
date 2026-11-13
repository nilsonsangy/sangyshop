<#
.SYNOPSIS
    Pester 5.x property tests for Resolve-LabRegion in lib/Common.ps1.

.DESCRIPTION
    Region precedence: the -Region parameter wins over Aws.Region from the config
    hashtable, and the result is trimmed. With neither source (absent, empty or
    whitespace only) the resolver writes an English message to stderr and exits
    with code 2.

    Resolve-LabRegion calls exit 2 on failure, so every call runs in a child pwsh
    process. The input space is covered exhaustively over a small set of values
    (absent, blank, padded, plain) for both sources.

    Run with:
        Invoke-Pester -Path ops/tests/Common.Region.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1')).Path
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("region-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    # Child runner: the region and config values arrive through environment
    # variables so that blank and padded values survive argument parsing.
    $script:Runner = Join-Path $script:Work 'runner.ps1'
    $runnerText = @'
param([string] $Common)
. $Common
$splat = @{}
if ($env:TEST_PARAM_SET -eq '1') { $splat['Region'] = $env:TEST_PARAM_VALUE }
if ($env:TEST_CONFIG_SET -eq '1') {
    $splat['Config'] = @{ Aws = @{ Region = $env:TEST_CONFIG_VALUE } }
}
elseif ($env:TEST_CONFIG_SET -eq 'nokey') {
    $splat['Config'] = @{ Aws = @{ AccountId = '123456789012' } }
}
$resolved = Resolve-LabRegion @splat
Write-Output "REGION=[$resolved]"
'@
    Set-Content -LiteralPath $script:Runner -Value $runnerText -Encoding UTF8

    function Invoke-Region {
        param($ParamValue, $ConfigValue, [switch] $ConfigNoKey)

        $names = 'TEST_PARAM_SET', 'TEST_PARAM_VALUE', 'TEST_CONFIG_SET', 'TEST_CONFIG_VALUE'
        $saved = @{}
        foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n, 'Process') }
        try {
            $paramSet = $PSBoundParameters.ContainsKey('ParamValue')
            $configSet = $PSBoundParameters.ContainsKey('ConfigValue')
            [Environment]::SetEnvironmentVariable('TEST_PARAM_SET', $(if ($paramSet) { '1' } else { $null }), 'Process')
            [Environment]::SetEnvironmentVariable('TEST_PARAM_VALUE', $ParamValue, 'Process')
            $cfgFlag = if ($configSet) { '1' } elseif ($ConfigNoKey) { 'nokey' } else { $null }
            [Environment]::SetEnvironmentVariable('TEST_CONFIG_SET', $cfgFlag, 'Process')
            [Environment]::SetEnvironmentVariable('TEST_CONFIG_VALUE', $ConfigValue, 'Process')

            $out = & $script:Pwsh -NoProfile -NonInteractive -File $script:Runner -Common $script:CommonPath 2>&1
            $code = $LASTEXITCODE
        }
        finally {
            foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n], 'Process') }
        }
        [pscustomobject]@{ ExitCode = $code; Output = (($out | ForEach-Object { "$_" }) -join "`n") }
    }
}

AfterAll {
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Resolve-LabRegion precedence' {
    # Built at discovery time because -ForEach reads it then. Each source is
    # absent, empty, blank, padded or plain.
    BeforeDiscovery {
        $States = @(
            @{ Name = 'absent'; Set = $false; Value = $null; Usable = $false }
            @{ Name = 'empty';  Set = $true;  Value = '';     Usable = $false }
            @{ Name = 'blank';  Set = $true;  Value = '   ';  Usable = $false }
            @{ Name = 'padded'; Set = $true;  Value = ' %s ';  Usable = $true }
            @{ Name = 'plain';  Set = $true;  Value = '%s';    Usable = $true }
        )
        $Cases = foreach ($p in $States) { foreach ($c in $States) {
            @{ P = $p; C = $c; Label = "param=$($p.Name) config=$($c.Name)" }
        } }
    }

    It 'resolves by precedence or exits with code 2 for <Label>' -ForEach $Cases {
        $pv = if ($P.Set) { $P.Value -replace '%s', 'eu-west-1' } else { $null }
        $cv = if ($C.Set) { $C.Value -replace '%s', 'us-east-2' } else { $null }

        $splat = @{}
        if ($P.Set) { $splat['ParamValue'] = $pv }
        if ($C.Set) { $splat['ConfigValue'] = $cv }
        $r = Invoke-Region @splat

        if ($P.Usable) {
            $r.ExitCode | Should -Be 0
            $r.Output | Should -Match ([regex]::Escape('REGION=[eu-west-1]'))
        }
        elseif ($C.Usable) {
            $r.ExitCode | Should -Be 0
            $r.Output | Should -Match ([regex]::Escape('REGION=[us-east-2]'))
        }
        else {
            $r.ExitCode | Should -Be 2
            $r.Output | Should -Match 'no AWS region available'
            $r.Output | Should -Not -Match 'REGION='
        }
    }

    It 'exits with code 2 when the config has no Region key and no parameter is given' {
        $r = Invoke-Region -ConfigNoKey
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'no AWS region available'
    }

    It 'exits with code 2 when neither a parameter nor a config is given' {
        $r = Invoke-Region
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'no AWS region available'
    }
}
