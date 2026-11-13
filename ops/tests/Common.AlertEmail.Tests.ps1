<#
.SYNOPSIS
    Pester 5.x tests for the alert e-mail helpers in lib/Common.ps1
    (Resolve-LabAlertEmail, Test-LabEmailFormat, Import-LabDotEnv).

.DESCRIPTION
    Covers three behaviors:

      * Source precedence: the -Email parameter wins over the LAB_ALERT_EMAIL
        environment variable, which wins over the .env file. With no source and no
        console the resolver exits with code 2.
      * Format validation and non-disclosure: an address is accepted only when it
        matches ^[^@\s]+@[^@\s]+\.[^@\s]+$, and an accepted address never appears in
        the captured output of the resolver.
      * .env loading keeps the process environment: a variable that already has a
        value is never overwritten, and only missing or empty variables are set.

    Resolve-LabAlertEmail calls exit 2 on failure, so every call to it runs in a
    child pwsh process with stdin redirected (no prompt is possible). The runs are
    exhaustive over the small input space, and the format and loader checks use
    seeded random inputs so failures are reproducible.

    Run with:
        Invoke-Pester -Path ops/tests/Common.AlertEmail.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1')).Path
    . $script:CommonPath

    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ("alertemail-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    # Child runner: dot-sources Common.ps1, resolves the e-mail and prints only a
    # marker line, so the test can check that the address was never echoed.
    $script:Runner = Join-Path $script:Work 'runner.ps1'
    $runnerText = @'
param([string] $Common, [string] $Email, [string] $DotEnvPath)
. $Common
$splat = @{ DotEnvPath = $DotEnvPath; NonInteractive = $true }
if ($Email) { $splat['Email'] = $Email }
$resolved = Resolve-LabAlertEmail @splat
Write-Output "RESOLVED-LENGTH=$($resolved.Length)"
Write-Output "RESOLVED-VALUE-HASH=$([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($resolved))))"
'@
    Set-Content -LiteralPath $script:Runner -Value $runnerText -Encoding UTF8

    function Get-Sha {
        param([string] $Text)
        [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)))
    }

    # Runs the resolver in a child pwsh. Returns exit code and combined output.
    function Invoke-Resolver {
        param([string] $Email, [string] $EnvValue, [string] $FileValue)

        $dotEnv = Join-Path $script:Work ("env-" + [guid]::NewGuid().ToString('N'))
        if ($PSBoundParameters.ContainsKey('FileValue') -and $FileValue) {
            Set-Content -LiteralPath $dotEnv -Value "LAB_ALERT_EMAIL=$FileValue" -Encoding UTF8
        }

        $saved = [Environment]::GetEnvironmentVariable('LAB_ALERT_EMAIL', 'Process')
        try {
            [Environment]::SetEnvironmentVariable('LAB_ALERT_EMAIL', $(if ($EnvValue) { $EnvValue } else { $null }), 'Process')
            $argList = @('-NoProfile', '-NonInteractive', '-File', $script:Runner, '-Common', $script:CommonPath, '-DotEnvPath', $dotEnv)
            if ($Email) { $argList += @('-Email', $Email) }
            $out = '' | & $script:Pwsh @argList 2>&1
            $code = $LASTEXITCODE
        }
        finally {
            [Environment]::SetEnvironmentVariable('LAB_ALERT_EMAIL', $saved, 'Process')
        }
        [pscustomobject]@{ ExitCode = $code; Output = (($out | ForEach-Object { "$_" }) -join "`n") }
    }
}

AfterAll {
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Resolve-LabAlertEmail source precedence' {
    BeforeAll {
        $script:ParamMail = 'param.user@example.com'
        $script:EnvMail   = 'env.user@example.com'
        $script:FileMail  = 'file.user@example.com'
    }

    # Every combination of the three sources being present or absent.
    It 'picks the first present source for param=<P> env=<E> file=<F>' -ForEach @(
        foreach ($p in $true, $false) { foreach ($e in $true, $false) { foreach ($f in $true, $false) {
            @{ P = $p; E = $e; F = $f }
        } } }
    ) {
        $args2 = @{}
        if ($P) { $args2['Email'] = $script:ParamMail }
        if ($E) { $args2['EnvValue'] = $script:EnvMail }
        if ($F) { $args2['FileValue'] = $script:FileMail }

        $r = Invoke-Resolver @args2

        if ($P -or $E -or $F) {
            $expected = if ($P) { $script:ParamMail } elseif ($E) { $script:EnvMail } else { $script:FileMail }
            $r.ExitCode | Should -Be 0
            $r.Output | Should -Match ([regex]::Escape("RESOLVED-VALUE-HASH=$(Get-Sha $expected)"))
            $expectedSource = if ($P) { 'the -Email parameter' } elseif ($E) { 'the LAB_ALERT_EMAIL environment variable' } else { 'the ops/.env file' }
            $r.Output | Should -Match ([regex]::Escape("Alert e-mail source: $expectedSource"))
        }
        else {
            $r.ExitCode | Should -Be 2
            $r.Output | Should -Match 'no alert e-mail available'
        }
    }

    It 'exits with code 2 when the first present source is malformed, ignoring later valid ones' {
        $r = Invoke-Resolver -Email 'not-an-email' -EnvValue $script:EnvMail -FileValue $script:FileMail
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Match 'not a valid address'
    }
}

Describe 'Test-LabEmailFormat and non-disclosure' {
    BeforeAll {
        $script:FormatRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
        $script:Rng = [System.Random]::new(20240607)
        $alphabet = 'abcXYZ019._-+@ '.ToCharArray()
        $script:RandomTexts = 1..400 | ForEach-Object {
            $len = $script:Rng.Next(0, 14)
            -join (1..$len | ForEach-Object { $alphabet[$script:Rng.Next(0, $alphabet.Length)] })
        }
    }

    It 'accepts a random text if and only if it matches the address pattern' {
        foreach ($t in $script:RandomTexts) {
            $expected = [bool]($t -cmatch $script:FormatRegex)
            (Test-LabEmailFormat -Email $t) | Should -Be $expected -Because "text '$t'"
        }
    }

    It 'rejects <Text> as an address' -ForEach @(
        @{ Text = '' }
        @{ Text = 'plain' }
        @{ Text = 'no-at.example.com' }
        @{ Text = 'a@b' }
        @{ Text = 'a@@b.c' }
        @{ Text = 'a b@c.d' }
        @{ Text = 'a@b .c' }
        @{ Text = '@b.c' }
    ) {
        (Test-LabEmailFormat -Email $Text) | Should -BeFalse
    }

    It 'rejects a null address' {
        (Test-LabEmailFormat -Email $null) | Should -BeFalse
    }

    It 'never prints an accepted address in the resolver output for <Address>' -ForEach @(
        @{ Address = 'ana@example.com' }
        @{ Address = 'first.last+tag@sub.example.org' }
        @{ Address = 'x_y-z@a.b' }
    ) {
        $r = Invoke-Resolver -Email $Address
        $r.ExitCode | Should -Be 0
        $r.Output | Should -Not -BeLike "*$Address*"
        $r.Output | Should -Not -BeLike "*$($Address.Split('@')[0])*"
    }

    It 'never prints an accepted address that came from the environment or the file' {
        $fromEnv  = Invoke-Resolver -EnvValue 'from.env@example.com'
        $fromFile = Invoke-Resolver -FileValue 'from.file@example.com'
        $fromEnv.ExitCode  | Should -Be 0
        $fromFile.ExitCode | Should -Be 0
        $fromEnv.Output  | Should -Not -BeLike '*from.env@example.com*'
        $fromFile.Output | Should -Not -BeLike '*from.file@example.com*'
    }

    It 'rejects an invalid address with exit code 2 and does not echo it for <Address>' -ForEach @(
        @{ Address = 'secretvalue' }
        @{ Address = 'secret@nodot' }
    ) {
        $r = Invoke-Resolver -Email $Address
        $r.ExitCode | Should -Be 2
        $r.Output | Should -Not -BeLike "*$Address*"
    }
}

Describe 'Import-LabDotEnv keeps the process environment' {
    BeforeAll {
        $script:VarPrefix = 'LABTEST_' + [guid]::NewGuid().ToString('N').Substring(0, 8).ToUpper()
        $script:Rng2 = [System.Random]::new(777)
        function New-Token {
            -join (1..($script:Rng2.Next(1, 12)) | ForEach-Object { [char]$script:Rng2.Next(97, 123) })
        }
    }

    AfterEach {
        foreach ($n in 'A', 'B') {
            [Environment]::SetEnvironmentVariable("$($script:VarPrefix)_$n", $null, 'Process')
        }
    }

    It 'never overwrites a value already present and sets only absent or empty variables' {
        $nameSet   = "$($script:VarPrefix)_A"
        $nameEmpty = "$($script:VarPrefix)_B"
        foreach ($i in 1..40) {
            $existing = New-Token
            $fromFile = New-Token
            $file = Join-Path $script:Work "dotenv-$i"
            Set-Content -LiteralPath $file -Value @("$nameSet=$fromFile", "$nameEmpty=$fromFile") -Encoding UTF8

            [Environment]::SetEnvironmentVariable($nameSet, $existing, 'Process')
            [Environment]::SetEnvironmentVariable($nameEmpty, $null, 'Process')

            $loaded = Import-LabDotEnv -Path $file

            [Environment]::GetEnvironmentVariable($nameSet, 'Process')   | Should -BeExactly $existing
            [Environment]::GetEnvironmentVariable($nameEmpty, 'Process') | Should -BeExactly $fromFile
            $loaded | Should -Contain $nameEmpty
            $loaded | Should -Not -Contain $nameSet
        }
    }

    It 'treats an empty existing value as absent' {
        $name = "$($script:VarPrefix)_A"
        $file = Join-Path $script:Work 'dotenv-empty'
        Set-Content -LiteralPath $file -Value "$name=filled" -Encoding UTF8
        [Environment]::SetEnvironmentVariable($name, '', 'Process')

        Import-LabDotEnv -Path $file | Out-Null

        [Environment]::GetEnvironmentVariable($name, 'Process') | Should -BeExactly 'filled'
    }

    It 'does not fail when the file is missing' {
        { Import-LabDotEnv -Path (Join-Path $script:Work 'does-not-exist') } | Should -Not -Throw
    }
}
