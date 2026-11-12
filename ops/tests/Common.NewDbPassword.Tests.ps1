<#
.SYNOPSIS
    Pester 5.x unit tests for New-DbPassword (lib/Common.ps1, task 2.6).

.DESCRIPTION
    Verifies the DB-password generator's security contract:

      * Req 4.4 - every generated password is at least 24 characters long (the
        hard floor is enforced even when a smaller -Length is requested) and
        always contains all four character classes: lowercase, uppercase,
        digits, and a symbol from the restricted set -_.=+*#%.

      * Req 3.2 - the generated value is the function's ONLY output and never
        leaks to the host / an echoed transcript. These tests capture everything
        the function writes to Write-Host and the information/success/stdout
        streams during generation and assert the password never appears there.

    Requires Pester 5.x (see tests/README.md). Windows PowerShell 5.1 ships with
    the legacy Pester 3.4.0, which is NOT compatible with this file's syntax.
    Run with:
        Invoke-Pester -Path ops/tests/Common.NewDbPassword.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1'
    . $script:CommonPath

    # The exact character classes New-DbPassword draws from (must match Common.ps1).
    $script:Lower   = 'abcdefghijklmnopqrstuvwxyz'
    $script:Upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $script:Digits  = '0123456789'
    $script:Symbols = '-_.=+*#%'
    $script:AllChars = $script:Lower + $script:Upper + $script:Digits + $script:Symbols

    function Test-HasClass {
        param([string] $Password, [string] $ClassChars)
        $set = [System.Collections.Generic.HashSet[char]]::new([char[]]$ClassChars)
        foreach ($c in $Password.ToCharArray()) {
            if ($set.Contains($c)) { return $true }
        }
        return $false
    }
}

Describe 'New-DbPassword length and floor (Req 4.4)' {
    # 1 and 24 exercise the floor; 32 is the default; 40 is above the floor.
    It 'returns at least 24 characters for -Length <Length>' -ForEach @(
        @{ Length = 1 }
        @{ Length = 24 }
        @{ Length = 32 }
        @{ Length = 40 }
    ) {
        $pw = New-DbPassword -Length $Length
        $pw.Length | Should -BeGreaterOrEqual 24
    }

    It 'honors an explicit length at or above the floor for -Length <Length>' -ForEach @(
        @{ Length = 24 }
        @{ Length = 32 }
        @{ Length = 40 }
    ) {
        $pw = New-DbPassword -Length $Length
        $pw.Length | Should -Be $Length
    }

    It 'floors sub-minimum requests to exactly 24 for -Length <Length>' -ForEach @(
        @{ Length = 1 }
        @{ Length = 0 }
        @{ Length = -5 }
    ) {
        $pw = New-DbPassword -Length $Length
        $pw.Length | Should -Be 24
    }

    It 'defaults to a 32-character password when -Length is omitted' {
        $pw = New-DbPassword
        $pw.Length | Should -Be 32
    }
}

Describe 'New-DbPassword character classes (Req 4.4)' {
    It 'includes all four character classes for -Length <Length>' -ForEach @(
        @{ Length = 1 }
        @{ Length = 24 }
        @{ Length = 32 }
        @{ Length = 40 }
    ) {
        $pw = New-DbPassword -Length $Length
        (Test-HasClass -Password $pw -ClassChars $script:Lower)   | Should -BeTrue -Because 'a lowercase letter is guaranteed'
        (Test-HasClass -Password $pw -ClassChars $script:Upper)   | Should -BeTrue -Because 'an uppercase letter is guaranteed'
        (Test-HasClass -Password $pw -ClassChars $script:Digits)  | Should -BeTrue -Because 'a digit is guaranteed'
        (Test-HasClass -Password $pw -ClassChars $script:Symbols) | Should -BeTrue -Because 'a symbol is guaranteed'
    }

    It 'uses only characters from the allowed set for -Length <Length>' -ForEach @(
        @{ Length = 24 }
        @{ Length = 32 }
        @{ Length = 40 }
    ) {
        $pw = New-DbPassword -Length $Length
        $allowed = [System.Collections.Generic.HashSet[char]]::new([char[]]$script:AllChars)
        foreach ($c in $pw.ToCharArray()) {
            $allowed.Contains($c) | Should -BeTrue -Because "'$c' must come from the restricted class set"
        }
    }
}

Describe 'New-DbPassword does not leak to an echoed transcript (Req 3.2)' {
    It 'never prints the generated value to any output stream for -Length <Length>' -ForEach @(
        @{ Length = 1 }
        @{ Length = 24 }
        @{ Length = 32 }
        @{ Length = 40 }
    ) {
        # Capture everything the function emits to the host / non-return streams.
        # In PowerShell, Write-Host writes to the Information stream (6>&1) and
        # anything accidentally written to stdout would come back on the success
        # stream. We separate the real return value (the password) from the
        # transcript by capturing streams 6/5/3 and stripping the returned object.
        $transcriptLines = [System.Collections.Generic.List[string]]::new()

        # 6>&1 folds the Information stream (Write-Host) into the success stream so
        # it is captured alongside any stray stdout. The function's return value is
        # the LAST element; everything before it is "transcript".
        $captured = New-DbPassword -Length $Length 6>&1 5>&1 3>&1
        $captured = @($captured)

        # The real return value is the final emitted object (the password string).
        $pw = [string]$captured[$captured.Count - 1]
        $pw.Length | Should -BeGreaterOrEqual 24

        # Everything emitted BEFORE the return value is host/echo transcript.
        for ($i = 0; $i -lt $captured.Count - 1; $i++) {
            $transcriptLines.Add([string]$captured[$i])
        }
        $transcript = ($transcriptLines -join "`n")

        # The password must not appear anywhere in the echoed transcript.
        $transcript | Should -Not -BeLike "*$pw*" -Because 'the secret must never be echoed to the host'
    }

    It 'emits the password as its only success-stream output for -Length <Length>' -ForEach @(
        @{ Length = 24 }
        @{ Length = 32 }
    ) {
        # Without stream redirection, the success stream (what a caller captures in
        # `$x = New-DbPassword`) must be exactly one string: the password.
        $result = New-DbPassword -Length $Length
        @($result).Count | Should -Be 1
        $result | Should -BeOfType [string]
    }
}
