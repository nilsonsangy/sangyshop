<#
.SYNOPSIS
    Pester 5.x unit tests for Invoke-Echoed (lib/Common.ps1, task 2.1).

.DESCRIPTION
    Covers Requirements 1.1, 1.2, 1.4, 1.5, 1.6:
      * 1.1 - the exact command line (exe + every arg, in order) is printed
              to stdout BEFORE the command runs.
      * 1.2 - arguments with whitespace / quotes / shell metacharacters are
              quoted-or-escaped in the printed line; simple args are not.
      * 1.4 - arguments are handed to the executable as a discrete array, with
              no shell / string (Invoke-Expression) evaluation, so an arg full
              of shell metacharacters reaches the exe verbatim.
      * 1.5 - a non-zero exit WITHOUT -AllowFail throws a terminating error that
              names the failed command and its exit code.
      * 1.6 - a non-zero exit WITH -AllowFail returns control and exposes the
              exit code ($LASTEXITCODE) to the caller.

    Requires Pester 5.x (see tests/README.md). Run with:
        Invoke-Pester -Path deployment-security/cloud/tests/Common.InvokeEchoed.Tests.ps1

    The external command used throughout is the CURRENT PowerShell host
    (pwsh / powershell). That keeps the tests cross-platform and CI-safe: no
    cloud CLI, no bash/sh, and a REAL executable so array-passing can be
    asserted against actual process argv. Argument-passing cases run the host
    with -File against a tiny temp script that echoes its $args, which gives a
    clean discrete-argv channel without the -Command line-reparse quirk.
#>

BeforeAll {
    $script:CommonPath = Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1'
    . $script:CommonPath

    # Resolve the current PowerShell executable so the tests run a REAL process
    # regardless of host (PowerShell 7 'pwsh' or Windows PowerShell 'powershell').
    $script:PwshExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($script:PwshExe)) {
        $cmd = Get-Command -Name pwsh -ErrorAction SilentlyContinue
        if ($cmd) { $script:PwshExe = $cmd.Source }
    }
    if ([string]::IsNullOrWhiteSpace($script:PwshExe)) {
        $cmd = Get-Command -Name powershell -ErrorAction SilentlyContinue
        if ($cmd) { $script:PwshExe = $cmd.Source }
    }

    # Temp script that prints each argument it receives on its own line, framed
    # with sentinels. Invoked via `-File`, so everything after it on the command
    # line arrives as discrete $args - the true argv the child process saw. This
    # lets us prove Invoke-Echoed did NOT route through a shell (Req 1.4).
    $script:EchoArgsScript = Join-Path ([System.IO.Path]::GetTempPath()) ("echoargs_{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    @'
foreach ($a in $args) {
    [Console]::Out.WriteLine("<<ARG>>" + $a + "<<END>>")
}
'@ | Set-Content -LiteralPath $script:EchoArgsScript -Encoding UTF8

    # Build the -File arg list: host runs the echo script with the given extra
    # args appended as discrete argv entries (no shell involved).
    function script:New-EchoArgs {
        param([string[]] $Extra)
        $base = @('-NoProfile', '-File', $script:EchoArgsScript)
        if ($Extra) { $base += $Extra }
        return $base
    }
}

AfterAll {
    if ($script:EchoArgsScript -and (Test-Path -LiteralPath $script:EchoArgsScript)) {
        Remove-Item -LiteralPath $script:EchoArgsScript -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Invoke-Echoed' {

    Context 'Req 1.1 / 1.2 - echoes the exact, correctly-quoted command line before executing' {

        BeforeEach {
            # Capture every Write-Host call so we can inspect the printed line.
            # (Invoke-Echoed prints with Write-Host "> ..." in Cyan.)
            $script:Printed = New-Object System.Collections.Generic.List[string]
            Mock Write-Host { $script:Printed.Add([string]$Object) } -ParameterFilter { $true }
        }

        It 'prints the executable followed by every argument in order' {
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @('alpha', 'beta')) | Out-Null

            # The first captured Write-Host is the "> <cmd>" echo line.
            $line = $script:Printed[0]
            $line | Should -Match '^> '

            $exeLeaf = Split-Path -Leaf $script:PwshExe
            $line | Should -Match ([regex]::Escape($exeLeaf))

            # Arguments appear in the order passed.
            $idxNoProfile = $line.IndexOf('-NoProfile')
            $idxFile      = $line.IndexOf('-File')
            $idxAlpha     = $line.IndexOf('alpha')
            $idxBeta      = $line.IndexOf('beta')
            $idxNoProfile | Should -BeGreaterThan 0
            $idxFile      | Should -BeGreaterThan $idxNoProfile
            $idxBeta      | Should -BeGreaterThan $idxAlpha
        }

        It 'prints the command line BEFORE the command executes' {
            # The child writes a marker to stdout; Invoke-Echoed re-emits that
            # stdout via Write-Host AFTER the "> ..." echo line. So the echo line
            # must be captured strictly before the command's own output marker.
            $marker = 'CHILD_RAN_MARKER_7f3a'
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @($marker)) | Out-Null

            $echoIndex   = -1
            $markerIndex = -1
            for ($i = 0; $i -lt $script:Printed.Count; $i++) {
                if ($echoIndex -lt 0 -and $script:Printed[$i] -like '> *') { $echoIndex = $i }
                if ($markerIndex -lt 0 -and $script:Printed[$i] -like "*<<ARG>>$marker<<END>>*") { $markerIndex = $i }
            }

            $echoIndex   | Should -BeGreaterOrEqual 0
            $markerIndex | Should -BeGreaterThan $echoIndex
        }

        It 'does NOT quote simple arguments' {
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @('simple')) | Out-Null
            $line = $script:Printed[0]
            # A plain flag like -NoProfile must appear bare, never wrapped in quotes.
            $line | Should -Match '(^|\s)-NoProfile(\s|$)'
            $line | Should -Not -Match '"-NoProfile"'
            $line | Should -Not -Match '"simple"'
        }

        It 'quotes an argument that contains whitespace' {
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @('hello world')) | Out-Null
            $line = $script:Printed[0]
            # The space-bearing token must be wrapped so it stays a single argument.
            $line | Should -Match '"hello world"'
        }

        It 'quotes and escapes an argument that contains a double quote' {
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @('a"b')) | Out-Null
            $line = $script:Printed[0]
            # Embedded double quote is backslash-escaped inside a quoted token: "a\"b"
            $line | Should -Match '"a\\"b"'
        }

        It 'quotes an argument that contains shell metacharacters' {
            $meta = 'a;b|c&d>e'
            Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @($meta)) | Out-Null
            $line = $script:Printed[0]
            # The metacharacter token must be quoted so the printed line is a
            # single runnable command, not an accidental pipeline/redirect.
            $line | Should -Match ('"' + [regex]::Escape($meta) + '"')
        }
    }

    Context 'Req 1.4 - arguments are passed as a discrete array (no shell / string evaluation)' {

        It 'passes a shell-metacharacter argument to the executable verbatim' {
            # If Invoke-Echoed used a shell or Invoke-Expression, this token would
            # be split on ';' / '|' / '&' or trigger a redirect. As a discrete
            # argv element it must arrive at the child EXACTLY as written, framed
            # by the echo script's sentinels.
            $payload = 'a;b|c & echo d > e'
            $out = Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @($payload)) 6>$null

            ($out -join "`n") | Should -Match ([regex]::Escape("<<ARG>>$payload<<END>>"))
        }

        It 'preserves multiple distinct arguments as separate argv entries' {
            # Three separate args must come back as three separately-framed lines -
            # proof they were not concatenated or re-split by a shell.
            $a1 = 'first arg'
            $a2 = 'second"quoted"'
            $a3 = 'third;meta'
            $out = Invoke-Echoed -Exe $script:PwshExe -CmdArgs (script:New-EchoArgs @($a1, $a2, $a3)) 6>$null

            $joined = ($out -join "`n")
            $joined | Should -Match ([regex]::Escape("<<ARG>>$a1<<END>>"))
            $joined | Should -Match ([regex]::Escape("<<ARG>>$a2<<END>>"))
            $joined | Should -Match ([regex]::Escape("<<ARG>>$a3<<END>>"))
        }
    }

    Context 'Req 1.5 - non-zero exit throws without -AllowFail' {

        It 'throws a terminating error on a non-zero exit' {
            {
                Invoke-Echoed -Exe $script:PwshExe `
                    -CmdArgs @('-NoProfile', '-Command', 'exit 3') 6>$null
            } | Should -Throw
        }

        It 'names the failed command and the exit code in the error' {
            $err = $null
            try {
                Invoke-Echoed -Exe $script:PwshExe `
                    -CmdArgs @('-NoProfile', '-Command', 'exit 42') 6>$null
            }
            catch {
                $err = $_
            }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -Match 'exit 42'
            $err.Exception.Message | Should -Match 'Command failed'
        }

        It 'does not throw when the command exits zero' {
            {
                Invoke-Echoed -Exe $script:PwshExe `
                    -CmdArgs @('-NoProfile', '-Command', 'exit 0') 6>$null
            } | Should -Not -Throw
        }
    }

    Context 'Req 1.6 - non-zero exit with -AllowFail returns control and exposes the exit code' {

        It 'does not throw when -AllowFail is set and the command fails' {
            {
                Invoke-Echoed -Exe $script:PwshExe `
                    -CmdArgs @('-NoProfile', '-Command', 'exit 7') -AllowFail 6>$null
            } | Should -Not -Throw
        }

        It 'makes the non-zero exit code available via $LASTEXITCODE' {
            Invoke-Echoed -Exe $script:PwshExe `
                -CmdArgs @('-NoProfile', '-Command', 'exit 7') -AllowFail 6>$null | Out-Null
            $LASTEXITCODE | Should -Be 7
        }

        It 'returns control for a successful command and sets exit code 0' {
            Invoke-Echoed -Exe $script:PwshExe `
                -CmdArgs @('-NoProfile', '-Command', 'exit 0') -AllowFail 6>$null | Out-Null
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context 'Regression - a same-named wrapper function cannot shadow the external executable' {
        # The real bug: deploy/teardown scripts define wrapper functions (Az, AzTry,
        # Docker) that call Invoke-Echoed, which then invoked `& $Exe`. Because
        # PowerShell resolves Function > Cmdlet > Application (case-insensitively),
        # `& 'az'` resolved back to the 'Az' FUNCTION, re-entering Invoke-Echoed and
        # recursing until the call stack overflowed. These tests define a function
        # whose name matches, case-insensitively, the executable leaf Invoke-Echoed
        # is asked to run, then assert the REAL external process runs instead.

        It 'runs the external process (no recursion) when a wrapper function shares the exe name' {
            $exeLeaf = [System.IO.Path]::GetFileNameWithoutExtension($script:PwshExe)
            $marker  = 'NO_RECURSION_MARKER_b19c'

            # Define a wrapper function named exactly like the executable leaf. If
            # Invoke-Echoed resolved by name instead of to the Application, `& $Exe`
            # would call THIS function, recurse, and overflow the stack.
            $wrapperBody = @"
function $exeLeaf {
    param([Parameter(ValueFromRemainingArguments = `$true)] `$Rest)
    Invoke-Echoed -Exe '$exeLeaf' -CmdArgs @(`$Rest)
}
"@
            . ([scriptblock]::Create($wrapperBody))

            # Invoke via the bare leaf name so resolution would hit the wrapper first.
            $out = Invoke-Echoed -Exe $exeLeaf `
                -CmdArgs (script:New-EchoArgs @($marker)) 6>$null

            # The real host process ran the echo script and framed the marker.
            ($out -join "`n") | Should -Match ([regex]::Escape("<<ARG>>$marker<<END>>"))
        }

        It 'resolves case-insensitively past an upper-cased wrapper function to the real binary' {
            $exeLeaf   = [System.IO.Path]::GetFileNameWithoutExtension($script:PwshExe)
            $upperLeaf = $exeLeaf.ToUpperInvariant()
            $marker    = 'CASE_INSENSITIVE_MARKER_5d8e'

            # A differently-cased wrapper still shadows by name (function names are
            # case-insensitive). Resolving to the Application sidesteps it entirely.
            $wrapperBody = @"
function $upperLeaf {
    param([Parameter(ValueFromRemainingArguments = `$true)] `$Rest)
    Invoke-Echoed -Exe '$upperLeaf' -CmdArgs @(`$Rest)
}
"@
            . ([scriptblock]::Create($wrapperBody))

            $out = Invoke-Echoed -Exe $upperLeaf `
                -CmdArgs (script:New-EchoArgs @($marker)) 6>$null

            ($out -join "`n") | Should -Match ([regex]::Escape("<<ARG>>$marker<<END>>"))
        }

        It 'throws a clear, readable error when the executable is not found on PATH' {
            # Missing CLI must fail fast with a named error, NOT fall back to `& $Exe`
            # (which would re-enter a wrapper) or overflow the stack.
            $missing = 'definitely-not-a-real-exe-6a2f1c'
            { Invoke-Echoed -Exe $missing -CmdArgs @('--version') 6>$null } |
                Should -Throw -ExpectedMessage "*$missing*"
        }
    }
}
