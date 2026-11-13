<#
.SYNOPSIS
    Pester test: ensure-lab-group.ps1 reaches the real AWS CLI path under strict mode when no
    test handler ($global:LabCliHandler) is defined.

.DESCRIPTION
    A real run has no handler. Reading an unset global variable under Set-StrictMode used to
    fail with "The variable '$global:LabCliHandler' cannot be retrieved because it has not been
    set". This test runs ensure-lab-group.ps1 -Describe in a CHILD pwsh process with strict mode
    on and no handler, with a fake 'aws' command found through a temporary directory that is
    prepended to the PATH of the child only. The fake records each call and prints a harmless
    JSON. The real AWS CLI is never called, and the parent PATH is never changed.

    Run: Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path ops/tests/LabGroup.StrictNoHandler.Tests.ps1
#>

BeforeAll {
    $script:OpsDir = Split-Path -Parent $PSScriptRoot
    $script:Script = Join-Path $script:OpsDir 'aws\iam\ensure-lab-group.ps1'
    $script:PwshExe = (Get-Process -Id $PID).Path
    $script:PathBefore = $env:PATH

    $script:ShimDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-fake-aws-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:ShimDir -Force | Out-Null
    $script:CallLog = Join-Path $script:ShimDir 'calls.log'

    if ($IsLinux -or $IsMacOS) {
        $shim = Join-Path $script:ShimDir 'aws'
        Set-Content -LiteralPath $shim -Encoding ASCII -Value @(
            '#!/bin/sh'
            'echo "$@" >> "' + $script:CallLog + '"'
            'echo "{}"'
            'exit 0'
        )
        & chmod +x $shim
    }
    else {
        $shim = Join-Path $script:ShimDir 'aws.cmd'
        Set-Content -LiteralPath $shim -Encoding ASCII -Value @(
            '@echo off'
            ('echo %* >> "' + $script:CallLog + '"')
            'echo {}'
            'exit /b 0'
        )
    }

    # Child: strict mode on, no handler variable anywhere, fake aws first on the child PATH only.
    $script:ChildFile = Join-Path $script:ShimDir 'child.ps1'
    Set-Content -LiteralPath $script:ChildFile -Encoding UTF8 -Value @'
param([string] $Target, [string] $Shim)
Set-StrictMode -Version Latest
$env:PATH = $Shim + [System.IO.Path]::PathSeparator + $env:PATH
if (Test-Path -LiteralPath 'variable:global:LabCliHandler') { Write-Output 'HANDLER-UNEXPECTEDLY-SET'; exit 9 }
& $Target -Describe -Region us-east-1
exit $LASTEXITCODE
'@
}

AfterAll {
    if ($script:ShimDir -and (Test-Path -LiteralPath $script:ShimDir)) {
        Remove-Item -LiteralPath $script:ShimDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'ensure-lab-group.ps1 without a test handler under strict mode' {

    It 'reaches the real aws CLI path without the strict-mode variable error' {
        $out = & $script:PwshExe -NoProfile -NonInteractive -File $script:ChildFile `
            -Target $script:Script -Shim $script:ShimDir 2>&1 | ForEach-Object { "$_" }
        $text = $out -join "`n"

        $text | Should -Not -Match 'HANDLER-UNEXPECTEDLY-SET'
        $text | Should -Not -Match 'LabCliHandler'
        $text | Should -Not -Match 'has not been set'

        # The fake aws was reached: at least one recorded call, and the first one is the identity read.
        Test-Path -LiteralPath $script:CallLog | Should -BeTrue -Because "the fake aws was never called. Output: $text"
        $calls = @(Get-Content -LiteralPath $script:CallLog)
        $calls.Count | Should -BeGreaterThan 0
        ($calls -join "`n") | Should -Match '--region us-east-1'
    }

    It 'leaves the PATH of this process untouched' {
        $env:PATH | Should -BeExactly $script:PathBefore
    }
}
