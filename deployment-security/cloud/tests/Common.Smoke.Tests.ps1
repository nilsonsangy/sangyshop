<#
.SYNOPSIS
    Smoke test: confirms lib/Common.ps1 dot-sources cleanly and exposes the four
    stub functions the later tasks fill in.

    Requires Pester 5.x (see tests/README.md). Run with:
        Invoke-Pester -Path deployment-security/cloud/tests/Common.Smoke.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1'
    . $script:CommonPath
}

Describe 'lib/Common.ps1 scaffold' {
    It 'exists on disk' {
        Test-Path $script:CommonPath | Should -BeTrue
    }

    It 'defines the <Name> function' -ForEach @(
        @{ Name = 'Invoke-Echoed' }
        @{ Name = 'Write-Step' }
        @{ Name = 'Get-CloudConfig' }
        @{ Name = 'New-DbPassword' }
    ) {
        Get-Command -Name $Name -CommandType Function -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty
    }
}
