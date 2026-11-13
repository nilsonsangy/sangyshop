<#
.SYNOPSIS
    Pester tests: the Azure full teardown fails cleanly when the cloud config has no Azure.Vm
    section, and still works when the section is present.
.DESCRIPTION
    Each case runs the script in a child PowerShell process (the failure used to depend on how
    exit behaves inside dot-sourced files). The child sets $global:LabAzHandler to a fake that
    answers every call with empty output, so no Azure call is ever made. The cloud config and
    the lab manifest are temporary files.
    Run: Invoke-Pester -Path ops/tests/AzureIrLab.ConfigMissing.Tests.ps1
#>
BeforeAll {
    $script:IrLabDir = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'ir-lab')).Path
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('azlab-cfg-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    $script:PwshExe = (Get-Process -Id $PID).Path

    $script:NoVmConfig = Join-Path $script:WorkDir 'no-vm.config.ps1'
    Set-Content -LiteralPath $script:NoVmConfig -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "labtest01"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Azure = @{ Location = "eastus"; ResourceGroup = "sangyshop-lab-rg" }
}
'@
    $script:VmConfig = Join-Path $script:WorkDir 'vm.config.ps1'
    Set-Content -LiteralPath $script:VmConfig -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "labtest01"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Azure = @{
        Location = "eastus"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "sangyshop-lab"; EvidenceGroupBase = "sangyshop-evidence" }
    }
}
'@

    function script:Invoke-Teardown {
        param([string]$Config, [string]$Script = 'full-teardown.ps1')
        $manifest = Join-Path $script:WorkDir 'manifest.json'
        $driver = Join-Path $script:WorkDir 'driver.ps1'
        $target = Join-Path $script:IrLabDir $Script
        Set-Content -LiteralPath $driver -Encoding UTF8 -Value @"
`$env:LAB_CLOUD_CONFIG_PATH = '$Config'
`$env:LAB_MANIFEST_PATH = '$manifest'
`$global:LabAzHandler = { param(`$a) if (`$a[0] -eq 'account' -and `$a[1] -eq 'show' -and `$a -contains 'id') { return [pscustomobject]@{ ExitCode = 0; Output = '00000000-0000-0000-0000-000000000000' } }; [pscustomobject]@{ ExitCode = 0; Output = '' } }
& '$target' -Subscription 00000000-0000-0000-0000-000000000000 -Region eastus -WhatIf
exit `$LASTEXITCODE
"@
        $out = & $script:PwshExe -NoProfile -ExecutionPolicy Bypass -File $driver 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
}

AfterAll {
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Azure full teardown with a missing Azure.Vm config section' {
    It 'exits with code 2 and one clear message, with no follow-on errors' {
        $r = Invoke-Teardown -Config $script:NoVmConfig
        $r.Code | Should -Be 2
        $r.Output | Should -Match 'could not load the cloud config'
        $r.Output | Should -Match 'Azure\.Vm'
        $r.Output | Should -Not -Match 'is not recognized'
        $r.Output | Should -Not -Match 'Initialize-Lab'
        $r.Output | Should -Not -Match 'Clear-LabTempFiles'
    }

    It 'works as before when the Azure.Vm section is present' {
        $r = Invoke-Teardown -Config $script:VmConfig
        $r.Code | Should -Be 0
        $r.Output | Should -Not -Match 'could not load the cloud config'
        $r.Output | Should -Not -Match 'is not recognized'
    }
}
