<#
.SYNOPSIS
    Pester 5.x tests for the Azure detection and blocker scripts under ops/azure/ir-lab.
.DESCRIPTION
    Covers the shared naming (every name comes from Get-VmLabNames through the cloud
    config), the optional alert e-mail (-Email, LAB_ALERT_EMAIL, format check, address
    never printed), the blocker defaults and the absence of leftover course or
    hard-coded names. The Azure CLI is never called: all calls go through the
    $global:LabAzHandler seam, and the blocker scripts only run their dry-run.
    Run with:
        Invoke-Pester -Path ops/tests/AzureIrLab.Detection.Tests.ps1
#>
BeforeAll {
    $script:AzDir = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'ir-lab')).Path
    $script:DetectionDir = Join-Path $script:AzDir 'detection'
    $script:BlockerDir = Join-Path $script:AzDir 'blocker'
    $script:VmNamesPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'vm' 'VmNames.ps1')).Path
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('azdet-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    function script:New-TestConfig {
        param([string]$Path, [string]$App = 'sangyshop', [string]$Suffix = 'abc12345', [string]$Location = 'eastus')
        $body = @"
@{
    UniqueSuffix = "$Suffix"
    Common = @{ AppName = "$App"; DbName = "$App"; DbUser = "$App"; ImageTag = "hardened" }
    Azure = @{
        Location = "$Location"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "$App-lab"; EvidenceGroupBase = "$App-evidence" }
    }
}
"@
        Set-Content -LiteralPath $Path -Value $body -Encoding UTF8
    }

    $script:CfgDefault = Join-Path $script:Work 'default.config.ps1'
    $script:CfgOther = Join-Path $script:Work 'other.config.ps1'
    New-TestConfig -Path $script:CfgDefault
    New-TestConfig -Path $script:CfgOther -App 'demoapp' -Suffix 'xyz98765' -Location 'westeurope'

    $script:PrevEnv = @{}
    foreach ($n in 'LAB_CLOUD_CONFIG_PATH', 'LAB_ALERT_EMAIL', 'LAB_MANIFEST_PATH') {
        $script:PrevEnv[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    $env:LAB_MANIFEST_PATH = Join-Path $script:Work 'manifest.json'

    # Fake Azure CLI: workspace exists, everything else is "not found" until created.
    $global:LabAzDetCalls = New-Object System.Collections.ArrayList
    $global:LabAzHandler = {
        param($a)
        [void]$global:LabAzDetCalls.Add(@($a))
        $words = @()
        foreach ($t in $a) { if ("$t".StartsWith('-')) { break }; $words += "$t" }
        $call = $words -join ' '
        switch -Exact ($call) {
            'account show' { return [pscustomobject]@{ ExitCode = 0; Output = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' } }
            'monitor log-analytics workspace show' {
                $o = '{"id":"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w","customerId":"c","tags":{"lab":"sangyshop-lab-azure"},"quota":1}'
                return [pscustomobject]@{ ExitCode = 0; Output = $o }
            }
            'monitor action-group create' { return [pscustomobject]@{ ExitCode = 0; Output = '{}' } }
            'monitor scheduled-query create' { return [pscustomobject]@{ ExitCode = 0; Output = '{}' } }
            default { return [pscustomobject]@{ ExitCode = 3; Output = 'ERROR: (ResourceNotFound) The Resource was not found.' } }
        }
    }

    function script:Invoke-LabScript {
        param([string]$Script, [hashtable]$Params = @{})
        $global:LabAzDetCalls.Clear()
        $global:LASTEXITCODE = $null
        $out = & $Script @Params *>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
}

AfterAll {
    foreach ($n in $script:PrevEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $script:PrevEnv[$n], 'Process') }
    $global:LabAzHandler = $null
    $global:LabAzDetCalls = $null
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Detection-Common naming' {
    It 'derives workspace, table, resource group and location from Get-VmLabNames' {
        $env:LAB_CLOUD_CONFIG_PATH = $script:CfgDefault
        . $script:VmNamesPath
        . (Join-Path $script:DetectionDir 'Detection-Common.ps1')
        $cfg = Get-CloudConfig -ConfigPath $script:CfgDefault -Cloud Azure -Modality vm
        $n = Get-VmLabNames -Config $cfg
        $script:LabWorkspaceName | Should -Be $n['Workspace']
        $script:LabAppTable | Should -Be $n['LogTable']
        $script:LabResourceGroup | Should -Be $n['LabGroup']
        $script:LabLocation | Should -Be $n['Location']
        $script:LabNsgName | Should -Be $n['Nsg']
        $script:LabVnetName | Should -Be $n['Vnet']
        $script:LabTagValue | Should -Be $script:VmLabName
    }

    It 'changes every derived name when the config changes' {
        $env:LAB_CLOUD_CONFIG_PATH = $script:CfgOther
        . (Join-Path $script:DetectionDir 'Detection-Common.ps1')
        $script:LabWorkspaceName | Should -Be 'demoapp-law-xyz98765'
        $script:LabLocation | Should -Be 'westeurope'
        $script:LabActionGroupName | Should -Be 'ag-demoapp-lab'
        $script:LabAlertRuleName | Should -Be 'demoapp-lab-bruteforce'
        $script:LabFlowLogName | Should -Be 'fl-demoapp-lab'
        $script:LabNsgBlockerName | Should -Be 'demoapp-lab-nsg-blocker'
        $script:LabBlockRulePrefix | Should -Be 'demoapp-lab-block-'
        $script:LabActionGroupShort.Length | Should -BeLessOrEqual 12
    }

    It 'masks secrets in the echoed command line' {
        $env:LAB_CLOUD_CONFIG_PATH = $script:CfgDefault
        . (Join-Path $script:DetectionDir 'Detection-Common.ps1')
        $secret = 'AKIAABCDEFGHIJKLMNOP'
        $out = (Invoke-LabAz -CliArgs @('tag', 'update', '--tags', "key=$secret") *>&1) | Out-String
        $out | Should -Not -Match $secret
    }
}

Describe 'enable-alerts.ps1 and enable-all.ps1 alert e-mail' {
    BeforeEach {
        $env:LAB_CLOUD_CONFIG_PATH = $script:CfgDefault
        Remove-Item Env:\LAB_ALERT_EMAIL -ErrorAction SilentlyContinue
    }

    It 'uses LAB_ALERT_EMAIL when -Email is omitted and never prints the address' {
        $env:LAB_ALERT_EMAIL = 'owner.test@example.com'
        $r = Invoke-LabScript -Script (Join-Path $script:DetectionDir 'enable-alerts.ps1') -Params @{ Subscription = 'sub'; ResourceGroup = 'rg-x' }
        $r.Code | Should -Be 0
        $r.Output | Should -Not -Match 'owner\.test@example\.com'
        $create = @($global:LabAzDetCalls | Where-Object { ($_ -join ' ') -match '^monitor action-group create' })
        $create.Count | Should -Be 1
        ($create[0] -join ' ') | Should -Match 'owner\.test@example\.com'
    }

    It 'prefers -Email over LAB_ALERT_EMAIL' {
        $env:LAB_ALERT_EMAIL = 'from.env@example.com'
        $r = Invoke-LabScript -Script (Join-Path $script:DetectionDir 'enable-alerts.ps1') -Params @{ Subscription = 'sub'; ResourceGroup = 'rg-x'; Email = 'from.param@example.com' }
        $r.Code | Should -Be 0
        $create = @($global:LabAzDetCalls | Where-Object { ($_ -join ' ') -match '^monitor action-group create' })
        ($create[0] -join ' ') | Should -Match 'from\.param@example\.com'
        ($create[0] -join ' ') | Should -Not -Match 'from\.env@example\.com'
    }

    It 'defaults the resource group and names to the VM lab names' {
        $env:LAB_ALERT_EMAIL = 'owner.test@example.com'
        $null = Invoke-LabScript -Script (Join-Path $script:DetectionDir 'enable-alerts.ps1') -Params @{ Subscription = 'sub' }
        $create = @($global:LabAzDetCalls | Where-Object { ($_ -join ' ') -match '^monitor action-group create' })
        $line = $create[0] -join ' '
        $line | Should -Match '--resource-group sangyshop-lab '
        $line | Should -Match '--name ag-sangyshop-lab '
    }

    It 'exits 2 on a malformed address and creates nothing' {
        $env:LAB_ALERT_EMAIL = 'not-an-address'
        $r = Invoke-LabScript -Script (Join-Path $script:DetectionDir 'enable-alerts.ps1') -Params @{ Subscription = 'sub'; ResourceGroup = 'rg-x' }
        $r.Code | Should -Be 2
        @($global:LabAzDetCalls | Where-Object { ($_ -join ' ') -match ' create ' }).Count | Should -Be 0
    }

    It 'enable-all.ps1 validates the address before it runs any component' {
        $env:LAB_ALERT_EMAIL = 'not-an-address'
        $r = Invoke-LabScript -Script (Join-Path $script:DetectionDir 'enable-all.ps1') -Params @{ Subscription = 'sub'; ResourceGroup = 'rg-x'; Region = 'eastus'; WhatIf = $true }
        $r.Code | Should -Be 2
        $global:LabAzDetCalls.Count | Should -Be 0
    }
}

Describe 'Blocker scripts' {
    BeforeEach { $env:LAB_CLOUD_CONFIG_PATH = $script:CfgDefault }

    It 'deploy-blocker.ps1 dry-run defaults every name from the VM lab and makes no Azure call' {
        $r = Invoke-LabScript -Script (Join-Path $script:BlockerDir 'deploy-blocker.ps1') -Params @{ Subscription = 'sub-id' }
        $r.Code | Should -Be 0
        $r.Output | Should -Match 'sangyshop-lab-nsg-blocker'
        $r.Output | Should -Match 'sangyshop-vm-nsg'
        $r.Output | Should -Match 'ag-sangyshop-lab'
        $r.Output | Should -Match 'dry-run'
        $global:LabAzDetCalls.Count | Should -Be 0
    }

    It 'remove-blocker.ps1 dry-run uses the derived block rule prefix' {
        $r = Invoke-LabScript -Script (Join-Path $script:BlockerDir 'remove-blocker.ps1') -Params @{ Subscription = 'sub-id' }
        $r.Code | Should -Be 0
        $r.Output | Should -Match 'sangyshop-lab-block-\*'
        $global:LabAzDetCalls.Count | Should -Be 0
    }

    It 'follows a different config instead of fixed names' {
        $env:LAB_CLOUD_CONFIG_PATH = $script:CfgOther
        $r = Invoke-LabScript -Script (Join-Path $script:BlockerDir 'deploy-blocker.ps1') -Params @{ Subscription = 'sub-id' }
        $r.Output | Should -Match 'demoapp-lab-nsg-blocker'
        $r.Output | Should -Not -Match 'sangyshop-(lab|vm)'
    }

    It 'keeps the role template and the Logic App template parameterized' {
        $role = Get-Content -LiteralPath (Join-Path $script:BlockerDir 'policies' 'nsg-blocker.role.json') -Raw | ConvertFrom-Json
        $role.Name | Should -Be '__ROLE_NAME__'
        $role.AssignableScopes[0] | Should -Be '__NSG_RESOURCE_ID__'
        $tpl = Get-Content -LiteralPath (Join-Path $script:BlockerDir 'logic-app.template.json') -Raw | ConvertFrom-Json
        $tpl.parameters.PSObject.Properties.Name | Should -Contain 'blockRulePrefix'
        (Get-Content -LiteralPath (Join-Path $script:BlockerDir 'logic-app.template.json') -Raw) | Should -Not -Match 'sangyshop'
    }
}

Describe 'Detection and blocker sources' {
    BeforeAll {
        $script:Sources = @(Get-ChildItem -LiteralPath $script:DetectionDir, $script:BlockerDir -Recurse -File)
    }

    It 'contain no em dash, en dash, spec numbering or course wording' {
        $dash = '[' + [char]0x2014 + [char]0x2013 + ']'
        foreach ($f in $script:Sources) {
            $text = Get-Content -LiteralPath $f.FullName -Raw
            $text | Should -Not -Match $dash -Because $f.Name
            $text | Should -Not -Match ('(?i)requirement \d|design D-\d|task \d+\.\d+|prof' + 'essor|\bau' + 'la\b|stu' + 'dent') -Because $f.Name
        }
    }

    It 'do not hard-code the old workspace name or reach into a sibling NimbusDFIR folder' {
        foreach ($f in $script:Sources | Where-Object { $_.Extension -eq '.ps1' }) {
            $text = Get-Content -LiteralPath $f.FullName -Raw
            $text | Should -Not -Match 'law-sangyshop-lab' -Because $f.Name
            $text | Should -Not -Match "'\.\.\\\.\.\\\.\.\\ir_lab_core" -Because $f.Name
        }
    }
}
