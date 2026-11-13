<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the Azure VM lab scripts
    (azure/vm/deploy.ps1 and azure/vm/teardown.ps1).

.DESCRIPTION
    Covers the guarantee that a simulation executes no external command, for the
    Azure VM modality.

    Each script runs in a FRESH child PowerShell against a well-formed temporary
    config written under $TestDrive. Nothing here touches a real cloud.

    "No external command runs" is proven two ways:
      1. SENTINEL SHIMS: a temp directory holding aws/az/docker/kubectl/gcloud .cmd
         shims is put FIRST on PATH. Any shim that is ever invoked appends a line to
         a sentinel file. After every -WhatIf run the sentinel file must not exist.
      2. DRY-RUN TRANSCRIPT: the scripts print the ordered planned list as
         "[ n] az ..." lines and a "DRY RUN complete" footer; the list must be
         non-empty and every line must be an `az ...` command.

    Source validation is checked as a fail-closed gate:
    0.0.0.0/0, ::/0, a missing value and anything that is not exactly a single-host
    IPv4 /32 make deploy.ps1 exit non-zero BEFORE any planned command is produced.

    Run with:
        Invoke-Pester -Path ops/tests/Azure.Vm.WhatIf.Tests.ps1
#>

BeforeDiscovery {
    $script:BadSources = @(
        @{ Label = '0.0.0.0/0';          Value = '0.0.0.0/0' }
        @{ Label = '::/0';               Value = '::/0' }
        @{ Label = '0.0.0.0/32';         Value = '0.0.0.0/32' }
        @{ Label = 'bare IP (no mask)';  Value = '203.0.113.7' }
        @{ Label = '/24 network';        Value = '203.0.113.0/24' }
        @{ Label = '/31 network';        Value = '203.0.113.7/31' }
        @{ Label = '/16 network';        Value = '10.0.0.0/16' }
        @{ Label = 'IPv6 /128';          Value = '2001:db8::1/128' }
        @{ Label = 'wildcard *';         Value = '*' }
        @{ Label = 'Internet';           Value = 'Internet' }
        @{ Label = 'Any';                Value = 'Any' }
        @{ Label = 'octet out of range'; Value = '256.1.1.1/32' }
    )
}

BeforeAll {
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'vm' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'vm' 'teardown.ps1')).Path

    # ---- Valid temporary Azure config (VM modality block included). ----------
    $script:ConfigPath = Join-Path $TestDrive 'cloud.config.ps1'
    $configBody = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Azure = @{
        Location      = "eastus"
        ResourceGroup = "sangyshop-lab-rg"
        AcrNameBase   = "sangyshoplab"
        KeyVaultBase  = "sangyshop-kv"
        AciName       = "sangyshop-lab-aci"
        AksCluster    = "sangyshop-lab-aks"
        Vm = @{
            VmSize            = "Standard_B1ms"
            PgSku             = "Standard_B1ms"
            PgStorageGb       = 32
            ResourceGroupBase = "sangyshop-lab"
            EvidenceGroupBase = "sangyshop-evidence"
        }
    }
}
'@
    Set-Content -LiteralPath $script:ConfigPath -Value $configBody -Encoding UTF8

    # ---- Sentinel shims: any real CLI invocation leaves a trace. --------------
    $script:ShimDir  = Join-Path $TestDrive 'shims'
    $script:Sentinel = Join-Path $TestDrive 'external-command-was-run.txt'
    New-Item -ItemType Directory -Path $script:ShimDir -Force | Out-Null
    foreach ($cli in 'aws', 'az', 'docker', 'kubectl', 'gcloud') {
        $shim = "@echo off`r`necho $cli %* >> `"%LAB_SENTINEL%`"`r`nexit /b 1`r`n"
        Set-Content -LiteralPath (Join-Path $script:ShimDir "$cli.cmd") -Value $shim -Encoding ASCII
    }
    $script:SavedPath     = $env:PATH
    $script:SavedSentinel = $env:LAB_SENTINEL
    $env:PATH         = $script:ShimDir + [System.IO.Path]::PathSeparator + $env:PATH
    $env:LAB_SENTINEL = $script:Sentinel

    $script:PsExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($script:PsExe)) { $script:PsExe = 'powershell' }

    function Invoke-WhatIfScript {
        param(
            [Parameter(Mandatory)][string]   $ScriptPath,
            [string[]] $ExtraArgs = @(),
            [string[]] $Ranges
        )
        if (Test-Path -LiteralPath $script:Sentinel) { Remove-Item -LiteralPath $script:Sentinel -Force }
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath,
            '-ConfigPath', $script:ConfigPath) + $ExtraArgs
        if ($Ranges) {
            # -File cannot bind a string[] from several words, so use -Command.
            $list = ($Ranges | ForEach-Object { "'$_'" }) -join ','
            $cmd  = "`$global:LASTEXITCODE = 0; & '$ScriptPath' -ConfigPath '$script:ConfigPath' -AllowedSourceRanges $list -WhatIf; exit `$LASTEXITCODE"
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd)
        }
        $out  = & $script:PsExe @argList *>&1
        $code = $LASTEXITCODE
        $ran  = Test-Path -LiteralPath $script:Sentinel
        return [pscustomobject]@{
            ExitCode        = $code
            Text            = ($out | Out-String)
            Lines           = @($out | ForEach-Object { [string]$_ })
            ExternalWasRun  = $ran
            ExternalCalls   = $(if ($ran) { Get-Content -LiteralPath $script:Sentinel -Raw } else { '' })
        }
    }

    # Planned commands are printed as "[ n] <command>" (ordinal right-aligned).
    function Get-PlannedCommands {
        param([Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]] $Lines)
        $planned = New-Object System.Collections.Generic.List[string]
        foreach ($line in $Lines) {
            if ($line -match '^\[\s*\d+\]\s+(.+)$') { $planned.Add($Matches[1].Trim()) }
        }
        return , $planned.ToArray()
    }
}

AfterAll {
    $env:PATH = $script:SavedPath
    if ($null -eq $script:SavedSentinel) { Remove-Item Env:\LAB_SENTINEL -ErrorAction SilentlyContinue }
    else { $env:LAB_SENTINEL = $script:SavedSentinel }
}

Describe 'Azure VM deploy.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', '203.0.113.7/32', '-WhatIf')
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Deploy.ExitCode | Should -Be 0 -Because ("Output:`n" + $script:Deploy.Text)
    }

    It 'executes NO external command (sentinel shims never invoked)' {
        $script:Deploy.ExternalWasRun | Should -BeFalse -Because ("shim calls: " + $script:Deploy.ExternalCalls)
    }

    It 'prints a non-empty ordered planned command list and reports nothing created' {
        $script:Deploy.Text | Should -Match 'DRY RUN'
        $script:Deploy.Text | Should -Match 'nothing was created'
        $script:DeployPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the sensible core steps in order: auth, groups, network, Key Vault, PostgreSQL, VM' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'az account show'
        $joined | Should -Match 'az group create'
        $joined | Should -Match 'az network nsg create'
        $joined | Should -Match 'az keyvault create'
        $joined | Should -Match 'az postgres flexible-server create'
        $joined | Should -Match 'az vm create'

        $idx = { param($p) for ($i = 0; $i -lt $script:DeployPlanned.Count; $i++) { if ($script:DeployPlanned[$i] -match $p) { return $i } } return -1 }
        $auth = & $idx 'az account show'
        $grp  = & $idx 'az group create'
        $kv   = & $idx 'az keyvault create'
        $pg   = & $idx 'az postgres flexible-server create'
        $vm   = & $idx 'az vm create'
        $auth | Should -Be 0
        $grp  | Should -BeLessThan $kv
        $kv   | Should -BeLessThan $pg
        $pg   | Should -BeLessThan $vm
    }

    It 'every planned line is an az command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) { $cmd | Should -Match '^az\b' }
    }

    It 'restricts every NSG inbound rule to the supplied /32 (never open to the internet)' {
        $rules = @($script:DeployPlanned | Where-Object { $_ -match 'az network nsg rule create' -and $_ -match '--access Allow' -and $_ -match '--direction Inbound' })
        $rules.Count | Should -BeGreaterThan 0
        foreach ($r in $rules) {
            $r | Should -Match '--source-address-prefixes 203\.0\.113\.7/32(\s|$)'
            $r | Should -Not -Match '0\.0\.0\.0/0'
            $r | Should -Not -Match '::/0'
            $r | Should -Not -Match '--source-address-prefixes (\*|Internet|Any)(\s|$)'
        }
    }

    It 'creates both resource groups with the lab tag and run-id' {
        $groups = @($script:DeployPlanned | Where-Object { $_ -match 'az group create' })
        $groups.Count | Should -Be 2
        foreach ($g in $groups) {
            $g | Should -Match 'lab=sangyshop-lab-azure'
            $g | Should -Match 'run-id='
        }
    }

    It 'stores the DB password in Key Vault via a file, never inline in a planned command' {
        $set = $script:DeployPlanned | Where-Object { $_ -match 'az keyvault secret set' } | Select-Object -First 1
        $set | Should -Not -BeNullOrEmpty
        $set | Should -Match '--file '
        $set | Should -Not -Match '--value '
    }
}

Describe 'Azure VM deploy.ps1 source-range validation' {
    It 'rejects <Label> ("<Value>") with a non-zero exit, before any command' -ForEach $script:BadSources {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', $Value, '-WhatIf')
        $r.ExitCode | Should -Not -Be 0 -Because ("Output:`n" + $r.Text)
        $r.Text | Should -Match 'ERROR'
        $r.ExternalWasRun | Should -BeFalse
        $planned = Get-PlannedCommands -Lines $r.Lines; $planned.Count | Should -Be 0
    }

    It 'rejects a missing -AllowedSourceRanges with a non-zero exit, before any command' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @('-WhatIf')
        $r.ExitCode | Should -Not -Be 0 -Because ("Output:`n" + $r.Text)
        $r.Text | Should -Match 'AllowedSourceRanges is required'
        $r.ExternalWasRun | Should -BeFalse
        $planned = Get-PlannedCommands -Lines $r.Lines; $planned.Count | Should -Be 0
    }

    It 'rejects a set where one valid /32 is mixed with an open range' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -Ranges @('203.0.113.7/32', '0.0.0.0/0')
        $r.ExitCode | Should -Not -Be 0
        $r.ExternalWasRun | Should -BeFalse
        $planned = Get-PlannedCommands -Lines $r.Lines; $planned.Count | Should -Be 0
    }

    It 'accepts several valid /32 sources' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -Ranges @('203.0.113.7/32', '198.51.100.9/32')
        $r.ExitCode | Should -Be 0 -Because ("Output:`n" + $r.Text)
        $r.ExternalWasRun | Should -BeFalse
    }
}

Describe 'Azure VM teardown.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript -ExtraArgs @('-WhatIf')
        $script:TeardownPlanned = Get-PlannedCommands -Lines $script:Teardown.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Teardown.ExitCode | Should -Be 0 -Because ("Output:`n" + $script:Teardown.Text)
    }

    It 'executes NO external command (sentinel shims never invoked)' {
        $script:Teardown.ExternalWasRun | Should -BeFalse -Because ("shim calls: " + $script:Teardown.ExternalCalls)
    }

    It 'prints a non-empty planned command list and reports nothing removed' {
        $script:Teardown.Text | Should -Match 'DRY RUN'
        $script:Teardown.Text | Should -Match 'nothing was removed'
        $script:TeardownPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the sensible removal order: verify tag, Sentinel/workspace, group, service principal, final group check' {
        $joined = ($script:TeardownPlanned -join "`n")
        $joined | Should -Match 'az group show .*tags\.lab'
        $joined | Should -Match 'az monitor log-analytics workspace delete'
        $joined | Should -Match 'az group delete'
        $joined | Should -Match 'az ad sp delete'
        $joined | Should -Match 'az group exists'

        $idx = { param($p) for ($i = 0; $i -lt $script:TeardownPlanned.Count; $i++) { if ($script:TeardownPlanned[$i] -match $p) { return $i } } return -1 }
        $tag = & $idx 'az group show .*tags\.lab'
        $law = & $idx 'az monitor log-analytics workspace delete'
        $grp = & $idx 'az group delete'
        $sp  = & $idx 'az ad sp delete'
        $tag | Should -BeLessThan $law
        $law | Should -BeLessThan $grp
        $grp | Should -BeLessThan $sp
        $script:TeardownPlanned[$script:TeardownPlanned.Count - 1] | Should -Match '^az group exists\b'
    }

    It 'every planned line is an az command (no bare external calls)' {
        foreach ($cmd in $script:TeardownPlanned) { $cmd | Should -Match '^az\b' }
    }

    It 'does not remove the evidence resource group (owned by the full teardown)' {
        $del = @($script:TeardownPlanned | Where-Object { $_ -match 'az group delete' })
        foreach ($d in $del) { $d | Should -Not -Match 'sangyshop-evidence' }
    }
}
