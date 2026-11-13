<#
.SYNOPSIS
    Pester tests: the read-only Azure lab tools (check-detection-ready, print-response-commands).

.DESCRIPTION
    PowerShell has no native property-based testing library, so this file generates
    cases with a FIXED SEED (declared project limitation). Each case runs a script
    in-process through the Invoke-LabAz / $global:LabAzHandler seam, against a fake
    Azure subscription whose state is drawn at random. The cloud config is a temp file
    named by LAB_CLOUD_CONFIG_PATH. No Azure call is ever made.

    Properties checked:
      * only read verbs (show, list) are issued, and none for print without -Subscription
      * check-detection-ready: exit 0 only when the four checks pass (workspace, Action
        Group with an enabled receiver, enabled alert rule, rule linked to the group),
        exit 4 for any pending item, exit 3 on a denied read; the stamp exists only after
        exit 0, carries no e-mail address, and an older stamp is left untouched otherwise
      * print-response-commands: nothing executed, exit 4 without the attack evidence file
      * no e-mail address ever appears in the output

    Run: Invoke-Pester -Path ops/tests/AzureIrLab.ReadOnly.Tests.ps1
#>

BeforeDiscovery {
    $rng = [System.Random]::new(48211)   # fixed seed: reproducible cases
    $regions = @('eastus', 'westeurope', 'brazilsouth', 'East US 2', 'southcentralus')
    $denyPool = @(
        'monitor log-analytics workspace show', 'monitor action-group show', 'monitor scheduled-query show'
    )
    $agModes = @('none', 'ok', 'allDisabled', 'groupDisabled')
    $ruleModes = @('none', 'ok', 'disabled', 'otherGroup', 'noGroup')

    $mk = {
        param($forceHealthy)
        $s = @{
            Workspace = ($rng.Next(4) -ne 0)
            Ag        = $agModes[$rng.Next($agModes.Count)]
            Rule      = $ruleModes[$rng.Next($ruleModes.Count)]
            Deny      = $null
        }
        if ($forceHealthy) { $s.Workspace = $true; $s.Ag = 'ok'; $s.Rule = 'ok' }
        elseif ($rng.Next(8) -eq 0) { $s.Deny = $denyPool[$rng.Next($denyPool.Count)] }
        $s
    }

    $readyCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 60; $i++) {
        [void]$readyCases.Add(@{
                Index = $i; State = (& $mk ($i % 3 -eq 0)); Region = $regions[$rng.Next($regions.Count)]
                Email = ('user{0}@example.com' -f $rng.Next(100000))
                OldStamp = ($rng.Next(2) -eq 1)
            })
    }
    $script:ReadyCases = $readyCases.ToArray()

    $printCases = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt 20; $i++) {
        [void]$printCases.Add(@{
                Index = $i; Region = $regions[$rng.Next($regions.Count)]
                Evidence = ($i % 2 -eq 0); WithSub = ($rng.Next(2) -eq 1)
                VmState = @('ok', 'missing', 'denied')[$rng.Next(3)]
                Nimbus = ($rng.Next(2) -eq 1)
                Email = ('user{0}@example.com' -f $rng.Next(100000))
            })
    }
    $script:PrintCases = $printCases.ToArray()
}

BeforeAll {
    $script:LabDir = (Resolve-Path (Join-Path $PSScriptRoot '..\azure\ir-lab')).Path
    $script:SubId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:SavedEnv = @{}
    foreach ($n in 'LAB_CLOUD_CONFIG_PATH', 'LAB_MANIFEST_PATH', 'LAB_ALERT_EMAIL', 'NIMBUSDFIR_PATH') {
        $script:SavedEnv[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('azlab-ro-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    # Self-contained config so the test does not depend on a local cloud.config.ps1.
    $script:ConfigFile = Join-Path $script:Work 'cloud.config.ps1'
    Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = 'abc12345'
    Common = @{ AppName = 'sangyshop'; DbName = 'sangyshop'; DbUser = 'sangyshop'; ImageTag = 'hardened' }
    Azure = @{
        Location = 'eastus'
        Vm = @{ VmSize = 'Standard_B1ms'; PgSku = 'Standard_B1ms'; PgStorageGb = 32; ResourceGroupBase = 'sangyshop-lab'; EvidenceGroupBase = 'sangyshop-evidence' }
    }
}
'@
    $env:LAB_CLOUD_CONFIG_PATH = $script:ConfigFile
    $env:NIMBUSDFIR_PATH = $null

    $script:AgId = "/subscriptions/$($script:SubId)/resourceGroups/sangyshop-lab-abc12345/providers/microsoft.insights/actionGroups/ag-sangyshop-lab"
    $global:LabTestSubId = $script:SubId
    $global:LabTestAgId = $script:AgId
    $global:LabReadOnlyVerbs = '^(show|list)$'

    # Fake of the Azure CLI driven by $global:LabReadState. Records every call.
    $global:LabAzHandler = {
        param($a)
        $s = $global:LabReadState
        $words = @()
        foreach ($t in $a) { if ("$t".StartsWith('-')) { break }; $words += "$t" }
        $key = $words -join ' '
        [void]$global:LabReadCalls.Add($key)
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 3; Output = 'ERROR: (ResourceNotFound) The Resource was not found.' }
        $json = { param($o) ConvertTo-Json -InputObject $o -Depth 6 -Compress }

        if ($s.Deny -and $s.Deny -eq $key) {
            $s.Denied = $true
            return [pscustomobject]@{ ExitCode = 1; Output = "ERROR: (AuthorizationFailed) The client does not have authorization to perform action '$key/read' over scope" }
        }
        switch ($key) {
            'account show' { return (& $ok $global:LabTestSubId) }
            'monitor log-analytics workspace show' {
                if ($s.Workspace) { return (& $ok (& $json @{ id = '/subscriptions/x/workspaces/w' })) } else { return $no }
            }
            'monitor action-group show' {
                if ($s.Ag -eq 'none') { return $no }
                $recv = @('Enabled')
                if ($s.Ag -eq 'allDisabled') { $recv = @('Disabled', 'Disabled') }
                return (& $ok (& $json @{ id = $global:LabTestAgId; enabled = ($s.Ag -ne 'groupDisabled'); receivers = $recv }))
            }
            'monitor scheduled-query show' {
                if ($s.Rule -eq 'none') { return $no }
                $groups = @($global:LabTestAgId)
                if ($s.Rule -eq 'otherGroup') { $groups = @('/subscriptions/x/resourceGroups/other/providers/microsoft.insights/actionGroups/other') }
                if ($s.Rule -eq 'noGroup') { $groups = @() }
                return (& $ok (& $json @{ id = '/subscriptions/x/scheduledqueryrules/r'; enabled = ($s.Rule -ne 'disabled'); groups = $groups }))
            }
            'vm show' {
                if ($s.Vm -eq 'ok') { return (& $ok 'sangyshop-vm-osdisk') }
                if ($s.Vm -eq 'denied') { $s.Denied = $true; return [pscustomobject]@{ ExitCode = 1; Output = "ERROR: (AuthorizationFailed) The client does not have authorization to perform action 'Microsoft.Compute/virtualMachines/read'" } }
                return $no
            }
            default { [void]$global:LabMutating.Add($key); return (& $ok '{}') }
        }
    }

    function script:Initialize-Case {
        param([hashtable]$State, [string]$Email, [string]$Name)
        $State['Denied'] = $false
        $global:LabReadState = $State
        $global:LabReadCalls = New-Object System.Collections.ArrayList
        $global:LabMutating = New-Object System.Collections.ArrayList
        $dir = Join-Path $script:Work $Name
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $env:LAB_MANIFEST_PATH = Join-Path $dir 'manifest.json'
        $env:LAB_ALERT_EMAIL = $Email
        return $dir
    }

    function script:Invoke-Tool {
        param([string]$Script, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        $text = (& (Join-Path $script:LabDir $Script) @Params *>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $text }
    }

    function script:Assert-ReadOnlyCalls {
        $bad = @($global:LabReadCalls | Where-Object { ($_ -split ' ')[-1] -notmatch $global:LabReadOnlyVerbs })
        $bad.Count | Should -Be 0 -Because "non-read calls: $($bad -join ', ')"
        $global:LabMutating.Count | Should -Be 0 -Because "unexpected calls: $($global:LabMutating -join ', ')"
    }
}

AfterAll {
    $global:LabAzHandler = $null
    $global:LabReadState = $null
    $global:LabReadCalls = $null
    $global:LabMutating = $null
    $global:LabReadOnlyVerbs = $null
    $global:LabTestSubId = $null
    $global:LabTestAgId = $null
    foreach ($n in $script:SavedEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $script:SavedEnv[$n], 'Process') }
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'check-detection-ready.ps1 (fixed seed, 60 cases)' {

    It 'case <Index>: reads only, exit code and stamp follow the four checks' -ForEach $script:ReadyCases {
        $dir = Initialize-Case -State $State -Email $Email -Name "ready-$Index"
        $stamp = Join-Path $dir 'readiness-sangyshop-lab-azure.json'
        if ($OldStamp) { Set-Content -LiteralPath $stamp -Value '{"old":true}' -Encoding UTF8 }
        $before = if ($OldStamp) { Get-Content -LiteralPath $stamp -Raw } else { $null }

        $r = Invoke-Tool -Script 'check-detection-ready.ps1' -Params @{ Subscription = $script:SubId; Region = $Region }

        Assert-ReadOnlyCalls
        $r.Text | Should -Not -Match ([regex]::Escape($Email))

        $allOk = ($State.Workspace -and $State.Ag -eq 'ok' -and $State.Rule -eq 'ok')
        if ($State.Denied) { $expected = 3 } elseif ($allOk) { $expected = 0 } else { $expected = 4 }
        $r.ExitCode | Should -Be $expected

        if ($expected -eq 0) {
            Test-Path -LiteralPath $stamp | Should -BeTrue
            $raw = Get-Content -LiteralPath $stamp -Raw
            $raw | Should -Not -Match ([regex]::Escape($Email))
            $raw | Should -Not -Match '@'
            $doc = $raw | ConvertFrom-Json
            $doc.region | Should -Be (($Region -replace '\s', '').ToLowerInvariant())
            $doc.lab | Should -Be 'sangyshop-lab-azure'
            $raw | Should -Match '"checked_utc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'
            foreach ($k in 'workspace', 'action_group', 'alert_rule', 'alert_action') {
                $doc.checks.$k | Should -BeTrue
            }
        } elseif ($OldStamp) {
            # An older stamp is left exactly as it was.
            (Get-Content -LiteralPath $stamp -Raw) | Should -Be $before
        } else {
            Test-Path -LiteralPath $stamp | Should -BeFalse
        }
        if ($expected -eq 4) { $r.Text | Should -Match 'MISSING' }
        if ($expected -eq 3) { $r.Text | Should -Match 'BLOCKED' }
    }

    It 'exits 2 without -Subscription and calls nothing' {
        $null = Initialize-Case -State @{ Deny = $null } -Email 'x@example.com' -Name 'nosub'
        $r = Invoke-Tool -Script 'check-detection-ready.ps1' -Params @{}
        $r.ExitCode | Should -Be 2
        $global:LabReadCalls.Count | Should -Be 0
    }
}

Describe 'print-response-commands.ps1 (fixed seed, 20 cases)' {

    It 'case <Index>: runs nothing, exit 4 without attack evidence, reads only the VM disk' -ForEach $script:PrintCases {
        $dir = Initialize-Case -State @{ Deny = $null; Vm = $VmState } -Email $Email -Name "print-$Index"
        $evidence = Join-Path $dir 'attack-steps.jsonl'
        if ($Evidence) { Set-Content -LiteralPath $evidence -Value '{"step":1}' -Encoding UTF8 }

        $marker = Join-Path $dir 'executed.marker'
        $nimbus = Join-Path $dir 'nimbus'
        $p = @{ Region = $Region; AttackEvidencePath = $evidence }
        if ($WithSub) { $p['Subscription'] = $script:SubId }
        if ($Nimbus) {
            New-Item -ItemType Directory -Path (Join-Path $nimbus 'ir_lab_core') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $nimbus 'aws') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $nimbus 'azure') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $nimbus 'ir_lab_core\__init__.py') -Value ''
            Set-Content -LiteralPath (Join-Path $nimbus 'aws\ec2_evidence_preservation.py') -Value ''
            foreach ($t in 'vm_isolate', 'disk_snapshot_hash', 'azure_activity_collect') {
                Set-Content -LiteralPath (Join-Path $nimbus "azure\$t.ps1") -Value "Set-Content -LiteralPath '$marker' -Value ran"
            }
            $p['NimbusDfirPath'] = $nimbus
        }

        $r = Invoke-Tool -Script 'print-response-commands.ps1' -Params $p

        Assert-ReadOnlyCalls
        Test-Path -LiteralPath $marker | Should -BeFalse
        $r.Text | Should -Not -Match ([regex]::Escape($Email))

        if (-not $Evidence) {
            $r.ExitCode | Should -Be 4
            $global:LabReadCalls.Count | Should -Be 0
            $r.Text | Should -Not -Match 'vm_isolate'
            return
        }
        if (-not $WithSub) {
            $global:LabReadCalls.Count | Should -Be 0 -Because "calls: $($global:LabReadCalls -join ', ')"
            $r.Text | Should -Match '<subscription-id>'
            $r.Text | Should -Match '<os-disk-name>'
        } else {
            @($global:LabReadCalls | Where-Object { $_ -ne 'vm show' }).Count | Should -Be 0
        }

        if ($WithSub -and $VmState -eq 'denied') {
            $r.ExitCode | Should -Be 3
            return
        }
        $r.ExitCode | Should -Be 0
        $r.Text | Should -Match 'Nothing was executed'
        $commandLines = @($r.Text -split "`r?`n" | Where-Object { $_ -match '^&\s' })
        $commandLines.Count | Should -Be 3
        @($commandLines | Where-Object { $_ -match '-Execute' }).Count | Should -Be 0
        if ($WithSub -and $VmState -eq 'ok') { $r.Text | Should -Match 'sangyshop-vm-osdisk' }
        if ($WithSub -and $VmState -eq 'missing') { $r.Text | Should -Match '<os-disk-name>' }
        if ($Nimbus) { $r.Text | Should -Match ([regex]::Escape($nimbus)) } else { $r.Text | Should -Match '<NimbusDFIR>' }
    }
}

