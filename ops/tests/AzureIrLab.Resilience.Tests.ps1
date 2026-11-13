<#
.SYNOPSIS
    Pester tests: the Azure detection scripts survive permission errors, converge on re-run,
    check before they create and never touch resources the lab did not create.

.DESCRIPTION
    Every Azure CLI call of the enable-*.ps1 scripts goes through Invoke-LabAz, so the tests set
    $global:LabAzHandler to a small stateful fake of Azure. No real Azure call is ever made.
    The cloud config is a temporary file named by LAB_CLOUD_CONFIG_PATH and the lab manifest is
    a temporary file named by LAB_MANIFEST_PATH.

    A clean run of enable-workspace.ps1 followed by enable-alerts.ps1 is recorded first. Then,
    for a sample of its calls (every mutating call and the first occurrence of key reads), a
    fresh account is built and that one call is made to fail with AuthorizationFailed:
      * the script must stop with exit code 3;
      * every resource created before the fault must already be in the lab manifest;
      * running the same scripts again with no fault must exit 0, create exactly what a clean
        run creates and never create anything twice.

    Other cases cover the existence check before every creation, additive reuse of a foreign
    workspace, action group and alert rule (recorded as reused, never changed), and the
    application gate of enable-all.ps1.

    Run: Invoke-Pester -Path ops/tests/AzureIrLab.Resilience.Tests.ps1
#>

BeforeAll {
    $script:DetectionDir = (Resolve-Path (Join-Path $PSScriptRoot '..' 'azure' 'ir-lab' 'detection')).Path
    $script:SavedEnv = @{}
    foreach ($n in 'LAB_CLOUD_CONFIG_PATH', 'LAB_MANIFEST_PATH', 'LAB_ALERT_EMAIL') {
        $script:SavedEnv[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
    }
    Remove-Item Env:\LAB_ALERT_EMAIL -ErrorAction SilentlyContinue

    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('azlab-resil-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

    # Self-contained config so the tests do not depend on a local cloud.config.ps1.
    $script:ConfigFile = Join-Path $script:WorkDir 'cloud.config.ps1'
    Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "labtest01"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Azure = @{
        Location = "eastus"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "sangyshop-lab"; EvidenceGroupBase = "sangyshop-evidence" }
    }
}
'@
    $env:LAB_CLOUD_CONFIG_PATH = $script:ConfigFile

    $global:AzResWsName = 'sangyshop-law-labtest01'
    $global:AzResAgName = 'ag-sangyshop-lab'
    $global:AzResRuleName = 'sangyshop-lab-bruteforce'
    $global:AzResTagJson = '{"lab":"sangyshop-lab-azure"}'

    # Stateful fake of the Azure CLI with fault injection (FailAt = index of the call to fail).
    $global:AzResHandler = {
        param($a)
        $s = $global:AzResState
        $words = @()
        foreach ($t in $a) { if ("$t".StartsWith('-')) { break }; $words += "$t" }
        $key = $words -join ' '
        $isMut = $key -match ' (create|update)$'
        $idx = $s.Seq.Count
        [void]$s.Seq.Add([pscustomobject]@{ Key = $key; Mutating = $isMut })

        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $notFound = [pscustomobject]@{ ExitCode = 3; Output = 'ERROR: (ResourceNotFound) The Resource was not found.' }
        $opt = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { $a[$i + 1] } }
        $dup = { param($what) [void]$s.Dups.Add($what); [pscustomobject]@{ ExitCode = 1; Output = "ERROR: (AlreadyExists) $what" } }
        $tags = { param($t) if ($t) { $global:AzResTagJson } else { 'null' } }
        $sid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

        if ($idx -eq $s.FailAt) {
            $s.Failed = $key
            return [pscustomobject]@{ ExitCode = 1; Output = "ERROR: (AuthorizationFailed) The client 'user@example.com' does not have authorization to perform action 'Microsoft.Insights/$key' over the scope." }
        }

        # Anything that changes a resource the lab does not own is recorded as alien.
        if ($isMut -or $key -eq 'tag update') {
            $joined = $a -join ' '
            foreach ($f in $s.Foreign) {
                if ($joined.Contains($f) -and $key -notin @('monitor log-analytics workspace table create', 'monitor scheduled-query create')) { [void]$s.Alien.Add("$key touches $f") }
            }
        }
        if ($key -eq 'tag update') { [void]$s.Alien.Add('tag update on a resource') }

        $rg = "/subscriptions/$sid/resourceGroups/sangyshop-lab/providers"
        $listFail = [pscustomobject]@{ ExitCode = 1; Output = 'ERROR: the service is temporarily unavailable' }

        switch ($key) {
            'account show' { return (& $ok $sid) }

            'vm show' {
                if ($s.Vm) { return (& $ok "$rg/Microsoft.Compute/virtualMachines/sangyshop-vm") }
                return $notFound
            }

            'monitor log-analytics workspace list' {
                if ($s.ListFails) { return $listFail }
                if (-not $s.Ws) { return (& $ok '[]') }
                $o = @(@{ name = $global:AzResWsName; id = "$rg/Microsoft.OperationalInsights/workspaces/$($global:AzResWsName)"; tags = ($s.Ws.Tagged ? @{ lab = 'sangyshop-lab-azure' } : $null) })
                return (& $ok (ConvertTo-Json -InputObject $o -Compress -Depth 5))
            }
            'monitor log-analytics workspace show' {
                if (-not $s.Ws) { return $notFound }
                return (& $ok ('{"id":"' + "$rg/Microsoft.OperationalInsights/workspaces/$($global:AzResWsName)" + '","customerId":"c","tags":' + (& $tags $s.Ws.Tagged) + ',"quota":' + $s.Ws.Quota + '}'))
            }
            'monitor log-analytics workspace create' {
                if ($s.Ws) { return (& $dup 'workspace') }
                $s.Ws = @{ Tagged = $true; Quota = [int](& $opt '--quota') }
                [void]$s.Creates.Add($key); [void]$s.CreatedNames.Add($global:AzResWsName)
                return (& $ok '{}')
            }
            'monitor log-analytics workspace update' {
                $s.Ws.Quota = [int](& $opt '--quota'); return (& $ok '{}')
            }
            'monitor log-analytics workspace table show' {
                if ($s.Table) { return (& $ok 'SangyShopApp_CL') }
                return $notFound
            }
            'monitor log-analytics workspace table create' {
                if ($s.Table) { return (& $dup 'table') }
                $s.Table = $true; [void]$s.Creates.Add($key)
                return (& $ok '{}')
            }

            'monitor action-group list' {
                if ($s.ListFails) { return $listFail }
                if (-not $s.Ag) { return (& $ok '[]') }
                $o = @(@{ name = $global:AzResAgName; id = "$rg/microsoft.insights/actionGroups/$($global:AzResAgName)"; tags = ($s.Ag.Tagged ? @{ lab = 'sangyshop-lab-azure' } : $null) })
                return (& $ok (ConvertTo-Json -InputObject $o -Compress -Depth 5))
            }
            'monitor action-group show' {
                if (-not $s.Ag) { return $notFound }
                return (& $ok ('{"id":"' + "$rg/microsoft.insights/actionGroups/$($global:AzResAgName)" + '","tags":' + (& $tags $s.Ag.Tagged) + '}'))
            }
            'monitor action-group create' {
                if ($s.Ag) { return (& $dup 'action group') }
                $s.Ag = @{ Tagged = $true }; [void]$s.Creates.Add($key); [void]$s.CreatedNames.Add($global:AzResAgName)
                return (& $ok '{}')
            }

            'monitor scheduled-query list' {
                if ($s.ListFails) { return $listFail }
                if (-not $s.Rule) { return (& $ok '[]') }
                $o = @(@{ name = $global:AzResRuleName; id = "$rg/microsoft.insights/scheduledqueryrules/$($global:AzResRuleName)"; tags = ($s.Rule.Tagged ? @{ lab = 'sangyshop-lab-azure' } : $null) })
                return (& $ok (ConvertTo-Json -InputObject $o -Compress -Depth 5))
            }
            'monitor scheduled-query show' {
                if (-not $s.Rule) { return $notFound }
                return (& $ok ('{"id":"' + "$rg/microsoft.insights/scheduledqueryrules/$($global:AzResRuleName)" + '","tags":' + (& $tags $s.Rule.Tagged) + '}'))
            }
            'monitor scheduled-query create' {
                if ($s.Rule) { return (& $dup 'alert rule') }
                $s.Rule = @{ Tagged = $true }; [void]$s.Creates.Add($key); [void]$s.CreatedNames.Add($global:AzResRuleName)
                return (& $ok '{}')
            }
            default { return (& $ok '') }
        }
    }

    function script:New-AzState {
        # Scenario keys: ForeignWorkspace, ForeignActionGroup, ForeignRule, NoVm, ListFails.
        param([hashtable]$Scenario = @{})
        $s = @{
            Seq = New-Object System.Collections.ArrayList
            Creates = New-Object System.Collections.ArrayList
            CreatedNames = New-Object System.Collections.ArrayList
            Dups = New-Object System.Collections.ArrayList
            Alien = New-Object System.Collections.ArrayList
            Foreign = New-Object System.Collections.ArrayList
            FailAt = -1; Failed = ''
            Vm = (-not $Scenario.NoVm); ListFails = [bool]$Scenario.ListFails
            Ws = $null; Table = $false; Ag = $null; Rule = $null
        }
        if ($Scenario.ForeignWorkspace) { $s.Ws = @{ Tagged = $false; Quota = 5 }; [void]$s.Foreign.Add($global:AzResWsName) }
        if ($Scenario.ForeignActionGroup) { $s.Ag = @{ Tagged = $false }; [void]$s.Foreign.Add($global:AzResAgName) }
        if ($Scenario.ForeignRule) { $s.Rule = @{ Tagged = $false }; [void]$s.Foreign.Add($global:AzResRuleName) }
        return $s
    }

    $script:CaseNo = 0
    $script:Params = @{ Subscription = 'sub'; Region = 'eastus'; RunId = '20260101T000000Z-0a0a' }

    function script:Invoke-Script {
        param([string]$Name, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        & (Join-Path $script:DetectionDir $Name) @Params *> $null
        return [int]$LASTEXITCODE
    }

    function script:Invoke-Pair {
        # enable-workspace.ps1 then enable-alerts.ps1; stops at the first non-zero exit code.
        $e = Invoke-Script -Name 'enable-workspace.ps1' -Params $script:Params
        if ($e -ne 0) { return $e }
        return (Invoke-Script -Name 'enable-alerts.ps1' -Params ($script:Params + @{ Email = 'owner.test@example.com' }))
    }

    function script:New-Account {
        param([hashtable]$Scenario = @{})
        $script:CaseNo++
        $env:LAB_MANIFEST_PATH = Join-Path $script:WorkDir ("manifest-$($script:CaseNo).json")
        $global:AzResState = New-AzState -Scenario $Scenario
        $global:LabAzHandler = $global:AzResHandler
    }

    function script:Get-ManifestEntries {
        if (-not (Test-Path -LiteralPath $env:LAB_MANIFEST_PATH)) { return @() }
        $o = Get-Content -LiteralPath $env:LAB_MANIFEST_PATH -Raw | ConvertFrom-Json
        return @($o.resources)
    }

    # Clean reference run.
    New-Account
    $script:BaselineExit = Invoke-Script -Name 'enable-workspace.ps1' -Params $script:Params
    $script:AlertsStart = $global:AzResState.Seq.Count
    $e2 = Invoke-Script -Name 'enable-alerts.ps1' -Params ($script:Params + @{ Email = 'owner.test@example.com' })
    if ($script:BaselineExit -eq 0) { $script:BaselineExit = $e2 }
    $script:Baseline = @{
        Creates = @($global:AzResState.Creates | Sort-Object)
        Seq     = @($global:AzResState.Seq)
        Dups    = $global:AzResState.Dups.Count
    }
    # Fault points: every mutating call plus the first occurrence of a few key reads.
    $seen = @{}
    $points = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $script:Baseline.Seq.Count; $i++) {
        $c = $script:Baseline.Seq[$i]
        $wantRead = $c.Key -in @('account show', 'monitor action-group list', 'monitor log-analytics workspace show', 'monitor action-group show', 'monitor scheduled-query show')
        if (($c.Mutating -or $wantRead) -and -not $seen.ContainsKey($c.Key)) { $seen[$c.Key] = $true; [void]$points.Add($i) }
    }
    # The alerts script reads the lists again in its own preflight: cover that read too.
    $lastList = (0..($script:Baseline.Seq.Count - 1) | Where-Object { $script:Baseline.Seq[$_].Key -eq 'monitor action-group list' } | Select-Object -Last 1)
    if ($points -notcontains $lastList) { [void]$points.Add($lastList) }
    $script:FaultPoints = $points.ToArray()
}

AfterAll {
    $global:LabAzHandler = $null
    $global:AzResHandler = $null
    $global:AzResState = $null
    $global:AzResTagJson = $null; $global:AzResWsName = $null; $global:AzResAgName = $null; $global:AzResRuleName = $null
    foreach ($n in $script:SavedEnv.Keys) { [Environment]::SetEnvironmentVariable($n, $script:SavedEnv[$n], 'Process') }
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Clean run of the workspace and alert scripts (reference for the fault cases)' {
    It 'exits 0 and creates the workspace, table, action group and alert rule once each' {
        $script:BaselineExit | Should -Be 0
        $script:Baseline.Dups | Should -Be 0
        $script:Baseline.Creates.Count | Should -Be 4
        $script:FaultPoints.Count | Should -BeGreaterThan 5
    }

    It 'records the resources it created in the manifest as created' {
        New-Account
        (Invoke-Pair) | Should -Be 0
        $entries = Get-ManifestEntries
        foreach ($t in 'log-analytics-workspace', 'action-group', 'alert-rule') {
            @($entries | Where-Object { $_.type -eq $t -and $_.ownership -eq 'created' }).Count | Should -Be 1 -Because $t
        }
    }
}

Describe 'A permission error stops with exit 3 and a re-run converges' {
    It 'stops with exit 3 at each creation and at key reads, keeps the manifest current, then a clean re-run finishes without duplicates' {
        $problems = New-Object System.Collections.ArrayList
        foreach ($p in $script:FaultPoints) {
            New-Account
            $global:AzResState.FailAt = $p
            $key = $script:Baseline.Seq[$p].Key
            try { $exit1 = Invoke-Pair } catch { $exit1 = -1; [void]$problems.Add("fault on '$key' (call $p): script threw $($_.Exception.Message)") }
            # The workspace script reads the other lists in its snapshot but does not need them, so a denied read there is not an error for it.
            $unneeded = ($p -lt $script:AlertsStart) -and ($key -match ' list$') -and ($key -ne 'monitor log-analytics workspace list')
            if ($exit1 -ne 3 -and -not ($unneeded -and $exit1 -eq 0)) { [void]$problems.Add("fault on '$key' (call $p): exit $exit1, expected 3") }
            if ($global:AzResState.Failed -ne $key) { [void]$problems.Add("fault on call $p was not injected at '$key' (got '$($global:AzResState.Failed)')") }

            # Everything created before the stop is already in the manifest.
            $ids = @(Get-ManifestEntries | ForEach-Object { [string]$_.id })
            foreach ($n in $global:AzResState.CreatedNames) {
                if (-not (@($ids | Where-Object { $_.Contains([string]$n) }).Count)) { [void]$problems.Add("fault on '$key': '$n' was created but is not in the manifest") }
            }

            # Same scripts again, fault gone: converges to the clean result without duplicates.
            $global:AzResState.FailAt = -1
            try { $exit2 = Invoke-Pair } catch { $exit2 = -1; [void]$problems.Add("re-run after fault on '$key': script threw $($_.Exception.Message)") }
            if ($exit2 -ne 0) { [void]$problems.Add("re-run after fault on '$key': exit $exit2, expected 0") }
            if ($global:AzResState.Dups.Count -ne 0) { [void]$problems.Add("re-run after fault on '$key': duplicate create ($($global:AzResState.Dups -join ', '))") }
            $created = @($global:AzResState.Creates | Sort-Object)
            if (($created -join '|') -ne ($script:Baseline.Creates -join '|')) { [void]$problems.Add("re-run after fault on '$key': creations differ from a clean run ($($created -join ', '))") }
        }
        $problems.Count | Should -Be 0 -Because ($problems -join '; ')
    }
}

Describe 'Re-running the scripts' {
    It 'creates nothing the second and the third time' {
        New-Account
        (Invoke-Pair) | Should -Be 0
        foreach ($round in 1..2) {
            $before = $global:AzResState.Creates.Count
            (Invoke-Pair) | Should -Be 0
            $global:AzResState.Creates.Count | Should -Be $before
            $global:AzResState.Dups.Count | Should -Be 0
        }
        @(Get-ManifestEntries).Count | Should -Be 3
    }
}

Describe 'Existence is checked before anything is created' {
    It 'reads each resource directly before the call that creates it' {
        $seq = $script:Baseline.Seq
        $pairs = @{
            'monitor log-analytics workspace create'       = 'monitor log-analytics workspace show'
            'monitor log-analytics workspace table create' = 'monitor log-analytics workspace table show'
            'monitor action-group create'                  = 'monitor action-group show'
            'monitor scheduled-query create'               = 'monitor scheduled-query show'
        }
        foreach ($create in $pairs.Keys) {
            $ci = (0..($seq.Count - 1) | Where-Object { $seq[$_].Key -eq $create } | Select-Object -First 1)
            $ci | Should -Not -BeNullOrEmpty -Because $create
            $before = @(0..($ci - 1) | Where-Object { $seq[$_].Key -eq $pairs[$create] })
            $before.Count | Should -BeGreaterThan 0 -Because "$create must follow $($pairs[$create])"
        }
    }

    It 'never takes a failed list as proof of absence: existing resources are found by a direct read' {
        New-Account -Scenario @{ ForeignWorkspace = $true; ForeignActionGroup = $true; ForeignRule = $true; ListFails = $true }
        (Invoke-Pair) | Should -Be 0
        $global:AzResState.Creates | Should -Not -Contain 'monitor log-analytics workspace create'
        $global:AzResState.Creates | Should -Not -Contain 'monitor action-group create'
        $global:AzResState.Creates | Should -Not -Contain 'monitor scheduled-query create'
        $global:AzResState.Dups.Count | Should -Be 0
    }
}

Describe 'Resources the lab did not create are reused and never changed' {
    It 'adds only the application table to a foreign workspace and records everything as reused' {
        New-Account -Scenario @{ ForeignWorkspace = $true; ForeignActionGroup = $true; ForeignRule = $true }
        (Invoke-Pair) | Should -Be 0
        $s = $global:AzResState
        @($s.Creates) | Should -Be @('monitor log-analytics workspace table create')
        $s.Ws.Tagged | Should -BeFalse
        $s.Ws.Quota | Should -Be 5
        $s.Ag.Tagged | Should -BeFalse
        $s.Rule.Tagged | Should -BeFalse
        $s.Alien.Count | Should -Be 0 -Because ($s.Alien -join '; ')
        $s.Dups.Count | Should -Be 0

        $entries = Get-ManifestEntries
        foreach ($t in 'log-analytics-workspace', 'action-group', 'alert-rule') {
            @($entries | Where-Object { $_.type -eq $t -and $_.ownership -eq 'reused' }).Count | Should -Be 1 -Because $t
            @($entries | Where-Object { $_.type -eq $t -and $_.ownership -eq 'created' }).Count | Should -Be 0 -Because $t
        }
        @($entries | Where-Object { $_.type -eq 'log-analytics-table' -and $_.ownership -eq 'created' }).Count | Should -Be 1
    }

    It 'keeps them reused and changes nothing when re-run' {
        New-Account -Scenario @{ ForeignWorkspace = $true; ForeignActionGroup = $true; ForeignRule = $true }
        (Invoke-Pair) | Should -Be 0
        $before = $global:AzResState.Creates.Count
        (Invoke-Pair) | Should -Be 0
        $global:AzResState.Creates.Count | Should -Be $before
        $global:AzResState.Alien.Count | Should -Be 0 -Because ($global:AzResState.Alien -join '; ')
        @(Get-ManifestEntries | Where-Object { $_.ownership -eq 'reused' }).Count | Should -Be 3
    }

    It 'creates only what is missing next to a foreign workspace' {
        New-Account -Scenario @{ ForeignWorkspace = $true }
        (Invoke-Pair) | Should -Be 0
        $s = $global:AzResState
        $s.Creates | Should -Not -Contain 'monitor log-analytics workspace create'
        $s.Creates | Should -Contain 'monitor action-group create'
        $s.Creates | Should -Contain 'monitor scheduled-query create'
        $s.Ws.Tagged | Should -BeFalse
        $s.Alien.Count | Should -Be 0 -Because ($s.Alien -join '; ')
    }
}

Describe 'Application gate of enable-all.ps1' {
    It 'stops with exit 3 and creates nothing when reading the VM is denied' {
        New-Account
        $global:AzResState.FailAt = 0
        (Invoke-Script -Name 'enable-all.ps1' -Params ($script:Params + @{ Email = 'owner.test@example.com' })) | Should -Be 3
        $global:AzResState.Failed | Should -Be 'vm show'
        $global:AzResState.Creates.Count | Should -Be 0
    }

    It 'stops with exit 4 and creates nothing when the application is not deployed' {
        New-Account -Scenario @{ NoVm = $true }
        (Invoke-Script -Name 'enable-all.ps1' -Params ($script:Params + @{ Email = 'owner.test@example.com' })) | Should -Be 4
        $global:AzResState.Creates.Count | Should -Be 0
        $global:AzResState.Alien.Count | Should -Be 0
    }
}
