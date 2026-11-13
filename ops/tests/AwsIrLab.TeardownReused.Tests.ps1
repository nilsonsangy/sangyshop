<#
.SYNOPSIS
    Pester tests: full-teardown.ps1 and verify-zero-cost.ps1 never remove or count resources the
    lab only reused,.

.DESCRIPTION
    The scripts run in-process through the Invoke-LabCli seam ($global:LabCliHandler) against a tiny
    in-memory account. No AWS call is ever made.

    Run: Invoke-Pester -Path ops/tests/AwsIrLab.TeardownReused.Tests.ps1
#>

BeforeAll {
    $script:AwsDir = (Resolve-Path (Join-Path $PSScriptRoot '..\aws\ir-lab')).Path
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-reused-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

    $script:ConfigPath = Join-Path $script:WorkDir 'cloud.config.ps1'
    $cfgText = @'
@{
    UniqueSuffix = 'labtest'
    Common       = @{ AppName = 'sangyshop' }
    Aws          = @{
        Region    = 'us-east-1'
        AccountId = '123456789012'
        Ec2       = @{ InstanceType = 't3.micro'; DbInstanceClass = 'db.t3.micro'; BucketBase = 'app'; VolumeGb = 20 }
    }
}
'@
    [System.IO.File]::WriteAllText($script:ConfigPath, $cfgText, (New-Object System.Text.UTF8Encoding($false)))
    $script:PreviousConfigPath = $env:LAB_CONFIG_PATH
    $env:LAB_CONFIG_PATH = $script:ConfigPath

    function global:Start-ReusedFake {
        # Two secrets exist and none carries tags; only the manifests say who owns them.
        $global:ReusedFake = @{ Secrets = @{ 'app/created-secret' = $false; 'app/reused-secret' = $false }; Deleted = (New-Object System.Collections.ArrayList) }
        $global:LabDeployTeardownHandler = { param($p) return 0 }
        $global:LabCliHandler = {
            param($a)
            $st = $global:ReusedFake
            $call = "$($a[2]) $($a[3])"
            $arg = { param($n) $i = [array]::IndexOf($a, $n); if ($i -ge 0 -and $i + 1 -lt $a.Count) { [string]$a[$i + 1] } else { $null } }
            $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
            switch ($call) {
                'sts get-caller-identity' { return (& $ok '123456789012') }
                'secretsmanager describe-secret' {
                    $id = & $arg '--secret-id'
                    if ($st.Secrets.ContainsKey($id) -and -not $st.Secrets[$id]) { return (& $ok $id) }
                    return [pscustomobject]@{ ExitCode = 254; Output = 'ResourceNotFound: does not exist' }
                }
                'secretsmanager list-secrets' {
                    $rows = @(foreach ($k in $st.Secrets.Keys) { if (-not $st.Secrets[$k]) { [pscustomobject]@{ id = $k; tags = $null } } })
                    return (& $ok (ConvertTo-Json -InputObject @($rows) -Compress))
                }
                'secretsmanager delete-secret' {
                    $id = & $arg '--secret-id'
                    [void]$st.Deleted.Add($id)
                    $st.Secrets[$id] = $true
                    return (& $ok '')
                }
                default { return (& $ok '[]') }
            }
        }
        $global:LabConfirmHandler = { param($p) return 'yes' }
    }

    function New-ReusedManifest {
        param([string]$Name, $Entries)
        $path = Join-Path $script:WorkDir $Name
        $json = ([ordered]@{ resources = @($Entries) }) | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
        return $path
    }

    function Invoke-LabScript {
        param([string]$Script, [hashtable]$Params)
        $global:LASTEXITCODE = $null
        $out = & $Script @Params *>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
}

AfterAll {
    $env:LAB_CONFIG_PATH = $script:PreviousConfigPath
    $global:LabCliHandler = $null
    $global:LabDeployTeardownHandler = $null
    $global:LabConfirmHandler = $null
    $global:ReusedFake = $null
    Remove-Item -LiteralPath 'Function:\global:Start-ReusedFake' -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Resources recorded as reused' {
    It 'full-teardown removes the created secret and keeps the reused one' {
        Start-ReusedFake
        $manifest = New-ReusedManifest -Name 'one.json' -Entries @(
            [ordered]@{ type = 'secret'; id = 'app/created-secret'; region = 'us-east-1'; run_id = 'run-a'; ownership = 'created' }
            [ordered]@{ type = 'secret'; id = 'app/reused-secret'; region = 'us-east-1'; run_id = 'run-a'; ownership = 'reused' }
        )
        $r = Invoke-LabScript -Script (Join-Path $script:AwsDir 'full-teardown.ps1') -Params @{ Region = 'us-east-1'; ManifestPath = $manifest; NonInteractive = $true }
        $r.Code | Should -Be 0
        @($global:ReusedFake.Deleted) -join ',' | Should -Be 'app/created-secret'
        $r.Output | Should -Match 'kept \(not created by the lab\): secret app/reused-secret'
    }

    It 'verify-zero-cost does not count a reused resource as pending' {
        Start-ReusedFake
        $global:ReusedFake.Secrets['app/created-secret'] = $true
        $manifest = New-ReusedManifest -Name 'two.json' -Entries @(
            [ordered]@{ type = 'secret'; id = 'app/reused-secret'; region = 'us-east-1'; run_id = 'run-a'; ownership = 'reused' }
        )
        $r = Invoke-LabScript -Script (Join-Path $script:AwsDir 'verify-zero-cost.ps1') -Params @{ Region = 'us-east-1'; ManifestPath = $manifest }
        $r.Code | Should -Be 0
        $r.Output | Should -Match 'nothing billable remaining'
        $r.Output | Should -Match 'kept \(not created by the lab\): secret app/reused-secret'
    }
}

Describe 'verify-zero-cost trail query' {
    It 'lists trails with the boolean no-include-shadow-trails flag and no stray value' {
        Start-ReusedFake
        $global:TrailInner = $global:LabCliHandler
        $global:TrailCalls = New-Object System.Collections.ArrayList
        $global:LabCliHandler = {
            param($a)
            if ("$($a[2]) $($a[3])" -eq 'cloudtrail describe-trails') { [void]$global:TrailCalls.Add(@($a)) }
            return (& $global:TrailInner $a)
        }
        $manifest = New-ReusedManifest -Name 'three.json' -Entries @()
        $r = Invoke-LabScript -Script (Join-Path $script:AwsDir 'verify-zero-cost.ps1') -Params @{ Region = 'us-east-1'; ManifestPath = $manifest }
        $calls = @($global:TrailCalls | Where-Object { $_ -contains 'trailList[].{id:Name}' })
        $global:TrailCalls = $null
        $global:TrailInner = $null
        $calls.Count | Should -Be 1
        (@($calls[0])[2..(@($calls[0]).Count - 1)] -join ' ') | Should -Be 'cloudtrail describe-trails --no-include-shadow-trails --query trailList[].{id:Name} --output json'
        (@($calls[0]) -contains 'false') | Should -BeFalse
    }
}
