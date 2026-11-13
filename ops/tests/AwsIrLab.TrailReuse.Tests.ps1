<#
.SYNOPSIS
    Pester tests: the lab tools follow a trail reused from the account (for example 'management-events').

.DESCRIPTION
    enable-cloudtrail.ps1 records a reused trail in the lab manifest as type 'cloudtrail-trail',
    ownership 'reused', component 'detection', with no delete block. These tests write that exact
    shape and check that check-detection-ready.ps1 and verify-lab-state.ps1 read the status of THAT
    trail (not the lab trail name), that the output and the stamp say which trail was checked, and
    that disable-cloudtrail.ps1 never stops or deletes a trail the manifest records as reused.

    Every AWS call goes through the fake $global:LabCliHandler. No real AWS call is made, and the
    manifest and config live in a temporary folder.

    Run: Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path ops/tests/AwsIrLab.TrailReuse.Tests.ps1
#>

BeforeAll {
    $script:OpsDir = Split-Path -Parent $PSScriptRoot
    $script:IrDir = Join-Path $script:OpsDir 'aws\ir-lab'
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-trail-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null

    $script:ConfigFile = Join-Path $script:WorkDir 'cloud.config.ps1'
    Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = 'labtest01'
    Common = @{ AppName = 'sangyshop'; DbName = 'sangyshop'; DbUser = 'sangyshop'; ImageTag = 'hardened' }
    Aws = @{
        Region = 'us-east-1'; AccountId = '123456789012'
        Ec2 = @{ InstanceType = 't3.small'; DbInstanceClass = 'db.t4g.micro'; BucketBase = 'sangyshop-lab'; VolumeGb = 20 }
    }
}
'@
    $env:LAB_CONFIG_PATH = $script:ConfigFile
    $script:ManifestFile = Join-Path $script:WorkDir 'manifest-sangyshop-lab-aws.json'
    $env:LAB_MANIFEST_PATH = $script:ManifestFile
    $script:StampFile = Join-Path $script:WorkDir 'readiness.json'

    # Only the reused trail 'management-events' exists and is logging; the lab trail name does not exist.
    $global:TrCalls = New-Object System.Collections.ArrayList
    $global:TrTrailLogging = $true
    $global:LabCliHandler = {
        param($a)
        $key = "$($a[2]) $($a[3])"
        [void]$global:TrCalls.Add(($a -join ' '))
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        $no = [pscustomobject]@{ ExitCode = 254; Output = 'An error occurred (TrailNotFoundException): not found' }
        $i = [array]::IndexOf($a, '--name')
        $name = if ($i -ge 0) { [string]$a[$i + 1] } else { '' }
        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'cloudtrail get-trail-status' {
                if ($name -ne 'management-events') { return $no }
                return (& $ok (ConvertTo-Json -Compress @{ IsLogging = $global:TrTrailLogging }))
            }
            'sns list-subscriptions-by-topic' { return (& $ok '{"Subscriptions":[{"Protocol":"email","SubscriptionArn":"arn:aws:sns:us-east-1:123456789012:t:abc"}]}') }
            'cloudwatch describe-alarms' { return (& $ok '{"MetricAlarms":[{"AlarmName":"x","AlarmActions":["arn:aws:sns:us-east-1:123456789012:t"]}]}') }
            'logs describe-log-groups' {
                $j = [array]::IndexOf($a, '--log-group-name-prefix')
                return (& $ok (ConvertTo-Json -Compress -Depth 4 @{ logGroups = @(@{ logGroupName = [string]$a[$j + 1] }) }))
            }
            'cloudtrail describe-trails' { return (& $ok '[]') }
            default { return (& $ok '{}') }
        }
    }

    function script:Write-ReusedManifest {
        # Same shape Add-LabManifestEntry writes for Add-LabReusedResource: no delete block.
        $doc = [ordered]@{
            schema = 1; lab = 'sangyshop-lab-aws'; run_id = '20261113T120806Z-d9d3'; region = 'us-east-1'
            resources = @(
                [ordered]@{ type = 'vpc'; id = 'vpc-04500595ad2c9e7f7'; region = 'us-east-1'; run_id = '20261113T095752Z-54e3'; component = 'deploy'; ownership = 'created' },
                [ordered]@{ type = 'cloudtrail-trail'; id = 'management-events'; region = 'us-east-1'; run_id = '20261113T120806Z-d9d3'; component = 'detection'; created_utc = '2026-11-13T12:00:00Z'; ownership = 'reused' }
            )
        }
        ConvertTo-Json -InputObject $doc -Depth 6 | Set-Content -LiteralPath $script:ManifestFile -Encoding UTF8
    }

    function script:Invoke-IrScript {
        param([string] $Name, [hashtable] $Params)
        $global:LASTEXITCODE = 0
        $out = (& (Join-Path $script:IrDir $Name) @Params *>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    }
}

AfterAll {
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    Remove-Variable -Name LabCliHandler, TrCalls, TrTrailLogging -Scope Global -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Trail reused from the account' {
    BeforeEach {
        $global:TrCalls.Clear()
        $global:TrTrailLogging = $true
        foreach ($f in $script:ManifestFile, $script:StampFile) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    }

    It 'uses the manifest path enable-cloudtrail writes (default and LAB_MANIFEST_PATH override)' {
        . (Join-Path $script:OpsDir 'lib\Common.ps1')
        Get-LabManifestPath -Lab 'sangyshop-lab-aws' | Should -BeExactly $script:ManifestFile
        $saved = $env:LAB_MANIFEST_PATH
        try {
            $env:LAB_MANIFEST_PATH = $null
            Get-LabManifestPath -Lab 'sangyshop-lab-aws' | Should -BeExactly (Join-Path (Join-Path $HOME '.sangyshop-lab') 'manifest-sangyshop-lab-aws.json')
        } finally { $env:LAB_MANIFEST_PATH = $saved }
    }

    It 'check-detection-ready checks the reused trail, exits 0 and stamps the trail name' {
        Write-ReusedManifest
        $r = Invoke-IrScript -Name 'check-detection-ready.ps1' -Params @{ Region = 'us-east-1'; StampPath = $script:StampFile }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Not -Match 'not found'
        $r.Output | Should -Match "trail 'management-events' \(reused from the account"
        $r.Output | Should -Match "Trail checked: 'management-events' \(reused\)"
        @($global:TrCalls | Where-Object { $_ -match 'get-trail-status --name management-events' }).Count | Should -BeGreaterThan 0
        @($global:TrCalls | Where-Object { $_ -match 'get-trail-status --name sangyshop-lab-trail' }).Count | Should -Be 0
        $doc = Get-Content -LiteralPath $script:StampFile -Raw | ConvertFrom-Json
        $doc.trail.name | Should -BeExactly 'management-events'
        $doc.trail.ownership | Should -BeExactly 'reused'
        $doc.checks.trail_logging | Should -BeTrue
    }

    It 'check-detection-ready exits 1 and names the reused trail when it is not logging' {
        Write-ReusedManifest
        $global:TrTrailLogging = $false
        $r = Invoke-IrScript -Name 'check-detection-ready.ps1' -Params @{ Region = 'us-east-1'; StampPath = $script:StampFile }
        $r.ExitCode | Should -Be 1 -Because $r.Output
        $r.Output | Should -Match "trail 'management-events'.*exists but is not logging"
        Test-Path -LiteralPath $script:StampFile | Should -BeFalse
    }

    It 'falls back to the lab trail name only when the manifest has no trail entry' {
        $r = Invoke-IrScript -Name 'check-detection-ready.ps1' -Params @{ Region = 'us-east-1'; StampPath = $script:StampFile }
        $r.ExitCode | Should -Be 1 -Because $r.Output
        $r.Output | Should -Match "trail 'sangyshop-lab-trail' \(lab trail name, no trail in the lab manifest\) not found"
        @($global:TrCalls | Where-Object { $_ -match 'get-trail-status --name sangyshop-lab-trail' }).Count | Should -BeGreaterThan 0
    }

    It 'verify-lab-state reports the reused trail as OK' {
        Write-ReusedManifest
        $r = Invoke-IrScript -Name 'verify-lab-state.ps1' -Params @{ Region = 'us-east-1'; SkipFlowLogs = $true; SkipGuardDuty = $true }
        $r.Output | Should -Match "OK\s+cloudtrail\s+trail 'management-events'"
        $r.Output | Should -Not -Match "MISSING\s+cloudtrail"
    }

    It 'disable-cloudtrail never stops or deletes a trail the manifest records as reused' {
        Write-ReusedManifest
        $r = Invoke-IrScript -Name 'detection\disable-cloudtrail.ps1' -Params @{ Region = 'us-east-1'; TrailName = 'management-events'; KeepTrailBucket = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'kept \(not created by the lab\)'
        @($global:TrCalls | Where-Object { $_ -match 'stop-logging|delete-trail|add-tags|put-event-selectors' }).Count | Should -Be 0
    }

    It 'print-response-commands names the trail from the manifest and makes no AWS call' {
        Write-ReusedManifest
        $evidence = Join-Path $script:WorkDir 'attack-steps.jsonl'
        Set-Content -LiteralPath $evidence -Value '{"step":1}' -Encoding UTF8
        $r = Invoke-IrScript -Name 'print-response-commands.ps1' -Params @{ Region = 'us-east-1'; AttackEvidencePath = $evidence }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match "CloudTrail source: trail 'management-events' \(reused\)"
        @($global:TrCalls | Where-Object { $_ -notmatch 'sts get-caller-identity' }).Count | Should -Be 0
    }
}
