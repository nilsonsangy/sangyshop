<#
.SYNOPSIS
    Pester 5.x tests for the shared helpers of the AWS detection and blocker scripts.
.DESCRIPTION
    Covers ops/aws/ir-lab/detection/Detection-Common.ps1 and the blocker scripts that
    build on it: names come from Get-AwsLabNames, tags come from Get-LabTags, run ids
    come from New-RunId, the manifest goes through Add-LabManifestEntry, the region
    falls back to the config, and printed commands are masked. Every AWS call goes
    through $global:LabCliHandler, so no real AWS call is made.
    Run with:
        Invoke-Pester -Path ops/tests/AwsIrLab.DetectionCommon.Tests.ps1
#>
BeforeAll {
    $script:IrLabDir = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'ir-lab')).Path
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-common-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null

    $script:SavedEnv = @{
        LAB_CONFIG_PATH   = $env:LAB_CONFIG_PATH
        LAB_MANIFEST_PATH = $env:LAB_MANIFEST_PATH
        LAB_RUN_ID        = $env:LAB_RUN_ID
        NIMBUSDFIR_PATH   = $env:NIMBUSDFIR_PATH
    }
    $script:ConfigFile = Join-Path $script:Work 'cloud.config.ps1'
    Set-Content -LiteralPath $script:ConfigFile -Encoding UTF8 -Value @'
@{
    UniqueSuffix = 'labtest01'
    Common = @{ AppName = 'shopx'; DbName = 'shopx'; DbUser = 'shopx'; ImageTag = 'hardened' }
    Aws = @{
        Region = 'eu-west-1'; AccountId = '111122223333'
        Ec2 = @{ InstanceType = 't3.small'; DbInstanceClass = 'db.t4g.micro'; BucketBase = 'shopx-lab'; VolumeGb = 20 }
    }
}
'@
    $env:LAB_CONFIG_PATH = $script:ConfigFile
    $env:LAB_MANIFEST_PATH = Join-Path $script:Work 'manifest.json'
    $env:LAB_RUN_ID = $null
    $env:NIMBUSDFIR_PATH = $null
    $global:LabCliHandler = $null

    # Dot-source in the test scope so the helpers and $script: variables are visible.
    . (Join-Path $script:IrLabDir 'detection' 'Detection-Common.ps1')
}

AfterAll {
    foreach ($k in $script:SavedEnv.Keys) { [Environment]::SetEnvironmentVariable($k, $script:SavedEnv[$k], 'Process') }
    $global:LabCliHandler = $null
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) {
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Detection-Common names and tags' {
    It 'derives every name from the application name in the config' {
        $script:LabTagValue | Should -Be 'shopx-lab-aws'
        $script:LabTrailName | Should -Be 'shopx-lab-trail'
        $script:LabAppLogGroup | Should -Be '/shopx/app'
        $script:LabFlowLogGroup | Should -Be '/shopx/vpcflow'
        $script:LabTopicName | Should -Be 'shopx-lab-alerts'
        $script:LabAlarmName | Should -Be 'shopx-lab-bruteforce'
        $script:LabFilterName | Should -Be 'shopx-auth-login-failure'
        $script:LabMetricName | Should -Be 'LoginFailure'
    }

    It 'builds tags from Get-LabTags with the lab, run-id and component keys' {
        $run = New-RunId
        (Get-LabTagPairs -RunId $run) | Should -Be @('Key=lab,Value=shopx-lab-aws', "Key=run-id,Value=$run", 'Key=component,Value=detection')
        (Get-LabTagMap -RunId $run -Component 'blocker') | Should -Be "lab=shopx-lab-aws,run-id=$run,component=blocker"
        $json = Get-LabTagJsonList -RunId $run | ConvertFrom-Json
        @($json).Count | Should -Be 3
        ($json | Where-Object Key -eq 'lab').Value | Should -Be 'shopx-lab-aws'
    }

    It 'recognizes the lab tag in list and map shapes and rejects other labs' {
        Test-LabTagged -Tags (ConvertFrom-Json '[{"Key":"lab","Value":"shopx-lab-aws"}]') | Should -BeTrue
        Test-LabTagged -Tags (ConvertFrom-Json '{"lab":"shopx-lab-aws"}') | Should -BeTrue
        Test-LabTagged -Tags (ConvertFrom-Json '[{"Key":"lab","Value":"other"}]') | Should -BeFalse
        Test-LabTagged -Tags $null | Should -BeFalse
    }
}

Describe 'Detection-Common run id and region' {
    It 'generates a run id in the New-RunId format when none is given' {
        Get-LabRunId | Should -Match '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$'
    }

    It 'keeps a valid run id and takes it from LAB_RUN_ID when the parameter is empty' {
        Get-LabRunId -RunId '20260101T000000Z-abcd' | Should -Be '20260101T000000Z-abcd'
        $env:LAB_RUN_ID = '20260202T000000Z-1234'
        try { Get-LabRunId | Should -Be '20260202T000000Z-1234' } finally { $env:LAB_RUN_ID = $null }
    }

    It 'uses the region parameter first and the config region otherwise' {
        $global:LabCliHandler = { param($a) [pscustomobject]@{ ExitCode = 0; Output = '' } }
        try {
            Initialize-Lab -Region 'us-west-2'
            $script:LabRegion | Should -Be 'us-west-2'
            Initialize-Lab
            $script:LabRegion | Should -Be 'eu-west-1'
        } finally { $global:LabCliHandler = $null }
    }
}

Describe 'Detection-Common CLI seam, masking and manifest' {
    BeforeEach {
        $script:Seen = New-Object System.Collections.ArrayList
        $global:LabCliHandler = { param($a) [void]$script:Seen.Add($a); [pscustomobject]@{ ExitCode = 0; Output = '' } }
        $script:LabRegion = 'eu-west-1'
    }
    AfterEach { $global:LabCliHandler = $null }

    It 'masks access key ids in the echoed command line' {
        $out = Invoke-LabCli -CliArgs @('iam', 'noop', 'AKIAABCDEFGHIJKLMNOP') 6>&1 | Out-String
        $out | Should -Not -Match 'AKIAABCDEFGHIJKLMNOP'
        $out | Should -Match 'REDACTED'
        $script:Seen[0] | Should -Contain 'AKIAABCDEFGHIJKLMNOP'
    }

    It 'echoes a mutating call without running it under WhatIf' {
        $WhatIfPreference = $true
        try { $r = Invoke-LabCli -Mutating -CliArgs @('sns', 'create-topic') 6>&1 | Out-Null } finally { $WhatIfPreference = $false }
        $script:Seen.Count | Should -Be 0
    }

    It 'records a resource through Add-LabManifestEntry with region, component and ownership' {
        Add-LabResource -Type 'sns-subscription' -Id 'arn|email|x' -RunId '20260101T000000Z-abcd' 6>&1 | Out-Null
        $doc = Get-Content -LiteralPath $env:LAB_MANIFEST_PATH -Raw | ConvertFrom-Json
        $doc.lab | Should -Be 'shopx-lab-aws'
        $e = @($doc.resources)[0]
        $e.type | Should -Be 'sns-subscription'
        $e.region | Should -Be 'eu-west-1'
        $e.component | Should -Be 'detection'
        $e.ownership | Should -Be 'created'
        @(Read-LabManifest).Count | Should -Be 1
        Remove-LabManifestEntry -Type 'sns-subscription' -Id 'arn|email|x'
        @(Read-LabManifest).Count | Should -Be 0
    }
}

Describe 'Blocker scripts' {
    BeforeAll {
        $global:LabCliHandler = {
            param($a)
            $key = "$($a[2]) $($a[3])"
            switch ($key) {
                'sts get-caller-identity' { return [pscustomobject]@{ ExitCode = 0; Output = '111122223333' } }
                'ec2 describe-network-acls' { return [pscustomobject]@{ ExitCode = 0; Output = '[{"Key":"lab","Value":"shopx-lab-aws"}]' } }
                'logs describe-log-groups' { return [pscustomobject]@{ ExitCode = 0; Output = '[]' } }
                default { return [pscustomobject]@{ ExitCode = 254; Output = 'NotFound' } }
            }
        }
    }
    AfterAll { $global:LabCliHandler = $null }

    It 'deploy-blocker prints a plan with names from the config under WhatIf' {
        $text = & (Join-Path $script:IrLabDir 'blocker' 'deploy-blocker.ps1') -NaclId 'acl-0123456789abcdef0' -WhatIf *>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'shopx-lab-blocker-role'
        $text | Should -Match 'shopx-lab-blocker-trigger'
        $text | Should -Match 'component=blocker'
        $text | Should -Not -Match 'sangyshop'
    }

    It 'remove-blocker finds nothing to do on an empty account' {
        $text = & (Join-Path $script:IrLabDir 'blocker' 'remove-blocker.ps1') -WhatIf *>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $text | Should -Match 'Nothing to do'
    }

    It 'keeps resource names out of the shared and blocker scripts' {
        $files = @(
            (Join-Path $script:IrLabDir 'detection' 'Detection-Common.ps1'),
            (Join-Path $script:IrLabDir 'blocker' 'Blocker-Common.ps1'),
            (Join-Path $script:IrLabDir 'blocker' 'deploy-blocker.ps1'),
            (Join-Path $script:IrLabDir 'blocker' 'remove-blocker.ps1'),
            (Join-Path $script:IrLabDir 'blocker' 'lambda_function.py')
        )
        foreach ($f in $files) {
            (Get-Content -LiteralPath $f -Raw) | Should -Not -Match '(?i)sangyshop' -Because $f
        }
    }
}
