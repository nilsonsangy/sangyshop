<#
.SYNOPSIS
    Pester tests: -LabBucket and -InstanceId of the AWS IR lab scripts have defaults.

.DESCRIPTION
    enable-all.ps1, enable-cloudtrail.ps1, plant-leaked-credential.ps1 and
    use-leaked-credential.ps1 derive the app bucket the way ops/aws/ec2/deploy.ps1 does
    (Aws.Ec2.BucketBase + '-' + UniqueSuffix) or read the s3-bucket entry of the deploy
    component in the lab manifest. plant-leaked-credential.ps1 also defaults -InstanceId from
    the ec2-instance manifest entry or from describe-instances with the lab Name and lab tags.

    Every AWS call goes through the fake $global:LabCliHandler. No real AWS call is made, and the
    manifest and config live in a temporary folder.

    Run: Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path ops/tests/AwsIrLab.Defaults.Tests.ps1
#>

BeforeAll {
    $script:OpsDir = Split-Path -Parent $PSScriptRoot
    $script:IrDir = Join-Path $script:OpsDir 'aws\ir-lab'
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-defaults-' + [guid]::NewGuid().ToString('N'))
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
    $script:ManifestFile = Join-Path $script:WorkDir 'manifest.json'
    $env:LAB_MANIFEST_PATH = $script:ManifestFile

    # Records every call; describe-instances answers come from $global:DefInstances.
    $global:DefCalls = New-Object System.Collections.ArrayList
    $global:DefInstances = '[]'
    $global:LabCliHandler = {
        param($a)
        $key = "$($a[2]) $($a[3])"
        [void]$global:DefCalls.Add($key)
        switch ($key) {
            'sts get-caller-identity' { return [pscustomobject]@{ ExitCode = 0; Output = '123456789012' } }
            'ec2 describe-instances' { return [pscustomobject]@{ ExitCode = 0; Output = $global:DefInstances } }
            's3api head-bucket' { return [pscustomobject]@{ ExitCode = 254; Output = 'NotFound' } }
            'iam get-user' { return [pscustomobject]@{ ExitCode = 254; Output = 'NoSuchEntity' } }
            default { return [pscustomobject]@{ ExitCode = 0; Output = '[]' } }
        }
    }

    function Write-TestManifest {
        param([object[]] $Resources)
        $doc = [ordered]@{ schema = 1; lab = 'sangyshop-lab-aws'; run_id = '20260101T000000Z-abcd'; region = 'us-east-1'; resources = $Resources }
        ConvertTo-Json -InputObject $doc -Depth 6 | Set-Content -LiteralPath $script:ManifestFile -Encoding UTF8
    }

    function Invoke-IrScript {
        param([string] $Path, [hashtable] $Params)
        $global:LASTEXITCODE = 0
        $out = (& $Path @Params *>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    }

    . (Join-Path $script:OpsDir 'lib\Common.ps1')
    . (Join-Path $script:OpsDir 'aws\AwsLabNames.ps1')
}

AfterAll {
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    Remove-Variable -Name LabCliHandler, DefCalls, DefInstances -Scope Global -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}


Describe 'AWS IR lab defaults' {
BeforeEach {
    $global:DefCalls.Clear()
    $global:DefInstances = '[]'
    if (Test-Path -LiteralPath $script:ManifestFile) { Remove-Item -LiteralPath $script:ManifestFile -Force }
}

Describe 'Get-AwsLabNames app bucket and instance name' {

    It 'derives AppBucket like deploy.ps1 and Ec2Name from the app name' {
        $cfg = & $script:ConfigFile
        $n = Get-AwsLabNames -Config $cfg
        $n['AppBucket'] | Should -BeExactly 'sangyshop-lab-labtest01'
        $n['Ec2Name'] | Should -BeExactly 'sangyshop-lab-ec2'
    }

    It 'leaves AppBucket empty when the config has no BucketBase or no UniqueSuffix' {
        $n = Get-AwsLabNames -Config @{ Common = @{ AppName = 'sangyshop' }; Aws = @{ Region = 'us-east-1'; AccountId = '123456789012' } }
        $n['AppBucket'] | Should -BeExactly ''
    }
}

Describe 'Find-LabManifestResourceId' {

    It 'returns the newest matching entry and ignores other components and regions' {
        Write-TestManifest @(
            @{ type = 's3-bucket'; id = 'old-bucket'; region = 'us-east-1'; component = 'deploy' },
            @{ type = 's3-bucket'; id = 'trail-bucket'; region = 'us-east-1'; component = 'detection' },
            @{ type = 's3-bucket'; id = 'other-region'; region = 'eu-west-1'; component = 'deploy' },
            @{ type = 's3-bucket'; id = 'new-bucket'; region = 'us-east-1'; component = 'deploy' }
        )
        Find-LabManifestResourceId -Type 's3-bucket' -Lab 'sangyshop-lab-aws' -Component 'deploy' -Region 'us-east-1' | Should -BeExactly 'new-bucket'
    }

    It 'returns null when there is no manifest or no matching entry' {
        Find-LabManifestResourceId -Type 's3-bucket' -Lab 'sangyshop-lab-aws' | Should -BeNullOrEmpty
        Write-TestManifest @(@{ type = 'ec2-instance'; id = 'i-0123456789abcdef0'; region = 'us-east-1'; component = 'deploy' })
        Find-LabManifestResourceId -Type 's3-bucket' -Lab 'sangyshop-lab-aws' | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-LabAppBucket and Resolve-LabInstanceId' {

    BeforeAll {
        . (Join-Path $script:IrDir 'detection\Detection-Common.ps1')
        Initialize-Lab -Region 'us-east-1'
    }

    It 'keeps an explicit bucket' {
        Resolve-LabAppBucket -LabBucket 'my-bucket' | Should -BeExactly 'my-bucket'
    }

    It 'uses the config derivation when no bucket is given' {
        Resolve-LabAppBucket -LabBucket '' 6>$null | Should -BeExactly 'sangyshop-lab-labtest01'
    }

    It 'falls back to the manifest when the config gives no bucket, and to empty when neither exists' {
        $saved = $script:LabNames['AppBucket']
        try {
            $script:LabNames['AppBucket'] = ''
            Resolve-LabAppBucket -LabBucket '' | Should -BeExactly ''
            Write-TestManifest @(@{ type = 's3-bucket'; id = 'manifest-bucket'; region = 'us-east-1'; component = 'deploy' })
            Resolve-LabAppBucket -LabBucket '' 6>$null | Should -BeExactly 'manifest-bucket'
        }
        finally { $script:LabNames['AppBucket'] = $saved }
    }

    It 'resolves the instance from the manifest without any AWS call' {
        Write-TestManifest @(@{ type = 'ec2-instance'; id = 'i-0123456789abcdef0'; region = 'us-east-1'; component = 'deploy' })
        Resolve-LabInstanceId -InstanceId '' 6>$null | Should -BeExactly 'i-0123456789abcdef0'
        $global:DefCalls.Count | Should -Be 0
    }

    It 'resolves the instance by the lab Name and lab tags when the manifest has none' {
        $global:DefInstances = '["i-0aaaaaaaaaaaaaaaa"]'
        $global:LastDescribe = $null
        Resolve-LabInstanceId -InstanceId '' 6>$null | Should -BeExactly 'i-0aaaaaaaaaaaaaaaa'
        $global:DefCalls | Should -Contain 'ec2 describe-instances'
    }

    It 'returns empty when no instance matches' {
        Resolve-LabInstanceId -InstanceId '' | Should -BeExactly ''
    }
}

Describe 'Scripts without -LabBucket or -InstanceId' {

    It 'enable-cloudtrail.ps1 -WhatIf uses the config bucket and exits 0' {
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'detection\enable-cloudtrail.ps1') -Params @{ Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match "app bucket 'sangyshop-lab-labtest01' from the lab config"
        $r.Output | Should -Not -Match 'Missing required parameter'
    }

    It 'enable-cloudtrail.ps1 -WhatIf with -LabBucket still works' {
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'detection\enable-cloudtrail.ps1') -Params @{ Region = 'us-east-1'; LabBucket = 'explicit-bucket'; WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Not -Match 'from the lab config'
    }

    It 'plant-leaked-credential.ps1 -WhatIf defaults the bucket and the instance from config and manifest' {
        Write-TestManifest @(@{ type = 'ec2-instance'; id = 'i-0123456789abcdef0'; region = 'us-east-1'; component = 'deploy' })
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'plant-leaked-credential.ps1') -Params @{ Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match "app bucket 'sangyshop-lab-labtest01' from the lab config"
        $r.Output | Should -Match "instance 'i-0123456789abcdef0' from the lab manifest"
        $r.Output | Should -Match 'i-0123456789abcdef0'
    }

    It 'plant-leaked-credential.ps1 -WhatIf finds the instance by tags when the manifest has none' {
        $global:DefInstances = '["i-0bbbbbbbbbbbbbbbb"]'
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'plant-leaked-credential.ps1') -Params @{ Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'Name=tag:Name,Values=sangyshop-lab-ec2'
        $r.Output | Should -Match 'i-0bbbbbbbbbbbbbbbb'
    }

    It 'plant-leaked-credential.ps1 exits 2 when no instance can be found' {
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'plant-leaked-credential.ps1') -Params @{ Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 2 -Because $r.Output
        $r.Output | Should -Match 'describe-instances'
    }

    It 'plant-leaked-credential.ps1 exits 2 when several instances match' {
        $global:DefInstances = '["i-0aaaaaaaaaaaaaaaa","i-0bbbbbbbbbbbbbbbb"]'
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'plant-leaked-credential.ps1') -Params @{ Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 2 -Because $r.Output
        $r.Output | Should -Match 'describe-instances'
    }

    It 'use-leaked-credential.ps1 -WhatIf defaults the bucket from the config' {
        $cred = Join-Path $script:WorkDir 'cred.json'
        Set-Content -LiteralPath $cred -Encoding UTF8 -Value '{"access_key_id":"AKIAEXAMPLEEXAMPLE","secret_access_key":"not-a-real-secret","region":"us-east-1"}'
        $r = Invoke-IrScript -Path (Join-Path $script:IrDir 'use-leaked-credential.ps1') -Params @{ CredentialPath = $cred; Region = 'us-east-1'; WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match "app bucket 'sangyshop-lab-labtest01' from the lab config"
        $r.Output | Should -Not -Match 'not-a-real-secret'
    }
}
}
