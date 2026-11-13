<#
.SYNOPSIS
    Pester tests: plant-leaked-credential.ps1 never writes a placeholder secret for an existing key.

.DESCRIPTION
    When the lab IAM user already has an access key but the secret is not available locally (for
    example a previous run failed after create-access-key), the script deletes that user's key(s),
    creates a fresh one and writes the real secret. It only does so for a user that carries the lab
    tag. The manifest drops the old key id and records the new one. -WhatIf changes nothing.

    Every AWS call goes through the fake $global:LabCliHandler. No real AWS call is made, and the
    manifest, config and output file live in a temporary folder.

    Run: Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path ops/tests/AwsIrLab.PlantCredential.Tests.ps1
#>

BeforeAll {
    $script:OpsDir = Split-Path -Parent $PSScriptRoot
    $script:IrDir = Join-Path $script:OpsDir 'aws\ir-lab'
    $script:SavedManifest = $env:LAB_MANIFEST_PATH
    $script:SavedConfigPath = $env:LAB_CONFIG_PATH
    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('lab-plant-' + [guid]::NewGuid().ToString('N'))
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
    $script:OutFile = Join-Path $script:WorkDir 'out\leaked.json'

    $script:OldKey = 'AKIAOLDOLDOLDOLDOLD1'
    $script:NewKey = 'AKIANEWNEWNEWNEWNEW2'
    $script:NewSecret = 'NEWSECRETvalue0123456789abcdefghijklmnop'

    $global:PlNewKey = $script:NewKey
    $global:PlNewSecret = $script:NewSecret
    $global:PlCalls = New-Object System.Collections.ArrayList
    $global:PlKeys = @()
    $global:PlTagged = $true
    $global:LabCliHandler = {
        param($a)
        $key = "$($a[2]) $($a[3])"
        [void]$global:PlCalls.Add(($a -join ' '))
        $ok = { param($o) [pscustomobject]@{ ExitCode = 0; Output = [string]$o } }
        switch ($key) {
            'sts get-caller-identity' { return (& $ok '123456789012') }
            'iam get-user' {
                if ($global:PlTagged) { return (& $ok '[{"Key":"lab","Value":"sangyshop-lab-aws"}]') }
                return (& $ok '[]')
            }
            'iam list-access-keys' { return (& $ok (ConvertTo-Json -Compress -InputObject @($global:PlKeys))) }
            'iam delete-access-key' {
                $i = [array]::IndexOf($a, '--access-key-id')
                $global:PlKeys = @($global:PlKeys | Where-Object { $_ -ne $a[$i + 1] })
                return (& $ok '')
            }
            'iam create-access-key' {
                $global:PlKeys = @($global:PlKeys) + $global:PlNewKey
                return (& $ok (ConvertTo-Json -Compress -Depth 4 @{ AccessKey = @{ AccessKeyId = $global:PlNewKey; SecretAccessKey = $global:PlNewSecret } }))
            }
            default { return (& $ok '{}') }
        }
    }

    function script:Write-KeyManifest {
        $doc = [ordered]@{
            schema = 1; lab = 'sangyshop-lab-aws'; run_id = '20261113T120806Z-d9d3'; region = 'us-east-1'
            resources = @(
                [ordered]@{ type = 'iam-user'; id = 'sangyshop-lab-leaked'; region = 'us-east-1'; run_id = '20261113T120806Z-d9d3'; component = 'credential'; ownership = 'created' },
                [ordered]@{ type = 'iam-access-key'; id = "sangyshop-lab-leaked/$($script:OldKey)"; region = 'us-east-1'; run_id = '20261113T120806Z-d9d3'; component = 'credential'; ownership = 'created' }
            )
        }
        ConvertTo-Json -InputObject $doc -Depth 6 | Set-Content -LiteralPath $script:ManifestFile -Encoding UTF8
    }

    function script:Invoke-Plant {
        param([hashtable] $Extra = @{})
        $p = @{ Region = 'us-east-1'; LabBucket = 'sangyshop-lab-labtest01'; LeakedFilePath = $script:OutFile }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        $global:LASTEXITCODE = 0
        $out = (& (Join-Path $script:IrDir 'plant-leaked-credential.ps1') @p *>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    }

    function script:Get-ManifestIds {
        $doc = Get-Content -LiteralPath $script:ManifestFile -Raw | ConvertFrom-Json
        return @($doc.resources | Where-Object { $_.type -eq 'iam-access-key' } | ForEach-Object { $_.id })
    }
}

AfterAll {
    $env:LAB_MANIFEST_PATH = $script:SavedManifest
    $env:LAB_CONFIG_PATH = $script:SavedConfigPath
    Remove-Variable -Name LabCliHandler, PlCalls, PlKeys, PlTagged, PlNewKey, PlNewSecret -Scope Global -ErrorAction SilentlyContinue
    if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
        Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'plant-leaked-credential.ps1 existing access key' {
    BeforeEach {
        $global:PlCalls.Clear()
        $global:PlTagged = $true
        $global:PlKeys = @($script:OldKey)
        if (Test-Path -LiteralPath (Split-Path -Parent $script:OutFile)) { Remove-Item -LiteralPath (Split-Path -Parent $script:OutFile) -Recurse -Force }
        Write-KeyManifest
    }

    It 'rotates a key whose secret is unavailable and writes the real secret' {
        $r = Invoke-Plant
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match '\[INFO\] Access key\(s\) of lab user .* Rotating'
        $r.Output | Should -Not -Match ([regex]::Escape($script:NewSecret))

        $del = @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key' })
        $del.Count | Should -Be 1
        $del[0] | Should -Match "--user-name sangyshop-lab-leaked --access-key-id $($script:OldKey)"
        $idxDel = [array]::IndexOf(@($global:PlCalls), $del[0])
        $idxNew = [array]::IndexOf(@($global:PlCalls), @($global:PlCalls | Where-Object { $_ -match 'iam create-access-key' })[0])
        $idxDel | Should -BeLessThan $idxNew

        $leaked = Get-Content -LiteralPath $script:OutFile -Raw | ConvertFrom-Json
        $leaked.access_key_id | Should -BeExactly $script:NewKey
        $leaked.secret_access_key | Should -BeExactly $script:NewSecret
        (Get-Content -LiteralPath $script:OutFile -Raw) | Should -Not -Match 'EXAMPLE-SECRET'

        $ids = Get-ManifestIds
        $ids | Should -Not -Contain "sangyshop-lab-leaked/$($script:OldKey)"
        $ids | Should -Contain "sangyshop-lab-leaked/$($script:NewKey)"
    }

    It 'deletes only the lab user keys' {
        $global:PlKeys = @($script:OldKey, 'AKIASECONDKEY00000003')
        $null = Invoke-Plant
        $del = @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key' })
        $del.Count | Should -Be 2
        @($del | Where-Object { $_ -notmatch '--user-name sangyshop-lab-leaked ' }).Count | Should -Be 0
    }

    It 'refuses an untagged user and neither deletes nor creates a key' {
        $global:PlTagged = $false
        $r = Invoke-Plant
        $r.ExitCode | Should -Be 1 -Because $r.Output
        @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key|iam create-access-key' }).Count | Should -Be 0
        (Get-ManifestIds) | Should -Contain "sangyshop-lab-leaked/$($script:OldKey)"
    }

    It 'keeps the key when the local file already holds its real secret' {
        New-Item -ItemType Directory -Path (Split-Path -Parent $script:OutFile) -Force | Out-Null
        @{ access_key_id = $script:OldKey; secret_access_key = 'REALOLDSECRETvalue0123456789abcdefghijklm' } | ConvertTo-Json | Set-Content -LiteralPath $script:OutFile -Encoding UTF8
        $r = Invoke-Plant
        $r.ExitCode | Should -Be 0 -Because $r.Output
        @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key|iam create-access-key' }).Count | Should -Be 0
        (Get-Content -LiteralPath $script:OutFile -Raw | ConvertFrom-Json).access_key_id | Should -BeExactly $script:OldKey
    }

    It 'replaces a placeholder left by an older run' {
        New-Item -ItemType Directory -Path (Split-Path -Parent $script:OutFile) -Force | Out-Null
        @{ access_key_id = $script:OldKey; secret_access_key = 'EXAMPLE-SECRET-ROTATE-TO-RETRIEVE-REAL-VALUE' } | ConvertTo-Json | Set-Content -LiteralPath $script:OutFile -Encoding UTF8
        $r = Invoke-Plant
        $r.ExitCode | Should -Be 0 -Because $r.Output
        (Get-Content -LiteralPath $script:OutFile -Raw | ConvertFrom-Json).secret_access_key | Should -BeExactly $script:NewSecret
    }

    It 'creates a key without deleting anything when the user has none' {
        $global:PlKeys = @()
        $r = Invoke-Plant
        $r.ExitCode | Should -Be 0 -Because $r.Output
        @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key' }).Count | Should -Be 0
        @($global:PlCalls | Where-Object { $_ -match 'iam create-access-key' }).Count | Should -Be 1
    }

    It '-WhatIf changes nothing: no call, no file, same manifest' {
        $before = Get-Content -LiteralPath $script:ManifestFile -Raw
        $r = Invoke-Plant -Extra @{ WhatIf = $true }
        $r.ExitCode | Should -Be 0 -Because $r.Output
        @($global:PlCalls | Where-Object { $_ -match 'iam delete-access-key|iam create-access-key|iam put-user-policy' }).Count | Should -Be 0
        $r.Output | Should -Match 'delete-access-key'
        Test-Path -LiteralPath $script:OutFile | Should -BeFalse
        (Get-Content -LiteralPath $script:ManifestFile -Raw) | Should -Be $before
        $global:PlKeys | Should -Contain $script:OldKey
    }
}
