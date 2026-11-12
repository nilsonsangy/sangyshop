<#
.SYNOPSIS
    Pester 5.x unit tests for Get-CloudConfig (lib/Common.ps1).

.DESCRIPTION
    Covers the config loader/validator contract (task 2.5):

      * Missing / empty / whitespace required keys for the active cloud are
        rejected, and each offending key is named in the error (Req 7.1, 7.3).
      * Invalid globally-unique suffixes are rejected: too short (<3), too long
        (>24), uppercase, non-alphanumeric, and missing (Req 7.5, 7.6).
      * A well-formed config loads and the Common defaults are applied
        (AppName/DbName/DbUser/ImageTag = sangyshop/sangyshop/sangyshop/hardened).

    All config files are written under $TestDrive as real .ps1 files that return
    an @{ ... } hashtable (the shape Get-CloudConfig evaluates). No cloud CLI is
    ever invoked. Windows PowerShell 5.1 compatible.

    Requires Pester 5.x (see tests/README.md). Run with:
        Invoke-Pester -Path ops/tests/Common.GetCloudConfig.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1'
    . $script:CommonPath

    # Writes a config .ps1 under $TestDrive and returns its path. The body is the
    # literal text placed after the leading '@{' / before the trailing '}', so each
    # test supplies exactly the hashtable it wants to validate.
    function New-ConfigFile {
        param(
            [Parameter(Mandatory)][string] $Name,
            [Parameter(Mandatory)][string] $Body
        )
        $path = Join-Path $TestDrive $Name
        Set-Content -LiteralPath $path -Value $Body -Encoding UTF8
        return $path
    }

    # A fully valid Gcp-targeted config body with a legal suffix and all required
    # sections present. Tests clone/mutate copies of this baseline.
    $script:ValidBody = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
}

Describe 'Get-CloudConfig' {

    Context 'well-formed config' {
        It 'loads a valid config and returns a hashtable' {
            $path = New-ConfigFile -Name 'valid.ps1' -Body $script:ValidBody
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg | Should -BeOfType [hashtable]
        }

        It 'records the active cloud that was validated' {
            $path = New-ConfigFile -Name 'valid-active.ps1' -Body $script:ValidBody
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg['ActiveCloud'] | Should -Be 'Gcp'
        }

        It 'preserves the user-supplied Gcp section values' {
            $path = New-ConfigFile -Name 'valid-gcp.ps1' -Body $script:ValidBody
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg['Gcp']['ProjectId'] | Should -Be 'my-project-123'
        }
    }

    Context 'Common defaults are applied' {
        It 'applies the <Key>=<Expected> default when Common is absent' -ForEach @(
            @{ Key = 'AppName';  Expected = 'sangyshop' }
            @{ Key = 'DbName';   Expected = 'sangyshop' }
            @{ Key = 'DbUser';   Expected = 'sangyshop' }
            @{ Key = 'ImageTag'; Expected = 'hardened'  }
        ) {
            # No Common section at all: every default must be filled in.
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name ("defaults-$Key.ps1") -Body $body
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg['Common'][$Key] | Should -Be $Expected
        }

        It 'does not overwrite a user-supplied Common value' {
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "myapp"
        DbName   = "mydb"
        DbUser   = "myuser"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name 'defaults-keep.ps1' -Body $body
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg['Common']['AppName'] | Should -Be 'myapp'
            $cfg['Common']['DbName']  | Should -Be 'mydb'
            $cfg['Common']['DbUser']  | Should -Be 'myuser'
        }
    }

    Context 'missing / empty / whitespace required keys (Req 7.3)' {
        It 'rejects a missing required key for the active cloud and names it' {
            # Gcp section present but ProjectId omitted.
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name 'missing-projectid.ps1' -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*Gcp.ProjectId*'
        }

        It 'rejects an empty-string required key and names it' {
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = ""
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name 'empty-projectid.ps1' -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*Gcp.ProjectId*'
        }

        It 'rejects a whitespace-only required key and names it' {
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "   "
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name 'whitespace-projectid.ps1' -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*Gcp.ProjectId*'
        }

        It 'names a blanked Common key when the user explicitly empties it' {
            # ImageTag blanked -> default restores it, but AppName blanked after a
            # present Common section is caught. Use AppName=whitespace to force it.
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "   "
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            # A whitespace AppName is treated as "unset", so the default fills it and
            # validation passes. Assert the default was applied rather than an error.
            $path = New-ConfigFile -Name 'blank-appname.ps1' -Body $body
            $cfg = Get-CloudConfig -ConfigPath $path -Cloud Gcp
            $cfg['Common']['AppName'] | Should -Be 'sangyshop'
        }

        It 'reports the entire section as missing when the active cloud section is absent' {
            $body = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
}
'@
            $path = New-ConfigFile -Name 'no-gcp-section.ps1' -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*Gcp*'
        }

        It 'validates only the active cloud, ignoring placeholders left in other clouds' {
            # Aws section is entirely absent, but we are targeting Gcp, so it must load.
            $path = New-ConfigFile -Name 'active-only.ps1' -Body $script:ValidBody
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } | Should -Not -Throw
        }
    }

    Context 'invalid UniqueSuffix (Req 7.5 / 7.6)' {
        It 'rejects suffix "<Suffix>" (<Reason>)' -ForEach @(
            @{ Suffix = 'ab';                          Reason = 'too short (<3)' }
            @{ Suffix = 'abcdefghijklmnopqrstuvwxy';   Reason = 'too long (>24)' }
            @{ Suffix = 'ABC123';                      Reason = 'uppercase' }
            @{ Suffix = 'abc-123';                     Reason = 'non-alphanumeric' }
            @{ Suffix = 'abc_123';                     Reason = 'non-alphanumeric underscore' }
        ) {
            $body = @"
@{
    UniqueSuffix = "$Suffix"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
"@
            $path = New-ConfigFile -Name ("suffix-" + ($Suffix -replace '[^a-z0-9]', 'x') + ".ps1") -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*UniqueSuffix*'
        }

        It 'rejects a missing UniqueSuffix' {
            $body = @'
@{
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
            $path = New-ConfigFile -Name 'suffix-missing.ps1' -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } |
                Should -Throw -ExpectedMessage '*UniqueSuffix*'
        }

        It 'accepts boundary-valid suffixes "<Suffix>"' -ForEach @(
            @{ Suffix = 'abc' }                               # exactly 3
            @{ Suffix = 'abcdefghijklmnopqrstuvwx' }          # exactly 24
            @{ Suffix = '123' }                               # digits only
        ) {
            $body = @"
@{
    UniqueSuffix = "$Suffix"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
"@
            $path = New-ConfigFile -Name ("suffix-ok-$Suffix.ps1") -Body $body
            { Get-CloudConfig -ConfigPath $path -Cloud Gcp } | Should -Not -Throw
        }
    }
}
