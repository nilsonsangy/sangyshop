<#
.SYNOPSIS
    Pester 5.x property-style tests for Get-AwsLabNames (ops/aws/AwsLabNames.ps1).

.DESCRIPTION
    Generates 100 random but valid configurations from a fixed seed and checks that
    the derived names are deterministic, complete, built from the application name,
    and, for the application name 'sangyshop', identical to the frozen names of the
    running lab. No cloud CLI is ever invoked.

    Run with:
        Invoke-Pester -Path ops/tests/AwsLabNames.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'aws' 'AwsLabNames.ps1')

    $script:ExpectedKeys = @(
        'LabTag', 'TrailName', 'TrailBucket', 'AppLogGroup', 'FlowLogGroup',
        'FlowRoleName', 'TopicName', 'FilterName', 'AlarmName', 'MetricNamespace',
        'MetricName', 'FilterPattern', 'BlockerFunction', 'BlockerRole',
        'BlockerPolicy', 'BlockerRule', 'BlockerStatement', 'LeakedUser',
        'LeakedPolicy', 'LabGroup'
    )

    $script:Regions = @('us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 'sa-east-1', 'ap-southeast-2')
    $script:AppAlphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()

    # Deterministic generator: one seeded Random instance for the whole run.
    $script:Rng = [System.Random]::new(20240611)

    function New-RandomConfig {
        param([string] $AppName)
        $r = $script:Rng
        if (-not $AppName) {
            $len = $r.Next(3, 13)
            $chars = for ($i = 0; $i -lt $len; $i++) { $script:AppAlphabet[$r.Next(0, $script:AppAlphabet.Length)] }
            $AppName = -join $chars
            if ($AppName[0] -match '\d') { $AppName = 'a' + $AppName }
        }
        $digits = -join (1..12 | ForEach-Object { $r.Next(0, 10) })
        return @{
            Common = @{ AppName = $AppName }
            Aws    = @{
                Region    = $script:Regions[$r.Next(0, $script:Regions.Count)]
                AccountId = $digits
            }
        }
    }

    $script:Cases = @(1..100 | ForEach-Object { New-RandomConfig })
    $script:FrozenCases = @(1..100 | ForEach-Object { New-RandomConfig -AppName 'sangyshop' })
}

Describe 'Get-AwsLabNames' {

    It 'returns identical names when called twice with the same configuration' {
        foreach ($cfg in $script:Cases) {
            $a = Get-AwsLabNames -Config $cfg
            $b = Get-AwsLabNames -Config $cfg
            ($a.Keys -join ',') | Should -BeExactly ($b.Keys -join ',')
            foreach ($k in $a.Keys) { $a[$k] | Should -BeExactly $b[$k] }
        }
    }

    It 'defines every expected key with a non-empty value' {
        foreach ($cfg in $script:Cases) {
            $n = Get-AwsLabNames -Config $cfg
            foreach ($k in $script:ExpectedKeys) {
                $n.Contains($k) | Should -BeTrue -Because "key $k must exist"
                [string]::IsNullOrWhiteSpace([string]$n[$k]) | Should -BeFalse -Because "key $k must not be empty"
            }
        }
    }

    It 'builds resource names from the application name and uses only safe characters' {
        $fixed = @('MetricNamespace', 'MetricName', 'FilterPattern')
        foreach ($cfg in $script:Cases) {
            $app = $cfg.Common.AppName
            $n = Get-AwsLabNames -Config $cfg
            foreach ($k in $script:ExpectedKeys) {
                if ($fixed -contains $k) { continue }
                $n[$k] | Should -Match '^[a-z0-9/-]+$' -Because "key $k"
                $n[$k] | Should -Match ([regex]::Escape($app)) -Because "key $k must contain the application name"
            }
            $n['LabTag']   | Should -BeExactly "$app-lab-aws"
            $n['LabGroup'] | Should -BeExactly "$app-lab-group"
        }
    }

    It 'returns exactly the frozen lab names when the application name is sangyshop' {
        foreach ($cfg in $script:FrozenCases) {
            $region  = $cfg.Aws.Region
            $account = $cfg.Aws.AccountId
            $expected = [ordered]@{
                LabTag           = 'sangyshop-lab-aws'
                TrailName        = 'sangyshop-lab-trail'
                TrailBucket      = "sangyshop-lab-trail-$account-$region"
                AppLogGroup      = '/sangyshop/app'
                FlowLogGroup     = '/sangyshop/vpcflow'
                FlowRoleName     = 'sangyshop-lab-flowlogs-role'
                TopicName        = 'sangyshop-lab-alerts'
                FilterName       = 'sangyshop-auth-login-failure'
                AlarmName        = 'sangyshop-lab-bruteforce'
                MetricNamespace  = 'SangyShopLab'
                MetricName       = 'LoginFailure'
                FilterPattern    = '{ $.event = "auth_login" && $.result = "failure" }'
                BlockerFunction  = 'sangyshop-lab-blocker'
                BlockerRole      = 'sangyshop-lab-blocker-role'
                BlockerPolicy    = 'sangyshop-lab-blocker-policy'
                BlockerRule      = 'sangyshop-lab-blocker-trigger'
                BlockerStatement = 'sangyshop-lab-blocker-eventbridge'
                LeakedUser       = 'sangyshop-lab-leaked'
                LeakedPolicy     = 'sangyshop-lab-leaked-readonly'
                LabGroup         = 'sangyshop-lab-group'
            }
            $n = Get-AwsLabNames -Config $cfg
            foreach ($k in $expected.Keys) {
                $n[$k] | Should -BeExactly $expected[$k] -Because "frozen name $k"
            }
        }
    }

    It 'keeps the frozen metric constants independent of the application name' {
        foreach ($cfg in $script:Cases) {
            $n = Get-AwsLabNames -Config $cfg
            $n['MetricNamespace'] | Should -BeExactly 'SangyShopLab'
            $n['MetricName']      | Should -BeExactly 'LoginFailure'
            $n['FilterPattern']   | Should -BeExactly '{ $.event = "auth_login" && $.result = "failure" }'
        }
    }
}
