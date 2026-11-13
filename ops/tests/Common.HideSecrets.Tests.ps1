<#
.SYNOPSIS
    Pester 5.x property style tests for Hide-LabSecrets (lib/Common.ps1).

.DESCRIPTION
    Verifies that the fallback masking never lets a secret through, across many
    randomly generated inputs: access key identifiers, labeled SecretAccessKey
    and SessionToken values (JSON, key=value and key: value forms), and
    stand-alone 40-character secret keys. Also checks that text without secrets
    is returned unchanged.

    Run with:
        Invoke-Pester -Path ops/tests/Common.HideSecrets.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1')

    $script:Rng = [System.Random]::new(20240917)
    $script:Iterations = 100

    function New-RandomString {
        param([string] $Alphabet, [int] $Length)
        $chars = for ($i = 0; $i -lt $Length; $i++) { $Alphabet[$script:Rng.Next($Alphabet.Length)] }
        -join $chars
    }

    $script:Upper  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $script:B64    = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'
    $script:Token  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+='

    function New-AccessKeyId { (@('AKIA', 'ASIA') | Get-Random -SetSeed $script:Rng.Next()) + (New-RandomString $script:Upper 16) }
    function New-SecretKey   { New-RandomString $script:B64 40 }
    function New-SessionTok  { New-RandomString $script:Token (60 + $script:Rng.Next(200)) }
}

Describe 'Hide-LabSecrets' {

    It 'returns null and empty input unchanged' {
        Hide-LabSecrets -Text '' | Should -BeExactly ''
        Hide-LabSecrets -Text $null | Should -BeNullOrEmpty
    }

    It 'masks every access key identifier in random surrounding text' {
        for ($i = 0; $i -lt $script:Iterations; $i++) {
            $id = New-AccessKeyId
            $text = "user created key $id for the lab; id=$id."
            $masked = Hide-LabSecrets -Text $text
            $masked | Should -Not -Match ([regex]::Escape($id))
            $masked | Should -Match '\[REDACTED\]'
        }
    }

    It 'masks labeled secret values in JSON, key=value and key: value forms' {
        $labels = 'SecretAccessKey', 'SessionToken', 'aws_secret_access_key', 'aws_session_token'
        for ($i = 0; $i -lt $script:Iterations; $i++) {
            $label = $labels[$script:Rng.Next($labels.Count)]
            $value = New-SessionTok
            $forms = @(
                "{`"$label`": `"$value`", `"Other`": `"keep`"}",
                "$label=$value",
                "$label : $value"
            )
            foreach ($text in $forms) {
                $masked = Hide-LabSecrets -Text $text
                $masked | Should -Not -Match ([regex]::Escape($value))
                $masked | Should -Match '\[REDACTED\]'
            }
        }
    }

    It 'masks stand-alone 40-character secret keys' {
        for ($i = 0; $i -lt $script:Iterations; $i++) {
            $secret = New-SecretKey
            $masked = Hide-LabSecrets -Text "key material $secret end"
            $masked | Should -Not -Match ([regex]::Escape($secret))
            $masked | Should -Match '\[REDACTED\]'
        }
    }

    It 'masks every secret when several appear in the same text' {
        for ($i = 0; $i -lt $script:Iterations; $i++) {
            $id = New-AccessKeyId
            $secret = New-SecretKey
            $tok = New-SessionTok
            $text = "AccessKeyId=$id`nSecretAccessKey=$secret`nSessionToken=$tok`nregion=us-east-1"
            $masked = Hide-LabSecrets -Text $text
            foreach ($s in @($id, $secret, $tok)) {
                $masked | Should -Not -Match ([regex]::Escape($s))
            }
            $masked | Should -Match 'region=us-east-1'
        }
    }

    It 'leaves text without secrets unchanged' {
        $plain = @(
            'Instance i-0abc1234 stopped in us-east-1',
            'Bucket lab-evidence-bucket created',
            'AKIA is only a prefix and AKIASHORT is too short'
        )
        foreach ($t in $plain) {
            Hide-LabSecrets -Text $t | Should -BeExactly $t
        }
    }

    It 'is idempotent' {
        for ($i = 0; $i -lt 20; $i++) {
            $text = "SecretAccessKey=$(New-SessionTok) id $(New-AccessKeyId) $(New-SecretKey)"
            $once = Hide-LabSecrets -Text $text
            Hide-LabSecrets -Text $once | Should -BeExactly $once
        }
    }
}
