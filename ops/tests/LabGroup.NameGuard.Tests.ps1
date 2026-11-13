<#
.SYNOPSIS
    Property test: the IAM lab group name guard.
.DESCRIPTION
    The group name guard accepts only names matching sangyshop-lab-[a-z0-9-]+
    and always rejects names that contain the foreign application token in any
    letter case. When the guard rejects a name, ensure-lab-group.ps1 exits with
    code 2 and makes zero AWS calls.

    No real CLI is invoked: every call would go through $global:LabCliHandler, and
    the handler records each call so the tests can assert there were none.
#>

BeforeAll {
    $script:IamDir = Join-Path $PSScriptRoot '..\aws\iam'
    $script:Script = Join-Path $script:IamDir 'ensure-lab-group.ps1'
    . (Join-Path $script:IamDir 'LabGroup-Common.ps1')

    # Foreign token assembled at run time, same as the helper does.
    $script:Foreign = ('know' + 'tree')

    # Seeded generator so failures are reproducible.
    $script:Rng = New-Object System.Random 19
    function New-RandomText {
        param([string] $Alphabet, [int] $Min, [int] $Max)
        $len = $script:Rng.Next($Min, $Max + 1)
        $sb = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $len; $i++) { [void]$sb.Append($Alphabet[$script:Rng.Next(0, $Alphabet.Length)]) }
        return $sb.ToString()
    }
    function ConvertTo-RandomCase {
        param([string] $Text)
        $sb = New-Object System.Text.StringBuilder
        foreach ($c in $Text.ToCharArray()) {
            if ($script:Rng.Next(0, 2) -eq 0) { [void]$sb.Append([char]::ToUpperInvariant($c)) } else { [void]$sb.Append([char]::ToLowerInvariant($c)) }
        }
        return $sb.ToString()
    }

    $script:Lower = 'abcdefghijklmnopqrstuvwxyz0123456789-'
    $script:Any = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+=,.@ /*'

    function Invoke-Guarded {
        param([string] $Name)
        $global:LabGuardCalls = New-Object System.Collections.Generic.List[string]
        $global:LabCliHandler = {
            param($CliArgs)
            $global:LabGuardCalls.Add(($CliArgs -join ' '))
            [pscustomobject]@{ ExitCode = 0; Output = '' }
        }
        $global:LASTEXITCODE = $null
        try {
            & $script:Script -GroupName $Name -Region us-east-1 -WhatIf *> $null
        }
        catch { }
        return [pscustomobject]@{ Exit = $global:LASTEXITCODE; Calls = $global:LabGuardCalls.Count }
    }
}

AfterAll {
    $global:LabCliHandler = $null
    Remove-Variable -Name LabGuardCalls -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Test-LabGroupNameAllowed' {

    It 'accepts generated names that match the lab prefix and character set' {
        for ($i = 0; $i -lt 100; $i++) {
            $name = 'sangyshop-lab-' + (New-RandomText -Alphabet 'abcdefghijklmnopqrstuvwxyz0123456789-' -Min 1 -Max 30)
            if ($name.ToLowerInvariant().Contains($script:Foreign)) { continue }
            Test-LabGroupNameAllowed -Name $name | Should -BeTrue -Because "'$name' is a lab name"
        }
    }

    It 'accepts the default group name' {
        Test-LabGroupNameAllowed -Name 'sangyshop-lab-group' | Should -BeTrue
    }

    It 'rejects generated names that lack the lab prefix' {
        for ($i = 0; $i -lt 100; $i++) {
            $name = New-RandomText -Alphabet $script:Any -Min 0 -Max 40
            if ($name -cmatch '^sangyshop-lab-[a-z0-9-]+$') { continue }
            Test-LabGroupNameAllowed -Name $name | Should -BeFalse -Because "'$name' is not a lab name"
        }
    }

    It 'rejects any name that contains the foreign token in any letter case' {
        for ($i = 0; $i -lt 100; $i++) {
            $token = ConvertTo-RandomCase -Text $script:Foreign
            $left = New-RandomText -Alphabet $script:Lower -Min 0 -Max 8
            $right = New-RandomText -Alphabet $script:Lower -Min 0 -Max 8
            foreach ($name in @("$left$token$right", "sangyshop-lab-$left$token$right", "$token-lab-$right")) {
                Test-LabGroupNameAllowed -Name $name | Should -BeFalse -Because "'$name' holds the foreign token"
            }
        }
    }

    It 'rejects prefix case variants, bad suffixes and look-alikes' {
        $bad = @(
            $null, '', ' ', 'sangyshop-lab-', 'sangyshop-lab', 'Sangyshop-Lab-group', 'SANGYSHOP-LAB-GROUP',
            'sangyshop-lab-Group', 'sangyshop-lab-gr_oup', 'sangyshop-lab-gr oup', 'sangyshop-lab-*',
            ' sangyshop-lab-group', 'sangyshop-lab-group ', "sangyshop-lab-group`n", 'xsangyshop-lab-group',
            'sangyshop-labs-group', 'sangyshop-group', 'admins', 'Administrators'
        )
        foreach ($name in $bad) {
            Test-LabGroupNameAllowed -Name $name | Should -BeFalse -Because "'$name' must be rejected"
        }
    }
}

Describe 'ensure-lab-group.ps1 with a rejected name' {

    It 'exits with code 2 and makes zero CLI calls for generated rejected names' {
        $names = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt 12; $i++) {
            $n = New-RandomText -Alphabet 'abcdefghijklmnopqrstuvwxyz0123456789-' -Min 1 -Max 20
            if (-not $n.StartsWith('sangyshop-lab-')) { $names.Add($n) }
            $names.Add('sangyshop-lab-' + (ConvertTo-RandomCase -Text $script:Foreign) + '-x')
        }
        $names.Add('Administrators')
        $names.Add('sangyshop-lab-')
        foreach ($name in $names) {
            Test-LabGroupNameAllowed -Name $name | Should -BeFalse
            $r = Invoke-Guarded -Name $name
            $r.Exit | Should -Be 2 -Because "'$name' is rejected"
            $r.Calls | Should -Be 0 -Because "no AWS call may happen for '$name'"
        }
    }

    It 'passes the guard for an allowed name, so the CLI is reached' {
        $r = Invoke-Guarded -Name 'sangyshop-lab-guardtest'
        $r.Exit | Should -Not -Be 2
        $r.Calls | Should -BeGreaterThan 0
    }
}
