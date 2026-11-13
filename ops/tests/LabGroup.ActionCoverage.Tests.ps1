<#
.SYNOPSIS
    Pester 5.x property tests: the IAM policy templates cover every action the
    AWS lab scripts need.

.DESCRIPTION
    Property: every real IAM action required by the AWS lab scripts is allowed
    by the union of the rendered templates in ops/aws/iam/policies. Two sources
    of "required" actions are checked:

      * the "Required IAM actions:" header block of each script under
        ops/aws/ir-lab and ops/aws/ec2, and
      * the aws calls found by scanning those scripts. The shared scanner
        (Get-RequiredActions) is complemented here with the -CliArgs call style
        used by the lab libraries. IAM action names are compared without regard
        to case, because the scanner derives PascalCase names (for example
        rds:CreateDbInstance) that differ in case from the real IAM names
        (rds:CreateDBInstance).

    Run with:
        Invoke-Pester -Path ops/tests/LabGroup.ActionCoverage.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'aws' 'iam' 'LabGroup-Common.ps1')

    $script:IamDir    = Join-Path $PSScriptRoot '..' 'aws' 'iam'
    $script:IrLabDir  = Join-Path $PSScriptRoot '..' 'aws' 'ir-lab'
    $script:Ec2Dir    = Join-Path $PSScriptRoot '..' 'aws' 'ec2'
    $script:AccountId = '123456789012'
    $script:Region    = 'us-east-1'

    # Union of every Allow action in every rendered template.
    $allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in (Get-LabPolicyTemplatePath -TemplateDir (Join-Path $script:IamDir 'policies'))) {
        $doc = Expand-LabPolicyTemplate -Path $t -AccountId $script:AccountId -Region $script:Region
        foreach ($a in (Get-PolicyActions -Document $doc)) { [void]$allowed.Add($a) }
    }
    $script:AllowedActions = @($allowed)

    # Scripts under test: the ir-lab tree and the EC2 lab scripts.
    $script:LabScripts = @(
        @(Get-ChildItem -LiteralPath $script:IrLabDir -Recurse -File -Filter '*.ps1') +
        @(Get-ChildItem -LiteralPath $script:Ec2Dir -File -Filter '*.ps1')
    )

    # Parses the "Required IAM actions:" block of a script header.
    function Get-HeaderActions {
        param([string] $Path)
        $lines = Get-Content -LiteralPath $Path -TotalCount 300
        $out = New-Object System.Collections.Generic.List[string]
        $inBlock = $false
        foreach ($line in $lines) {
            if (-not $inBlock) {
                if ($line -match 'Required IAM actions:') { $inBlock = $true }
                continue
            }
            if ($line -match '^\s*(\.[A-Z]+|#>)') { break }
            if ($line -match '^\s*$') { continue }
            foreach ($m in [regex]::Matches($line, '(?<![\w:])[a-z0-9]+:[A-Za-z0-9*]+')) { $out.Add($m.Value) }
        }
        return @($out | Sort-Object -Unique)
    }

    # Scans the -CliArgs call style: -CliArgs @('svc', 'op', ...)
    function Get-CliArgsActions {
        param([string] $Path)
        $pattern = '-CliArgs\s+\(?@\(\s*''(?<svc>[a-z][a-z0-9]*)''\s*,\s*''(?<op>[a-z][a-z0-9-]*)'''
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($line in (Get-Content -LiteralPath $Path)) {
            if ($line -match '^\s*#') { continue }
            foreach ($m in [regex]::Matches($line, $pattern)) {
                foreach ($a in (ConvertTo-IamAction -Service $m.Groups['svc'].Value -Operation $m.Groups['op'].Value)) { $out.Add($a) }
            }
        }
        return @($out | Sort-Object -Unique)
    }
}

BeforeDiscovery {
    $irLab = Join-Path $PSScriptRoot '..' 'aws' 'ir-lab'
    $ec2   = Join-Path $PSScriptRoot '..' 'aws' 'ec2'
    $found = @(
        @(Get-ChildItem -LiteralPath $irLab -Recurse -File -Filter '*.ps1') +
        @(Get-ChildItem -LiteralPath $ec2 -File -Filter '*.ps1')
    )
    $scriptCases = @($found | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

Describe 'IAM action coverage by the policy templates' {
    It 'finds lab scripts and rendered templates' {
        $script:LabScripts.Count | Should -BeGreaterThan 0
        $script:AllowedActions.Count | Should -BeGreaterThan 0
    }

    It 'covers the scanner helpers on known call styles' {
        Test-IamActionCovered -Action 'rds:CreateDbInstance' -Allowed $script:AllowedActions | Should -BeTrue
        Test-IamActionCovered -Action 's3:ListAllMyBuckets' -Allowed $script:AllowedActions | Should -BeTrue
        Test-IamActionCovered -Action 'ec2:NotARealAction' -Allowed $script:AllowedActions | Should -BeFalse
    }

    Context 'script <Name>' -ForEach $scriptCases {
        It 'has every action in its Required IAM actions header covered' {
            $missing = @(Get-HeaderActions -Path $Path | Where-Object { -not (Test-IamActionCovered -Action $_ -Allowed $script:AllowedActions) })
            $missing | Should -BeNullOrEmpty -Because 'the templates must allow every documented action'
        }

        It 'has every scanned aws call covered' {
            $scanned = @(Get-RequiredActions -Path $Path) + @(Get-CliArgsActions -Path $Path)
            $missing = @($scanned | Sort-Object -Unique | Where-Object { -not (Test-IamActionCovered -Action $_ -Allowed $script:AllowedActions) })
            $missing | Should -BeNullOrEmpty -Because 'the templates must allow every action the script calls'
        }
    }

    It 'covers the union of all scanned actions across the lab scripts' {
        $all = @()
        foreach ($s in $script:LabScripts) {
            $all += @(Get-RequiredActions -Path $s.FullName) + @(Get-CliArgsActions -Path $s.FullName)
        }
        $missing = @($all | Sort-Object -Unique | Where-Object { -not (Test-IamActionCovered -Action $_ -Allowed $script:AllowedActions) })
        $missing | Should -BeNullOrEmpty
    }

    It 'allows s3:BypassGovernanceRetention, used when emptying a locked trail bucket' {
        Test-IamActionCovered -Action 's3:BypassGovernanceRetention' -Allowed $script:AllowedActions | Should -BeTrue
    }

    It 'lists s3:BypassGovernanceRetention in the full-teardown header' {
        Get-HeaderActions -Path (Join-Path $script:IrLabDir 'full-teardown.ps1') | Should -Contain 's3:BypassGovernanceRetention'
    }
}
