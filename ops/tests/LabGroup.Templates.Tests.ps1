<#
.SYNOPSIS
    Pester 5.x property tests for the IAM policy templates in ops/aws/iam/policies.

.DESCRIPTION
    Property: for every policy template file,

      * it is valid JSON with a Statement list,
      * its size, counting characters other than whitespace, is at most 6144
        (the AWS limit for a managed policy),
      * the only placeholders are ${AccountId} and ${Region},
      * it holds no literal 12-digit account id,
      * every IAM write action (anything under iam: that is not Get*, List* or
        Simulate*) is allowed only on resources scoped to sangyshop-* names,
      * iam:PassRole is always conditioned on iam:PassedToService.

    Run with:
        Invoke-Pester -Path ops/tests/LabGroup.Templates.Tests.ps1
#>

BeforeDiscovery {
    $policyDir = Join-Path $PSScriptRoot '..' 'aws' 'iam' 'policies'
    $templates = @(Get-ChildItem -Path $policyDir -Filter '*.json' -File |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

Describe 'IAM policy templates' {
    It 'finds at least one template' {
        $dir = Join-Path $PSScriptRoot '..' 'aws' 'iam' 'policies'
        @(Get-ChildItem -Path $dir -Filter '*.json' -File).Count | Should -BeGreaterThan 0
    }

    Context 'template <Name>' -ForEach $templates {
        BeforeAll {
            $raw = Get-Content -LiteralPath $Path -Raw
            $doc = $raw | ConvertFrom-Json

            function ConvertTo-List($value) { if ($null -eq $value) { @() } else { @($value) } }

            $statements = @(ConvertTo-List $doc.Statement)
            $writeStatements = @()
            $passRoleStatements = @()
            foreach ($s in $statements) {
                if ($s.Effect -ne 'Allow') { continue }
                $actions = @(ConvertTo-List $s.Action)
                $iamWrites = @($actions | Where-Object { $_ -match '^iam:' -and $_ -notmatch '^iam:(Get|List|Simulate)' })
                if ($iamWrites.Count -gt 0) { $writeStatements += $s }
                if ($actions -contains 'iam:PassRole') { $passRoleStatements += $s }
            }
        }

        It 'is valid JSON with a Statement list' {
            { $raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
            $statements.Count | Should -BeGreaterThan 0
        }

        It 'is at most 6144 characters excluding whitespace' {
            ($raw -replace '\s', '').Length | Should -BeLessOrEqual 6144
        }

        It 'uses only the AccountId and Region placeholders' {
            $found = @([regex]::Matches($raw, '\$\{[^}]*\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
            $unexpected = @($found | Where-Object { $_ -notin @('${AccountId}', '${Region}') })
            $unexpected | Should -BeNullOrEmpty
        }

        It 'contains no literal 12-digit account id' {
            [regex]::Matches($raw, '(?<!\d)\d{12}(?!\d)').Count | Should -Be 0
        }

        It 'scopes every IAM write to sangyshop-* resources' {
            foreach ($s in $writeStatements) {
                $resources = @(ConvertTo-List $s.Resource)
                $resources.Count | Should -BeGreaterThan 0 -Because "statement $($s.Sid) needs resources"
                foreach ($r in $resources) {
                    $r | Should -Match '^arn:aws:iam::\$\{AccountId\}:(role|user|policy|group|instance-profile)/sangyshop-' -Because "statement $($s.Sid) must stay scoped"
                }
            }
        }

        It 'conditions iam:PassRole on iam:PassedToService' {
            foreach ($s in $passRoleStatements) {
                $s.Condition | Should -Not -BeNullOrEmpty -Because "statement $($s.Sid) needs a condition"
                $keys = @($s.Condition.PSObject.Properties | ForEach-Object { $_.Value.PSObject.Properties.Name })
                $keys | Should -Contain 'iam:PassedToService'
            }
        }
    }
}
