<#
.SYNOPSIS
    Pester tests: the permission tables in ops/lib/LabPermissions.ps1 and the README tables agree.

.DESCRIPTION
    The AWS and Azure permission tables in the library are the single source for the console
    messages. The READMEs repeat them for the operator. These tests compare both directions:

      - every service, prefix and managed policy (AWS) and every command group and built-in
        role (Azure) in the library appears in the README table with the identical name;
      - every row and every policy or role named in a README table exists in the library.

    Compared files:
      ops/aws/ir-lab/README.md    full AWS table (service, prefix, policy)
      ops/azure/ir-lab/README.md  full Azure table (command group, role)
      ops/README.md               policy and role tables (policy and role names)

    Pure text checks. No cloud CLI is invoked.

    Run: Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path ops/tests/LabPermissions.Docs.Tests.ps1
#>

BeforeAll {
    $script:OpsDir = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:OpsDir 'lib\LabPermissions.ps1')

    # Returns the data rows of the first markdown table whose header starts with $HeaderStart,
    # each row as an array of trimmed cell strings.
    function Get-DocTableRows {
        param([string] $Path, [string] $HeaderStart)

        $lines = Get-Content -LiteralPath $Path
        $rows = New-Object System.Collections.Generic.List[object]
        $inTable = $false
        foreach ($line in $lines) {
            if (-not $inTable) {
                if ($line.TrimStart().StartsWith($HeaderStart)) { $inTable = $true }
                continue
            }
            if (-not $line.TrimStart().StartsWith('|')) { break }
            if ($line -match '^\s*\|\s*-{2,}') { continue }
            $cells = @($line.Trim().Trim('|').Split('|') | ForEach-Object { $_.Trim() })
            $rows.Add($cells)
        }
        return , $rows.ToArray()
    }

    # Backticked names in a cell, or the plain comma separated names when there are no backticks.
    function Get-CellNames {
        param([string] $Cell)

        $found = [regex]::Matches($Cell, '`([^`]+)`') | ForEach-Object { $_.Groups[1].Value }
        if (@($found).Count -gt 0) { return @($found) }
        return @($Cell.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    $script:AwsReadme = Join-Path $script:OpsDir 'aws\ir-lab\README.md'
    $script:AzureReadme = Join-Path $script:OpsDir 'azure\ir-lab\README.md'
    $script:OpsReadme = Join-Path $script:OpsDir 'README.md'
}

Describe 'Permission tables and README tables agree' {

    Context 'AWS table in ops/aws/ir-lab/README.md' {
        BeforeAll {
            $script:AwsRows = Get-DocTableRows -Path $script:AwsReadme -HeaderStart '| Service | IAM prefix'
        }

        It 'has the same set of services as the library table' {
            $docServices = @($script:AwsRows | ForEach-Object { $_[0] })
            $libServices = @($script:LabAwsPermissionTable.Keys)
            $missingInDoc = @($libServices | Where-Object { $docServices -notcontains $_ })
            $extraInDoc = @($docServices | Where-Object { $libServices -notcontains $_ })
            $missingInDoc | Should -BeNullOrEmpty -Because "services missing in the README: $($missingInDoc -join ', ')"
            $extraInDoc | Should -BeNullOrEmpty -Because "services only in the README: $($extraInDoc -join ', ')"
        }

        It 'lists the identical IAM prefix and managed policy names for every service' {
            $problems = @()
            foreach ($row in $script:AwsRows) {
                $svc = $row[0]
                if (-not $script:LabAwsPermissionTable.Contains($svc)) { continue }
                $entry = $script:LabAwsPermissionTable[$svc]
                if ($row[1] -ne $entry.Prefix) { $problems += "$svc prefix '$($row[1])' != '$($entry.Prefix)'" }

                $docNames = @(Get-CellNames -Cell $row[2] | Where-Object { $_ -notmatch '^none' })
                $expected = @($entry.Policies)
                if ($entry.ContainsKey('WritePolicies')) { $expected = @($expected + @($entry.WritePolicies)) }
                if ($expected.Count -eq 0 -and $entry.ContainsKey('Scoped')) {
                    # Documented as: none (use `template.json`)
                    if ($row[2] -notmatch [regex]::Escape($entry.Scoped)) { $problems += "$svc does not name template $($entry.Scoped)" }
                    if ($row[2] -notmatch '^none') { $problems += "$svc should be documented as 'none'" }
                }
                else {
                    $diff = Compare-Object -ReferenceObject $expected -DifferenceObject $docNames
                    if ($diff) { $problems += "$svc policies differ: library [$($expected -join ', ')] README [$($docNames -join ', ')]" }
                }
            }
            $problems | Should -BeNullOrEmpty -Because ($problems -join '; ')
        }
    }

    Context 'Azure table in ops/azure/ir-lab/README.md' {
        BeforeAll {
            $script:AzureRows = Get-DocTableRows -Path $script:AzureReadme -HeaderStart '| Command group | Built-in role'
        }

        It 'has the same set of command groups as the library table' {
            $docGroups = @($script:AzureRows | ForEach-Object { $_[0] })
            $libGroups = @($script:LabAzurePermissionTable.Keys)
            $missingInDoc = @($libGroups | Where-Object { $docGroups -notcontains $_ })
            $extraInDoc = @($docGroups | Where-Object { $libGroups -notcontains $_ })
            $missingInDoc | Should -BeNullOrEmpty -Because "groups missing in the README: $($missingInDoc -join ', ')"
            $extraInDoc | Should -BeNullOrEmpty -Because "groups only in the README: $($extraInDoc -join ', ')"
        }

        It 'lists the identical built-in role names for every command group' {
            $problems = @()
            foreach ($row in $script:AzureRows) {
                $grp = $row[0]
                if (-not $script:LabAzurePermissionTable.Contains($grp)) { continue }
                $expected = @($script:LabAzurePermissionTable[$grp].Roles)
                $docNames = @(Get-CellNames -Cell $row[1])
                $diff = Compare-Object -ReferenceObject $expected -DifferenceObject $docNames
                if ($diff) { $problems += "$grp roles differ: library [$($expected -join ', ')] README [$($docNames -join ', ')]" }
            }
            $problems | Should -BeNullOrEmpty -Because ($problems -join '; ')
        }
    }

    Context 'Summary tables in ops/README.md' {
        BeforeAll {
            $script:OpsAwsRows = Get-DocTableRows -Path $script:OpsReadme -HeaderStart '| AWS service | Managed policy'
            $script:OpsAzureRows = Get-DocTableRows -Path $script:OpsReadme -HeaderStart '| Azure area | Built-in role'
        }

        It 'names exactly the managed policies of the library table' {
            $docNames = @($script:OpsAwsRows | ForEach-Object { Get-CellNames -Cell $_[1] } |
                Where-Object { $_ -notmatch '\.json$' -and $_ -notmatch '^none' } | Sort-Object -Unique)
            $libNames = @($script:LabAwsPermissionTable.Values | ForEach-Object {
                    $_.Policies
                    if ($_.ContainsKey('WritePolicies')) { $_.WritePolicies }
                } | Where-Object { $_ } | Sort-Object -Unique)
            $diff = Compare-Object -ReferenceObject $libNames -DifferenceObject $docNames
            $diff | Should -BeNullOrEmpty -Because (($diff | ForEach-Object { "$($_.InputObject) $($_.SideIndicator)" }) -join '; ')
        }

        It 'points the IAM row to the scoped template named in the library table' {
            $scoped = $script:LabAwsPermissionTable['iam'].Scoped
            $iamRow = @($script:OpsAwsRows | Where-Object { $_[0] -eq 'IAM' })
            $iamRow.Count | Should -Be 1
            $iamRow[0][1] | Should -Match ([regex]::Escape($scoped))
        }

        It 'names exactly the built-in roles of the library table' {
            $docNames = @($script:OpsAzureRows | ForEach-Object { Get-CellNames -Cell $_[1] } | Sort-Object -Unique)
            $libNames = @($script:LabAzurePermissionTable.Values | ForEach-Object { $_.Roles } | Sort-Object -Unique)
            $diff = Compare-Object -ReferenceObject $libNames -DifferenceObject $docNames
            $diff | Should -BeNullOrEmpty -Because (($diff | ForEach-Object { "$($_.InputObject) $($_.SideIndicator)" }) -join '; ')
        }
    }
}
