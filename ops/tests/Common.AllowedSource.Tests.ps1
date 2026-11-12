<#
.SYNOPSIS
    Pester 5.x tests for Assert-AllowedSource32 (lib/Common.ps1, task 9.2).

.DESCRIPTION
    Property 1: Validacao de origem permitida.
    **Validates: Requirements 10.12, 10.13, 20.7, 30.4, 30.5, 32.3, 41.3**

    There is no mature property-based testing library for PowerShell, so the
    property is exercised with generated cases (>= 100 per group) drawn from a
    System.Random with a FIXED seed, making every run reproducible.

      * Valid:   any canonical IPv4 host with the /32 suffix must pass.
      * Invalid: open ranges, empty/missing input, non-/32 prefixes, malformed
                 IPs, wildcards/keywords and IPv6 must all throw.

    Requires Pester 5.x (see tests/README.md). Run with:
        Invoke-Pester -Path ops/tests/Common.AllowedSource.Tests.ps1
#>

BeforeAll {
    $script:CommonPath = Join-Path $PSScriptRoot '..' 'lib' 'Common.ps1'
    . $script:CommonPath

    $script:Seed = 20240611
    $script:Cases = 200
}

Describe 'Assert-AllowedSource32 (Property 1: Validacao de origem permitida)' {

    Context 'valid single-host IPv4 /32 (generated)' {
        It 'accepts every generated a.b.c.d/32 (octets 0-255)' {
            $rng = [System.Random]::new($script:Seed)
            $failures = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $script:Cases; $i++) {
                $o = 1..4 | ForEach-Object { $rng.Next(0, 256) }
                $cidr = ($o -join '.') + '/32'
                # 0.0.0.0/32 and 255.255.255.255/32 are deliberately rejected by the implementation.
                if ($cidr -ceq '0.0.0.0/32' -or $cidr -ceq '255.255.255.255/32') { continue }
                try { Assert-AllowedSource32 -Ranges $cidr } catch { $failures.Add($cidr) }
            }
            $failures | Should -BeNullOrEmpty
        }

        It 'accepts a list of valid /32 ranges' {
            { Assert-AllowedSource32 -Ranges @('203.0.113.10/32', '198.51.100.7/32') } | Should -Not -Throw
        }

        It 'accepts boundary octets' {
            { Assert-AllowedSource32 -Ranges '0.0.0.1/32' } | Should -Not -Throw
            { Assert-AllowedSource32 -Ranges '255.255.255.254/32' } | Should -Not -Throw
        }
    }

    Context 'invalid values (fixed)' {
        It 'rejects <_>' -ForEach @(
            '0.0.0.0/0', '::/0', '*', 'Internet', 'Any', 'internet', 'any',
            '0.0.0.0/32', '255.255.255.255/32',
            '203.0.113.10', '203.0.113.10/24', '203.0.113.10/16', '203.0.113.10/0',
            '203.0.113.10/31', '203.0.113.10/33', '203.0.113.10/',
            '256.1.1.1/32', '1.2.3/32', '1.2.3.4.5/32', 'a.b.c.d/32',
            '01.2.3.4/32', '1.2.3.4//32', ' 1.2.3.4/32', '1.2.3.4/32 ',
            '::1/128', '2001:db8::1/128', '2001:db8::/32', 'fe80::1/64',
            '', ' '
        ) {
            { Assert-AllowedSource32 -Ranges $_ } | Should -Throw
        }

        It 'rejects missing / null / empty input' {
            { Assert-AllowedSource32 } | Should -Throw
            { Assert-AllowedSource32 -Ranges $null } | Should -Throw
            { Assert-AllowedSource32 -Ranges @() } | Should -Throw
        }

        It 'rejects a list containing even one invalid entry' {
            { Assert-AllowedSource32 -Ranges @('203.0.113.10/32', '0.0.0.0/0') } | Should -Throw
        }

        It 'names the offending value in the error message' {
            { Assert-AllowedSource32 -Ranges '0.0.0.0/0' } | Should -Throw -ExpectedMessage '*0.0.0.0/0*'
        }
    }

    Context 'invalid values (generated)' {
        It 'rejects every valid IPv4 with a non-/32 prefix' {
            $rng = [System.Random]::new($script:Seed + 1)
            $accepted = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $script:Cases; $i++) {
                $ip = (1..4 | ForEach-Object { $rng.Next(0, 256) }) -join '.'
                $prefix = $rng.Next(0, 129)
                if ($prefix -eq 32) { $prefix = 24 }
                $cidr = "$ip/$prefix"
                try { Assert-AllowedSource32 -Ranges $cidr; $accepted.Add($cidr) } catch { }
            }
            $accepted | Should -BeNullOrEmpty
        }

        It 'rejects malformed IPs (octet > 255, wrong octet count, non-numeric)' {
            $rng = [System.Random]::new($script:Seed + 2)
            $accepted = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $script:Cases; $i++) {
                switch ($i % 4) {
                    0 { # one octet out of range
                        $o = @(1..4 | ForEach-Object { $rng.Next(0, 256) })
                        $o[$rng.Next(0, 4)] = $rng.Next(256, 1000)
                        $cidr = ($o -join '.') + '/32'
                    }
                    1 { # too few octets
                        $n = $rng.Next(1, 4)
                        $cidr = ((1..$n | ForEach-Object { $rng.Next(0, 256) }) -join '.') + '/32'
                    }
                    2 { # too many octets
                        $n = $rng.Next(5, 8)
                        $cidr = ((1..$n | ForEach-Object { $rng.Next(0, 256) }) -join '.') + '/32'
                    }
                    3 { # non-numeric octet
                        $o = @(1..4 | ForEach-Object { [string]$rng.Next(0, 256) })
                        $o[$rng.Next(0, 4)] = [string][char]$rng.Next(97, 123)
                        $cidr = ($o -join '.') + '/32'
                    }
                }
                try { Assert-AllowedSource32 -Ranges $cidr; $accepted.Add($cidr) } catch { }
            }
            $accepted | Should -BeNullOrEmpty
        }

        It 'rejects generated IPv6 addresses (with and without prefix)' {
            $rng = [System.Random]::new($script:Seed + 3)
            $accepted = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $script:Cases; $i++) {
                $groups = 1..8 | ForEach-Object { '{0:x}' -f $rng.Next(0, 65536) }
                $addr = $groups -join ':'
                $cidr = switch ($i % 3) {
                    0 { $addr }
                    1 { "$addr/128" }
                    2 { "$addr/32" }
                }
                try { Assert-AllowedSource32 -Ranges $cidr; $accepted.Add($cidr) } catch { }
            }
            $accepted | Should -BeNullOrEmpty
        }

        It 'rejects generated wildcard / keyword values in any casing' {
            $rng = [System.Random]::new($script:Seed + 4)
            $words = @('*', 'Internet', 'Any', '0.0.0.0/0', '::/0', 'all', 'AzureCloud')
            $accepted = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $script:Cases; $i++) {
                $w = $words[$rng.Next(0, $words.Count)]
                $v = -join ($w.ToCharArray() | ForEach-Object {
                    if ($rng.Next(0, 2) -eq 0) { [string]$_.ToString().ToUpperInvariant() } else { [string]$_.ToString().ToLowerInvariant() }
                })
                try { Assert-AllowedSource32 -Ranges $v; $accepted.Add($v) } catch { }
            }
            $accepted | Should -BeNullOrEmpty
        }
    }
}
