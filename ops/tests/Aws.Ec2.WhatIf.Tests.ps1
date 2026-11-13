<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the AWS EC2 lab scripts
    (aws/ec2/deploy.ps1 and aws/ec2/teardown.ps1).

.DESCRIPTION
    Covers the guarantee that a simulation executes no external command, for the
    EC2 modality.

    Each script runs in a FRESH child PowerShell against a well-formed temporary
    config written under $TestDrive. Nothing here touches a real cloud.

    "No external command runs" is proven two ways:
      1. SENTINEL SHIMS: a temp directory holding aws/az/docker/kubectl/gcloud .cmd
         shims is put FIRST on PATH. Any shim that is ever invoked appends a line to
         a sentinel file. After every -WhatIf run the sentinel file must not exist.
      2. DRY-RUN TRANSCRIPT: the script prints its ordered planned command list and a
         footer reporting "none executed"; the list must be non-empty and every line
         must be an `aws ...` command.

    Source validation is checked as a fail-closed gate: 0.0.0.0/0,
    ::/0, a missing value and anything that is not exactly a single-host IPv4 /32 make
    deploy.ps1 exit non-zero BEFORE any planned command is printed or executed.

    Run with:
        Invoke-Pester -Path ops/tests/Aws.Ec2.WhatIf.Tests.ps1
#>

BeforeDiscovery {
    # Values that must be rejected by -AllowedSourceRanges.
    $script:BadSources = @(
        @{ Label = '0.0.0.0/0';          Value = '0.0.0.0/0' }
        @{ Label = '::/0';               Value = '::/0' }
        @{ Label = '0.0.0.0/32';         Value = '0.0.0.0/32' }
        @{ Label = 'bare IP (no mask)';  Value = '203.0.113.7' }
        @{ Label = '/24 network';        Value = '203.0.113.0/24' }
        @{ Label = '/31 network';        Value = '203.0.113.7/31' }
        @{ Label = '/16 network';        Value = '10.0.0.0/16' }
        @{ Label = 'IPv6 /128';          Value = '2001:db8::1/128' }
        @{ Label = 'wildcard *';         Value = '*' }
        @{ Label = 'Internet';           Value = 'Internet' }
        @{ Label = 'octet out of range'; Value = '256.1.1.1/32' }
        @{ Label = 'leading zeros';      Value = '203.000.113.007/32' }
    )
}

BeforeAll {
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'ec2' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'ec2' 'teardown.ps1')).Path

    # ---- Valid temporary AWS config (EC2 modality block included). -----------
    $script:ConfigPath = Join-Path $TestDrive 'cloud.config.ps1'
    $configBody = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Aws = @{
        Region     = "us-east-1"
        AccountId  = "123456789012"
        EcrRepo    = "sangyshop"
        EcsCluster = "sangyshop-lab"
        EksCluster = "sangyshop-lab"
        Ec2 = @{
            InstanceType    = "t3.small"
            DbInstanceClass = "db.t4g.micro"
            BucketBase      = "sangyshop-lab"
            VolumeGb        = 20
        }
    }
}
'@
    Set-Content -LiteralPath $script:ConfigPath -Value $configBody -Encoding UTF8

    # ---- Sentinel shims: any real CLI invocation leaves a trace. --------------
    $script:ShimDir  = Join-Path $TestDrive 'shims'
    $script:Sentinel = Join-Path $TestDrive 'external-command-was-run.txt'
    New-Item -ItemType Directory -Path $script:ShimDir -Force | Out-Null
    foreach ($cli in 'aws', 'az', 'docker', 'kubectl', 'gcloud') {
        $shim = "@echo off`r`necho $cli %* >> `"%LAB_SENTINEL%`"`r`nexit /b 1`r`n"
        Set-Content -LiteralPath (Join-Path $script:ShimDir "$cli.cmd") -Value $shim -Encoding ASCII
    }
    $script:SavedPath     = $env:PATH
    $script:SavedSentinel = $env:LAB_SENTINEL
    $env:PATH         = $script:ShimDir + [System.IO.Path]::PathSeparator + $env:PATH
    $env:LAB_SENTINEL = $script:Sentinel

    $script:PsExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($script:PsExe)) { $script:PsExe = 'powershell' }

    # Run a script in a child host; return exit code, merged text and lines, plus
    # whether any shimmed external CLI was invoked.
    function Invoke-WhatIfScript {
        param(
            [Parameter(Mandatory)][string]   $ScriptPath,
            [string[]] $ExtraArgs = @(),
            [string[]] $Ranges
        )
        if (Test-Path -LiteralPath $script:Sentinel) { Remove-Item -LiteralPath $script:Sentinel -Force }
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath,
            '-ConfigPath', $script:ConfigPath) + $ExtraArgs
        if ($Ranges) {
            # -File cannot bind a string[] from several words, so use -Command.
            $list = ($Ranges | ForEach-Object { "'$_'" }) -join ','
            $cmd  = "`$global:LASTEXITCODE = 0; & '$ScriptPath' -ConfigPath '$script:ConfigPath' -AllowedSourceRanges $list -WhatIf; exit `$LASTEXITCODE"
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd)
        }
        $out  = & $script:PsExe @argList *>&1
        $code = $LASTEXITCODE
        $ran  = Test-Path -LiteralPath $script:Sentinel
        return [pscustomobject]@{
            ExitCode        = $code
            Text            = ($out | Out-String)
            Lines           = @($out | ForEach-Object { [string]$_ })
            ExternalWasRun  = $ran
            ExternalCalls   = $(if ($ran) { Get-Content -LiteralPath $script:Sentinel -Raw } else { '' })
        }
    }

    # Planned commands from the numbered list printed after the
    # "planned command list" banner ("  <n>. <command>").
    function Get-PlannedCommands {
        param([Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]] $Lines)
        $planned = New-Object System.Collections.Generic.List[string]
        $inList  = $false
        foreach ($line in $Lines) {
            if ($line -match 'planned command list') { $inList = $true; continue }
            if (-not $inList) { continue }
            if ($line -match '^\s*\d+\.\s+(.+)$') { $planned.Add($Matches[1].Trim()) }
        }
        return , $planned.ToArray()
    }
}

AfterAll {
    $env:PATH = $script:SavedPath
    if ($null -eq $script:SavedSentinel) { Remove-Item Env:\LAB_SENTINEL -ErrorAction SilentlyContinue }
    else { $env:LAB_SENTINEL = $script:SavedSentinel }
}

Describe 'AWS EC2 deploy.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', '203.0.113.7/32', '-WhatIf')
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Deploy.ExitCode | Should -Be 0 -Because ("Output:`n" + $script:Deploy.Text)
    }

    It 'executes NO external command (sentinel shims never invoked)' {
        $script:Deploy.ExternalWasRun | Should -BeFalse -Because ("shim calls: " + $script:Deploy.ExternalCalls)
    }

    It 'prints a non-empty ordered planned command list and reports none executed' {
        $script:Deploy.Text | Should -Match 'planned command list'
        $script:Deploy.Text | Should -Match 'none executed'
        $script:DeployPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the sensible core steps in order: auth, network, SGs, secret, RDS, EC2' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'aws sts get-caller-identity'
        $joined | Should -Match 'aws ec2 (describe-vpcs|create-vpc)'
        $joined | Should -Match 'aws ec2 create-security-group'
        $joined | Should -Match 'aws secretsmanager (describe-secret|create-secret)'
        $joined | Should -Match 'aws rds create-db-instance'
        $joined | Should -Match 'aws ec2 run-instances'

        $idx = { param($p) for ($i = 0; $i -lt $script:DeployPlanned.Count; $i++) { if ($script:DeployPlanned[$i] -match $p) { return $i } } return -1 }
        $auth = & $idx 'aws sts get-caller-identity'
        $vpc  = & $idx 'aws ec2 create-vpc'
        $rds  = & $idx 'aws rds create-db-instance'
        $ec2  = & $idx 'aws ec2 run-instances'
        $auth | Should -Be 0
        $vpc  | Should -BeLessThan $rds
        $rds  | Should -BeLessThan $ec2
    }

    It 'every planned line is an aws command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) { $cmd | Should -Match '^aws\b' }
    }

    It 'opens the application port only to the supplied /32 (never 0.0.0.0/0 or ::/0 on a security group)' {
        $ingress = @($script:DeployPlanned | Where-Object { $_ -match 'authorize-security-group-ingress' })
        $ingress.Count | Should -BeGreaterThan 0
        ($ingress -join "`n") | Should -Match '--cidr 203\.0\.113\.7/32'
        foreach ($c in $ingress) {
            $c | Should -Not -Match '0\.0\.0\.0/0'
            $c | Should -Not -Match '::/0'
        }
    }

    It 'tags created resources with the lab tag and run-id' {
        ($script:DeployPlanned -join "`n") | Should -Match 'Key=lab,Value=sangyshop-lab-aws'
        ($script:DeployPlanned -join "`n") | Should -Match 'Key=run-id,Value='
    }

    It 'never prints a generated DB password value' {
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD=\S'
    }
}

Describe 'AWS EC2 deploy.ps1 source-range validation' {
    It 'rejects <Label> ("<Value>") with a non-zero exit, before any command' -ForEach $script:BadSources {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', $Value, '-WhatIf')
        $r.ExitCode | Should -Not -Be 0 -Because ("Output:`n" + $r.Text)
        $r.Text | Should -Match 'ERROR'
        $r.ExternalWasRun | Should -BeFalse
        $planned = Get-PlannedCommands -Lines $r.Lines; $planned.Count | Should -Be 0
        $r.Text | Should -Not -Match '(?m)^>\s+aws\b'
    }

    It 'rejects a missing -AllowedSourceRanges with a non-zero exit, before any command' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @('-WhatIf')
        $r.ExitCode | Should -Not -Be 0 -Because ("Output:`n" + $r.Text)
        $r.Text | Should -Match 'AllowedSourceRanges is required'
        $r.ExternalWasRun | Should -BeFalse
        $planned = Get-PlannedCommands -Lines $r.Lines; $planned.Count | Should -Be 0
    }

    It 'rejects a set where one valid /32 is mixed with an open range' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -Ranges @('203.0.113.7/32', '0.0.0.0/0')
        $r.ExitCode | Should -Not -Be 0
        $r.ExternalWasRun | Should -BeFalse
    }

    It 'accepts several valid /32 sources' {
        $r = Invoke-WhatIfScript -ScriptPath $script:DeployScript -Ranges @('203.0.113.7/32', '198.51.100.9/32')
        $r.ExitCode | Should -Be 0 -Because ("Output:`n" + $r.Text)
        $r.ExternalWasRun | Should -BeFalse
    }
}

Describe 'AWS EC2 teardown.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript -ExtraArgs @('-WhatIf')
        $script:TeardownPlanned = Get-PlannedCommands -Lines $script:Teardown.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Teardown.ExitCode | Should -Be 0 -Because ("Output:`n" + $script:Teardown.Text)
    }

    It 'executes NO external command (sentinel shims never invoked)' {
        $script:Teardown.ExternalWasRun | Should -BeFalse -Because ("shim calls: " + $script:Teardown.ExternalCalls)
    }

    It 'prints a non-empty planned command list and reports none executed' {
        $script:Teardown.Text | Should -Match 'planned command list'
        $script:Teardown.Text | Should -Match 'none executed'
        $script:TeardownPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the reverse-order deletes: EC2, then RDS, then secret, with the VPC last' {
        $joined = ($script:TeardownPlanned -join "`n")
        $joined | Should -Match 'aws ec2 terminate-instances'
        $joined | Should -Match 'aws rds delete-db-instance'
        $joined | Should -Match 'aws secretsmanager delete-secret'
        $joined | Should -Match 'aws ec2 delete-vpc'

        $idx = { param($p) for ($i = 0; $i -lt $script:TeardownPlanned.Count; $i++) { if ($script:TeardownPlanned[$i] -match $p) { return $i } } return -1 }
        $ec2 = & $idx 'aws ec2 terminate-instances'
        $rds = & $idx 'aws rds delete-db-instance'
        $sec = & $idx 'aws secretsmanager delete-secret'
        $vpc = & $idx 'aws ec2 delete-vpc'
        $ec2 | Should -BeLessThan $rds
        $rds | Should -BeLessThan $sec
        $sec | Should -BeLessThan $vpc
        $vpc | Should -Be ($script:TeardownPlanned.Count - 1)
    }

    It 'every planned line is an aws command (no bare external calls)' {
        foreach ($cmd in $script:TeardownPlanned) { $cmd | Should -Match '^aws\b' }
    }

    It 'only targets resources through the lab tag (no unmarked-resource wildcard deletes)' {
        ($script:TeardownPlanned -join "`n") | Should -Match 'Name=tag:lab,Values=sangyshop-lab-aws'
    }
}
