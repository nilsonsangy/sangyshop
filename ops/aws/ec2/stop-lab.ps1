<#
.SYNOPSIS
    Intermediate stop of the EC2 + RDS lab (intermediate stop). Nothing is deleted.

.DESCRIPTION
    Stops the EC2 instance and then the RDS instance created by deploy.ps1 at the
    end of a lab day. start-lab.ps1 resumes them.

    Warnings are printed BEFORE anything runs:
      * A stopped RDS instance is started again automatically by AWS after 7 days.
      * EBS and RDS storage (and any Elastic IP) keep being billed while stopped.
      * Stopping does not replace teardown.ps1 or the account-wide full AWS teardown.

    Every external command is echoed before it runs. -WhatIf prints the planned
    commands and stops nothing. Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1 (default: ops/cloud.config.ps1).

.PARAMETER WhatIf
    Dry run: print the planned command list, stop nothing, exit 0.

.EXAMPLE
    .\stop-lab.ps1
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs
    )
    $displayParts = @($Exe)
    foreach ($a in $CmdArgs) {
        if ($null -eq $a -or $a -eq '') { $displayParts += '""' }
        elseif ($a -match '[\s"]') { $displayParts += ('"' + ($a -replace '"', '\"') + '"') }
        else { $displayParts += $a }
    }
    $display = $displayParts -join ' '
    if ($WhatIf) {
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }
    $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

function Get-Scalar {
    param($Value)
    if ($null -eq $Value) { return '' }
    $lines = @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return '' }
    return $lines[$lines.Count - 1].Trim()
}

function Write-StderrLine {
    param([string] $Text)
    [Console]::Error.WriteLine($Text)
}

try {
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws' -Modality 'ec2'
}
catch {
    Write-StderrLine "ERROR: $($_.Exception.Message)"
    exit 1
}

$region  = [string]$cfg.Aws.Region
$appName = [string]$cfg.Common.AppName
$lab     = 'sangyshop-lab-aws'
$prefix  = "$appName-lab"
$ec2Name = "$prefix-ec2"
$rdsId   = "$prefix-pg"
$rg      = @('--region', $region)

# Warnings first (English), before any command runs.
Write-Host ""
Write-Host "WARNING: RDS instance '$rdsId' restarts automatically after 7 days stopped." -ForegroundColor Yellow
Write-Host "WARNING: EBS and RDS storage (and any Elastic IP) keep being billed while the lab is stopped." -ForegroundColor Yellow
Write-Host "WARNING: stopping is NOT a teardown. Run teardown.ps1 or the full AWS teardown to stop all billing." -ForegroundColor Yellow
Write-Host "NOTE: the instance public IP changes on the next start (no Elastic IP is used)." -ForegroundColor Yellow
Write-Host ""

if ($WhatIf) { Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed." }

Write-Step "Checking AWS authentication via sts get-caller-identity"
Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
if ($script:LastCliExit -ne 0) {
    Write-StderrLine "ERROR: AWS authentication/CLI check failed (aws sts get-caller-identity). Authenticate as the lab operator and re-run."
    exit 1
}

$failed = New-Object System.Collections.Generic.List[string]

Write-Step "Stopping EC2 instance '$ec2Name'"
$out = Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'describe-instances') + $rg + @('--filters', "Name=tag:Name,Values=$ec2Name", "Name=tag:lab,Values=$lab", 'Name=instance-state-name,Values=pending,running,stopping', '--query', 'Reservations[0].Instances[0].InstanceId', '--output', 'text'))
$instanceId = if ($WhatIf) { '<instance-id>' } else { Get-Scalar $out }
if ($instanceId -and $instanceId -ne 'None') {
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'stop-instances') + $rg + @('--instance-ids', $instanceId)) | Out-Null
    if ($script:LastCliExit -ne 0) { $failed.Add("ec2-instance $instanceId") }
    else { Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'wait', 'instance-stopped') + $rg + @('--instance-ids', $instanceId)) | Out-Null }
}
else { Write-Host "  no running EC2 instance found (already stopped or not deployed)" -ForegroundColor DarkGray }

Write-Step "Stopping RDS instance '$rdsId'"
$out = Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].DBInstanceStatus', '--output', 'text'))
$rdsStatus = if ($WhatIf) { 'available' } else { Get-Scalar $out }
if ($rdsStatus -eq 'available') {
    Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'stop-db-instance') + $rg + @('--db-instance-identifier', $rdsId)) | Out-Null
    if ($script:LastCliExit -ne 0) { $failed.Add("rds-instance $rdsId") }
}
else { Write-Host "  RDS instance not in 'available' state (status: '$rdsStatus'); nothing to stop" -ForegroundColor DarkGray }

if ($WhatIf) {
    Write-Step "Dry run (-WhatIf): planned command list (no command was executed)"
    $i = 0
    foreach ($c in $script:PlannedCommands) { $i++; Write-Host ("  {0,2}. {1}" -f $i, $c) }
    Write-Host ""
    Write-Host "Dry run complete: $($script:PlannedCommands.Count) command(s) planned, none executed."
    exit 0
}

if ($failed.Count -gt 0) {
    Write-StderrLine "ERROR: could not stop: $($failed -join ', ')"
    exit 1
}
Write-Host ""
Write-Host "Lab stopped. Resume with ops/aws/ec2/start-lab.ps1. Remember the 7-day RDS auto-restart." -ForegroundColor Green
exit 0
