<#
.SYNOPSIS
    Resume the EC2 + RDS lab after stop-lab.ps1 (intermediate stop).

.DESCRIPTION
    Starts the RDS instance, waits until it is available, then starts the EC2
    instance (the container restarts by itself: restart policy unless-stopped)
    and prints the new public URL.

    Warnings are printed BEFORE anything runs:
      * A stopped RDS instance is started again automatically by AWS after 7 days.
      * EBS and RDS storage (and any Elastic IP) are billed while stopped, and
        the lab is billed again as soon as it runs.
      * Starting/stopping does not replace teardown.ps1 or the full AWS teardown.

    Every external command is echoed before it runs. -WhatIf prints the planned
    commands and starts nothing. Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1 (default: ops/cloud.config.ps1).

.PARAMETER WhatIf
    Dry run: print the planned command list, start nothing, exit 0.

.EXAMPLE
    .\start-lab.ps1
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

Write-Host ""
Write-Host "WARNING: RDS instance '$rdsId' restarts automatically after 7 days stopped." -ForegroundColor Yellow
Write-Host "WARNING: EBS and RDS storage (and any Elastic IP) are billed while stopped; compute is billed again from now on." -ForegroundColor Yellow
Write-Host "WARNING: stopping/starting is NOT a teardown. Run teardown.ps1 or the full AWS teardown when the lab is finished." -ForegroundColor Yellow
Write-Host ""

if ($WhatIf) { Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed." }

Write-Step "Checking AWS authentication via sts get-caller-identity"
Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
if ($script:LastCliExit -ne 0) {
    Write-StderrLine "ERROR: AWS authentication/CLI check failed (aws sts get-caller-identity). Authenticate as the lab operator and re-run."
    exit 1
}

$failed = New-Object System.Collections.Generic.List[string]

Write-Step "Starting RDS instance '$rdsId'"
$out = Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].DBInstanceStatus', '--output', 'text'))
$rdsStatus = if ($WhatIf) { 'stopped' } else { Get-Scalar $out }
if ($rdsStatus -eq 'stopped') {
    Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'start-db-instance') + $rg + @('--db-instance-identifier', $rdsId)) | Out-Null
    if ($script:LastCliExit -ne 0) { $failed.Add("rds-instance $rdsId") }
}
else { Write-Host "  RDS status is '$rdsStatus'; no start needed" -ForegroundColor DarkGray }
if ($failed.Count -eq 0) {
    Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'wait', 'db-instance-available') + $rg + @('--db-instance-identifier', $rdsId)) | Out-Null
}

Write-Step "Starting EC2 instance '$ec2Name'"
$out = Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'describe-instances') + $rg + @('--filters', "Name=tag:Name,Values=$ec2Name", "Name=tag:lab,Values=$lab", 'Name=instance-state-name,Values=stopped,stopping', '--query', 'Reservations[0].Instances[0].InstanceId', '--output', 'text'))
$instanceId = if ($WhatIf) { '<instance-id>' } else { Get-Scalar $out }
$publicIp = $null
if ($instanceId -and $instanceId -ne 'None') {
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'start-instances') + $rg + @('--instance-ids', $instanceId)) | Out-Null
    if ($script:LastCliExit -ne 0) { $failed.Add("ec2-instance $instanceId") }
    else {
        Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'wait', 'instance-running') + $rg + @('--instance-ids', $instanceId)) | Out-Null
        $ipOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'describe-instances') + $rg + @('--instance-ids', $instanceId, '--query', 'Reservations[0].Instances[0].PublicIpAddress', '--output', 'text'))
        $publicIp = if ($WhatIf) { '<instance-public-ip>' } else { Get-Scalar $ipOut }
    }
}
else { Write-Host "  no stopped EC2 instance found (already running or not deployed)" -ForegroundColor DarkGray }

if ($WhatIf) {
    Write-Step "Dry run (-WhatIf): planned command list (no command was executed)"
    $i = 0
    foreach ($c in $script:PlannedCommands) { $i++; Write-Host ("  {0,2}. {1}" -f $i, $c) }
    Write-Host ""
    Write-Host "Dry run complete: $($script:PlannedCommands.Count) command(s) planned, none executed."
    exit 0
}

if ($failed.Count -gt 0) {
    Write-StderrLine "ERROR: could not start: $($failed -join ', ')"
    exit 1
}
Write-Host ""
if ($publicIp) { Write-Host "Application URL: http://${publicIp}:3000 (the public IP changed; update your allowed-source notes if needed)" -ForegroundColor Green }
Write-Host "Lab resumed. Stop it again at the end of the day with ops/aws/ec2/stop-lab.ps1." -ForegroundColor Green
exit 0
