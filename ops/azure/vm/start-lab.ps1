<#
.SYNOPSIS
    Resumes the Azure VM lab after stop-lab.ps1.

.DESCRIPTION
    Starts the PostgreSQL Flexible Server first (`az postgres flexible-server start`),
    then starts the deallocated VM (`az vm start`). The static public IP is kept, so
    the application URL does not change. The app container has `--restart
    unless-stopped`, so it comes back by itself.

    Prints the same cost reminders in English: disks and the public IP were billed
    while stopped, a stopped server is restarted automatically by Azure after the
    period in the current documentation, and this does not replace teardown.ps1.
    Every external command is echoed before it runs.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to ops/cloud.config.ps1.

.PARAMETER RunId
    Optional run id; when given, the lab group must carry the same run-id tag.

.PARAMETER WhatIf
    Prints the commands that would run; changes nothing.

.PARAMETER NonInteractive
    Do not ask for confirmation.

.EXAMPLE
    .\start-lab.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $RunId,
    [switch] $WhatIf,
    [switch] $NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = (Join-Path $scriptDir '..\..\cloud.config.ps1')
}

. (Join-Path $scriptDir '..\..\lib\Common.ps1')
. (Join-Path $scriptDir 'VmNames.ps1')

$script:PlanOrdinal = 0
function Invoke-Planned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
    )
    if ($WhatIf) {
        $script:PlanOrdinal++
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, ((@($Exe) + $CmdArgs) -join ' ')) -ForegroundColor DarkCyan
        return $null
    }
    return (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail:$AllowFail)
}
function Az { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A }
function Write-StdErr { param([string] $Message) [Console]::Error.WriteLine($Message) }

try {
    Write-Step "Loading configuration (Azure, VM modality)"
    $cfg   = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure' -Modality 'vm'
    $names = Get-VmLabNames -Config $cfg
    $rg = $names['LabGroup']

    Write-Step "Reminders before starting the lab"
    Write-Host "  * Disks and the static public IP were billed while the lab was stopped." -ForegroundColor Yellow
    Write-Host "  * Azure restarts a stopped PostgreSQL Flexible Server on its own after the period in the current" -ForegroundColor Yellow
    Write-Host "    Azure documentation (7 days at the time of writing; confirm it on the execution date)." -ForegroundColor Yellow
    Write-Host "  * Running again bills compute by the hour. Stop daily; remove everything with teardown.ps1." -ForegroundColor Yellow

    if (-not $WhatIf -and -not $NonInteractive) {
        $answer = Read-Host "Start PostgreSQL '$($names['PgServer'])' and VM '$($names['VmName'])'? Type 'yes' to continue"
        if ($answer -ne 'yes') {
            Write-Host "Cancelled. Nothing was changed."
            exit 0
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RunId) -and -not $WhatIf) {
        $tag = @(Invoke-Echoed -Exe 'az' -CmdArgs @('group', 'show', '--name', $rg, '--query', 'tags."run-id"', '--output', 'tsv') -AllowFail |
                Where-Object { $_ -is [string] -and $_.Trim() }) | Select-Object -Last 1
        if ($null -eq $tag -or ([string]$tag).Trim() -ne $RunId) {
            throw "Resource group '$rg' does not carry run-id '$RunId'. Refusing to start it."
        }
    }

    Write-Step "Starting the PostgreSQL Flexible Server '$($names['PgServer'])'"
    Az postgres flexible-server start --name $names['PgServer'] --resource-group $rg --output none

    Write-Step "Starting the VM '$($names['VmName'])'"
    Az vm start --name $names['VmName'] --resource-group $rg --output none

    Write-Step "Fetching the public IP"
    Az network public-ip show --name $names['PublicIp'] --resource-group $rg --query ipAddress --output tsv

    if ($WhatIf) {
        Write-Step "DRY RUN complete. $script:PlanOrdinal command(s) listed; nothing was changed."
    }
    else {
        Write-Host ("Lab started. The app listens on port {0} of the public IP printed above." -f $names['AppPort']) -ForegroundColor Green
    }
    exit 0
}
catch {
    Write-StdErr ("ERROR: " + $_.Exception.Message)
    exit 1
}
