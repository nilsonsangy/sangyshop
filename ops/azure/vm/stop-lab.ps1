<#
.SYNOPSIS
    Intermediate stop (intermediate stop) of the Azure VM lab at the end of a lab day.

.DESCRIPTION
    DEALLOCATES the VM (`az vm deallocate`, the VM is kept) and STOPS the PostgreSQL
    Flexible Server (`az postgres flexible-server stop`). Nothing is deleted.

    Before acting it prints a warning in English and asks for confirmation (skip with
    -NonInteractive or -WhatIf):
      * Azure automatically restarts a stopped Flexible Server after the period in
        the current Azure documentation (7 days at the time of writing; confirm the
        value on the execution date).
      * Managed disks and the static public IP keep being billed while stopped.
      * Stopping does NOT replace teardown.ps1 / the full Azure teardown.

    Every external command is echoed before it runs. Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to ops/cloud.config.ps1.

.PARAMETER RunId
    Optional run id; when given, the lab group must carry the same run-id tag.

.PARAMETER WhatIf
    Prints the commands that would run; changes nothing.

.PARAMETER NonInteractive
    Do not ask for confirmation.

.EXAMPLE
    .\stop-lab.ps1 -WhatIf

.EXAMPLE
    .\stop-lab.ps1 -RunId 20261114T120000Z-a1b2 -NonInteractive
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
function Az    { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A }
function Write-StdErr { param([string] $Message) [Console]::Error.WriteLine($Message) }

try {
    Write-Step "Loading configuration (Azure, VM modality)"
    $cfg   = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure' -Modality 'vm'
    $names = Get-VmLabNames -Config $cfg
    $rg = $names['LabGroup']

    Write-Step "Warnings before stopping the lab"
    Write-Host "  * Azure automatically restarts a stopped PostgreSQL Flexible Server after the period stated in the" -ForegroundColor Yellow
    Write-Host "    current Azure documentation (7 days at the time of writing; confirm it on the execution date)." -ForegroundColor Yellow
    Write-Host "  * Managed disks and the static public IP are STILL billed while the lab is stopped." -ForegroundColor Yellow
    Write-Host "  * Stopping does NOT replace teardown.ps1 / the full Azure teardown." -ForegroundColor Yellow

    if (-not $WhatIf -and -not $NonInteractive) {
        $answer = Read-Host "Deallocate VM '$($names['VmName'])' and stop PostgreSQL '$($names['PgServer'])'? Type 'yes' to continue"
        if ($answer -ne 'yes') {
            Write-Host "Cancelled. Nothing was changed."
            exit 0
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($RunId) -and -not $WhatIf) {
        $tag = @(Invoke-Echoed -Exe 'az' -CmdArgs @('group', 'show', '--name', $rg, '--query', 'tags."run-id"', '--output', 'tsv') -AllowFail |
                Where-Object { $_ -is [string] -and $_.Trim() }) | Select-Object -Last 1
        if ($null -eq $tag -or ([string]$tag).Trim() -ne $RunId) {
            throw "Resource group '$rg' does not carry run-id '$RunId'. Refusing to stop it."
        }
    }

    Write-Step "Deallocating the VM '$($names['VmName'])'"
    Az vm deallocate --name $names['VmName'] --resource-group $rg --output none

    Write-Step "Stopping the PostgreSQL Flexible Server '$($names['PgServer'])'"
    Az postgres flexible-server stop --name $names['PgServer'] --resource-group $rg --output none

    if ($WhatIf) {
        Write-Step "DRY RUN complete. $script:PlanOrdinal command(s) listed; nothing was changed."
    }
    else {
        Write-Host "Lab stopped. Resume with start-lab.ps1; remove everything with teardown.ps1." -ForegroundColor Green
    }
    exit 0
}
catch {
    Write-StdErr ("ERROR: " + $_.Exception.Message)
    exit 1
}
