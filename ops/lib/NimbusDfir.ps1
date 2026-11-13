<#
.SYNOPSIS
    Explicit, opt-in resolution of a local NimbusDFIR checkout.
.DESCRIPTION
    Dot-source this file from any script that needs to call a generic incident
    response tool. The checkout location is never guessed: it comes only from an
    explicit parameter, the NIMBUSDFIR_PATH environment variable, or the
    Common.NimbusDfirPath key of cloud.config.ps1. Sibling or relative
    directories are never probed.
    Windows PowerShell 5.1 compatible.
#>
Set-StrictMode -Version Latest

# Files that must exist under a directory for it to count as a NimbusDFIR checkout.
$script:NimbusDfirMarkers = @(
    'ir_lab_core\__init__.py',
    'aws\ec2_evidence_preservation.py'
)

function Test-NimbusDfirPathValid {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    foreach ($marker in $script:NimbusDfirMarkers) {
        if (-not (Test-Path -LiteralPath (Join-Path $Path $marker) -PathType Leaf)) { return $false }
    }
    return $true
}

function Resolve-NimbusDfirPath {
    <#
    .SYNOPSIS
        Returns the validated path of a NimbusDFIR checkout.
    .DESCRIPTION
        Sources are tried in this order, and the first one that points to a valid
        checkout wins:
          1. -Path
          2. $env:NIMBUSDFIR_PATH
          3. $Config.Common.NimbusDfirPath
        A directory is valid only when it contains ir_lab_core\__init__.py and
        aws\ec2_evidence_preservation.py. Nothing else is searched.
        Without -Optional, a missing or invalid setting throws a message that
        explains how to set the path. With -Optional, $null is returned instead.
    #>
    [CmdletBinding()]
    param(
        [string]    $Path,
        [hashtable] $Config,
        [switch]    $Optional
    )

    $candidates = New-Object System.Collections.Generic.List[object]
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $candidates.Add(@{ Source = '-Path'; Value = $Path })
    }
    $envValue = [Environment]::GetEnvironmentVariable('NIMBUSDFIR_PATH')
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        $candidates.Add(@{ Source = 'NIMBUSDFIR_PATH'; Value = $envValue })
    }
    if ($null -ne $Config -and $Config.ContainsKey('Common') -and ($Config['Common'] -is [System.Collections.IDictionary]) `
            -and $Config['Common'].Contains('NimbusDfirPath')) {
        $cfgValue = [string]$Config['Common']['NimbusDfirPath']
        if (-not [string]::IsNullOrWhiteSpace($cfgValue)) {
            $candidates.Add(@{ Source = 'Common.NimbusDfirPath'; Value = $cfgValue })
        }
    }

    foreach ($c in $candidates) {
        if (Test-NimbusDfirPathValid -Path $c.Value) {
            return (Resolve-Path -LiteralPath $c.Value).ProviderPath
        }
    }

    if ($Optional) { return $null }

    $markerList = ($script:NimbusDfirMarkers -join ', ')
    if ($candidates.Count -gt 0) {
        $tried = ($candidates | ForEach-Object { "$($_.Source) = '$($_.Value)'" }) -join '; '
        throw ("Resolve-NimbusDfirPath: no valid NimbusDFIR checkout found. Tried: $tried. " +
               "A valid directory contains: $markerList.")
    }
    throw ("Resolve-NimbusDfirPath: NimbusDFIR path is not set. Provide it with -Path, set the " +
           "NIMBUSDFIR_PATH environment variable (for example `$env:NIMBUSDFIR_PATH = 'C:\path\to\NimbusDFIR'), " +
           "or set Common.NimbusDfirPath in cloud.config.ps1. A valid directory contains: $markerList.")
}

function Get-NimbusToolPath {
    <#
    .SYNOPSIS
        Returns the full path of a tool inside a NimbusDFIR checkout.
    .PARAMETER NimbusDfirPath
        Checkout root, as returned by Resolve-NimbusDfirPath.
    .PARAMETER Relative
        Tool path relative to the root, for example 'aws/ec2_evidence_preservation.py'.
        Throws when the file does not exist.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $NimbusDfirPath,
        [Parameter(Mandatory)][string] $Relative
    )
    $rel = $Relative -replace '/', '\'
    $full = Join-Path $NimbusDfirPath $rel
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Get-NimbusToolPath: tool not found at '$full'. Check that NimbusDFIR is up to date."
    }
    return (Resolve-Path -LiteralPath $full).ProviderPath
}
