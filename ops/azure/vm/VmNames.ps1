# =============================================================================
# VmNames.ps1 -- shared, side-effect-free naming for ops/azure/vm/*.ps1
# =============================================================================
# Dot-sourced by deploy.ps1, teardown.ps1, stop-lab.ps1 and start-lab.ps1 so all
# four scripts derive IDENTICAL resource names from the same config. No az call,
# no file write, no secret. Windows PowerShell 5.1 compatible.

Set-StrictMode -Version Latest

# Lab identifier used by the Tag_Lab (tag lab=...) and the Manifesto_Lab file name.
$script:VmLabName = 'sangyshop-lab-azure'

function Get-BoundedName {
    <#
    .SYNOPSIS
        Joins Prefix + Separator + Suffix and keeps the result within MaxLength by
        trimming the PREFIX (the unique suffix is always preserved).
    #>
    param(
        [Parameter(Mandatory)][string] $Prefix,
        [Parameter(Mandatory)][string] $Suffix,
        [Parameter(Mandatory)][int]    $MaxLength,
        [string] $Separator = ''
    )
    $room = $MaxLength - $Suffix.Length - $Separator.Length
    if ($room -lt 1) {
        throw "Get-BoundedName: UniqueSuffix '$Suffix' is too long to build a name of at most $MaxLength characters."
    }
    if ($Prefix.Length -gt $room) { $Prefix = $Prefix.Substring(0, $room) }
    $Prefix = $Prefix.TrimEnd('-')
    return ($Prefix + $Separator + $Suffix)
}

function Get-VmLabNames {
    <#
    .SYNOPSIS
        Returns the ordered hashtable of every resource name used by the VM lab.
    .PARAMETER Config
        Hashtable returned by Get-CloudConfig -Cloud Azure -Modality vm.
    #>
    param([Parameter(Mandatory)][hashtable] $Config)

    $suffix  = [string]$Config['UniqueSuffix']
    $app     = ([string]$Config['Common']['AppName']).ToLowerInvariant()
    $vmCfg   = $Config['Azure']['Vm']
    $appAlnum = ($app -replace '[^a-z0-9]', '')

    $n = [ordered]@{}
    $n['Suffix']          = $suffix
    $n['Location']        = [string]$Config['Azure']['Location']
    $n['LabGroup']        = [string]$vmCfg['ResourceGroupBase']
    $n['EvidenceGroup']   = [string]$vmCfg['EvidenceGroupBase']
    $n['Vnet']            = "$app-vm-vnet"
    $n['Subnet']          = 'app'
    $n['Nsg']             = "$app-vm-nsg"
    $n['PublicIp']        = "$app-vm-pip"
    $n['Identity']        = "$app-vm-id"
    $n['VmName']          = "$app-vm"
    # Key Vault: 3-24 chars, globally unique. Short prefix keeps it distinct from the ACI vault.
    $kvPrefix = $app
    if ($kvPrefix.Length -gt 6) { $kvPrefix = $kvPrefix.Substring(0, 6) }
    $n['KeyVault']        = Get-BoundedName -Prefix ($kvPrefix + '-vmkv') -Suffix $suffix -MaxLength 24 -Separator '-'
    $n['SecretName']      = 'db-password'
    # PostgreSQL Flexible Server: globally unique DNS label.
    $n['PgServer']        = Get-BoundedName -Prefix "$app-vmpg" -Suffix $suffix -MaxLength 63 -Separator '-'
    # Storage account: 3-24 lowercase alphanumerics, globally unique.
    $n['StorageAccount']  = Get-BoundedName -Prefix ($appAlnum + 'vm') -Suffix $suffix -MaxLength 24
    $n['StorageContainer'] = "$app-media"
    $n['Workspace']       = "$app-law-$suffix"
    $n['LogTable']        = 'SangyShopApp_CL'
    $n['Dcr']             = "$app-dcr-app"
    $n['DcrAssociation']  = "$app-dcra-app"
    $n['LeakedSp']        = 'sp-lab-leaked'
    $n['AppPort']         = 3000
    return $n
}
