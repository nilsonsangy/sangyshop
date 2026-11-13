<#
.SYNOPSIS
    Removes the 'sangyshop-lab-diag' diagnostic settings from the Storage Account and the Key Vault (idempotent).

.DESCRIPTION
    Targets are found by name or by the lab tag (see enable-diagnostics.ps1). Only the lab-named
    setting is removed. A missing target or setting exits 0. Supports -WhatIf.

.EXAMPLE
    .\disable-diagnostics.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$StorageAccountName,
    [string]$KeyVaultName
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$null = Get-LabSubscriptionId

function Remove-LabDiagnostic {
    param([string]$Label, [string]$ResourceId)
    $name = $script:LabDiagName
    if (Test-LabManifestReused -Type 'diagnostic-setting' -Id "$ResourceId|$name") {
        Write-LabInfo "$Label diagnostic setting '$name' kept (not created by the lab)."
        Remove-LabManifestEntry -Type 'diagnostic-setting' -Id "$ResourceId|$name"
        return
    }
    $s = Invoke-LabAz -CliArgs @('monitor', 'diagnostic-settings', 'show', '--name', $name, '--resource', $ResourceId, '--query', 'name', '--output', 'tsv')
    Stop-LabIfDenied -Result $s -Service 'monitor' -Action 'diagnostic-settings show' -Step 'diagnostic-settings show'
    if ($s.ExitCode -ne 0) {
        if (Test-LabNotFound -Text $s.Output) {
            Write-LabInfo "$Label diagnostic setting '$name' not found. Nothing to remove."
        } else {
            Stop-Lab -Code 1 -Message "Could not read the $Label diagnostic setting. $($s.Output)"
        }
    } else {
        $d = Invoke-LabAz -Mutating -CliArgs @('monitor', 'diagnostic-settings', 'delete', '--name', $name, '--resource', $ResourceId)
        if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete the $Label diagnostic setting. $($d.Output)" }
        Write-LabInfo "Removed $Label diagnostic setting '$name'."
    }
    Remove-LabManifestEntry -Type 'diagnostic-setting' -Id "$ResourceId|$name"
}

try {
    $sa = Resolve-LabResourceId -ResourceGroup $ResourceGroup -ResourceType 'Microsoft.Storage/storageAccounts' -Name $StorageAccountName
    if ($sa) { Remove-LabDiagnostic -Label 'Blob Storage' -ResourceId "$sa/blobServices/default" } else { Write-LabInfo 'No application Storage Account found. Nothing to remove.' }

    $kv = Resolve-LabResourceId -ResourceGroup $ResourceGroup -ResourceType 'Microsoft.KeyVault/vaults' -Name $KeyVaultName
    if ($kv) { Remove-LabDiagnostic -Label 'Key Vault' -ResourceId $kv } else { Write-LabInfo 'No Key Vault found. Nothing to remove.' }
} finally {
    Clear-LabTempFiles
}
exit 0
