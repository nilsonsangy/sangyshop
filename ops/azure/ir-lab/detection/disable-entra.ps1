<#
.SYNOPSIS
    Removes the Entra ID diagnostic setting 'sangyshop-lab-entra' if it exists (idempotent).

.DESCRIPTION
    Only the lab-named tenant setting is removed. If the setting is missing, or the caller cannot
    read tenant diagnostic settings (no licence or role), the script reports it and exits 0.
    Supports -WhatIf.

.EXAMPLE
    .\disable-entra.ps1 -Subscription <id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
$null = Get-LabSubscriptionId

try {
    $name = $script:LabEntraDiagName
    if (Test-LabManifestReused -Type 'diagnostic-setting-entra' -Id $name) {
        Write-LabInfo "Entra ID export '$name' kept (not created by the lab)."
        Remove-LabManifestEntry -Type 'diagnostic-setting-entra' -Id $name
        exit 0
    }
    $url = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/${name}?api-version=2017-04-01-preview"
    $g = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $url, '--query', 'name', '--output', 'tsv')
    if ($g.ExitCode -ne 0) {
        Write-LabInfo "Entra ID export '$name' not found or not readable (no licence or role). Nothing to remove."
    } else {
        $d = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'delete', '--url', $url)
        if ($d.ExitCode -ne 0 -and -not (Test-LabNotFound -Text $d.Output)) { Stop-Lab -Code 1 -Message "Could not delete '$name'. $($d.Output)" }
        Write-LabInfo "Removed Entra ID export '$name'."
    }
    Remove-LabManifestEntry -Type 'diagnostic-setting-entra' -Id $name
} finally {
    Clear-LabTempFiles
}
exit 0
