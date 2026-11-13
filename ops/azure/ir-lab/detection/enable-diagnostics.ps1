<#
.SYNOPSIS
    Exports Blob Storage and Key Vault resource logs to the lab workspace (idempotent).

.DESCRIPTION
    Creates the diagnostic setting 'sangyshop-lab-diag' on:
      - the application Storage Account blob service (StorageRead, StorageWrite, StorageDelete,
        table StorageBlobLogs), and
      - the Key Vault (AuditEvent, table AzureDiagnostics).
    Targets are found by name (-StorageAccountName, -KeyVaultName) or, when omitted, by the lab tag in
    the resource group. A target that cannot be found is skipped with a warning. Settings cannot
    carry tags, so they are recorded in the lab manifest. Re-running creates nothing new.
    Supports -WhatIf.

.EXAMPLE
    .\enable-diagnostics.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName,
    [string]$StorageAccountName,
    [string]$KeyVaultName
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

function Set-LabDiagnostic {
    param([string]$Label, [string]$ResourceId, [string]$LogsJson, $Workspace)
    $name = $script:LabDiagName
    $s = Invoke-LabAz -CliArgs @('monitor', 'diagnostic-settings', 'show', '--name', $name, '--resource', $ResourceId, '--query', 'workspaceId', '--output', 'tsv')
    Stop-LabIfDenied -Result $s -Service 'monitor' -Action 'diagnostic-settings show' -Step 'diagnostic-settings show'
    $mid = "$ResourceId|$name"
    if ($s.ExitCode -eq 0 -and "$($s.Output)".Trim() -ieq "$($Workspace.id)") {
        $own = Get-LabExistingOwnership -Type 'diagnostic-setting' -Id $mid
        if ($own -eq 'reused') { Write-LabInfo "$Label diagnostic setting '$name' already exists and was not created by the lab. Reusing it as is; it is never changed or removed." }
        else { Write-LabInfo "$Label diagnostic setting '$name' already exists. Nothing to create." }
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs @('monitor', 'diagnostic-settings', 'create', '--name', $name, '--resource', $ResourceId,
            '--workspace', "$($Workspace.id)", '--logs', (New-LabTempFile -Text $LogsJson))
        Assert-LabAzOk -Result $c -Service 'monitor' -Action 'diagnostic-settings create' -Failure "Could not create the $Label diagnostic setting."
        Write-LabInfo "$Label logs -> $($Workspace.id.Split('/')[-1])."
        $own = 'created'
    }
    Add-LabManifestEntry -Type 'diagnostic-setting' -Id $mid -RunId $RunId -Ownership $own
}

try {
    $ws = Get-LabWorkspaceRequired -ResourceGroup $ResourceGroup -Name $WorkspaceName

    $sa = Resolve-LabResourceId -ResourceGroup $ResourceGroup -ResourceType 'Microsoft.Storage/storageAccounts' -Name $StorageAccountName
    if ($sa) {
        $blobLogs = '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true},{"category":"StorageDelete","enabled":true}]'
        Set-LabDiagnostic -Label 'Blob Storage' -ResourceId "$sa/blobServices/default" -LogsJson $blobLogs -Workspace $ws
    } else {
        Write-LabWarn 'No application Storage Account found (use -StorageAccountName). Skipping Blob Storage logs.'
    }

    $kv = Resolve-LabResourceId -ResourceGroup $ResourceGroup -ResourceType 'Microsoft.KeyVault/vaults' -Name $KeyVaultName
    if ($kv) {
        Set-LabDiagnostic -Label 'Key Vault' -ResourceId $kv -LogsJson '[{"category":"AuditEvent","enabled":true}]' -Workspace $ws
    } else {
        Write-LabWarn 'No Key Vault found (use -KeyVaultName). Skipping Key Vault logs.'
    }
} finally {
    Clear-LabTempFiles
}
exit 0
