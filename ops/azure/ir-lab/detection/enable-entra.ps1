<#
.SYNOPSIS
    Exports Microsoft Entra ID sign-in and audit logs to the workspace, only when the licence allows (idempotent).

.DESCRIPTION
    CONDITIONAL component. Entra ID diagnostic settings need a Microsoft Entra
    ID P1 or P2 licence in the tenant and a role that can write tenant diagnostic settings
    (Global Administrator or Security Administrator). The script checks the tenant SKUs through
    Microsoft Graph (-EntraLicense Auto) or trusts the switch (-EntraLicense Yes / No).

    When the licence is NOT available, or the check or the call is not permitted, the script
    exits 0 without changes and prints the documented LIMITATION and FALLBACK:
      - No Entra sign-in or audit logs reach the workspace.
      - Identity triage uses the Activity Log (table AzureActivity: Caller, CallerIpAddress,
        first call time in UTC) and resource logs (Storage, Key Vault) instead. See
        queries\serviceprincipal-activity.kql and queries\activitylog-summary.kql.
      - Service principal sign-ins themselves (token requests) are not visible in that case.
    Exported categories: SignInLogs, AuditLogs, ServicePrincipalSignInLogs. The setting is
    tenant-level, cannot carry tags and is recorded in the lab manifest. Re-running creates
    nothing new. Supports -WhatIf.

.EXAMPLE
    .\enable-entra.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -EntraLicense Auto -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName,
    [ValidateSet('Auto', 'Yes', 'No')][string]$EntraLicense = 'Auto'
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

function Write-LabEntraFallback {
    Write-LabWarn 'LIMITATION: Entra ID sign-in and audit logs are NOT exported (needs Entra ID P1 or P2 and a role that can write tenant diagnostic settings).'
    Write-LabWarn 'FALLBACK: use the Activity Log (AzureActivity: Caller, CallerIpAddress, first call in UTC) and the resource logs of Storage and Key Vault.'
    Write-LabWarn 'See queries\serviceprincipal-activity.kql and queries\activitylog-summary.kql. Service principal token requests are not visible without the licence.'
}

try {
    # Licence check
    $licensed = $false
    if ($EntraLicense -eq 'Yes') {
        $licensed = $true
    } elseif ($EntraLicense -eq 'Auto') {
        $k = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', 'https://graph.microsoft.com/v1.0/subscribedSkus', '--query', 'value[].servicePlans[].{n:servicePlanName,s:provisioningStatus}', '--output', 'json')
        if ($k.ExitCode -eq 0) {
            $plans = @(ConvertFrom-LabJson -Text $k.Output)
            $licensed = [bool](@($plans | Where-Object { $_ -and "$($_.n)" -match '^AAD_PREMIUM(_P2)?$' -and "$($_.s)" -eq 'Success' }).Count -gt 0)
        } else {
            Write-LabWarn 'Could not read the tenant licences through Microsoft Graph (permission or sign-in). Treating Entra ID P1/P2 as unavailable.'
        }
    }
    if (-not $licensed) {
        Write-LabInfo 'Microsoft Entra ID P1/P2 licence not available. Entra log export skipped.'
        Write-LabEntraFallback
        exit 0
    }

    $ws = Get-LabWorkspaceRequired -ResourceGroup $ResourceGroup -Name $WorkspaceName
    $name = $script:LabEntraDiagName
    $url = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/${name}?api-version=2017-04-01-preview"
    $g = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $url, '--query', 'properties.workspaceId', '--output', 'tsv')
    Stop-LabIfDenied -Result $g -Service 'monitor' -Action 'tenant diagnostic settings read' -Step 'entra export read'
    if ($g.ExitCode -eq 0 -and "$($g.Output)".Trim() -ieq "$($ws.id)") {
        $own = Get-LabExistingOwnership -Type 'diagnostic-setting-entra' -Id $name
        if ($own -eq 'reused') { Write-LabInfo "Entra ID export '$name' already exists and was not created by the lab. Reusing it as is; it is never changed or removed." }
        else { Write-LabInfo "Entra ID export '$name' already points to '$WorkspaceName'. Nothing to create." }
        Add-LabManifestEntry -Type 'diagnostic-setting-entra' -Id $name -RunId $RunId -Ownership $own
    } else {
        $body = [ordered]@{
            properties = [ordered]@{
                workspaceId = "$($ws.id)"
                logs = @(
                    [ordered]@{ category = 'SignInLogs'; enabled = $true },
                    [ordered]@{ category = 'AuditLogs'; enabled = $true },
                    [ordered]@{ category = 'ServicePrincipalSignInLogs'; enabled = $true })
            }
        }
        $p = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'put', '--url', $url, '--body', (New-LabTempFile -Text ($body | ConvertTo-Json -Depth 6)))
        if ($p.ExitCode -ne 0) {
            Stop-LabIfDenied -Result $p -Service 'monitor' -Action 'tenant diagnostic settings write' -Step 'entra export write'
            Write-LabWarn "Could not create the Entra ID diagnostic setting: $($p.Output)"
            Write-LabEntraFallback
        } else {
            Write-LabInfo "Entra ID sign-in and audit logs -> $WorkspaceName."
            Add-LabManifestEntry -Type 'diagnostic-setting-entra' -Id $name -RunId $RunId -Ownership 'created'
        }
    }
} finally {
    Clear-LabTempFiles
}
exit 0
