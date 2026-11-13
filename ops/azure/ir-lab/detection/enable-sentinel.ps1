<#
.SYNOPSIS
    Enables Microsoft Sentinel on the lab workspace and creates the brute-force analytics rule (idempotent).

.DESCRIPTION
    1. Onboards Sentinel on the workspace (onboardingStates/default). The 31-day free trial covers
       the first 10 GB per day; the workspace daily cap (1 GB) limits ingestion anyway.
    2. Creates the scheduled analytics rule 'sangyshop-lab-bruteforce' over SangyShopApp_CL, using
       queries\login-failure-bruteforce.kql (10 or more failed logins in a 1-minute bin per IP).
       It runs every 5 minutes over a 10-minute window and opens an incident (tactic
       CredentialAccess, technique T1110) so that the incident appears within 15 minutes of the
       brute-force step. The IP is mapped as an entity.
    Sentinel keeps being supported in the Azure portal only until 2027-03-31; after that use the
    Microsoft Defender portal (the REST calls used here do not change).
    Onboarding and rules carry no tags: they live on the workspace, are recorded in the lab
    manifest and are removed by remove-sentinel.ps1. Re-running creates nothing new.
    Supports -WhatIf.

.EXAMPLE
    .\enable-sentinel.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $ws = Get-LabWorkspaceRequired -ResourceGroup $ResourceGroup -Name $WorkspaceName
    $api = $script:LabSentinelApi

    # 1. Onboarding
    $onUrl = Get-LabRestUrl -WorkspaceId "$($ws.id)" -Suffix '/providers/Microsoft.SecurityInsights/onboardingStates/default' -ApiVersion $api
    $o = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $onUrl, '--query', 'name', '--output', 'tsv')
    Stop-LabIfDenied -Result $o -Service 'sentinel' -Action 'onboarding state read' -Step 'sentinel onboarding read'
    $onId = "$ResourceGroup/$WorkspaceName"
    if ($o.ExitCode -eq 0 -and "$($o.Output)".Trim() -eq 'default') {
        # Already on: it is the lab's only when an earlier lab run recorded it.
        $own = Get-LabExistingOwnership -Type 'sentinel-onboarding' -Id $onId
        if ($own -eq 'reused') { Write-LabInfo "Sentinel is already enabled on '$WorkspaceName' and was not enabled by the lab. Reusing it as is; it is never removed." }
        else { Write-LabInfo "Sentinel is already enabled on '$WorkspaceName'." }
    } else {
        $c = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'put', '--url', $onUrl, '--body', (New-LabTempFile -Text '{"properties":{}}'))
        Assert-LabAzOk -Result $c -Service 'sentinel' -Action 'onboarding state put' -Failure "Could not enable Sentinel on '$WorkspaceName'."
        Write-LabInfo "Sentinel enabled on '$WorkspaceName' (31-day free trial; first 10 GB per day free)."
        $own = 'created'
    }
    Add-LabManifestEntry -Type 'sentinel-onboarding' -Id $onId -RunId $RunId -Ownership $own

    # 2. Analytics rule
    $ruleId = $script:LabSentinelRuleId
    $ruleUrl = Get-LabRestUrl -WorkspaceId "$($ws.id)" -Suffix "/providers/Microsoft.SecurityInsights/alertRules/$ruleId" -ApiVersion $api
    $g = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $ruleUrl, '--query', 'name', '--output', 'tsv')
    Stop-LabIfDenied -Result $g -Service 'sentinel' -Action 'analytics rule read' -Step 'sentinel analytics rule read'
    $ruleManifestId = "$ResourceGroup/$WorkspaceName/$ruleId"
    if ($g.ExitCode -eq 0 -and "$($g.Output)".Trim() -eq $ruleId) {
        $own = Get-LabExistingOwnership -Type 'sentinel-analytics-rule' -Id $ruleManifestId
        if ($own -eq 'reused') { Write-LabInfo "Analytics rule '$ruleId' already exists and was not created by the lab. Reusing it as is; it is never changed or removed." }
        else { Write-LabInfo "Analytics rule '$ruleId' already exists. Nothing to create." }
    } else {
        $query = Get-LabQueryText -Name 'login-failure-bruteforce.kql'
        $body = [ordered]@{
            kind = 'Scheduled'
            properties = [ordered]@{
                displayName = 'SangyShop lab: brute-force login failures'
                description = 'Ten or more failed logins from one IP inside one minute (table SangyShopApp_CL, event auth_login, result failure).'
                severity = 'Medium'
                enabled = $true
                query = $query
                queryFrequency = 'PT5M'
                queryPeriod = 'PT10M'
                triggerOperator = 'GreaterThan'
                triggerThreshold = 0
                suppressionEnabled = $false
                suppressionDuration = 'PT1H'
                tactics = @('CredentialAccess')
                techniques = @('T1110')
                incidentConfiguration = [ordered]@{
                    createIncident = $true
                    groupingConfiguration = [ordered]@{ enabled = $false; reopenClosedIncident = $false; lookbackDuration = 'PT5H'; matchingMethod = 'AllEntities' }
                }
                entityMappings = @([ordered]@{ entityType = 'IP'; fieldMappings = @([ordered]@{ identifier = 'Address'; columnName = 'client_ip' }) })
            }
        }
        $json = $body | ConvertTo-Json -Depth 10
        $p = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'put', '--url', $ruleUrl, '--body', (New-LabTempFile -Text $json))
        Assert-LabAzOk -Result $p -Service 'sentinel' -Action 'analytics rule put' -Failure 'Could not create the analytics rule.'
        Write-LabInfo "Created analytics rule '$ruleId' (every 5 min over 10 min; opens an incident)."
        $own = 'created'
    }
    Add-LabManifestEntry -Type 'sentinel-analytics-rule' -Id $ruleManifestId -RunId $RunId -Ownership $own
} finally {
    Clear-LabTempFiles
}
exit 0
