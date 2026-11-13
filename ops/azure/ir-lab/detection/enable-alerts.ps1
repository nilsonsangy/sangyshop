<#
.SYNOPSIS
    Creates the Action Group (e-mail) and the brute-force log search alert rule (idempotent).

.DESCRIPTION
    Starts with one read-only discovery of the subscription and prints one line per resource type.
    1. Action Group 'ag-sangyshop-lab' with one e-mail receiver, tagged with the lab tag.
    2. Log search alert rule 'sangyshop-lab-bruteforce' on the workspace. It runs the saved query
       queries\login-failure-bruteforce.kql (10 or more failed logins from one IP inside one
       minute) every 5 minutes over a 10-minute window, severity 2, and notifies the Action Group.
       The query returns rows only on a brute-force burst, so the condition is "rows > 0".
       Alert delivery should arrive within about 10 minutes of the brute-force step; ingestion
       latency of the text-log pipeline adds a few minutes.
    The address comes from -Email, then LAB_ALERT_EMAIL (environment or ops/.env), then a prompt.
    A same-named group or rule without the lab tag is reused as is: it is not tagged, edited or
    removed, and the lab e-mail is not added to it. It is recorded in the manifest as reused.
    Each resource is written to the manifest right after it is created. A denied call exits
    with code 3 and names the exact built-in role. Re-running creates nothing new.
    The Action Group is also where the NSG blocker (Logic App) attaches its receiver.
    Supports -WhatIf.

.EXAMPLE
    .\enable-alerts.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$RunId,
    [string]$WorkspaceName,
    [string]$Email
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $WorkspaceName) { $WorkspaceName = $script:LabWorkspaceName }
Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
# -Email is optional: Resolve-LabAlertEmail falls back to LAB_ALERT_EMAIL (ops/.env) or a prompt,
# validates the format (exit code 2 on failure) and never prints the address.
$Email = Resolve-LabAlertEmail -Email $Email -NonInteractive:([bool]$global:LabAzHandler)
[void]$script:LabMaskedValues.Add($Email)   # the address is never echoed back in command lines
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $null = Get-LabPreflightDecision -Type actiongroup -ExpectedName $script:LabActionGroupName
    $null = Get-LabPreflightDecision -Type alertrule -ExpectedName $script:LabAlertRuleName

    $ws = Get-LabWorkspaceRequired -ResourceGroup $ResourceGroup -Name $WorkspaceName

    # 1. Action Group
    $agName = $script:LabActionGroupName
    $a = Invoke-LabAz -CliArgs @('monitor', 'action-group', 'show', '--resource-group', $ResourceGroup, '--name', $agName, '--query', '{id:id,tags:tags}', '--output', 'json')
    Stop-LabIfDenied -Result $a -Service 'monitor' -Action 'action-group show' -Step 'action-group show'
    $agId = $null
    $agReused = $false
    if ($a.ExitCode -eq 0) {
        $ag = ConvertFrom-LabJson -Text $a.Output
        $agId = "$($ag.id)"
        if (Test-LabTagged -Tags $ag.tags) {
            Write-LabInfo "Action Group '$agName' already exists with the lab tag."
            Add-LabManifestEntry -Type 'action-group' -Id "$ResourceGroup/$agName" -RunId $RunId -Ownership 'created'
        } else {
            $agReused = $true
            Write-LabInfo "Action Group '$agName' already exists and was not created by the lab. Reusing it as is: it is not tagged, edited or removed, and its receivers are unchanged."
            Add-LabManifestEntry -Type 'action-group' -Id "$ResourceGroup/$agName" -RunId $RunId -Ownership 'reused'
        }
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs (@('monitor', 'action-group', 'create', '--resource-group', $ResourceGroup, '--name', $agName, '--short-name', $script:LabActionGroupShort,
                '--action', 'email', 'lab-alert', $Email, '--tags') + (Get-LabTagArgs -RunId $RunId))
        Assert-LabAzOk -Result $c -Service 'monitor' -Action 'action-group create' -Failure 'Could not create the Action Group.'
        $agId = "/subscriptions/$(Get-LabSubscriptionId)/resourceGroups/$ResourceGroup/providers/microsoft.insights/actionGroups/$agName"
        Write-LabInfo "Created Action Group '$agName' (e-mail receiver). Check the inbox: Azure sends a confirmation message."
        Add-LabManifestEntry -Type 'action-group' -Id "$ResourceGroup/$agName" -RunId $RunId -Ownership 'created'
    }

    # 2. Log search alert rule
    $ruleName = $script:LabAlertRuleName
    $r = Invoke-LabAz -CliArgs @('monitor', 'scheduled-query', 'show', '--resource-group', $ResourceGroup, '--name', $ruleName, '--query', '{id:id,tags:tags}', '--output', 'json')
    Stop-LabIfDenied -Result $r -Service 'monitor' -Action 'scheduled-query show' -Step 'scheduled-query show'
    $ruleReused = $false
    if ($r.ExitCode -eq 0) {
        $rule = ConvertFrom-LabJson -Text $r.Output
        if (Test-LabTagged -Tags $rule.tags) {
            Write-LabInfo "Alert rule '$ruleName' already exists with the lab tag. Nothing to create."
            Add-LabManifestEntry -Type 'alert-rule' -Id "$ResourceGroup/$ruleName" -RunId $RunId -Ownership 'created'
        } else {
            $ruleReused = $true
            Write-LabInfo "Alert rule '$ruleName' already exists and was not created by the lab. Reusing it as is: it is not tagged, edited or removed."
            Add-LabManifestEntry -Type 'alert-rule' -Id "$ResourceGroup/$ruleName" -RunId $RunId -Ownership 'reused'
        }
    } else {
        $query = Get-LabQueryText -Name 'login-failure-bruteforce.kql'
        $c = Invoke-LabAz -Mutating -CliArgs (@('monitor', 'scheduled-query', 'create', '--resource-group', $ResourceGroup, '--name', $ruleName,
                '--scopes', "$($ws.id)", '--condition', "count 'bruteforce' > 0", '--condition-query', "bruteforce=$query",
                '--evaluation-frequency', '5m', '--window-duration', '10m', '--severity', '2',
                '--action-groups', $agId, '--description', 'Lab alert: 10 or more failed logins from one IP in one minute',
                '--skip-query-validation', 'true', '--tags') + (Get-LabTagArgs -RunId $RunId))
        Assert-LabAzOk -Result $c -Service 'monitor' -Action 'scheduled-query create' -Failure 'Could not create the alert rule.'
        Write-LabInfo "Created alert rule '$ruleName' (every 5 min over 10 min, severity 2)."
        Add-LabManifestEntry -Type 'alert-rule' -Id "$ResourceGroup/$ruleName" -RunId $RunId -Ownership 'created'
    }
    Write-Host ("Result actiongroup: {0} ({1})" -f $agName, $(if ($agReused) { 'reused, not created by the lab' } else { 'lab resource' }))
    Write-Host ("Result alertrule: {0} ({1})" -f $ruleName, $(if ($ruleReused) { 'reused, not created by the lab' } else { 'lab resource' }))
} finally {
    Clear-LabTempFiles
}
exit 0
