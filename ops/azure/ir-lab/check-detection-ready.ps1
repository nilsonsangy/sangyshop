<#
.SYNOPSIS
    Read-only check that the Azure detection stack is ready before the simulated attack.

.DESCRIPTION
    Confirms four things, using only read calls (show, list) through Invoke-LabAz:
      1. workspace      the Log Analytics workspace of the lab exists
      2. action_group   the Action Group exists and has at least one enabled e-mail receiver
      3. alert_rule     the brute-force log search alert rule exists and is enabled
      4. alert_action   the alert rule notifies the Action Group
    Exit codes:
      0  all four checks passed. A local readiness stamp is written next to the lab manifest
         (readiness-<lab>.json: lab, region, check time in UTC and the four results, never an
         e-mail address). The attack script reads that file and nothing else.
      3  a read was denied. The message names the exact built-in role to assign.
      4  something is not ready. The message names the script that creates it. No stamp is
         written, and an older stamp is left untouched.
      2  configuration problem (missing -Subscription, unreadable cloud config).
    Nothing is created, changed or deleted. The script only prints the next step as text.

    Required Azure permissions: Reader on the lab resource group (the built-in Monitoring
    Reader role also covers the Action Group and alert rule reads).

.PARAMETER Subscription
    Subscription id or name (required, no default subscription is used).
.PARAMETER ResourceGroup
    Lab resource group. Defaults to the group derived from the cloud config.
.PARAMETER Region
    Lab region. Defaults to the location in the cloud config. It is recorded in the stamp.
.PARAMETER WorkspaceName
    Workspace name. Defaults to the name derived from the cloud config.

.EXAMPLE
    .\check-detection-ready.ps1 -Subscription 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$WorkspaceName
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
. (Join-Path $PSScriptRoot '..\..\lib\LabPermissions.ps1')
# The libraries turn strict mode on; this script reads optional CLI output.
Set-StrictMode -Off

Initialize-Lab -Subscription $Subscription -Region $Region
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { $ResourceGroup = $script:LabResourceGroup }
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) { $WorkspaceName = $script:LabWorkspaceName }
$null = Get-LabSubscriptionId

function Read-LabCheckJson {
    <# Runs one read call. Exits 3 when the read is denied. Returns $null for a missing or unreadable resource. #>
    param([string[]]$CliArgs, [string]$Service, [string]$Action)
    $r = Invoke-LabAz -CliArgs $CliArgs
    if ($r.ExitCode -eq 0) { return (ConvertFrom-LabJson -Text $r.Output) }
    if (Test-LabAccessDenied -Text $r.Output) {
        $hint = Get-LabPermissionHint -Cloud Azure -Service $Service -Action $Action
        Stop-LabForPermission -Hint $hint -Step 'check-detection-ready'
    }
    return $null
}

$lines = New-Object System.Collections.ArrayList
$checks = [ordered]@{ workspace = $false; action_group = $false; alert_rule = $false; alert_action = $false }

# 1. Workspace
$ws = Read-LabCheckJson -Service 'loganalytics' -Action 'workspace show' -CliArgs @(
    'monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName,
    '--query', '{id:id}', '--output', 'json')
if ($ws -and $ws.id) { $checks['workspace'] = $true }
else { [void]$lines.Add("workspace '$WorkspaceName' not found in '$ResourceGroup'. Run ops/azure/ir-lab/detection/enable-workspace.ps1.") }

# 2. Action Group (receiver status only, the address is never read back)
$agName = $script:LabActionGroupName
$ag = Read-LabCheckJson -Service 'monitor' -Action 'action-group show' -CliArgs @(
    'monitor', 'action-group', 'show', '--resource-group', $ResourceGroup, '--name', $agName,
    '--query', '{id:id,enabled:enabled,receivers:emailReceivers[].status}', '--output', 'json')
$agId = ''
if ($ag -and $ag.id) {
    $agId = "$($ag.id)"
    $enabledReceivers = @(@($ag.receivers) | Where-Object { $_ -and "$_" -ne 'Disabled' })
    $agEnabled = ($null -eq $ag.enabled) -or [bool]$ag.enabled
    if ($agEnabled -and $enabledReceivers.Count -gt 0) { $checks['action_group'] = $true }
    else { [void]$lines.Add("Action Group '$agName' has no enabled e-mail receiver. Run ops/azure/ir-lab/detection/enable-alerts.ps1.") }
} else {
    [void]$lines.Add("Action Group '$agName' not found. Run ops/azure/ir-lab/detection/enable-alerts.ps1.")
}

# 3 and 4. Alert rule and its action
$ruleName = $script:LabAlertRuleName
$rule = Read-LabCheckJson -Service 'monitor' -Action 'scheduled-query show' -CliArgs @(
    'monitor', 'scheduled-query', 'show', '--resource-group', $ResourceGroup, '--name', $ruleName,
    '--query', '{id:id,enabled:enabled,groups:actions.actionGroups}', '--output', 'json')
if ($rule -and $rule.id) {
    $ruleEnabled = ($null -eq $rule.enabled) -or [bool]$rule.enabled
    if ($ruleEnabled) { $checks['alert_rule'] = $true }
    else { [void]$lines.Add("Alert rule '$ruleName' is disabled. Run ops/azure/ir-lab/detection/enable-alerts.ps1 or enable the rule.") }
    $groups = @(@($rule.groups) | Where-Object { $_ })
    $linked = $false
    if ($groups.Count -gt 0) {
        if ($agId) { $linked = [bool]@($groups | Where-Object { "$_" -ieq $agId }).Count }
        else { $linked = $true }
    }
    if ($linked) { $checks['alert_action'] = $true }
    else { [void]$lines.Add("Alert rule '$ruleName' does not notify Action Group '$agName'. Run ops/azure/ir-lab/detection/enable-alerts.ps1.") }
} else {
    [void]$lines.Add("Alert rule '$ruleName' not found. Run ops/azure/ir-lab/detection/enable-alerts.ps1.")
}

foreach ($k in $checks.Keys) {
    $state = if ($checks[$k]) { 'OK     ' } else { 'MISSING' }
    Write-Host ("{0} {1}" -f $state, $k)
}

if ($lines.Count -gt 0) {
    foreach ($l in $lines) { Write-Host "BLOCKED: $l" -ForegroundColor Red }
    Write-Host 'The detection stack is not ready. No readiness stamp was written.'
    exit 4
}

# All four checks passed: write the local stamp (atomic replace, no e-mail address).
$stampDir = Split-Path -Parent (Get-LabManifestPath)
$stampPath = Join-Path $stampDir ("readiness-{0}.json" -f $script:LabTagValue)
$stamp = [ordered]@{
    schema      = 1
    lab         = $script:LabTagValue
    region      = $script:LabRegion
    checked_utc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    checks      = $checks
}
if (-not (Test-Path -LiteralPath $stampDir)) { New-Item -ItemType Directory -Path $stampDir -Force | Out-Null }
$tmp = "$stampPath.$([guid]::NewGuid().ToString('N')).tmp"
[System.IO.File]::WriteAllText($tmp, ($stamp | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath $tmp -Destination $stampPath -Force
Write-LabInfo 'Detection is ready. Readiness stamp written.'
Write-Host 'Next step: run the simulated attack (attack-simulation/attack.js).'
exit 0
