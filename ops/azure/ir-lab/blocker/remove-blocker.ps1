# Remove the automatic IP blocker and undo its blocks.
#
# Removes (idempotent, missing resources are skipped):
#   1. Logic App receiver from the Action Group
#   2. Role assignment on the lab NSG
#   3. Block rules '<app>-lab-block-*' in the lab NSG (skip with -KeepBlockRules)
#   4. Logic App and its run-failed alert (deleted via the resource group deployment resources)
#   5. Custom role definition (default name <app>-lab-nsg-blocker)
#
# Safety: dry-run by default. -Execute performs the changes. -WhatIf forces dry-run.
#         A dry-run makes no Azure calls.
#
# Usage:
#   .\remove-blocker.ps1 -Subscription <id>
#   .\remove-blocker.ps1 -Subscription <id> -Execute
#
# Names default to the names of the VM lab (ops\azure\vm\VmNames.ps1 and the cloud config);
# every one can be overridden by a parameter.

param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$NsgName,
    [string]$NsgResourceGroup,
    [string]$ActionGroupName,
    [string]$ActionGroupResourceGroup,
    [string]$LogicAppName,
    [string]$RoleName,
    [string]$ReceiverName,
    [switch]$KeepBlockRules,
    [switch]$Execute,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) { Write-Error $Message; exit 2 }

# Names come from the shared detection helpers (cloud config + VmNames).
. "$PSScriptRoot\..\detection\Detection-Common.ps1"
$ErrorActionPreference = 'Stop'
if (-not $ResourceGroup) { $ResourceGroup = $script:LabResourceGroup }
if (-not $NsgName) { $NsgName = $script:LabNsgName }
if (-not $ActionGroupName) { $ActionGroupName = $script:LabActionGroupName }
if (-not $LogicAppName) { $LogicAppName = $script:LabNsgBlockerName }
if (-not $RoleName) { $RoleName = $script:LabNsgBlockerName }
if (-not $ReceiverName) { $ReceiverName = $script:LabNsgBlockerName }

foreach ($p in 'Subscription', 'ResourceGroup', 'NsgName') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable $p).Value)) { Fail "Missing required parameter: -$p" }
}
if (-not $NsgResourceGroup) { $NsgResourceGroup = $ResourceGroup }
if (-not $ActionGroupResourceGroup) { $ActionGroupResourceGroup = $ResourceGroup }

$dryRun = (-not $Execute) -or $WhatIf
$nsgId = "/subscriptions/$Subscription/resourceGroups/$NsgResourceGroup/providers/Microsoft.Network/networkSecurityGroups/$NsgName"
$logicAppId = "/subscriptions/$Subscription/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$LogicAppName"
$alertId = "/subscriptions/$Subscription/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/metricAlerts/$LogicAppName-run-failed"
$blockPrefix = $script:LabBlockRulePrefix

function Invoke-Az {
    $out = & az @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed: $out" }
    return $out
}

Write-Host "Mode: $(if ($dryRun) { 'dry-run (no Azure calls)' } else { 'execute' })"
Write-Host 'Plan:'
if ($ActionGroupName) { Write-Host "  1. Remove Logic App receiver '$ReceiverName' from Action Group $ActionGroupName" }
else { Write-Host '  1. Skip Action Group (no -ActionGroupName given)' }
Write-Host "  2. Delete role assignment '$RoleName' on $nsgId"
if ($KeepBlockRules) { Write-Host "  3. Keep NSG rules '$blockPrefix*' (-KeepBlockRules)" }
else { Write-Host "  3. Delete NSG rules '$blockPrefix*' in $NsgName (undo IP blocks)" }
Write-Host "  4. Delete Logic App $LogicAppName and alert $LogicAppName-run-failed"
Write-Host "  5. Delete custom role definition '$RoleName'"

if ($dryRun) {
    Write-Host 'Dry-run only. Re-run with -Execute to apply.'
    exit 0
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) { Fail 'Azure CLI (az) not found.' }
Invoke-Az account set --subscription $Subscription | Out-Null

# 1. Action Group receiver
if ($ActionGroupName) {
    $receivers = Invoke-Az monitor action-group show --name $ActionGroupName --resource-group $ActionGroupResourceGroup --query 'logicAppReceivers[].name' -o tsv
    if ($receivers -and (@($receivers) -contains $ReceiverName)) {
        Invoke-Az monitor action-group update --name $ActionGroupName --resource-group $ActionGroupResourceGroup --remove-action $ReceiverName | Out-Null
        Write-Host '[1/5] Action Group receiver removed.'
    } else { Write-Host '[1/5] Action Group receiver not present, skipping.' }
}

# 2. Role assignments for the Logic App identity (looked up by role + scope)
$assignmentIds = Invoke-Az role assignment list --role $RoleName --scope $nsgId --query '[].id' -o tsv
if ($assignmentIds) {
    foreach ($id in @($assignmentIds)) { Invoke-Az role assignment delete --ids $id | Out-Null }
    Write-Host '[2/5] Role assignment(s) deleted.'
} else { Write-Host '[2/5] No role assignment found, skipping.' }

# 3. Block rules created by the Logic App (no lab block rule may remain)
if (-not $KeepBlockRules) {
    $rules = Invoke-Az network nsg rule list --nsg-name $NsgName --resource-group $NsgResourceGroup `
        --query "[?starts_with(name, '$blockPrefix')].name" -o tsv
    if ($rules) {
        foreach ($r in @($rules)) {
            Invoke-Az network nsg rule delete --nsg-name $NsgName --resource-group $NsgResourceGroup --name $r | Out-Null
        }
        Write-Host "[3/5] Deleted $(@($rules).Count) block rule(s)."
    } else { Write-Host '[3/5] No block rules found, skipping.' }
}

# 4. Logic App + failure alert
foreach ($rid in $alertId, $logicAppId) {
    $exists = Invoke-Az resource list --resource-group $ResourceGroup --query "[?id=='$rid'] | length(@)" -o tsv
    if ([int]$exists -gt 0) { Invoke-Az resource delete --ids $rid | Out-Null }
}
Write-Host '[4/5] Logic App and alert removed (if present).'

# 5. Custom role definition (after assignments are gone)
$roleId = Invoke-Az role definition list --name $RoleName --custom-role-only true --query '[0].id' -o tsv
if ($roleId -and $roleId.ToString().Trim()) {
    Invoke-Az role definition delete --name $RoleName | Out-Null
    Write-Host '[5/5] Custom role definition deleted.'
} else { Write-Host '[5/5] Custom role definition not found, skipping.' }

Write-Host 'Blocker removed.'
