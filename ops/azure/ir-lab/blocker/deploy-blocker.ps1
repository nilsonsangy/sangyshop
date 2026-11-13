# Deploy the automatic IP blocker for the IR lab.
# Flow: log search alert -> Action Group -> Logic App (managed identity) -> NSG Deny rule.
#
# Creates / updates (idempotent, safe to re-run):
#   1. Logic App + system-assigned identity + "run failed" metric alert (logic-app.template.json)
#   2. Custom RBAC role (default name <app>-lab-nsg-blocker; securityRules read/write/delete only),
#      assignable ONLY on the lab NSG
#   3. Role assignment of that role to the Logic App identity, scoped to the lab NSG
#   4. Logic App receiver on the existing Action Group (created by detection/enable-alerts.ps1)
#
# Safety: dry-run by default. -Execute performs the changes. -WhatIf forces dry-run.
#         A dry-run makes no Azure calls.
#
# Usage:
#   .\deploy-blocker.ps1 -Subscription <id>
#   .\deploy-blocker.ps1 -Subscription <id> -Execute
#
# Resource group, NSG, Action Group, Logic App, role and receiver names default to the names of the
# VM lab (ops\azure\vm\VmNames.ps1 and the cloud config); every one can be overridden by a parameter.

param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$NsgName,
    [string]$NsgResourceGroup,      # defaults to -ResourceGroup
    [string]$ActionGroupName,
    [string]$ActionGroupResourceGroup, # defaults to -ResourceGroup
    [string]$Location,              # defaults to the resource group location
    [string]$LogicAppName,
    [string]$RoleName,
    [string]$ReceiverName,
    [string]$LabTag,
    [string]$RunId = 'manual',
    [switch]$Execute,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) { Write-Error $Message; exit 2 }

# Names and the lab tag come from the shared detection helpers (cloud config + VmNames).
. "$PSScriptRoot\..\detection\Detection-Common.ps1"
$ErrorActionPreference = 'Stop'
if (-not $ResourceGroup) { $ResourceGroup = $script:LabResourceGroup }
if (-not $NsgName) { $NsgName = $script:LabNsgName }
if (-not $ActionGroupName) { $ActionGroupName = $script:LabActionGroupName }
if (-not $LogicAppName) { $LogicAppName = $script:LabNsgBlockerName }
if (-not $RoleName) { $RoleName = $script:LabNsgBlockerName }
if (-not $ReceiverName) { $ReceiverName = $script:LabNsgBlockerName }
if (-not $LabTag) { $LabTag = $script:LabTagValue }

foreach ($p in 'Subscription', 'ResourceGroup', 'NsgName', 'ActionGroupName') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable $p).Value)) { Fail "Missing required parameter: -$p" }
}
if (-not $NsgResourceGroup) { $NsgResourceGroup = $ResourceGroup }
if (-not $ActionGroupResourceGroup) { $ActionGroupResourceGroup = $ResourceGroup }

$dryRun = (-not $Execute) -or $WhatIf
$nsgId = "/subscriptions/$Subscription/resourceGroups/$NsgResourceGroup/providers/Microsoft.Network/networkSecurityGroups/$NsgName"
$agId = "/subscriptions/$Subscription/resourceGroups/$ActionGroupResourceGroup/providers/microsoft.insights/actionGroups/$ActionGroupName"
$templateFile = Join-Path $PSScriptRoot 'logic-app.template.json'
$roleTemplate = Join-Path $PSScriptRoot 'policies\nsg-blocker.role.json'

function Invoke-Az {
    # Runs az and returns stdout; stops on a non-zero exit code.
    $out = & az @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed: $out" }
    return $out
}

Write-Host "Mode:        $(if ($dryRun) { 'dry-run (no Azure calls)' } else { 'execute' })"
Write-Host "Logic App:   $LogicAppName (resource group $ResourceGroup)"
Write-Host "Lab NSG:     $nsgId"
Write-Host "Action Group: $agId"
Write-Host 'Plan:'
Write-Host "  1. Deploy $templateFile (Logic App + managed identity + run-failed alert)"
Write-Host "  2. Create or update custom role '$RoleName' (assignable only on the lab NSG)"
Write-Host "  3. Assign '$RoleName' to the Logic App identity on the lab NSG"
Write-Host "  4. Add Logic App receiver '$ReceiverName' to the Action Group (common alert schema)"

if ($dryRun) {
    Write-Host 'Dry-run only. Re-run with -Execute to apply.'
    exit 0
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) { Fail 'Azure CLI (az) not found.' }
Invoke-Az account set --subscription $Subscription | Out-Null

if (-not $Location) { $Location = (Invoke-Az group show --name $ResourceGroup --query location -o tsv).Trim() }

# 1. Logic App
Write-Host '[1/4] Deploying Logic App...'
$deployment = Invoke-Az deployment group create --resource-group $ResourceGroup `
    --name "deploy-$LogicAppName" --template-file $templateFile `
    --parameters logicAppName=$LogicAppName location=$Location nsgResourceId=$nsgId `
    actionGroupResourceId=$agId labTag=$LabTag runId=$RunId blockRulePrefix=$script:LabBlockRulePrefix `
    --query 'properties.outputs' -o json | ConvertFrom-Json
$principalId = $deployment.principalId.value
$logicAppId = $deployment.logicAppResourceId.value

# 2. Custom role (created or updated in place)
Write-Host '[2/4] Creating or updating custom role...'
$roleJson = (Get-Content -Raw $roleTemplate).Replace('__NSG_RESOURCE_ID__', $nsgId).Replace('__ROLE_NAME__', $RoleName)
$existingRole = Invoke-Az role definition list --name $RoleName --custom-role-only true --query '[0].id' -o tsv
$roleFile = Join-Path ([IO.Path]::GetTempPath()) "role-$([guid]::NewGuid()).json"
try {
    if ($existingRole -and $existingRole.ToString().Trim()) {
        $obj = $roleJson | ConvertFrom-Json
        $obj | Add-Member -NotePropertyName id -NotePropertyValue $existingRole.ToString().Trim() -Force
        $obj | ConvertTo-Json -Depth 10 | Set-Content -Path $roleFile -Encoding utf8
        Invoke-Az role definition update --role-definition $roleFile | Out-Null
    } else {
        Set-Content -Path $roleFile -Value $roleJson -Encoding utf8
        Invoke-Az role definition create --role-definition $roleFile | Out-Null
    }
} finally {
    Remove-Item -Path $roleFile -Force -ErrorAction SilentlyContinue
}

# 3. Role assignment on the NSG only
Write-Host '[3/4] Assigning role on the lab NSG...'
$assigned = Invoke-Az role assignment list --assignee $principalId --role $RoleName --scope $nsgId --query 'length(@)' -o tsv
if ([int]$assigned -eq 0) {
    # The new identity can take a moment to replicate; retry a few times.
    $ok = $false
    foreach ($attempt in 1..6) {
        try {
            Invoke-Az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
                --role $RoleName --scope $nsgId | Out-Null
            $ok = $true; break
        } catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Seconds 10
        }
    }
} else {
    Write-Host '  Assignment already present, skipping.'
}

# 4. Wire the Action Group (the callback URL is a secret: it is never printed)
Write-Host '[4/4] Wiring the Action Group...'
$callback = (Invoke-Az rest --method post --url "$logicAppId/triggers/manual/listCallbackUrl?api-version=2016-06-01" --query value -o tsv).ToString().Trim()
$receivers = Invoke-Az monitor action-group show --name $ActionGroupName --resource-group $ActionGroupResourceGroup --query 'logicAppReceivers[].name' -o tsv
if ($receivers -and (@($receivers) -contains $ReceiverName)) {
    Invoke-Az monitor action-group update --name $ActionGroupName --resource-group $ActionGroupResourceGroup --remove-action $ReceiverName | Out-Null
}
Invoke-Az monitor action-group update --name $ActionGroupName --resource-group $ActionGroupResourceGroup `
    --add-action logicapp $ReceiverName $logicAppId $callback usecommonalertschema | Out-Null

Write-Host 'Blocker deployed.'
Write-Host "  Logic App:      $logicAppId"
Write-Host "  Identity:       $principalId"
Write-Host "  Role scope:     $nsgId"
