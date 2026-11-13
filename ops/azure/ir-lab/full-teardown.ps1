<#
.SYNOPSIS
    full Azure teardown: removes everything the Azure incident response lab created in an Azure subscription.

.DESCRIPTION
    One script that removes the whole Azure incident response laboratory. Discovery never uses typed names:
      - lab tag (lab=sangyshop-lab-azure): resource groups, resources, flow logs, soft-deleted
        Key Vaults and workspaces (az group list --tag, az resource list --tag).
      - lab manifest ($HOME/.sangyshop-lab/manifest-sangyshop-lab-azure.json, or -ManifestPath,
        or $env:LAB_MANIFEST_PATH): only for items that cannot carry tags (service principals,
        diagnostic settings, Defender plans, RBAC).
    A resource without lab tag that is not in the manifest is never removed. It is listed
    as Unmarked_Resource ("unmarked") and left unchanged.

    Removal order (reverse dependency):
      1  block              rules of the lab NSGs (attacker blocks, user ingress)
      2  blocker            blocker role assignment, Logic App, custom role
      3  credential-secrets secrets of the lab service principals (limits exposure early)
      4  sentinel           Microsoft Sentinel rules and onboarding, BEFORE the workspace
      5  flowlogs           VNet flow logs
      6  diagnostics        resource, Activity Log and Entra diagnostic settings
      7  defender           Defender for Cloud plans back to Free
      8  alerts             alert rules, then Action Groups
      9  workspace          Log Analytics workspace, permanent (forced) delete
      10 deploy             ops/azure/vm/teardown.ps1 (next to this folder) when it exists
      11 lab-group          Lab resource group (and every resource in it)
      12 resources          tagged resources outside a deletable group
      13 keyvault-purge     purge soft-deleted Key Vaults when purge protection allows
      14 evidence-preserve  with -PreserveEvidence: tag evidence=preserved and keep
      15 evidence-group     Evidence resource group (default: removed)
      16 keyvault-purge     again, for vaults in the evidence group
      17 service-principals role assignments, app and service principal, LAST

    When the VM teardown script exists, it also removes its own
    sp-lab-leaked service principal inside step 10. The final step then finds nothing
    left to remove for it.

    Evidence: removed by default. -PreserveEvidence keeps it (tag evidence=preserved) and
    prints the continuing monthly cost. Removing evidence that already has
    evidence=preserved needs -ConfirmPreservedEvidenceRemoval AND a second confirmation.
    A retention/immutability policy that blocks deletion is reported on stderr with the
    end date and the removal of the other resources continues; the exit code is 5.

    Modes: -WhatIf lists every item (type, id, scope) and the commands, changes nothing,
    exit 0. Without -NonInteractive the plan is shown and the operator must confirm.

    Exit codes: 0 success / nothing to do / simulation; 1 a resource could not be removed;
    2 invalid parameter; 3 credentials missing or expired; 5 cancelled, or only
    retention-blocked resources remain.

.PARAMETER Subscription
    Subscription id or name. Required, no default.
.PARAMETER Region
    Lab region (for example eastus). Required, no default.
.PARAMETER RunId
    Only remove items of this run-id. Default (or -AllRuns): every lab tag item.
.PARAMETER ManifestPath
    Lab manifest path (default: $HOME/.sangyshop-lab/manifest-sangyshop-lab-azure.json, or $env:LAB_MANIFEST_PATH).

.EXAMPLE
    .\full-teardown.ps1 -Subscription 00000000-0000-0000-0000-000000000000 -Region eastus -WhatIf

.EXAMPLE
    .\full-teardown.ps1 -Subscription 00000000-0000-0000-0000-000000000000 -Region eastus -PreserveEvidence
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$Region,
    [string]$RunId,
    [switch]$AllRuns,
    [switch]$NonInteractive,
    [switch]$PreserveEvidence,
    [switch]$ConfirmPreservedEvidenceRemoval,
    [string]$ManifestPath
)
. "$PSScriptRoot\Teardown-Common.ps1"

# Reference prices for the preserved-evidence estimate. Static estimates, NOT looked up at run time:
# confirm current prices at https://azure.microsoft.com/pricing/ before relying on them.
$script:EvidencePriceDate = '2026-11-11'
$script:EvidenceSnapshotUsdPerGbMonth = 0.05
$script:EvidenceBlobUsdPerGbMonth = 0.0184
$script:EvidenceBlobAssumedGb = 1
$script:UsdToBrl = 5.50

$script:StepOrder = @('block', 'blocker', 'credential-secrets', 'sentinel', 'flowlogs', 'diagnostics', 'defender', 'alerts',
    'workspace', 'deploy', 'lab-group', 'resources', 'keyvault-purge', 'evidence-preserve', 'evidence-group', 'keyvault-purge-2', 'service-principals')
$script:StepLabels = @{
    'block' = 'Block and ingress rules of lab NSGs'; 'blocker' = 'Automatic blocker (RBAC, Logic App, role)'
    'credential-secrets' = 'Service principal secrets'; 'sentinel' = 'Microsoft Sentinel (before the workspace)'
    'flowlogs' = 'VNet flow logs'; 'diagnostics' = 'Diagnostic settings'; 'defender' = 'Defender for Cloud plans'
    'alerts' = 'Alert rules and Action Groups'; 'workspace' = 'Log Analytics workspace (permanent delete)'
    'deploy' = 'VM deploy teardown'; 'lab-group' = 'Lab resource group'; 'resources' = 'Tagged resources outside deletable groups'
    'keyvault-purge' = 'Key Vault purge'; 'evidence-preserve' = 'Preserve evidence (tag evidence=preserved)'
    'evidence-group' = 'Evidence resource group'; 'keyvault-purge-2' = 'Key Vault purge (evidence group)'
    'service-principals' = 'Service principals, app registrations and their role assignments (last)'
}

# ---------------------------------------------------------------- seams and helpers
function Read-LabConfirmation {
    <# Returns the operator's answer. Tests set $global:LabConfirmHandler (scriptblock taking the prompt). #>
    param([string]$Prompt)
    if ($global:LabConfirmHandler) { return (& $global:LabConfirmHandler $Prompt) }
    return (Read-Host $Prompt)
}

function Invoke-LabChildScript {
    <# Runs the VM deploy teardown (ops\azure\vm\teardown.ps1). Tests set $global:LabChildHandler (scriptblock taking script path and run id). #>
    param([string]$ScriptPath, [string]$ChildRunId)
    if ($global:LabChildHandler) { return (& $global:LabChildHandler $ScriptPath $ChildRunId) }
    $exe = (Get-Process -Id $PID).Path
    $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
    if ($ChildRunId) { $childArgs += @('-RunId', $ChildRunId) }
    Write-Host ("+ " + $exe + ' ' + ($childArgs -join ' '))
    & $exe @childArgs
    return $LASTEXITCODE
}

function Write-LabStdErr {
    param([string]$Message)
    [Console]::Error.WriteLine((Protect-LabText -Text $Message))
}

function Get-DeleteRank {
    param([string]$Type)
    $t = "$Type".ToLowerInvariant()
    if ($t -like 'microsoft.compute/virtualmachines*') { return 0 }
    if ($t -like 'microsoft.dbforpostgresql/*' -or $t -like 'microsoft.web/*' -or $t -like 'microsoft.logic/*') { return 1 }
    if ($t -like 'microsoft.network/networkinterfaces' -or $t -like 'microsoft.network/loadbalancers' -or $t -like 'microsoft.network/natgateways' -or
        $t -like 'microsoft.network/applicationgateways' -or $t -like 'microsoft.network/bastionhosts' -or $t -like 'microsoft.network/azurefirewalls') { return 2 }
    if ($t -like 'microsoft.network/publicipaddresses') { return 3 }
    if ($t -like 'microsoft.compute/disks' -or $t -like 'microsoft.compute/snapshots') { return 4 }
    if ($t -like 'microsoft.network/networksecuritygroups' -or $t -like 'microsoft.network/virtualnetworks' -or $t -like 'microsoft.managedidentity/*') { return 8 }
    return 5
}

function New-PlanItem {
    param(
        [string]$Step, $Entry, [string[]]$Cli, [string[]]$Pre, [switch]$NoSubscription,
        [int]$Rank = 5, [string]$Scope = '', [string]$Note = '', [switch]$Covered, [string]$Id = '', [string]$Type = ''
    )
    $scopeText = $Scope
    if (-not $scopeText -and $Entry) { $scopeText = if ($Entry.Group) { "resource group $($Entry.Group)" } else { 'subscription' } }
    return [pscustomobject]@{
        Step = $Step; Entry = $Entry; Cli = $Cli; Pre = $Pre; NoSubscription = [bool]$NoSubscription; Rank = $Rank
        Type = $(if ($Type) { $Type } elseif ($Entry) { $Entry.Type } else { '' })
        Id = $(if ($Id) { $Id } elseif ($Entry) { $Entry.Id } else { '' })
        Scope = $scopeText; Source = $(if ($Entry) { $Entry.Source } else { 'tag' }); Note = $Note; Covered = [bool]$Covered
    }
}

function Build-Plan {
    <#
    .SYNOPSIS
        Turns an inventory into an ordered removal plan (pure: no Azure calls).
    .OUTPUTS
        @{ Items; Notes; Unmarked; Refused; RequiresPreservedConfirm; KeptEvidence; PlannedVaultNames }
    #>
    param($Inventory, [bool]$Preserve, [string]$ChildScript, [string]$ChildRunId)
    $items = New-Object System.Collections.ArrayList
    $notes = New-Object System.Collections.ArrayList
    $refused = New-Object System.Collections.ArrayList
    $kept = New-Object System.Collections.ArrayList
    $needConfirm = New-Object System.Collections.ArrayList

    $inv = @($Inventory)
    $unmarked = @($inv | Where-Object { $_.Source -eq 'unmarked' })
    $tagged = @($inv | Where-Object { $_.Source -ne 'unmarked' })
    $groups = @($tagged | Where-Object { $_.Kind -eq 'group' })
    $taggedIds = @{}
    foreach ($e in $tagged) { $taggedIds["$($e.Id)".ToLowerInvariant()] = $true }

    # Which groups can be deleted as a whole?
    $deleteGroups = @{}   # lower name -> entry
    $evidenceKept = @{}
    foreach ($g in $groups) {
        $evGroup = [bool]$g.Extra.Evidence
        $inside = @($unmarked | Where-Object {
                $_.Kind -eq 'resource' -and $_.Group -ieq $g.Name -and -not (
                    $_.Class -eq 'managed-disk' -and $_.Extra.ManagedBy -and $taggedIds.ContainsKey("$($_.Extra.ManagedBy)".ToLowerInvariant()))
            })
        if ($inside.Count -gt 0) {
            [void]$refused.Add([pscustomobject]@{ Group = $g.Name; Unmarked = $inside })
            continue
        }
        if ($evGroup) {
            $childPreserved = @($tagged | Where-Object { $_.Kind -eq 'resource' -and $_.Group -ieq $g.Name -and (Get-LabTagValue -Tags $_.Extra.Tags -Key 'evidence') -eq 'preserved' })
            $isPreserved = ($g.Extra.Preserved -or $childPreserved.Count -gt 0)
            if ($Preserve) { $evidenceKept[$g.Name.ToLowerInvariant()] = $g; continue }
            if ($isPreserved) { [void]$needConfirm.Add($g) }
        }
        $deleteGroups[$g.Name.ToLowerInvariant()] = $g
    }

    $plannedWorkspaces = @{}
    foreach ($e in $tagged) { if ($e.Kind -eq 'resource' -and $e.Type -ieq 'microsoft.operationalinsights/workspaces') { $plannedWorkspaces["$($e.Name)".ToLowerInvariant()] = $true } }

    $vaultNames = New-Object System.Collections.ArrayList
    foreach ($e in $tagged) {
        $gl = "$($e.Group)".ToLowerInvariant()
        $inKept = ($e.Group -and $evidenceKept.ContainsKey($gl))
        $inDeleted = ($e.Group -and $deleteGroups.ContainsKey($gl))
        switch ($e.Kind) {
            'nsg-rule' {
                if ($inKept) { break }
                [void]$items.Add((New-PlanItem -Step 'block' -Entry $e -Cli @('network', 'nsg', 'rule', 'delete', '--ids', $e.Id) -Note "rule of NSG $($e.Extra.Nsg)"))
            }
            'role-assignment' {
                [void]$items.Add((New-PlanItem -Step 'blocker' -Entry $e -Rank 0 -Scope $(if ($e.Extra.Scope) { $e.Extra.Scope } else { 'subscription' }) -Cli @('role', 'assignment', 'delete', '--ids', $e.Id)))
            }
            'role-definition' {
                $guid = "$($e.Id)" -replace '^.*/', ''
                [void]$items.Add((New-PlanItem -Step 'blocker' -Entry $e -Rank 2 -Scope 'subscription' -Cli @('role', 'definition', 'delete', '--name', $guid)))
            }
            'sp-secret' {
                [void]$items.Add((New-PlanItem -Step 'credential-secrets' -Entry $e -Scope 'Microsoft Entra ID' -NoSubscription -Cli @('ad', 'app', 'credential', 'delete', '--id', $e.Extra.AppId, '--key-id', $e.Extra.KeyId)))
            }
            'sentinel-rule' {
                $url = "https://management.azure.com$($e.Id)?api-version=$($script:LabSentinelApi)"
                [void]$items.Add((New-PlanItem -Step 'sentinel' -Entry $e -Rank 0 -NoSubscription -Cli @('rest', '--method', 'delete', '--url', $url)))
            }
            'sentinel-onboarding' {
                $url = "https://management.azure.com$($e.Id)?api-version=$($script:LabSentinelApi)"
                [void]$items.Add((New-PlanItem -Step 'sentinel' -Entry $e -Rank 1 -NoSubscription -Cli @('rest', '--method', 'delete', '--url', $url) -Note "Sentinel on workspace $($e.Extra.WorkspaceName)"))
            }
            'flowlog' {
                $loc = ConvertTo-LabRegionKey -Region $e.Location
                [void]$items.Add((New-PlanItem -Step 'flowlogs' -Entry $e -Scope "Network Watcher ($loc)" -Cli @('network', 'watcher', 'flow-log', 'delete', '--location', $loc, '--name', $e.Name)))
            }
            'res-diag' {
                [void]$items.Add((New-PlanItem -Step 'diagnostics' -Entry $e -Rank 0 -Scope $e.Extra.ResourceId -Cli @('monitor', 'diagnostic-settings', 'delete', '--name', $e.Name, '--resource', $e.Extra.ResourceId)))
            }
            'sub-diag' {
                [void]$items.Add((New-PlanItem -Step 'diagnostics' -Entry $e -Rank 1 -Cli @('monitor', 'diagnostic-settings', 'subscription', 'delete', '--name', $e.Name, '--yes')))
            }
            'entra-diag' {
                [void]$items.Add((New-PlanItem -Step 'diagnostics' -Entry $e -Rank 2 -Scope 'Microsoft Entra ID tenant' -NoSubscription -Cli @('rest', '--method', 'delete', '--url', $e.Extra.Url)))
            }
            'defender-plan' {
                [void]$items.Add((New-PlanItem -Step 'defender' -Entry $e -Cli @('security', 'pricing', 'create', '--name', $e.Name, '--tier', 'free') -Note "revert to Free (was $($e.Extra.Tier))"))
            }
            'deleted-workspace' {
                if ($e.Group) {
                    [void]$items.Add((New-PlanItem -Step 'workspace' -Entry $e -Rank 1 -Pre @('monitor', 'log-analytics', 'workspace', 'recover', '--resource-group', $e.Group, '--workspace-name', $e.Name) -Cli @('monitor', 'log-analytics', 'workspace', 'delete', '--resource-group', $e.Group, '--workspace-name', $e.Name, '--force', 'true', '--yes') -Note 'soft-deleted: recover, then permanent delete'))
                } else {
                    [void]$notes.Add("Soft-deleted workspace '$($e.Name)' has no resource group in its id; remove it manually (recover, then delete with --force).")
                }
            }
            'deleted-vault' {
                if ($e.Extra.PurgeProtected) {
                    [void]$notes.Add("Key Vault '$($e.Name)' is soft-deleted with purge protection and cannot be purged now. Azure removes it automatically at $($e.Extra.PurgeDate). The vault name stays reserved until then.")
                } else {
                    [void]$items.Add((New-PlanItem -Step 'keyvault-purge' -Entry $e -Scope "location $($e.Location)" -Cli @('keyvault', 'purge', '--name', $e.Name, '--location', "$($e.Location)", '--output', 'none')))
                    [void]$vaultNames.Add($e.Name)
                }
            }
            'sp-role-assignment' {
                [void]$items.Add((New-PlanItem -Step 'service-principals' -Entry $e -Rank 0 -Scope $(if ($e.Extra.Scope) { $e.Extra.Scope } else { 'subscription' }) -Cli @('role', 'assignment', 'delete', '--ids', $e.Id) -Note "role assignment of service principal $($e.Extra.AppId)"))
            }
            'sp' {
                [void]$items.Add((New-PlanItem -Step 'service-principals' -Entry $e -Rank 1 -Scope 'Microsoft Entra ID' -NoSubscription -Cli @('ad', 'sp', 'delete', '--id', $e.Extra.AppId)))
                [void]$items.Add((New-PlanItem -Step 'service-principals' -Entry $e -Rank 2 -Scope 'Microsoft Entra ID' -NoSubscription -Type 'Microsoft.Graph/applications' -Id $e.Extra.AppId -Cli @('ad', 'app', 'delete', '--id', $e.Extra.AppId) -Note 'app registration'))
            }
            'resource' {
                $t = "$($e.Type)".ToLowerInvariant()
                $explicitStep = $null; $rank = 5; $cli = @('resource', 'delete', '--ids', $e.Id)
                switch -Exact ($t) {
                    'microsoft.logic/workflows' { $explicitStep = 'blocker'; $rank = 1 }
                    'microsoft.insights/scheduledqueryrules' { $explicitStep = 'alerts'; $rank = 0 }
                    'microsoft.insights/metricalerts' { $explicitStep = 'alerts'; $rank = 0 }
                    'microsoft.insights/activitylogalerts' { $explicitStep = 'alerts'; $rank = 0 }
                    'microsoft.insights/actiongroups' { $explicitStep = 'alerts'; $rank = 1 }
                    'microsoft.operationalinsights/workspaces' {
                        $explicitStep = 'workspace'; $rank = 2
                        $cli = @('monitor', 'log-analytics', 'workspace', 'delete', '--resource-group', $e.Group, '--workspace-name', $e.Name, '--force', 'true', '--yes')
                    }
                    'microsoft.keyvault/vaults' { [void]$vaultNames.Add($e.Name) }
                }
                if ($e.Class -eq 'sentinel') {
                    $wsName = ("$($e.Name)" -replace '^SecurityInsights\((.*)\)$', '$1').ToLowerInvariant()
                    if ($plannedWorkspaces.ContainsKey($wsName)) { $explicitStep = $null; $cli = $null }
                }
                if ($inKept) { [void]$kept.Add($e); break }
                if ($explicitStep) {
                    [void]$items.Add((New-PlanItem -Step $explicitStep -Entry $e -Rank $rank -Cli $cli))
                    if ($inDeleted) {
                        # Also listed under its group as covered? No: explicit removal comes first.
                    }
                } elseif ($null -eq $cli) {
                    [void]$items.Add((New-PlanItem -Step 'workspace' -Entry $e -Covered -Note 'removed with its workspace'))
                } elseif ($inDeleted) {
                    $stepName = if ($deleteGroups[$gl].Extra.Evidence) { 'evidence-group' } else { 'lab-group' }
                    [void]$items.Add((New-PlanItem -Step $stepName -Entry $e -Covered -Rank 9 -Note "removed with group $($e.Group)"))
                } else {
                    [void]$items.Add((New-PlanItem -Step 'resources' -Entry $e -Rank (Get-DeleteRank -Type $e.Type) -Cli $cli))
                }
            }
        }
    }

    foreach ($g in $groups) {
        $gl = $g.Name.ToLowerInvariant()
        if ($deleteGroups.ContainsKey($gl)) {
            $stepName = if ($g.Extra.Evidence) { 'evidence-group' } else { 'lab-group' }
            [void]$items.Add((New-PlanItem -Step $stepName -Entry $g -Rank 10 -Scope 'subscription' -Cli @('group', 'delete', '--name', $g.Name, '--yes') -Note $(if ($g.Extra.Preserved) { 'evidence=preserved' } else { '' })))
        }
    }

    # Preserve evidence: tag the group and its evidence-bearing resources.
    foreach ($g in $evidenceKept.Values) {
        [void]$kept.Add($g)
        if (-not $g.Extra.Preserved) {
            [void]$items.Add((New-PlanItem -Step 'evidence-preserve' -Entry $g -Scope 'subscription' -Cli @('tag', 'update', '--resource-id', $g.Id, '--operation', 'Merge', '--tags', 'evidence=preserved') -Note 'tag evidence=preserved (kept)'))
        }
        foreach ($c in @($tagged | Where-Object { $_.Kind -eq 'resource' -and $_.Group -ieq $g.Name -and $_.Class -in @('storage-account', 'snapshot') })) {
            if ((Get-LabTagValue -Tags $c.Extra.Tags -Key 'evidence') -ne 'preserved') {
                [void]$items.Add((New-PlanItem -Step 'evidence-preserve' -Entry $c -Cli @('tag', 'update', '--resource-id', $c.Id, '--operation', 'Merge', '--tags', 'evidence=preserved') -Note 'tag evidence=preserved (kept)'))
            }
        }
    }

    # Deploy teardown (lower-level script) only while a deletable lab group still exists.
    $labGroups = @($deleteGroups.Values | Where-Object { -not $_.Extra.Evidence })
    if ($ChildScript -and $labGroups.Count -gt 0) {
        [void]$items.Add((New-PlanItem -Step 'deploy' -Entry $null -Type 'script' -Id $ChildScript -Scope 'ops/azure/vm' -Note 'VM deploy teardown (also removes sp-lab-leaked)'))
    }

    $sorted = @($items | Sort-Object -Property @{ Expression = { [array]::IndexOf($script:StepOrder, $_.Step) } }, Rank)
    return @{
        Items = $sorted; Notes = @($notes); Unmarked = $unmarked; Refused = @($refused)
        RequiresPreservedConfirm = @($needConfirm); KeptEvidence = @($kept); PlannedVaultNames = @($vaultNames)
        DeletedGroups = @($deleteGroups.Values)
    }
}

function Write-Plan {
    param($Plan, [bool]$Simulation)
    $items = @($Plan.Items)
    $count = @($items | Where-Object { -not $_.Covered }).Count
    $head = if ($Simulation) { 'Simulation (-WhatIf): these items WOULD be removed' } else { 'These items will be removed' }
    Write-Host ''
    Write-Host "== $head ($($items.Count) listed, $count removal action(s)) =="
    foreach ($step in $script:StepOrder) {
        $inStep = @($items | Where-Object { $_.Step -eq $step })
        if ($inStep.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ("[{0}] {1}" -f $step, $script:StepLabels[$step])
        foreach ($i in $inStep) {
            $extra = @("scope: $($i.Scope)", "source: $($i.Source)")
            if ($i.Note) { $extra += $i.Note }
            Write-Host ("  - {0}  {1}  ({2})" -f $i.Type, $i.Id, ($extra -join '; '))
        }
    }
    Write-Host ''
    $vaultText = 'none'
    if (@($Plan.PlannedVaultNames).Count -gt 0) { $vaultText = (@($Plan.PlannedVaultNames) | Select-Object -Unique) -join ', ' }
    Write-Host "[keyvault-purge] Key Vaults are purged after the resource group delete when purge protection allows (names: $vaultText)"
    foreach ($n in @($Plan.Notes)) { Write-Host "  NOTE: $n" }
    foreach ($r in @($Plan.Refused)) {
        Write-Host "  REFUSED: resource group '$($r.Group)' contains resources without lab tag, so it will NOT be deleted as a whole:"
        foreach ($u in @($r.Unmarked)) { Write-Host "    - $($u.Type)  $($u.Id)  (unmarked)" }
    }
    Write-Host ''
}

function Get-RetentionEnd {
    <# Best effort end date of blob immutability in a storage account. Returns text ('unknown' when it cannot be read). #>
    param([string]$Account, [string]$Group)
    $latest = $null
    $containers = @(Get-LabList -Label "containers of $Account" -CliArgs @('storage', 'container', 'list', '--account-name', $Account, '--auth-mode', 'login', '--query', '[].name', '--output', 'json'))
    foreach ($c in ($containers | Select-Object -First 20)) {
        $q = Invoke-LabAz -CliArgs @('storage', 'blob', 'list', '--account-name', $Account, '--container-name', "$c", '--auth-mode', 'login', '--include', 'i', '--query', 'max_by([?properties.immutabilityPolicy.expiryTime!=null], &properties.immutabilityPolicy.expiryTime).properties.immutabilityPolicy.expiryTime', '--output', 'tsv')
        if ($q.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace("$($q.Output)")) {
            $d = [datetime]::MinValue
            if ([datetime]::TryParse("$($q.Output)".Trim(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
                if ($null -eq $latest -or $d -gt $latest) { $latest = $d }
            }
        }
    }
    if ($latest) { return $latest.ToString('yyyy-MM-dd') }
    return 'unknown (check the immutability policy of each container)'
}

function Get-PurgeCandidates {
    <# Soft-deleted vaults that belong to the lab: tagged, or named like a tagged vault of this run. #>
    param([string[]]$PlannedNames, [string]$RunId)
    $out = @()
    $dvs = @(Get-LabList -Label 'soft-deleted Key Vaults' -CliArgs @('keyvault', 'list-deleted', '--resource-type', 'vault', '--query', '[].{name:name,location:properties.location,purge:properties.purgeProtectionEnabled,purgeDate:properties.scheduledPurgeDate,tags:properties.tags}', '--output', 'json'))
    foreach ($v in $dvs) {
        $ok = (Test-LabTagged -Tags $v.tags)
        if ($ok -and $RunId -and (Get-LabTagValue -Tags $v.tags -Key 'run-id') -ne $RunId) { $ok = $false }
        if (-not $ok -and $v.tags -eq $null -and ($PlannedNames -contains "$($v.name)")) { $ok = $true }
        if ($ok) { $out += $v }
    }
    return $out
}

# ---------------------------------------------------------------- execution engine
$script:Results = @{ Removed = New-Object System.Collections.ArrayList; Failed = New-Object System.Collections.ArrayList; Retention = New-Object System.Collections.ArrayList; Notes = New-Object System.Collections.ArrayList }

function Invoke-RemovalCommand {
    <# Returns 'ok', 'gone', 'simulated', 'retention' or 'failed'. Output text is stored in $script:LastOutput. #>
    param([string[]]$CliArgs, [bool]$NoSub)
    $r = Invoke-LabAz -Mutating -NoSubscription:$NoSub -CliArgs $CliArgs
    $script:LastOutput = "$($r.Output)"
    if ($r.PSObject.Properties['Skipped'] -and $r.Skipped) { return 'simulated' }
    if ($r.ExitCode -eq 0) { return 'ok' }
    if (Test-LabNotFound -Text $r.Output) { return 'gone' }
    if ("$($r.Output)" -match '(?i)immutab|legal\s*hold|time-based retention|retention polic|ContainerHasImmutab|BlobsUnderRetention') { return 'retention' }
    return 'failed'
}

function Invoke-PlanItem {
    param($Item)
    if ($Item.Covered) { return }
    $label = "$($Item.Type) $($Item.Id)"
    if ($Item.Step -eq 'deploy') {
        if ($WhatIfPreference) { Write-Host "What if: run $($Item.Id)"; return }
        $code = Invoke-LabChildScript -ScriptPath $Item.Id -ChildRunId $runFilter
        if ($code -ne 0) { [void]$script:Results.Failed.Add("$label (deploy teardown exited with code $code)"); return }
        [void]$script:Results.Removed.Add($label)
        return
    }
    if ($Item.Pre) {
        $p = Invoke-RemovalCommand -CliArgs $Item.Pre -NoSub $Item.NoSubscription
        if ($p -eq 'failed' -or $p -eq 'retention') { [void]$script:Results.Failed.Add("$label (recover failed)"); return }
        if ($p -eq 'gone') { [void]$script:Results.Removed.Add("$label (already absent)"); return }
    }
    $res = Invoke-RemovalCommand -CliArgs $Item.Cli -NoSub $Item.NoSubscription
    switch ($res) {
        'simulated' { }
        'ok' { [void]$script:Results.Removed.Add($label) }
        'gone' { [void]$script:Results.Removed.Add("$label (already absent)") }
        'retention' {
            $accts = @()
            if ($Item.Entry -and $Item.Entry.Kind -eq 'group') { $accts = @($script:CurrentInventory | Where-Object { $_.Kind -eq 'resource' -and $_.Class -eq 'storage-account' -and $_.Group -ieq $Item.Entry.Name }) }
            elseif ($Item.Entry -and $Item.Entry.Class -eq 'storage-account') { $accts = @($Item.Entry) }
            if ($accts.Count -eq 0) {
                Write-LabStdErr ("Error: cannot remove $label because an immutability or retention policy blocks the deletion. Repeat full-teardown.ps1 after the retention ends.")
            }
            foreach ($a in $accts) {
                $end = Get-RetentionEnd -Account $a.Name -Group $a.Group
                Write-LabStdErr ("Error: cannot remove storage account '$($a.Name)' (resource group '$($a.Group)'): an immutability or retention policy blocks the deletion until $end. Repeat full-teardown.ps1 after that date.")
            }
            [void]$script:Results.Retention.Add($Item)
        }
        default {
            $first = (("$script:LastOutput" -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
            Write-LabStdErr "Error: could not remove $label. $first"
            [void]$script:Results.Failed.Add($label)
        }
    }
}

function Invoke-VaultPurgeStep {
    param([string[]]$PlannedNames, [string]$RunId)
    $cands = @(Get-PurgeCandidates -PlannedNames $PlannedNames -RunId $RunId)
    if ($cands.Count -eq 0) { Write-LabInfo 'No soft-deleted lab Key Vault to purge.'; return }
    foreach ($v in $cands) {
        if ("$($v.purge)" -match '^(?i:true)$') {
            $msg = "Key Vault '$($v.name)' has purge protection enabled and cannot be purged now; Azure removes it automatically at $($v.purgeDate). The name stays reserved until then."
            Write-LabWarn $msg
            [void]$script:Results.Notes.Add($msg)
            continue
        }
        $it = New-PlanItem -Step 'keyvault-purge' -Entry (New-LabEntry -Kind 'deleted-vault' -Type 'Microsoft.KeyVault/deletedVaults' -Id "$($v.name)" -Name "$($v.name)" -Location "$($v.location)") -Scope "location $($v.location)" -Cli @('keyvault', 'purge', '--name', "$($v.name)", '--location', "$($v.location)", '--output', 'none')
        Invoke-PlanItem -Item $it
    }
}

function Get-EvidenceCostEstimate {
    param($Groups, $Inventory)
    $snapGb = 0
    foreach ($g in $Groups) {
        $sizes = @(Get-LabList -Label "snapshots in $($g.Name)" -CliArgs @('snapshot', 'list', '--resource-group', $g.Name, '--query', '[].diskSizeGb', '--output', 'json'))
        foreach ($s in $sizes) { $snapGb += [double]$s }
    }
    $accounts = 0
    foreach ($g in $Groups) { $accounts += @($Inventory | Where-Object { $_.Kind -eq 'resource' -and $_.Class -eq 'storage-account' -and $_.Group -ieq $g.Name }).Count }
    $usd = ($snapGb * $script:EvidenceSnapshotUsdPerGbMonth) + ($accounts * $script:EvidenceBlobAssumedGb * $script:EvidenceBlobUsdPerGbMonth)
    return @{ SnapshotGb = $snapGb; Accounts = $accounts; Usd = [math]::Round($usd, 2); Brl = [math]::Round($usd * $script:UsdToBrl, 2) }
}

# ---------------------------------------------------------------- main
$prevManifestEnv = $env:LAB_MANIFEST_PATH
try {
    Initialize-Lab -Subscription $Subscription -Region $Region
    if ($RunId -and $AllRuns) { Stop-Lab -Code 2 -Message 'Use either -RunId or -AllRuns, not both.' }
    if ($RunId -and $RunId -notmatch '^[0-9A-Za-z._-]{1,64}$') { Stop-Lab -Code 2 -Message "Invalid -RunId '$RunId'." }
    if ($ManifestPath) { $env:LAB_MANIFEST_PATH = $ManifestPath }
    $wi = [bool]$WhatIfPreference
    $runFilter = if ($RunId) { $RunId.Trim() } else { '' }

    Write-LabInfo ("full Azure teardown for tag $($script:LabTagKey)=$($script:LabTagValue) in $($script:LabRegion)" + $(if ($runFilter) { ", run-id $runFilter" } else { ' (all runs)' }) + $(if ($wi) { ' [simulation]' } else { '' }))
    $null = Get-LabSubscriptionId   # exit 3 when the login is missing or expired

    if (-not (Test-Path -LiteralPath (Get-LabManifestPath))) {
        Write-LabInfo "Lab manifest not found at $(Get-LabManifestPath). Only lab tag discovery applies; settings without tags (service principals, diagnostic settings, Defender plans) cannot be discovered."
    }

    # Deploy teardown script: ops\azure\vm\teardown.ps1, located relative to this script.
    $childScript = [System.IO.Path]::GetFullPath((Join-Path (Join-Path $PSScriptRoot '..\vm') 'teardown.ps1'))
    if (-not (Test-Path -LiteralPath $childScript)) {
        Write-LabInfo "VM teardown script not found at '$childScript'. The tagged sweep removes the deploy resources anyway."
        $childScript = ''
    }

    $script:CurrentInventory = @(Get-LabInventory -Region $script:LabRegion -RunId $runFilter -IncludeUnmarked)
    if ($script:LabInventoryErrors.Count -gt 0) {
        foreach ($e in $script:LabInventoryErrors) { Write-LabStdErr "Error: discovery failed: $e" }
        Stop-Lab -Code 1 -Message 'Discovery was incomplete, so nothing was removed. Fix the error above (login, permissions) and run again.'
    }

    # Never delete the credential that runs this script.
    $who = Invoke-LabAz -CliArgs @('account', 'show', '--query', 'user.name', '--output', 'tsv')
    $whoName = "$($who.Output)".Trim()
    foreach ($e in @($script:CurrentInventory | Where-Object { $_.Kind -eq 'sp' -and $_.Source -ne 'unmarked' })) {
        if ($whoName -and ($whoName -ieq "$($e.Extra.AppId)" -or $whoName -ieq "$($e.Id)")) {
            Stop-Lab -Code 2 -Message "The Azure CLI is signed in as the lab service principal '$($e.Name)', which this script would delete. Sign in as the operator ('az login') and run again. No changes were made."
        }
    }

    $plan = Build-Plan -Inventory $script:CurrentInventory -Preserve ([bool]$PreserveEvidence) -ChildScript $childScript -ChildRunId $runFilter

    # Preserved evidence needs the extra, distinct confirmation.
    $preservedGroups = @($plan.RequiresPreservedConfirm)
    if ($preservedGroups.Count -gt 0) {
        $names = ($preservedGroups | ForEach-Object { $_.Name }) -join ', '
        if ($wi) {
            Write-LabWarn "Evidence group(s) $names carry evidence=preserved. A real run needs -ConfirmPreservedEvidenceRemoval plus a second confirmation to remove them."
        } elseif (-not $ConfirmPreservedEvidenceRemoval) {
            Write-LabStdErr "Error: evidence group(s) $names carry evidence=preserved. Removing preserved evidence needs -ConfirmPreservedEvidenceRemoval (and a second confirmation). Use -PreserveEvidence to keep it. No changes were made."
            exit 5
        }
    }

    $actionable = @($plan.Items | Where-Object { -not $_.Covered })
    $unmarkedCount = @($plan.Unmarked).Count

    function Write-UnmarkedReport {
        param($Plan)
        if (@($Plan.Unmarked).Count -eq 0) { return }
        Write-Host ''
        Write-Host 'Unmarked_Resource (no lab tag, not in the manifest): left UNCHANGED. Decide manually:'
        foreach ($u in @($Plan.Unmarked)) { Write-Host ("  - {0}  {1}  (scope: {2})" -f $u.Type, $u.Id, $(if ($u.Group) { "resource group $($u.Group)" } else { 'subscription' })) }
    }

    function Write-ReusedReport {
        # Resources the lab found already in place and recorded as reused: never removed.
        $reused = @(Get-LabReusedManifestEntries -RunId $runFilter)
        if ($reused.Count -eq 0) { return }
        Write-Host ''
        Write-Host 'Reused resources (recorded in the manifest, left in place):'
        foreach ($u in $reused) { Write-Host ("  - {0}  {1}  (kept (not created by the lab))" -f $u.type, $u.id) }
    }
    Write-ReusedReport

    if ($PreserveEvidence -and @($plan.KeptEvidence).Count -gt 0) {
        $kg = @($plan.KeptEvidence | Where-Object { $_.Kind -eq 'group' })
        $c = Get-EvidenceCostEstimate -Groups $kg -Inventory $script:CurrentInventory
        Write-Host ''
        Write-Host ("Evidence is KEPT (-PreserveEvidence) and keeps costing every month: about USD {0:N2} / BRL {1:N2} per month (price date {2}; snapshots {3} GB, {4} storage account(s), blob capacity assumed {5} GB each, USD 1 = BRL {6}). Estimate only: confirm at https://azure.microsoft.com/pricing/. Remove it later with this script without -PreserveEvidence." -f $c.Usd, $c.Brl, $script:EvidencePriceDate, $c.SnapshotGb, $c.Accounts, $script:EvidenceBlobAssumedGb, $script:UsdToBrl)
    }

    if ($actionable.Count -eq 0) {
        Write-Plan -Plan $plan -Simulation $wi
        Write-UnmarkedReport -Plan $plan
        if ($wi) { Write-LabInfo 'Simulation complete: 0 changes made. No lab resources remain.'; exit 0 }
        # Prune stale manifest records (resources are confirmed gone) unless evidence is kept.
        if (@($plan.KeptEvidence).Count -eq 0) {
            $stale = @(Get-LabManifestEntries -RunId $runFilter)
            if ($stale.Count -gt 0) {
                $keep = @(Read-LabManifest | Where-Object { $m = $_; -not ($stale | Where-Object { $_.type -eq $m.type -and $_.id -eq $m.id }) })
                Write-LabManifest -Entries $keep
            }
        }
        foreach ($n in @($plan.Notes)) { Write-LabWarn $n }
        Write-Host 'No lab resources remain. Nothing to remove.'
        if ($unmarkedCount -gt 0) { Write-LabInfo 'Run verify-zero-cost.ps1 to review the unmarked resources.' }
        exit 0
    }

    Write-Plan -Plan $plan -Simulation $wi
    Write-UnmarkedReport -Plan $plan

    if ($wi) {
        Write-Host 'Commands that would run:'
    } elseif (-not $NonInteractive) {
        $ans = Read-LabConfirmation -Prompt "Type 'yes' to remove the $($actionable.Count) item(s) above from subscription $($script:LabSubscriptionId)"
        if ("$ans".Trim() -ne 'yes') {
            Write-Host 'Cancelled by the operator. No changes were made.'
            exit 5
        }
        if ($preservedGroups.Count -gt 0) {
            $ans2 = Read-LabConfirmation -Prompt "Second confirmation: evidence marked evidence=preserved will be PERMANENTLY deleted. Type 'delete preserved evidence' to continue"
            if ("$ans2".Trim() -ne 'delete preserved evidence') {
                Write-Host 'Cancelled by the operator. Preserved evidence and every other resource were left unchanged.'
                exit 5
            }
        }
    }

    # Execute step by step.
    foreach ($step in $script:StepOrder) {
        if ($step -eq 'keyvault-purge' -or $step -eq 'keyvault-purge-2') {
            if ($step -eq 'keyvault-purge-2' -and @($plan.DeletedGroups | Where-Object { $_.Extra.Evidence }).Count -eq 0) { continue }
            Write-Host ''
            Write-LabInfo "=== $($script:StepLabels[$step]) ==="
            if ($wi) {
                foreach ($v in @($plan.PlannedVaultNames)) { Write-Host "What if: az keyvault purge --name $v (only if the vault is soft-deleted and purge protection is off)" }
                continue
            }
            Invoke-VaultPurgeStep -PlannedNames @($plan.PlannedVaultNames) -RunId $runFilter
            continue
        }
        $stepItems = @($plan.Items | Where-Object { $_.Step -eq $step -and -not $_.Covered })
        if ($stepItems.Count -eq 0) { continue }
        Write-Host ''
        Write-LabInfo "=== $($script:StepLabels[$step]) ==="
        foreach ($it in $stepItems) { Invoke-PlanItem -Item $it }
    }

    if ($wi) {
        Write-Host ''
        Write-LabInfo 'Simulation complete: 0 changes made.'
        exit 0
    }

    # Remove manifest records of what was removed, then re-discover.
    foreach ($it in @($plan.Items | Where-Object { -not $_.Covered -and $_.Entry -and $_.Entry.Source -eq 'manifest' })) {
        $mt = $it.Entry.Extra.ManifestType
        if (-not $mt) { $mt = switch ($it.Entry.Kind) { 'sub-diag' { 'diagnostic-setting-subscription' } 'res-diag' { 'diagnostic-setting' } 'entra-diag' { 'diagnostic-setting-entra' } 'defender-plan' { 'defender-plan' } 'sp' { 'ad:service-principal' } default { '' } } }
        if ($mt -and ($script:Results.Removed -contains "$($it.Type) $($it.Id)" -or $script:Results.Removed -contains "$($it.Type) $($it.Id) (already absent)")) {
            Remove-LabManifestEntry -Type $mt -Id $it.Entry.Id
            if ($it.Entry.Kind -eq 'sp') { Remove-LabManifestEntry -Type 'ad:service-principal' -Id $it.Entry.Id }
        }
    }

    Write-Host ''
    Write-LabInfo '=== Verifying what remains ==='
    $script:CurrentInventory = @(Get-LabInventory -Region $script:LabRegion -RunId $runFilter -IncludeUnmarked)
    $plan2 = Build-Plan -Inventory $script:CurrentInventory -Preserve ([bool]$PreserveEvidence) -ChildScript '' -ChildRunId $runFilter
    $remaining = @($plan2.Items | Where-Object { $_.Step -notin @('evidence-preserve', 'deploy') -and ($_.Cli -or $_.Covered) })
    $remainingKeep = @($plan2.Items | Where-Object { $_.Step -eq 'evidence-preserve' })

    foreach ($n in @($script:Results.Notes)) { Write-Host "  NOTE: $n" }
    if ($script:Results.Removed.Count -gt 0) {
        Write-Host 'Removed:'
        foreach ($r in $script:Results.Removed) { Write-Host "  - $r" }
    }
    Write-UnmarkedReport -Plan $plan2

    $retentionGroups = @($script:Results.Retention | ForEach-Object { if ($_.Entry.Kind -eq 'group') { $_.Entry.Name } else { $_.Entry.Group } })
    $unexplained = @($remaining | Where-Object { -not ($_.Entry -and ($retentionGroups -contains $_.Entry.Group -or $retentionGroups -contains $_.Entry.Name)) })

    if ($remaining.Count -eq 0 -and $script:Results.Failed.Count -eq 0 -and $script:Results.Retention.Count -eq 0) {
        if (@($plan2.KeptEvidence).Count -eq 0) {
            $stale = @(Get-LabManifestEntries -RunId $runFilter)
            if ($stale.Count -gt 0) {
                $keep = @(Read-LabManifest | Where-Object { $m = $_; -not ($stale | Where-Object { $_.type -eq $m.type -and $_.id -eq $m.id }) })
                Write-LabManifest -Entries $keep
            }
        }
        Write-Host 'Teardown complete: no lab resources remain.'
        exit 0
    }

    Write-LabStdErr 'Teardown finished but these resources remain:'
    foreach ($r in $remaining) { Write-LabStdErr ("  - {0}  {1}" -f $r.Type, $r.Id) }
    foreach ($f in $script:Results.Failed) { Write-LabStdErr ("  - failed: {0}" -f $f) }
    Write-LabStdErr 'Run full-teardown.ps1 again to retry. Removed resources are skipped.'
    if ($script:Results.Failed.Count -eq 0 -and $script:Results.Retention.Count -gt 0 -and $unexplained.Count -eq 0) { exit 5 }
    exit 1
} finally {
    $env:LAB_MANIFEST_PATH = $prevManifestEnv
    Clear-LabTempFiles
}
