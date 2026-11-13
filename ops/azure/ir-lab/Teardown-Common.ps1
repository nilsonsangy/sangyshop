<#
.SYNOPSIS
    Shared inventory (discovery) for full-teardown.ps1 and verify-zero-cost.ps1.

.DESCRIPTION
    Dot-source it:
        . "$PSScriptRoot\Teardown-Common.ps1"

    It builds ONE flat inventory of everything the Azure incident response lab can have left in a
    subscription. Discovery is read-only and never uses hand-typed resource names:
      - lab tag (lab=sangyshop-lab-azure): resource groups, resources, flow logs,
        soft-deleted Key Vaults and soft-deleted workspaces.
      - lab manifest: only for settings that cannot carry tags (diagnostic settings,
        Defender plans, Sentinel, service principals, RBAC).
      - Derived from tagged scopes: custom roles whose assignable scopes are all
        inside a tagged resource group (the blocker role) and their assignments.
    Resources of a billable class that have no lab tag and are not in the manifest
    are returned with Source 'unmarked' (Unmarked_Resource). They are only ever
    reported, never removed.

    Every Azure call goes through Invoke-LabAz (Detection-Common.ps1), so tests can
    set $global:LabAzHandler and no real Azure call is made.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

# Detection-Common also loads the shared ops libraries (Hide-LabSecrets, config, names).
. "$PSScriptRoot\detection\Detection-Common.ps1"

function Protect-LabText {
    <# Masks secret-looking values in text that is about to be printed. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if (Get-Command Hide-LabSecrets -ErrorAction SilentlyContinue) { return (Hide-LabSecrets -Text $Text) }
    return $Text
}

# Billable (or credential) risk classes the lab can leave behind, keyed by lower-case resource type.
$script:LabResourceClasses = @{
    'microsoft.compute/virtualmachines'            = 'virtual-machine'
    'microsoft.compute/disks'                      = 'managed-disk'
    'microsoft.compute/snapshots'                  = 'snapshot'
    'microsoft.network/publicipaddresses'          = 'public-ip'
    'microsoft.network/natgateways'                = 'nat-gateway'
    'microsoft.network/loadbalancers'              = 'load-balancer'
    'microsoft.network/applicationgateways'        = 'application-gateway'
    'microsoft.network/bastionhosts'               = 'azure-bastion'
    'microsoft.network/azurefirewalls'             = 'azure-firewall'
    'microsoft.dbforpostgresql/flexibleservers'    = 'postgresql-flexible-server'
    'microsoft.storage/storageaccounts'            = 'storage-account'
    'microsoft.keyvault/vaults'                    = 'key-vault'
    'microsoft.operationalinsights/workspaces'     = 'log-analytics-workspace'
    'microsoft.insights/actiongroups'              = 'action-group'
    'microsoft.insights/scheduledqueryrules'       = 'alert-rule'
    'microsoft.insights/metricalerts'              = 'alert-rule'
    'microsoft.insights/activitylogalerts'         = 'alert-rule'
    'microsoft.logic/workflows'                    = 'logic-app'
    'microsoft.web/sites'                          = 'function-app'
    'microsoft.network/networkwatchers/flowlogs'   = 'vnet-flow-log'
}

# Manifest types that authorise removing something that cannot carry a tag.
$script:LabManifestSettingTypes = @(
    'diagnostic-setting-subscription', 'diagnostic-setting', 'diagnostic-setting-entra',
    'monitor:subscription-diagnostic-setting', 'defender-plan', 'security:pricing-plan',
    'network-watcher:flow-log', 'ad:service-principal', 'ad:secret',
    'rbac:role-assignment', 'azure:role-assignment', 'rbac:role-definition', 'azure:role-definition'
)

$script:LabInventoryErrors = New-Object System.Collections.ArrayList

function ConvertTo-LabArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Get-LabResourceClass {
    <# Risk class of a resource (type + name), or '' when the type is not a risk class. #>
    param([string]$Type, [string]$Name = '')
    $t = "$Type".ToLowerInvariant()
    if ($t -eq 'microsoft.operationsmanagement/solutions' -and "$Name" -like 'SecurityInsights(*') { return 'sentinel' }
    if ($script:LabResourceClasses.ContainsKey($t)) { return $script:LabResourceClasses[$t] }
    return ''
}

function Get-LabTagValue {
    param($Tags, [string]$Key)
    if ($null -eq $Tags) { return $null }
    $p = $Tags.PSObject.Properties[$Key]
    if ($p) { return "$($p.Value)" }
    return $null
}

function ConvertTo-LabRegionKey {
    param([string]$Region)
    return (("$Region" -replace '\s', '').ToLowerInvariant())
}

function New-LabEntry {
    param(
        [string]$Kind, [string]$Type, [string]$Id, [string]$Name,
        [string]$Group = '', [string]$Location = '', [string]$Source = 'tag',
        [string]$Class = '', [hashtable]$Extra = @{}, [string]$RunId = ''
    )
    return [pscustomobject]@{
        Kind = $Kind; Type = $Type; Id = $Id; Name = $Name; Group = $Group; Location = $Location
        Source = $Source; Class = $Class; Extra = $Extra; RunId = $RunId
    }
}

function Get-LabList {
    <# Runs a read-only JSON query. Returns @() on failure; unexpected failures are recorded in LabInventoryErrors. #>
    param([string[]]$CliArgs, [string]$Label, [switch]$NoSubscription)
    $r = Invoke-LabAz -CliArgs $CliArgs -NoSubscription:$NoSubscription
    if ($r.ExitCode -ne 0) {
        if (-not (Test-LabNotFound -Text $r.Output)) {
            $first = (("$($r.Output)" -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
            [void]$script:LabInventoryErrors.Add("${Label}: $(Protect-LabText -Text $first)")
        }
        return @()
    }
    $obj = ConvertFrom-LabJson -Text $r.Output
    if ($null -eq $obj) { return @() }
    return @($obj)
}

function Test-LabRemoteExists {
    <# $true when the read command succeeds, $false when it reports not found, $null on any other failure. #>
    param([string[]]$CliArgs, [switch]$NoSubscription)
    $r = Invoke-LabAz -CliArgs $CliArgs -NoSubscription:$NoSubscription
    if ($r.ExitCode -eq 0) { return (-not [string]::IsNullOrWhiteSpace("$($r.Output)")) }
    if (Test-LabNotFound -Text $r.Output) { return $false }
    return $null
}

function Get-LabManifestField {
    <# Reads one field of a manifest entry; $null when the entry does not have it. #>
    param($Entry, [string]$Name)
    if ($null -eq $Entry) { return $null }
    $p = $Entry.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-LabManifestOwnership {
    <# 'reused' for an entry that records a resource that existed before the lab; 'created' otherwise (also for old entries without the field). #>
    param($Entry)
    if ("$(Get-LabManifestField -Entry $Entry -Name 'ownership')" -eq 'reused') { return 'reused' }
    return 'created'
}

function Get-LabManifestRecords {
    <# Every manifest entry for the run, in both field spellings (run_id and run-id), with its ownership. #>
    param([string]$RunId = '')
    $out = @()
    foreach ($m in @(Read-LabManifest)) {
        if ($null -eq $m -or [string]::IsNullOrWhiteSpace("$(Get-LabManifestField -Entry $m -Name 'type')")) { continue }
        $mr = "$(Get-LabManifestField -Entry $m -Name 'run_id')"
        if (-not $mr) { $mr = "$(Get-LabManifestField -Entry $m -Name 'run-id')" }
        if ($RunId -and $mr -and $mr -ne $RunId) { continue }
        if ($RunId -and -not $mr) { continue }
        $out += [pscustomobject]@{
            type = "$($m.type)"; id = "$(Get-LabManifestField -Entry $m -Name 'id')"; run = $mr
            delete = (Get-LabManifestField -Entry $m -Name 'delete'); ownership = (Get-LabManifestOwnership -Entry $m)
        }
    }
    return $out
}

function Get-LabManifestEntries {
    <# Manifest entries the lab created and may remove (reused entries are never returned here). #>
    param([string]$RunId = '')
    return @(Get-LabManifestRecords -RunId $RunId | Where-Object { $_.ownership -ne 'reused' })
}

function Get-LabReusedManifestEntries {
    <# Manifest entries that record resources the lab found already in place. They are reported and never deleted. #>
    param([string]$RunId = '')
    return @(Get-LabManifestRecords -RunId $RunId | Where-Object { $_.ownership -eq 'reused' })
}

function Write-LabManifest {
    <#
    Replaces the resources list of the manifest and keeps every other field of the file
    (schema, lab, run id, region, creation time) as it is. Atomic write: temp file, then rename.
    Defined after the detection helpers on purpose: it replaces their writer so that
    Remove-LabManifestEntry also keeps the header and the ownership of each entry.
    #>
    param($Entries)
    $path = Get-LabManifestPath
    $header = [ordered]@{ schema = 1; lab = $script:LabTagValue }
    if (Test-Path -LiteralPath $path) {
        $existing = ConvertFrom-LabJson -Text (Get-Content -LiteralPath $path -Raw)
        if ($existing) {
            foreach ($p in $existing.PSObject.Properties) {
                if ($p.Name -eq 'resources') { continue }
                $v = $p.Value
                # PowerShell 7 turns ISO timestamps into DateTime; write them back in the same shape.
                if ($v -is [datetime]) { $v = $v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) }
                $header[$p.Name] = $v
            }
        }
    }
    $header['resources'] = @($Entries)
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $header -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Test-LabInManifest {
    param($Manifest, $Resource)
    $keys = @("$($Resource.id)".ToLowerInvariant(), "$($Resource.rg)/$($Resource.name)".ToLowerInvariant())
    foreach ($m in @($Manifest)) {
        $mid = "$($m.id)".ToLowerInvariant()
        if ($mid -and ($keys -contains $mid)) { return $true }
    }
    return $false
}

function Get-LabSentinelState {
    <# Returns @{ Enabled; Rules } for a workspace id (rules = array of @{id;name}). Never throws. #>
    param([string]$WorkspaceId)
    $api = $script:LabSentinelApi
    $onUrl = Get-LabRestUrl -WorkspaceId $WorkspaceId -Suffix '/providers/Microsoft.SecurityInsights/onboardingStates/default' -ApiVersion $api
    $o = Invoke-LabAz -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $onUrl, '--query', 'name', '--output', 'tsv')
    $enabled = ($o.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace("$($o.Output)"))
    if (-not $enabled -and $o.ExitCode -ne 0 -and "$($o.Output)" -match 'AuthorizationFailed|Forbidden|Unauthorized') {
        [void]$script:LabInventoryErrors.Add("Sentinel state of ${WorkspaceId}: access denied")
    }
    $rules = @()
    if ($enabled) {
        $rUrl = Get-LabRestUrl -WorkspaceId $WorkspaceId -Suffix '/providers/Microsoft.SecurityInsights/alertRules' -ApiVersion $api
        $rules = @(Get-LabList -NoSubscription -Label 'Sentinel analytics rules' -CliArgs @('rest', '--method', 'get', '--url', $rUrl, '--query', 'value[].{id:id,name:name}', '--output', 'json'))
    }
    return @{ Enabled = $enabled; Rules = $rules }
}

function Get-LabInventory {
    <#
    .SYNOPSIS
        Builds the flat inventory (array of entries from New-LabEntry). Read-only.
    .DESCRIPTION
        Kinds: group, resource, flowlog, deleted-vault, deleted-workspace, sentinel-onboarding,
        sentinel-rule, sub-diag, res-diag, entra-diag, defender-plan, role-assignment,
        role-definition, sp, sp-secret, sp-role-assignment, nsg-rule.
        Source is 'tag', 'manifest' or 'unmarked'.
    #>
    param([string]$Region, [string]$RunId = '', [switch]$IncludeUnmarked)
    $script:LabInventoryErrors.Clear()
    $entries = New-Object System.Collections.ArrayList
    $seen = @{}
    $tagFilter = "$($script:LabTagKey)=$($script:LabTagValue)"
    $regionKey = ConvertTo-LabRegionKey -Region $Region
    $manifest = @(Get-LabManifestEntries -RunId $RunId)
    $manifestAll = @(Get-LabManifestEntries)
    # Reused records never authorise a removal, but a resource they name is known to the lab, not 'unmarked'.
    $manifestEvery = @(Get-LabManifestRecords)
    $groupIds = New-Object System.Collections.ArrayList

    function Add-Unique {
        param($Entry)
        $k = "$($Entry.Kind)|$("$($Entry.Id)".ToLowerInvariant())"
        if ($seen.ContainsKey($k)) { return }
        $seen[$k] = $true
        [void]$entries.Add($Entry)
    }

    # 1. Resource groups by lab tag.
    $groups = @(Get-LabList -Label 'resource groups' -CliArgs @('group', 'list', '--tag', $tagFilter, '--query', '[].{id:id,name:name,location:location,tags:tags}', '--output', 'json'))
    foreach ($g in $groups) {
        $run = Get-LabTagValue -Tags $g.tags -Key 'run-id'
        if ($RunId -and $run -ne $RunId) { continue }
        $evTag = Get-LabTagValue -Tags $g.tags -Key 'evidence'
        $isEv = ($null -ne $evTag) -or ((Get-LabTagValue -Tags $g.tags -Key 'component') -eq 'evidence')
        [void]$groupIds.Add("$($g.id)".ToLowerInvariant())
        Add-Unique (New-LabEntry -Kind 'group' -Type 'Microsoft.Resources/resourceGroups' -Id "$($g.id)" -Name "$($g.name)" -Group "$($g.name)" -Location "$($g.location)" -Class 'resource-group' -RunId $run -Extra @{ Evidence = $isEv; Preserved = ($evTag -eq 'preserved'); Tags = $g.tags })
    }

    # 2. Tagged resources.
    $resources = @(Get-LabList -Label 'tagged resources' -CliArgs @('resource', 'list', '--tag', $tagFilter, '--query', '[].{id:id,name:name,type:type,location:location,rg:resourceGroup,tags:tags,managedBy:managedBy}', '--output', 'json'))
    $taggedWorkspaces = @()
    foreach ($r in $resources) {
        $run = Get-LabTagValue -Tags $r.tags -Key 'run-id'
        if ($RunId -and $run -ne $RunId) { continue }
        if ("$($r.type)" -ieq 'microsoft.network/networkwatchers/flowlogs') { continue }
        $cls = Get-LabResourceClass -Type "$($r.type)" -Name "$($r.name)"
        $e = New-LabEntry -Kind 'resource' -Type "$($r.type)" -Id "$($r.id)" -Name "$($r.name)" -Group "$($r.rg)" -Location "$($r.location)" -Class $cls -RunId $run -Extra @{ Tags = $r.tags; ManagedBy = "$($r.managedBy)" }
        Add-Unique $e
        if ("$($r.type)" -ieq 'microsoft.operationalinsights/workspaces') { $taggedWorkspaces += $e }
    }

    # 3. Flow logs (tag or manifest).
    $flowManifest = @($manifestAll | Where-Object { $_.type -eq 'network-watcher:flow-log' })
    $flows = @()
    if ($regionKey) {
        $flows = @(Get-LabList -Label 'VNet flow logs' -CliArgs @('network', 'watcher', 'flow-log', 'list', '--location', $regionKey, '--query', '[].{id:id,name:name,tags:tags,location:location}', '--output', 'json'))
    }
    foreach ($f in $flows) {
        $tagged = Test-LabTagged -Tags $f.tags
        $inMan = $false
        foreach ($m in $flowManifest) { if ("$($m.id)" -ieq "$($f.name)" -or "$($m.id)" -ieq "$($f.id)" -or "$($m.id)" -like "*/$($f.name)") { $inMan = $true } }
        if ($tagged) {
            $run = Get-LabTagValue -Tags $f.tags -Key 'run-id'
            if ($RunId -and $run -ne $RunId) { continue }
            Add-Unique (New-LabEntry -Kind 'flowlog' -Type 'Microsoft.Network/networkWatchers/flowLogs' -Id "$($f.id)" -Name "$($f.name)" -Location "$($f.location)" -Class 'vnet-flow-log' -RunId $run)
        } elseif ($inMan) {
            Add-Unique (New-LabEntry -Kind 'flowlog' -Type 'Microsoft.Network/networkWatchers/flowLogs' -Id "$($f.id)" -Name "$($f.name)" -Location "$($f.location)" -Source 'manifest' -Class 'vnet-flow-log')
        } elseif ($IncludeUnmarked) {
            Add-Unique (New-LabEntry -Kind 'flowlog' -Type 'Microsoft.Network/networkWatchers/flowLogs' -Id "$($f.id)" -Name "$($f.name)" -Location "$($f.location)" -Source 'unmarked' -Class 'vnet-flow-log')
        }
    }

    # 4. Soft-deleted Key Vaults.
    $kvMan = @($manifestAll | Where-Object { $_.type -eq 'azure:keyvault' })
    $dvs = @(Get-LabList -Label 'soft-deleted Key Vaults' -CliArgs @('keyvault', 'list-deleted', '--resource-type', 'vault', '--query', '[].{name:name,id:id,location:properties.location,purge:properties.purgeProtectionEnabled,purgeDate:properties.scheduledPurgeDate,tags:properties.tags}', '--output', 'json'))
    foreach ($v in $dvs) {
        $tagged = Test-LabTagged -Tags $v.tags
        $inMan = $false
        foreach ($m in $kvMan) { if ("$($m.id)" -like "*/$($v.name)" -or "$($m.id)" -ieq "$($v.name)") { $inMan = $true } }
        $src = if ($tagged) { 'tag' } elseif ($inMan) { 'manifest' } else { 'unmarked' }
        if ($src -eq 'unmarked' -and -not $IncludeUnmarked) { continue }
        if ($src -eq 'tag' -and $RunId) {
            $run = Get-LabTagValue -Tags $v.tags -Key 'run-id'
            if ($run -ne $RunId) { continue }
        }
        $prot = ("$($v.purge)" -match '^(?i:true)$')
        Add-Unique (New-LabEntry -Kind 'deleted-vault' -Type 'Microsoft.KeyVault/deletedVaults' -Id "$($v.id)" -Name "$($v.name)" -Location "$($v.location)" -Source $src -Class 'key-vault' -Extra @{ PurgeProtected = $prot; PurgeDate = "$($v.purgeDate)" })
    }

    # 5. Soft-deleted workspaces.
    $dws = @(Get-LabList -Label 'soft-deleted workspaces' -CliArgs @('monitor', 'log-analytics', 'workspace', 'list-deleted-workspaces', '--query', '[].{id:id,name:name,location:location,tags:tags}', '--output', 'json'))
    foreach ($w in $dws) {
        $tagged = Test-LabTagged -Tags $w.tags
        if (-not $tagged -and -not $IncludeUnmarked) { continue }
        if ($tagged -and $RunId -and (Get-LabTagValue -Tags $w.tags -Key 'run-id') -ne $RunId) { continue }
        $rg = ''
        if ("$($w.id)" -match '(?i)/resourceGroups/([^/]+)/') { $rg = $Matches[1] }
        Add-Unique (New-LabEntry -Kind 'deleted-workspace' -Type 'Microsoft.OperationalInsights/deletedWorkspaces' -Id "$($w.id)" -Name "$($w.name)" -Group $rg -Location "$($w.location)" -Source $(if ($tagged) { 'tag' } else { 'unmarked' }) -Class 'log-analytics-workspace')
    }

    # 6. Sentinel on tagged workspaces.
    foreach ($w in $taggedWorkspaces) {
        $s = Get-LabSentinelState -WorkspaceId "$($w.Id)"
        if ($s.Enabled) {
            Add-Unique (New-LabEntry -Kind 'sentinel-onboarding' -Type 'Microsoft.SecurityInsights/onboardingStates' -Id ("$($w.Id)" + '/providers/Microsoft.SecurityInsights/onboardingStates/default') -Name "$($w.Name)" -Group $w.Group -Class 'sentinel' -Extra @{ WorkspaceId = "$($w.Id)"; WorkspaceName = "$($w.Name)" })
            foreach ($rule in @($s.Rules)) {
                Add-Unique (New-LabEntry -Kind 'sentinel-rule' -Type 'Microsoft.SecurityInsights/alertRules' -Id "$($rule.id)" -Name "$($rule.name)" -Group $w.Group -Extra @{ WorkspaceName = "$($w.Name)" })
            }
        }
    }

    # 7. Manifest-only settings (cannot carry tags).
    $defenderNeeded = ($IncludeUnmarked -or @($manifest | Where-Object { $_.type -in @('defender-plan', 'security:pricing-plan') }).Count -gt 0)
    foreach ($m in $manifest) {
        switch -Exact ($m.type) {
            { $_ -in @('diagnostic-setting-subscription', 'monitor:subscription-diagnostic-setting') } {
                $ex = Test-LabRemoteExists -CliArgs @('monitor', 'diagnostic-settings', 'subscription', 'show', '--name', $m.id, '--query', 'name', '--output', 'tsv')
                if ($ex) { Add-Unique (New-LabEntry -Kind 'sub-diag' -Type 'Microsoft.Insights/diagnosticSettings (subscription)' -Id $m.id -Name $m.id -Source 'manifest' -RunId $m.run -Extra @{ ManifestType = $m.type }) }
                elseif ($null -eq $ex) { [void]$script:LabInventoryErrors.Add("Activity Log diagnostic setting '$($m.id)' could not be read") }
            }
            'diagnostic-setting' {
                $parts = "$($m.id)" -split '\|', 2
                if ($parts.Count -eq 2) {
                    $ex = Test-LabRemoteExists -CliArgs @('monitor', 'diagnostic-settings', 'show', '--name', $parts[1], '--resource', $parts[0], '--query', 'name', '--output', 'tsv')
                    if ($ex) { Add-Unique (New-LabEntry -Kind 'res-diag' -Type 'Microsoft.Insights/diagnosticSettings (resource)' -Id $m.id -Name $parts[1] -Source 'manifest' -RunId $m.run -Extra @{ ResourceId = $parts[0] }) }
                }
            }
            'diagnostic-setting-entra' {
                $url = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$($m.id)?api-version=2017-04-01-preview"
                $ex = Test-LabRemoteExists -NoSubscription -CliArgs @('rest', '--method', 'get', '--url', $url, '--query', 'name', '--output', 'tsv')
                if ($ex) { Add-Unique (New-LabEntry -Kind 'entra-diag' -Type 'Microsoft.AADIAM/diagnosticSettings (tenant)' -Id $m.id -Name $m.id -Source 'manifest' -RunId $m.run -Extra @{ Url = $url }) }
            }
            'ad:service-principal' {
                $sp = @(Get-LabList -Label "service principal $($m.id)" -CliArgs @('ad', 'sp', 'show', '--id', $m.id, '--query', '{id:id,appId:appId,name:displayName}', '--output', 'json') -NoSubscription)
                if ($sp.Count -gt 0 -and $sp[0]) {
                    $s0 = $sp[0]
                    Add-Unique (New-LabEntry -Kind 'sp' -Type 'Microsoft.Graph/servicePrincipals' -Id "$($s0.id)" -Name "$($s0.name)" -Source 'manifest' -Class 'service-principal' -RunId $m.run -Extra @{ AppId = "$($s0.appId)" })
                    $keys = @(Get-LabList -Label "credentials of $($s0.appId)" -NoSubscription -CliArgs @('ad', 'app', 'credential', 'list', '--id', "$($s0.appId)", '--query', '[].keyId', '--output', 'json'))
                    foreach ($k in $keys) { if ($k) { Add-Unique (New-LabEntry -Kind 'sp-secret' -Type 'Microsoft.Graph/applications/passwordCredentials' -Id "$($s0.appId)/$k" -Name "$k" -Source 'manifest' -Class 'service-principal-secret' -RunId $m.run -Extra @{ AppId = "$($s0.appId)"; KeyId = "$k" }) } }
                    $ras = @(Get-LabList -Label "role assignments of $($s0.appId)" -NoSubscription:$false -CliArgs @('role', 'assignment', 'list', '--all', '--assignee', "$($s0.appId)", '--query', '[].{id:id,scope:scope,role:roleDefinitionName}', '--output', 'json'))
                    foreach ($ra in $ras) { Add-Unique (New-LabEntry -Kind 'sp-role-assignment' -Type 'Microsoft.Authorization/roleAssignments' -Id "$($ra.id)" -Name "$($ra.role)" -Source 'manifest' -Class 'role-assignment' -RunId $m.run -Extra @{ Scope = "$($ra.scope)"; AppId = "$($s0.appId)" }) }
                }
            }
            { $_ -in @('rbac:role-assignment', 'azure:role-assignment') } {
                if ("$($m.id)" -match '(?i)^/subscriptions/.+/roleAssignments/') {
                    $ex = Test-LabRemoteExists -CliArgs @('role', 'assignment', 'show', '--ids', $m.id, '--query', 'id', '--output', 'tsv')
                    if ($ex) { Add-Unique (New-LabEntry -Kind 'role-assignment' -Type 'Microsoft.Authorization/roleAssignments' -Id $m.id -Name $m.id -Source 'manifest' -Class 'role-assignment' -RunId $m.run) }
                }
            }
            { $_ -in @('rbac:role-definition', 'azure:role-definition') } {
                $rd = @(Get-LabList -Label "role definition $($m.id)" -CliArgs @('role', 'definition', 'list', '--name', ("$($m.id)" -replace '^.*/', ''), '--custom-role-only', 'true', '--query', '[].{id:id,name:roleName}', '--output', 'json'))
                foreach ($d in $rd) { if ($d) { Add-Unique (New-LabEntry -Kind 'role-definition' -Type 'Microsoft.Authorization/roleDefinitions' -Id "$($d.id)" -Name "$($d.name)" -Source 'manifest' -Class 'role-definition' -RunId $m.run) } }
            }
        }
    }

    # Defender plans: manifest-listed plans above Free (and, for the report, any other plan above Free).
    if ($defenderNeeded) {
        $pl = Invoke-LabAz -CliArgs @('security', 'pricing', 'list', '--output', 'json')
        $plans = @()
        if ($pl.ExitCode -eq 0) {
            $po = ConvertFrom-LabJson -Text $pl.Output
            if ($po -and $po.PSObject.Properties['value']) { $plans = @($po.value) } elseif ($po) { $plans = @($po) }
        } elseif (-not (Test-LabNotFound -Text $pl.Output)) {
            [void]$script:LabInventoryErrors.Add('Defender for Cloud plans could not be read')
        }
        foreach ($p in $plans) {
            if (-not $p -or "$($p.pricingTier)" -ieq 'Free') { continue }
            $inMan = $false
            foreach ($m in $manifest) { if ($m.type -in @('defender-plan', 'security:pricing-plan') -and "$($m.id)" -ieq "$($p.name)") { $inMan = $true } }
            if ($inMan) { Add-Unique (New-LabEntry -Kind 'defender-plan' -Type 'Microsoft.Security/pricings' -Id "$($p.name)" -Name "$($p.name)" -Source 'manifest' -Class 'defender-plan' -Extra @{ Tier = "$($p.pricingTier)" }) }
            elseif ($IncludeUnmarked) { Add-Unique (New-LabEntry -Kind 'defender-plan' -Type 'Microsoft.Security/pricings' -Id "$($p.name)" -Name "$($p.name)" -Source 'unmarked' -Class 'defender-plan' -Extra @{ Tier = "$($p.pricingTier)" }) }
        }
    }

    # 8. Derived RBAC: custom roles whose assignable scopes are all inside a tagged lab group.
    if ($groupIds.Count -gt 0) {
        $roles = @(Get-LabList -Label 'custom roles' -CliArgs @('role', 'definition', 'list', '--custom-role-only', 'true', '--query', '[].{id:id,name:roleName,scopes:assignableScopes}', '--output', 'json'))
        foreach ($role in $roles) {
            $scopes = @($role.scopes | Where-Object { $_ })
            if ($scopes.Count -eq 0) { continue }
            $allInside = $true
            foreach ($sc in $scopes) {
                $s = "$sc".ToLowerInvariant()
                $hit = $false
                foreach ($gid in $groupIds) { if ($s -eq $gid -or $s.StartsWith($gid + '/')) { $hit = $true } }
                if (-not $hit) { $allInside = $false }
            }
            if (-not $allInside) { continue }
            Add-Unique (New-LabEntry -Kind 'role-definition' -Type 'Microsoft.Authorization/roleDefinitions' -Id "$($role.id)" -Name "$($role.name)" -Class 'role-definition')
            $ras = @(Get-LabList -Label "assignments of role $($role.name)" -CliArgs @('role', 'assignment', 'list', '--all', '--role', "$($role.name)", '--query', '[].{id:id,scope:scope}', '--output', 'json'))
            foreach ($ra in $ras) { Add-Unique (New-LabEntry -Kind 'role-assignment' -Type 'Microsoft.Authorization/roleAssignments' -Id "$($ra.id)" -Name "$($role.name)" -Class 'role-assignment' -Extra @{ Scope = "$($ra.scope)" }) }
        }
    }

    # 9. Rules of tagged NSGs (block rules, user ingress, anything open inbound).
    foreach ($e in @($entries | Where-Object { $_.Kind -eq 'resource' -and $_.Type -ieq 'microsoft.network/networksecuritygroups' })) {
        $rules = @(Get-LabList -Label "rules of NSG $($e.Name)" -CliArgs @('network', 'nsg', 'rule', 'list', '--nsg-name', $e.Name, '--resource-group', $e.Group, '--query', '[].{id:id,name:name,direction:direction,access:access}', '--output', 'json'))
        foreach ($ru in $rules) { Add-Unique (New-LabEntry -Kind 'nsg-rule' -Type 'Microsoft.Network/networkSecurityGroups/securityRules' -Id "$($ru.id)" -Name "$($ru.name)" -Group $e.Group -Extra @{ Nsg = $e.Name; Direction = "$($ru.direction)"; Access = "$($ru.access)" }) }
    }

    # 10. Unmarked billable resources in the lab region (reported, never removed).
    if ($IncludeUnmarked) {
        $all = @(Get-LabList -Label 'subscription resources' -CliArgs @('resource', 'list', '--query', '[].{id:id,name:name,type:type,location:location,rg:resourceGroup,tags:tags,managedBy:managedBy}', '--output', 'json'))
        foreach ($r in $all) {
            $cls = Get-LabResourceClass -Type "$($r.type)" -Name "$($r.name)"
            if (-not $cls) { continue }
            if (Test-LabTagged -Tags $r.tags) { continue }
            if ("$($r.type)" -ieq 'microsoft.network/networkwatchers/flowlogs') { continue }
            $loc = ConvertTo-LabRegionKey -Region "$($r.location)"
            if ($regionKey -and $loc -and $loc -ne $regionKey -and $loc -ne 'global') { continue }
            if (Test-LabInManifest -Manifest $manifestEvery -Resource $r) { continue }
            $cls2 = $cls
            Add-Unique (New-LabEntry -Kind 'resource' -Type "$($r.type)" -Id "$($r.id)" -Name "$($r.name)" -Group "$($r.rg)" -Location "$($r.location)" -Source 'unmarked' -Class $cls2 -Extra @{ Tags = $r.tags; ManagedBy = "$($r.managedBy)" })
            if ($cls -eq 'log-analytics-workspace') {
                $s = Get-LabSentinelState -WorkspaceId "$($r.id)"
                if ($s.Enabled) { Add-Unique (New-LabEntry -Kind 'sentinel-onboarding' -Type 'Microsoft.SecurityInsights/onboardingStates' -Id ("$($r.id)" + '/providers/Microsoft.SecurityInsights/onboardingStates/default') -Name "$($r.name)" -Group "$($r.rg)" -Source 'unmarked' -Class 'sentinel') }
            }
        }
        $sps = @(Get-LabList -Label 'lab-like service principals' -NoSubscription -CliArgs @('ad', 'sp', 'list', '--filter', "startswith(displayName,'sp-lab-')", '--query', '[].{id:id,appId:appId,name:displayName}', '--output', 'json'))
        foreach ($s in $sps) {
            if (-not $s) { continue }
            $known = $false
            foreach ($e in $entries) { if ($e.Kind -eq 'sp' -and ($e.Id -ieq "$($s.id)" -or $e.Extra.AppId -ieq "$($s.appId)")) { $known = $true } }
            if (-not $known) { Add-Unique (New-LabEntry -Kind 'sp' -Type 'Microsoft.Graph/servicePrincipals' -Id "$($s.id)" -Name "$($s.name)" -Source 'unmarked' -Class 'service-principal' -Extra @{ AppId = "$($s.appId)" }) }
        }
    }

    return @($entries)
}
