<#
.SYNOPSIS
    Shared helpers for the Azure detection stack scripts (ops/azure/ir-lab/detection).

.DESCRIPTION
    Dot-source it from each script:
        . "$PSScriptRoot\Detection-Common.ps1"

    Mirror of the AWS detection helpers. Resource names come from the cloud config (see Initialize-LabNames). What it provides:
      - Invoke-LabAz: the single seam through which every Azure CLI call goes.
        * Mutating calls are only echoed (not executed) when -WhatIf is active.
        * Every executed command is echoed before it runs (secrets redacted).
        * Tests can intercept all calls by setting $global:LabAzHandler to a
          scriptblock that receives the full argument array and returns an object
          with ExitCode and Output. No Azure call is made while the handler is set.
      - the lab tag constants and tag helpers (lab=sangyshop-lab-azure plus run-id).
      - A small lab manifest writer for settings that cannot carry tags
        (diagnostic settings, Defender plans, Sentinel onboarding, analytics rules).
      - Helpers to read the shared KQL files in ..\queries.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

# Shared libraries: config loading, naming, e-mail resolution, secret masking.
# The lab manifest helpers defined further down intentionally replace the ones in Common.ps1
# (this stack records settings that cannot carry tags, with its own entry shape).
. (Join-Path $PSScriptRoot '..\..\..\lib\Common.ps1')
. (Join-Path $PSScriptRoot '..\..\vm\VmNames.ps1')
# Permission hints (exact built-in roles) and the read-only account discovery.
. (Join-Path $PSScriptRoot '..\..\..\lib\LabPermissions.ps1')
. (Join-Path $PSScriptRoot '..\..\..\lib\LabPreflight.ps1')
# The libraries turn strict mode on; this inherited code reads optional CLI output and
# the optional test handler without declaring them first.
Set-StrictMode -Off
# The test seam must be readable under strict mode even when no test set it.
if (-not (Test-Path -LiteralPath 'variable:global:LabAzHandler')) { $global:LabAzHandler = $null }

$script:LabTagKey = 'lab'
$script:LabTagValue = $script:VmLabName
$script:LabSubscription = ''
$script:LabSubscriptionId = $null
$script:LabRegion = ''
$script:LabTempFiles = New-Object System.Collections.ArrayList
$script:LabSnapshot = $null
# Values (such as the alert e-mail address) that must never appear in an echoed command line.
$script:LabMaskedValues = New-Object System.Collections.ArrayList

# Fixed (not name-derived) settings.
$script:LabSentinelApi = '2024-03-01'
$script:LabDefenderPlan = 'VirtualMachines'
$script:LabDefenderSubPlan = 'P2'
$script:LabDailyQuotaGb = 1

function Initialize-LabNames {
    <#
    .SYNOPSIS
        Derives every lab resource name from the cloud config, through Get-VmLabNames.
    .DESCRIPTION
        The config file is ops\cloud.config.ps1, or the file named by $env:LAB_CLOUD_CONFIG_PATH.
        Names shared by the enable/disable pairs are deterministic, so re-runs find the same
        resources, and they match the names the VM deploy script uses for the same lab.
        Exits with code 2 when the config cannot be loaded.
    #>
    $path = $env:LAB_CLOUD_CONFIG_PATH
    if ([string]::IsNullOrWhiteSpace($path)) {
        $path = Join-Path (Join-Path $PSScriptRoot '..\..\..') 'cloud.config.ps1'
    }
    try {
        $cfg = Get-CloudConfig -ConfigPath $path -Cloud 'Azure' -Modality 'vm'
    } catch {
        # Do not exit here: an exit inside a dot-sourced file only ends that file, so the helper
        # functions below would never be defined. Remember the problem; Initialize-Lab and
        # Assert-LabConfigLoaded stop the calling script with exit code 2 and one clear message.
        $script:LabConfigError = "could not load the cloud config ($path). $($_.Exception.Message)"
        return
    }
    $script:LabConfigError = $null
    $script:LabConfig = $cfg
    $n = Get-VmLabNames -Config $cfg
    $app = ([string]$cfg['Common']['AppName']).ToLowerInvariant()
    $short = ($app -replace '[^a-z0-9]', '')
    if ($short.Length -gt 9) { $short = $short.Substring(0, 9) }

    $script:LabLocation = $n['Location']
    $script:LabResourceGroup = $n['LabGroup']
    $script:LabVnetName = $n['Vnet']
    $script:LabNsgName = $n['Nsg']
    $script:LabWorkspaceName = $n['Workspace']
    $script:LabAppTable = $n['LogTable']
    $script:LabActivityDiagName = "$app-lab-activitylog"
    $script:LabDiagName = "$app-lab-diag"
    $script:LabEntraDiagName = "$app-lab-entra"
    $script:LabFlowLogName = "fl-$app-lab"
    $script:LabActionGroupName = "ag-$app-lab"
    $script:LabActionGroupShort = "${short}lab"
    $script:LabAlertRuleName = "$app-lab-bruteforce"
    $script:LabSentinelRuleId = "$app-lab-bruteforce"
    $script:LabNsgBlockerName = "$app-lab-nsg-blocker"
    $script:LabBlockRulePrefix = "$app-lab-block-"
}

# Echoed command lines are masked with Hide-LabSecrets from Common.ps1 (secrets must never reach the console).
$script:LabConfigError = $null
$script:LabConfig = $null
Initialize-LabNames
Set-StrictMode -Off
function Write-LabInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-LabWarn {
    param([string]$Message)
    Write-Host "[WARN] $Message"
}

function Stop-Lab {
    <# Prints an English error to stderr and exits with the given code. #>
    param([string]$Message, [int]$Code = 1)
    [Console]::Error.WriteLine("Error: $Message")
    exit $Code
}

function Assert-LabConfigLoaded {
    <# Stops the calling script with exit code 2 and a clear message when the cloud config could not be loaded. #>
    if ($script:LabConfigError) { Stop-Lab -Code 2 -Message $script:LabConfigError }
}

function Initialize-Lab {
    <# Validates the shared parameters and checks that the Azure CLI exists (unless a test handler is set). #>
    param([string]$Subscription, [string]$Region, [switch]$RegionOptional)
    Assert-LabConfigLoaded
    if ([string]::IsNullOrWhiteSpace($Subscription)) {
        Stop-Lab -Code 2 -Message 'Missing required parameter: -Subscription (no default subscription is used)'
    }
    if (-not $RegionOptional -and [string]::IsNullOrWhiteSpace($Region)) { $Region = $script:LabLocation }
    $script:LabSubscription = $Subscription.Trim()
    $script:LabRegion = if ($Region) { (($Region -replace '\s', '').ToLowerInvariant()) } else { '' }
    if (-not $global:LabAzHandler) {
        if (-not (Get-Command az -CommandType Application -ErrorAction SilentlyContinue)) {
            Stop-Lab -Code 1 -Message 'Azure CLI (az) is not installed or not in PATH'
        }
    }
}

function Get-LabRunId {
    <# Returns the run-id: the provided value, then $env:LAB_RUN_ID, then a new UTC timestamp. #>
    param([string]$RunId)
    if (-not [string]::IsNullOrWhiteSpace($RunId)) { return $RunId.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($env:LAB_RUN_ID)) { return $env:LAB_RUN_ID.Trim() }
    return [datetime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")
}

function Invoke-LabAz {
    <#
    .SYNOPSIS
        Thin wrapper around the Azure CLI (the seam used by tests).
    .DESCRIPTION
        Returns an object with ExitCode and Output. -Mutating marks calls that
        change Azure state: they are echoed as "What if" and skipped under -WhatIf.
        -NoSubscription omits the --subscription argument (use it for 'az rest',
        which takes the subscription id from the URL).
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$CliArgs,
        [switch]$Mutating,
        [switch]$NoSubscription
    )
    $full = @($CliArgs)
    if (-not $NoSubscription) { $full += @('--subscription', $script:LabSubscription) }
    $full += '--only-show-errors'
    $shown = 'az ' + ($full -join ' ')
    $shown = Hide-LabSecrets -Text $shown
    foreach ($m in @($script:LabMaskedValues)) { if ($m) { $shown = $shown.Replace("$m", '[masked]') } }
    if ($shown.Length -gt 400) { $shown = $shown.Substring(0, 400) + ' ...' }

    if ($Mutating -and $WhatIfPreference) {
        Write-Host "What if: $shown"
        return [pscustomobject]@{ ExitCode = 0; Output = ''; Skipped = $true }
    }
    Write-Host "+ $shown"
    if ($global:LabAzHandler) {
        $r = & $global:LabAzHandler $full
        if ($null -eq $r) { $r = [pscustomobject]@{ ExitCode = 0; Output = '' } }
        return $r
    }
    $native = $full
    if ($PSVersionTable.PSVersion -lt [version]'7.3') {
        # Older PowerShell strips embedded double quotes from native arguments.
        $native = @($full | ForEach-Object { $_ -replace '"', '\"' })
    }
    $text = (& az @native 2>&1 | Out-String)
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $text }
}

function ConvertFrom-LabJson {
    <# Parses CLI JSON output; returns $null for blank or invalid text. #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return (ConvertFrom-Json -InputObject $Text) } catch { return $null }
}

function Get-LabSubscriptionId {
    <# Resolves (and caches) the subscription id; exits with code 3 when the login is missing or invalid. #>
    if ($script:LabSubscriptionId) { return $script:LabSubscriptionId }
    $r = Invoke-LabAz -CliArgs @('account', 'show', '--query', 'id', '--output', 'tsv')
    $id = "$($r.Output)".Trim()
    if ($r.ExitCode -ne 0 -or $id -notmatch '^[0-9a-fA-F-]{36}$') {
        Stop-Lab -Code 3 -Message "Azure CLI login is missing, invalid or expired, or the subscription is not accessible. Run 'az login' and check -Subscription. No changes were made."
    }
    $script:LabSubscriptionId = $id
    return $id
}

function Get-LabTagArgs {
    <# the lab tag plus run-id and component as separate "k=v" items (for az --tags). #>
    param([string]$RunId, [string]$Component = 'detection')
    return @("$($script:LabTagKey)=$($script:LabTagValue)", "run-id=$RunId", "component=$Component")
}

function Test-LabTagged {
    <# $true when a tag map ({k:v}) contains lab=sangyshop-lab-azure. #>
    param($Tags)
    if ($null -eq $Tags) { return $false }
    foreach ($t in @($Tags)) {
        if ($null -eq $t) { continue }
        $p = $t.PSObject.Properties[$script:LabTagKey]
        if ($p -and "$($p.Value)" -eq $script:LabTagValue) { return $true }
    }
    return $false
}

function New-LabTempFile {
    <# Writes text to a temp file and returns "@<path>" for CLI arguments (avoids shell quoting issues). #>
    param([string]$Text)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("lab-{0}.json" -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding($false)))
    [void]$script:LabTempFiles.Add($path)
    return '@' + $path
}

function Clear-LabTempFiles {
    foreach ($f in @($script:LabTempFiles)) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -WhatIf:$false -ErrorAction SilentlyContinue }
    }
    $script:LabTempFiles.Clear()
}

function Get-LabManifestPath {
    if (-not [string]::IsNullOrWhiteSpace($env:LAB_MANIFEST_PATH)) { return $env:LAB_MANIFEST_PATH }
    $homeDir = if ($HOME) { $HOME } else { [Environment]::GetFolderPath('UserProfile') }
    return (Join-Path (Join-Path $homeDir '.sangyshop-lab') "manifest-$($script:LabTagValue).json")
}

function Read-LabManifest {
    $path = Get-LabManifestPath
    if (Test-Path -LiteralPath $path) {
        $obj = ConvertFrom-LabJson -Text (Get-Content -LiteralPath $path -Raw)
        if ($obj -and $obj.resources) { return @($obj.resources) }
    }
    return @()
}

function Write-LabManifest {
    param($Entries)
    $path = Get-LabManifestPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = ([ordered]@{ schema = 1; lab = $script:LabTagValue; resources = @($Entries) }) | ConvertTo-Json -Depth 5
    $tmp = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Add-LabManifestEntry {
    <#
    .SYNOPSIS
        Records a resource or setting in the lab manifest (type, id, run-id, ownership). No duplicates.
    .DESCRIPTION
        -Ownership is 'created' (the lab made it, so teardown may remove it) or 'reused' (it
        existed before the lab, so teardown keeps it). An entry that is already recorded is
        never rewritten, so a re-run cannot turn a created entry into a reused one.
    #>
    param([string]$Type, [string]$Id, [string]$RunId, [ValidateSet('created', 'reused')][string]$Ownership = 'created')
    if ($WhatIfPreference) {
        Write-Host "What if: record $Type '$Id' in the lab manifest ($Ownership)"
        return
    }
    $entries = @(Read-LabManifest)
    foreach ($e in $entries) {
        if ($e.type -eq $Type -and $e.id -eq $Id) { return }
    }
    $entries += [pscustomobject]@{ type = $Type; id = $Id; 'run-id' = $RunId; ownership = $Ownership }
    Write-LabManifest -Entries $entries
    Write-LabInfo "Recorded $Type in the lab manifest ($Ownership)."
}

function Get-LabExistingOwnership {
    <# Ownership to record for something that already exists: 'created' when the manifest already lists it as the lab's, otherwise 'reused'. #>
    param([string]$Type, [string]$Id)
    foreach ($e in @(Read-LabManifest)) {
        if ($e.type -eq $Type -and $e.id -eq $Id) {
            if ("$($e.ownership)" -eq 'reused') { return 'reused' }
            return 'created'
        }
    }
    return 'reused'
}

function Test-LabManifestReused {
    <# $true when the manifest records this entry as reused (not created by the lab). #>
    param([string]$Type, [string]$Id)
    foreach ($e in @(Read-LabManifest)) {
        if ($e.type -eq $Type -and $e.id -eq $Id -and "$($e.ownership)" -eq 'reused') { return $true }
    }
    return $false
}

function Stop-LabIfDenied {
    <# Stops with exit code 3 and the exact built-in role when a result carries an authorization error. #>
    param($Result, [string]$Service, [string]$Action, [string]$Step = 'unknown')
    if ($null -eq $Result -or $Result.ExitCode -eq 0) { return }
    if (Test-LabAccessDenied -Text "$($Result.Output)") {
        $hint = Get-LabPermissionHint -Cloud Azure -Service $Service -Action $Action
        Stop-LabForPermission -Hint $hint -Step $Step
    }
}

function Assert-LabAzOk {
    <# Passes a successful result. A denied call exits 3 with the role to assign; any other failure exits 1 with the message. #>
    param($Result, [string]$Service, [string]$Action, [string]$Failure)
    if ($null -eq $Result -or $Result.ExitCode -eq 0) { return }
    Stop-LabIfDenied -Result $Result -Service $Service -Action $Action -Step "$Service $Action"
    Stop-Lab -Code 1 -Message "$Failure $($Result.Output)"
}

function Get-LabPreflightDecision {
    <#
    .SYNOPSIS
        One read-only discovery of the account, then one decision line for a resource type.
    .DESCRIPTION
        Type is workspace, actiongroup or alertrule. The account is listed once per run and
        the snapshot is reused. A denied read exits 3 with the role to assign. A read that
        fails for another reason is never taken as "does not exist": the decision stays
        Blocked and the caller must confirm with a direct read before it creates anything.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('workspace', 'actiongroup', 'alertrule')][string]$Type,
        [string]$ExpectedName
    )
    if (-not $script:LabSnapshot) {
        $script:LabSnapshot = Get-LabAccountSnapshot -Cloud Azure -LabTag $script:LabTagValue
    }
    $d = Resolve-ResourceDecision -Snapshot $script:LabSnapshot -Type $Type -ExpectedName $ExpectedName
    if ($d.Decision -eq 'Blocked') {
        $res = $script:LabSnapshot.Types[$Type]
        if ($res -and $res.Status -eq 'Denied') {
            $svc = if ($Type -eq 'workspace') { 'loganalytics' } else { 'monitor' }
            $hint = Get-LabPermissionHint -Cloud Azure -Service $svc -Action $res.Action
            Stop-LabForPermission -Hint $hint -Step "preflight $Type"
        }
        Write-LabWarn "The $Type list could not be read. Each resource is checked directly before anything is created."
    }
    return $d
}

function Test-LabManifestEntry {
    param([string]$Type, [string]$Id)
    foreach ($e in @(Read-LabManifest)) {
        if ($e.type -eq $Type -and $e.id -eq $Id) { return $true }
    }
    return $false
}

function Remove-LabManifestEntry {
    param([string]$Type, [string]$Id)
    if ($WhatIfPreference) {
        Write-Host "What if: remove $Type '$Id' from the lab manifest"
        return
    }
    $entries = @(Read-LabManifest)
    $keep = @($entries | Where-Object { -not ($_.type -eq $Type -and $_.id -eq $Id) })
    if ($keep.Count -ne $entries.Count) { Write-LabManifest -Entries $keep }
}

function Confirm-LabUntaggedRefusal {
    <# Standard refusal for a same-named resource that lacks the lab tag. Exits with code 1. #>
    param([string]$Kind, [string]$Name, [string]$Hint = '')
    Stop-Lab -Code 1 -Message "$Kind '$Name' exists but does not carry the tag $($script:LabTagKey)=$($script:LabTagValue). It was left unchanged. $Hint".Trim()
}

function Test-LabNotFound {
    <# $true when CLI output looks like a missing resource. #>
    param([string]$Text)
    return ("$Text" -match 'ResourceNotFound|ResourceGroupNotFound|was not found|could not be found|does not exist|NotFound|\(404\)|Not Found')
}

function Get-LabQueryText {
    <# Reads a KQL file from ..\queries, drops // comment lines and joins the rest with newlines. #>
    param([Parameter(Mandatory = $true)][string]$Name)
    $path = Join-Path (Join-Path $PSScriptRoot 'queries') $Name
    if (-not (Test-Path -LiteralPath $path)) { Stop-Lab -Code 1 -Message "Query file not found: $path" }
    $lines = Get-Content -LiteralPath $path | Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('//') }
    return (($lines | ForEach-Object { $_.TrimEnd() }) -join "`n")
}

function Get-LabWorkspace {
    <#
    .SYNOPSIS
        Returns the lab workspace (id, customerId, tags) or $null when it does not exist.
    #>
    param([string]$ResourceGroup, [string]$Name)
    $r = Invoke-LabAz -CliArgs @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $ResourceGroup, '--workspace-name', $Name, '--query', '{id:id,customerId:customerId,tags:tags,quota:workspaceCapping.dailyQuotaGb}', '--output', 'json')
    if ($r.ExitCode -ne 0) {
        Stop-LabIfDenied -Result $r -Service 'loganalytics' -Action 'workspace show' -Step 'workspace show'
        if (Test-LabNotFound -Text $r.Output) { return $null }
        Stop-Lab -Code 1 -Message "Could not read workspace '$Name'. $($r.Output)"
    }
    return (ConvertFrom-LabJson -Text $r.Output)
}

function Get-LabWorkspaceRequired {
    <#
    .SYNOPSIS
        Returns the lab workspace or exits with code 1 when it does not exist.
    .DESCRIPTION
        Under -WhatIf a missing workspace returns a placeholder (nothing is created), so a
        full dry-run of enable-all.ps1 still prints every command.
    #>
    param([string]$ResourceGroup, [string]$Name)
    $ws = Get-LabWorkspace -ResourceGroup $ResourceGroup -Name $Name
    if ($ws) { return $ws }
    if ($WhatIfPreference) {
        Write-LabWarn "Workspace '$Name' does not exist yet (dry-run): using a placeholder id."
        $sid = if ($script:LabSubscriptionId) { $script:LabSubscriptionId } else { '00000000-0000-0000-0000-000000000000' }
        return [pscustomobject]@{
            id = "/subscriptions/$sid/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Name"
            customerId = '00000000-0000-0000-0000-000000000000'; tags = $null; quota = $null
        }
    }
    Stop-Lab -Code 1 -Message "Log Analytics workspace '$Name' not found in resource group '$ResourceGroup'. Run enable-workspace.ps1 first."
}

function Resolve-LabResourceId {
    <#
    .SYNOPSIS
        Finds the resource id of a lab resource: by name when given, otherwise by the lab tag in the resource group.
    .DESCRIPTION
        Returns $null when nothing matches. Exits with code 2 when more than one resource matches,
        so the caller can pass the name explicitly. Resources tagged component=flowlogs are ignored
        (the flow-log storage account is not the application storage account).
    #>
    param([string]$ResourceGroup, [string]$ResourceType, [string]$Name)
    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $r = Invoke-LabAz -CliArgs @('resource', 'list', '--resource-group', $ResourceGroup, '--resource-type', $ResourceType, '--name', $Name, '--query', '[].id', '--output', 'json')
    } else {
        $r = Invoke-LabAz -CliArgs @('resource', 'list', '--resource-group', $ResourceGroup, '--resource-type', $ResourceType, '--tag', "$($script:LabTagKey)=$($script:LabTagValue)", '--query', "[?tags.component!='flowlogs'].id", '--output', 'json')
    }
    $ids = @()
    if ($r.ExitCode -eq 0) { $ids = @(ConvertFrom-LabJson -Text $r.Output | Where-Object { $_ }) }
    if ($ids.Count -gt 1) { Stop-Lab -Code 2 -Message "More than one $ResourceType matches in '$ResourceGroup'. Pass the resource name explicitly." }
    if ($ids.Count -eq 1) { return "$($ids[0])" }
    return $null
}

function Get-LabFlowStorageName {
    <# Deterministic, globally-unlikely name for the flow-log storage account: stflowlab + 10 hex chars of the subscription id hash. #>
    $sid = Get-LabSubscriptionId
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sid.ToLowerInvariant()))
    } finally { $sha.Dispose() }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return 'stflowlab' + $hex.Substring(0, 10)
}

function Get-LabRestUrl {
    <# Builds an ARM URL below the lab workspace (Microsoft.SecurityInsights and friends). #>
    param([string]$WorkspaceId, [string]$Suffix, [string]$ApiVersion)
    return ("https://management.azure.com{0}{1}?api-version={2}" -f $WorkspaceId, $Suffix, $ApiVersion)
}
