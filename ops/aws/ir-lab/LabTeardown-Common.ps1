<#
.SYNOPSIS
    Shared helpers for full-teardown.ps1 and verify-zero-cost.ps1 (aws/ir-lab).

.DESCRIPTION
    Dot-source it from the two scripts:
        . "$PSScriptRoot\LabTeardown-Common.ps1"

    It builds on detection\Detection-Common.ps1 (Invoke-LabCli seam, lab tag helpers,
    $global:LabCliHandler for tests) and adds:
      - lab inventory: tag:GetResources (Resource Groups Tagging API) + lab manifest +
        per-class service queries, every candidate re-checked for existence (the tagging
        API is eventually consistent, so a just-deleted resource may still be listed);
      - the billable risk-class scan (tagged and unmarked);
      - one removal routine per resource type (used only by full-teardown.ps1).

    Safety rule enforced here and in the callers: a resource is only ever removed when it
    carries lab tag (lab=<app>-lab-aws) or is listed in the lab manifest. Anything else
    is a unmarked resource: reported, never touched.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

. "$PSScriptRoot\detection\Detection-Common.ps1"
# Detection-Common loads the shared ops libraries, which switch strict mode on. The inventory and removal
# code below was written for the default (non-strict) mode and probes optional CLI properties, so strict mode
# is switched off again for the scripts that include this file.
Set-StrictMode -Off

$script:LabGlobalRegion = 'us-east-1'
# Seconds to wait between retries of dependency-bound deletions (tests set it to 0).
$script:LabRetryDelay = 15
# Phase boundaries (see Get-LabItemPhase).
$script:LabDeployPhaseMin = 40
$script:LabDeployPhaseMax = 89
# Indicative list prices used only for the "cost of keeping preserved evidence" estimate.
$script:LabPriceDate = '2026-11-11'
$script:LabPriceEbsSnapshotGbMonth = 0.05
$script:LabPriceRdsSnapshotGbMonth = 0.095
$script:LabPriceS3StandardGbMonth = 0.023

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

function ConvertTo-LabList {
    <# Returns the non-null elements of a value as an array (safe for $null and single objects). #>
    param($Value)
    $out = New-Object System.Collections.ArrayList
    if ($null -ne $Value) {
        foreach ($v in @($Value)) { if ($null -ne $v) { [void]$out.Add($v) } }
    }
    return $out.ToArray()
}

function ConvertTo-LabTagMap {
    <# Accepts [{Key,Value}] (or {key,value}) and returns a case-insensitive hashtable. #>
    param($Tags)
    $map = @{}
    foreach ($t in @(ConvertTo-LabList $Tags)) {
        if ($t -is [string]) { continue }
        $p = $t.PSObject.Properties
        if ($p['Key'] -and $null -ne $p['Key'].Value) {
            $v = ''
            if ($p['Value'] -and $null -ne $p['Value'].Value) { $v = "$($p['Value'].Value)" }
            $map["$($p['Key'].Value)"] = $v
        }
    }
    return $map
}

function Invoke-LabQuery {
    <# Read-only CLI call; returns Ok, Data (parsed JSON), Output and ExitCode. #>
    param([Parameter(Mandatory = $true)][string[]]$CliArgs)
    # A denied or failed read is reported by the caller as an inconclusive inventory (nothing is
    # removed or declared clean), so it must not stop the script with the permission exit code.
    $prevPass = $script:LabPassDenied
    $script:LabPassDenied = $true
    try { $r = Invoke-LabCli -CliArgs $CliArgs } finally { $script:LabPassDenied = $prevPass }
    $data = $null
    if ($r.ExitCode -eq 0) { $data = ConvertFrom-LabJson -Text "$($r.Output)" }
    return [pscustomobject]@{ Ok = ($r.ExitCode -eq 0); Data = $data; Output = "$($r.Output)"; ExitCode = $r.ExitCode }
}

function Use-LabRegion {
    <# Runs a scriptblock with the CLI region temporarily switched (global services live in us-east-1). #>
    param([string]$Region, [scriptblock]$Script)
    $old = $script:LabRegion
    $script:LabRegion = $Region
    try { return (& $Script) } finally { $script:LabRegion = $old }
}

function Test-LabNotFound {
    param($Result)
    return ($Result.ExitCode -ne 0 -and "$($Result.Output)" -match 'NotFound|NoSuchEntity|NoSuchBucket|NoSuchKey|ResourceNotFound|does not exist|DBInstanceNotFound|DBSnapshotNotFound|DBSubnetGroupNotFound|\b404\b|InvalidInstanceID|ParameterNotFound|RepositoryDoesNotExist|TrailNotFound|InvalidParameterException.*not found|NotFoundException')
}

function Get-LabErrorLine {
    param($Result)
    $line = ("$($Result.Output)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $line) { return "exit code $($Result.ExitCode)" }
    $line = $line.Trim()
    if ($line.Length -gt 300) { $line = $line.Substring(0, 300) }
    return $line
}

function Read-LabConfirmation {
    <# Asks the operator to type an exact phrase. Tests may set $global:LabConfirmHandler (prompt -> answer). #>
    param([string]$Prompt)
    if ($global:LabConfirmHandler) { return [string](& $global:LabConfirmHandler $Prompt) }
    try { return [string](Read-Host $Prompt) } catch { return '' }
}

# ---------------------------------------------------------------------------
# ARN parsing and inventory items
# ---------------------------------------------------------------------------

function ConvertFrom-LabArn {
    <# Maps an ARN to a lab resource Type/Id. Unknown shapes become Type 'unsupported:<service>'. #>
    param([string]$Arn)
    if ($Arn -notmatch '^arn:aws[a-z-]*:([^:]+):([^:]*):([^:]*):(.*)$') { return $null }
    $svc = $Matches[1]; $reg = $Matches[2]; $res = $Matches[4]
    $type = "unsupported:$svc"; $id = $res

    if ($svc -eq 'ec2') {
        $parts = $res -split '/', 2
        $map = @{
            'instance' = 'ec2-instance'; 'volume' = 'ebs-volume'; 'snapshot' = 'ebs-snapshot'; 'vpc' = 'vpc'
            'subnet' = 'subnet'; 'security-group' = 'security-group'; 'route-table' = 'route-table'
            'internet-gateway' = 'internet-gateway'; 'network-acl' = 'network-acl'; 'elastic-ip' = 'elastic-ip'
            'natgateway' = 'nat-gateway'; 'key-pair' = 'key-pair'; 'vpc-flow-log' = 'flow-log'
        }
        if ($parts.Count -eq 2 -and $map.ContainsKey($parts[0])) { $type = $map[$parts[0]]; $id = $parts[1] }
        else { $type = "unsupported:ec2/$($parts[0])" }
    } elseif ($svc -eq 'rds') {
        if ($res -match '^db:(.+)$') { $type = 'rds-instance'; $id = $Matches[1] }
        elseif ($res -match '^snapshot:(.+)$') { $type = 'rds-snapshot'; $id = $Matches[1] }
        elseif ($res -match '^subgrp:(.+)$') { $type = 'db-subnet-group'; $id = $Matches[1] }
        else { $type = 'unsupported:rds' }
    } elseif ($svc -eq 's3') {
        if ($res -notmatch '/') { $type = 's3-bucket'; $id = $res } else { $type = 'unsupported:s3/object' }
    } elseif ($svc -eq 'secretsmanager') {
        if ($res -match '^secret:(.+)$') { $type = 'secret'; $id = ($Matches[1] -replace '-[A-Za-z0-9]{6}$', '') }
    } elseif ($svc -eq 'iam') {
        if ($res -match '^(role|user|instance-profile|policy)/(?:.*/)?([^/]+)$') {
            $kind = $Matches[1]; $id = $Matches[2]
            $type = @{ 'role' = 'iam-role'; 'user' = 'iam-user'; 'instance-profile' = 'instance-profile'; 'policy' = 'iam-policy' }[$kind]
        }
    } elseif ($svc -eq 'logs') {
        if ($res -match '^log-group:(.+?)(?::\*)?$') { $type = 'log-group'; $id = $Matches[1] }
    } elseif ($svc -eq 'sns') {
        if ($res -notmatch ':') { $type = 'sns-topic'; $id = $res }
    } elseif ($svc -eq 'lambda') {
        if ($res -match '^function:([^:]+)') { $type = 'lambda-function'; $id = $Matches[1] }
    } elseif ($svc -eq 'events') {
        if ($res -match '^rule/(?:.*/)?([^/]+)$') { $type = 'eventbridge-rule'; $id = $Matches[1] }
    } elseif ($svc -eq 'guardduty') {
        if ($res -match '^detector/([^/]+)$') { $type = 'guardduty-detector'; $id = $Matches[1] }
    } elseif ($svc -eq 'cloudtrail') {
        if ($res -match '^trail/(.+)$') { $type = 'cloudtrail-trail'; $id = $Matches[1] }
    } elseif ($svc -eq 'cloudwatch') {
        if ($res -match '^alarm:(.+)$') { $type = 'cloudwatch-alarm'; $id = $Matches[1] }
    } elseif ($svc -eq 'kms') {
        if ($res -match '^key/(.+)$') { $type = 'kms-key'; $id = $Matches[1] }
    } elseif ($svc -eq 'codecommit') {
        $type = 'codecommit-repo'; $id = $res
    }
    return [pscustomobject]@{ Type = $type; Id = $id; Region = $reg; Service = $svc }
}

function New-LabItem {
    param(
        [string]$Type, [string]$Id, [string]$Region, $Tags, [string]$RunId = '', [string]$Arn = '',
        [string]$Source, [switch]$Tagged, [switch]$InManifest
    )
    $tm = @{}
    if ($Tags -is [hashtable]) { $tm = $Tags } else { $tm = ConvertTo-LabTagMap $Tags }
    $rid = $RunId
    if (-not $rid -and $tm.ContainsKey('run-id')) { $rid = "$($tm['run-id'])" }
    $ev = ''
    if ($tm.ContainsKey('evidence')) { $ev = "$($tm['evidence'])" }
    $comp = ''
    if ($tm.ContainsKey('component')) { $comp = "$($tm['component'])" }
    $item = [pscustomobject]@{
        Type = $Type; Id = $Id; Key = "$Type|$Id"; Region = $Region; Arn = $Arn; Tags = $tm
        RunId = $rid; Evidence = $ev; Component = $comp
        Sources = (New-Object System.Collections.ArrayList)
        Tagged = [bool]$Tagged; InManifest = [bool]$InManifest
        Phase = 0; Detail = ''; Kept = $false; Billable = $false; Class = ''; Reused = $false
    }
    if ($Source) { [void]$item.Sources.Add($Source) }
    return $item
}

function Merge-LabItem {
    <# Adds an item to a hashtable keyed by Type|Id, merging sources, flags and tags when it is already there. #>
    param([hashtable]$Table, $Item)
    if (-not $Table.ContainsKey($Item.Key)) { $Table[$Item.Key] = $Item; return }
    $cur = $Table[$Item.Key]
    foreach ($s in $Item.Sources) { if ($cur.Sources -notcontains $s) { [void]$cur.Sources.Add($s) } }
    if ($Item.Tagged) { $cur.Tagged = $true }
    if ($Item.InManifest) { $cur.InManifest = $true }
    if ($Item.Reused) { $cur.Reused = $true }
    foreach ($k in @($Item.Tags.Keys)) { if (-not $cur.Tags.ContainsKey($k)) { $cur.Tags[$k] = $Item.Tags[$k] } }
    if (-not $cur.RunId) { $cur.RunId = $Item.RunId }
    if (-not $cur.Evidence) { $cur.Evidence = $Item.Evidence }
    if (-not $cur.Component) { $cur.Component = $Item.Component }
    if (-not $cur.Arn) { $cur.Arn = $Item.Arn }
    if (-not $cur.Region) { $cur.Region = $Item.Region }
}

function Get-LabItemPhase {
    <#
    Deletion phase = reverse dependency order:
      10-19 block / isolation, 20-29 blocker, 30-39 detection stack,
      40-89 deploy (EC2, RDS, secrets, app bucket, role/profile, network),
      90-99 evidence, 100+ credentials, 999 = unsupported type (never removed).
    The component tag / well-known names only influence ORDER, never selection.
    #>
    param($Item)
    $id = "$($Item.Id)"; $c = "$($Item.Component)"
    # Well-known names come from Get-AwsLabNames (through Detection-Common), never from literals.
    $trailBucketPrefix = "$([string]$script:LabNames['TrailName'])-"
    $blockerRole = [string]$script:LabNames['BlockerRole']
    $flowRole = [string]$script:LabNames['FlowRoleName']
    switch -Exact ($Item.Type) {
        'nacl-block-entry' { return 10 }
        'sg-ingress-rule' { return 12 }
        'eventbridge-rule' { return 20 }
        'lambda-function' { return 21 }
        'cloudwatch-alarm' { return 30 }
        'logs-metric-filter' { return 31 }
        'flow-log' { return 32 }
        'log-group' { return 33 }
        'cloudtrail-trail' { return 34 }
        'guardduty-detector' { return 36 }
        'sns-subscription' { return 38 }
        'sns-topic' { return 39 }
        'ec2-instance' { return 40 }
        'nat-gateway' { return 41 }
        'elastic-ip' { return 42 }
        'ebs-volume' { return 43 }
        'key-pair' { return 44 }
        'rds-instance' { return 50 }
        'db-subnet-group' { return 51 }
        'secret' { return 55 }
        'codecommit-repo' { return 61 }
        'instance-profile' { return 70 }
        'security-group' { return 80 }
        'subnet' { return 81 }
        'network-acl' { return 82 }
        'route-table' { return 83 }
        'internet-gateway' { return 84 }
        'vpc' { return 85 }
        'kms-key' { return 88 }
        'ebs-snapshot' { return 90 }
        'rds-snapshot' { return 92 }
        'iam-access-key' { return 100 }
        'iam-user' { return 102 }
        's3-bucket' {
            if ($Item.Evidence -or $c -eq 'evidence') { return 91 }
            if ($c -eq 'detection' -or $id.StartsWith($trailBucketPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { return 35 }
            return 60
        }
        'iam-role' {
            if ($c -eq 'blocker' -or $id -eq $blockerRole) { return 22 }
            if ($c -eq 'detection' -or $id -eq $flowRole) { return 37 }
            return 71
        }
        'iam-policy' {
            if ($c -eq 'credential') { return 101 }
            return 72
        }
        default { return 999 }
    }
}

function Get-LabPhaseGroup {
    param([int]$Phase)
    if ($Phase -lt 20) { return 'block/isolation' }
    if ($Phase -lt 30) { return 'blocker' }
    if ($Phase -lt 40) { return 'detection' }
    if ($Phase -lt 90) { return 'deploy' }
    if ($Phase -lt 100) { return 'evidence' }
    if ($Phase -lt 999) { return 'credentials' }
    return 'unsupported'
}

# ---------------------------------------------------------------------------
# lab manifest (two on-disk shapes are accepted)
# ---------------------------------------------------------------------------
# Legacy shape: {resources:[{type,id,region,"run-id"}]}.  Current shape: {schema,lab,run_id,region,resources:[{type,id,region,run_id,component,ownership}]}.
# Every candidate file is merged additively. An entry with ownership "reused" describes a resource that
# existed before the lab; it is never part of a removal plan. Entries without the field count as created.

function Get-LabManifestCandidates {
    param([string]$ManifestPath)
    if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) { return @($ManifestPath) }
    $homeDir = if ($HOME) { $HOME } else { [Environment]::GetFolderPath('UserProfile') }
    $dir = Join-Path $homeDir '.sangyshop-lab'
    $list = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($env:LAB_MANIFEST_PATH)) { [void]$list.Add($env:LAB_MANIFEST_PATH) }
    foreach ($p in @((Join-Path $dir 'lab-manifest.json'), (Join-Path $dir "manifest-$($script:LabTagValue).json"))) {
        if ($list -notcontains $p) { [void]$list.Add($p) }
    }
    return $list.ToArray()
}

function Read-LabManifestFile {
    <# Returns normalized entries {Type,Id,Region,RunId,Component,Reused}, or $null when the file is not valid JSON. #>
    param([string]$Path)
    $obj = ConvertFrom-LabJson -Text (Get-Content -LiteralPath $Path -Raw)
    if ($null -eq $obj) { return $null }
    $out = New-Object System.Collections.ArrayList
    $res = $null
    if ($obj.PSObject.Properties['resources']) { $res = $obj.resources }
    foreach ($e in @(ConvertTo-LabList $res)) {
        $rid = ''
        foreach ($n in @('run-id', 'run_id')) {
            if ($e.PSObject.Properties[$n] -and $e.PSObject.Properties[$n].Value) { $rid = "$($e.PSObject.Properties[$n].Value)"; break }
        }
        $comp = ''
        if ($e.PSObject.Properties['component'] -and $e.component) { $comp = "$($e.component)" }
        $reused = $false
        if ($e.PSObject.Properties['ownership'] -and "$($e.ownership)" -eq 'reused') { $reused = $true }
        [void]$out.Add([pscustomobject]@{ Type = "$($e.type)"; Id = "$($e.id)"; Region = "$($e.region)"; RunId = $rid; Component = $comp; Reused = $reused })
    }
    # The leading comma keeps an EMPTY list from collapsing to $null (which means "invalid JSON" to the caller).
    return , $out.ToArray()
}

function Read-LabManifestEntries {
    <# Reads every candidate manifest. An explicit -ManifestPath that is missing or invalid exits 4. #>
    param([string]$ManifestPath)
    $explicit = -not [string]::IsNullOrWhiteSpace($ManifestPath)
    $all = New-Object System.Collections.ArrayList
    $seen = @{}   # key -> the merged entry already in $all
    foreach ($p in @(Get-LabManifestCandidates -ManifestPath $ManifestPath)) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            if ($explicit) { Stop-Lab -Code 4 -Message "Manifest file not found or unreadable: $p" }
            continue
        }
        $entries = Read-LabManifestFile -Path $p
        if ($null -eq $entries) {
            if ($explicit) { Stop-Lab -Code 4 -Message "Manifest file is not valid JSON: $p" }
            Write-LabWarn "Ignoring unreadable manifest: $p"
            continue
        }
        foreach ($e in $entries) {
            $k = "$($e.Type)|$($e.Id)|$($e.Region)"
            if ($seen.ContainsKey($k)) {
                # Additive merge: a reused marker in any file wins, so nothing pre-existing is ever removed.
                if ($e.Reused) { $seen[$k].Reused = $true }
                continue
            }
            $seen[$k] = $e
            [void]$all.Add($e)
        }
    }
    return $all.ToArray()
}

# ---------------------------------------------------------------------------
# Existence checks (the tagging API lags behind deletions, so every candidate is re-checked)
# ---------------------------------------------------------------------------

function Get-LabExistsSpec {
    <# Returns @{Args=..; Mode='nonempty'|'exit'|'notpending'} for a type, or $null when the type is not checkable. #>
    param($Item)
    $id = "$($Item.Id)"
    switch -Exact ($Item.Type) {
        'ec2-instance' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-instances', '--instance-ids', $id, '--query', "Reservations[].Instances[?State.Name!='terminated' && State.Name!='shutting-down'].InstanceId", '--output', 'text') } }
        'ebs-volume' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-volumes', '--volume-ids', $id, '--query', 'Volumes[].VolumeId', '--output', 'text') } }
        'ebs-snapshot' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-snapshots', '--snapshot-ids', $id, '--query', 'Snapshots[].SnapshotId', '--output', 'text') } }
        'key-pair' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-key-pairs', '--key-pair-ids', $id, '--query', 'KeyPairs[].KeyPairId', '--output', 'text') } }
        'elastic-ip' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-addresses', '--allocation-ids', $id, '--query', 'Addresses[].AllocationId', '--output', 'text') } }
        'nat-gateway' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-nat-gateways', '--nat-gateway-ids', $id, '--query', "NatGateways[?State!='deleted' && State!='deleting'].NatGatewayId", '--output', 'text') } }
        'vpc' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-vpcs', '--vpc-ids', $id, '--query', 'Vpcs[].VpcId', '--output', 'text') } }
        'subnet' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-subnets', '--subnet-ids', $id, '--query', 'Subnets[].SubnetId', '--output', 'text') } }
        'security-group' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-security-groups', '--group-ids', $id, '--query', 'SecurityGroups[].GroupId', '--output', 'text') } }
        'route-table' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-route-tables', '--route-table-ids', $id, '--query', 'RouteTables[].RouteTableId', '--output', 'text') } }
        'internet-gateway' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-internet-gateways', '--internet-gateway-ids', $id, '--query', 'InternetGateways[].InternetGatewayId', '--output', 'text') } }
        'network-acl' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-network-acls', '--network-acl-ids', $id, '--query', 'NetworkAcls[].NetworkAclId', '--output', 'text') } }
        'flow-log' { return @{ Mode = 'nonempty'; Args = @('ec2', 'describe-flow-logs', '--flow-log-ids', $id, '--query', 'FlowLogs[].FlowLogId', '--output', 'text') } }
        'rds-instance' { return @{ Mode = 'nonempty'; Args = @('rds', 'describe-db-instances', '--db-instance-identifier', $id, '--query', 'DBInstances[].DBInstanceIdentifier', '--output', 'text') } }
        'rds-snapshot' { return @{ Mode = 'nonempty'; Args = @('rds', 'describe-db-snapshots', '--db-snapshot-identifier', $id, '--query', 'DBSnapshots[].DBSnapshotIdentifier', '--output', 'text') } }
        'db-subnet-group' { return @{ Mode = 'nonempty'; Args = @('rds', 'describe-db-subnet-groups', '--db-subnet-group-name', $id, '--query', 'DBSubnetGroups[].DBSubnetGroupName', '--output', 'text') } }
        'secret' { return @{ Mode = 'nonempty'; Args = @('secretsmanager', 'describe-secret', '--secret-id', $id, '--query', 'Name', '--output', 'text') } }
        's3-bucket' { return @{ Mode = 'exit'; Args = @('s3api', 'head-bucket', '--bucket', $id) } }
        'iam-role' { return @{ Mode = 'nonempty'; Args = @('iam', 'get-role', '--role-name', $id, '--query', 'Role.RoleName', '--output', 'text') } }
        'instance-profile' { return @{ Mode = 'nonempty'; Args = @('iam', 'get-instance-profile', '--instance-profile-name', $id, '--query', 'InstanceProfile.InstanceProfileName', '--output', 'text') } }
        'iam-user' { return @{ Mode = 'nonempty'; Args = @('iam', 'get-user', '--user-name', $id, '--query', 'User.UserName', '--output', 'text') } }
        'iam-policy' {
            $arn = "$($Item.Arn)"
            if (-not $arn) { return $null }
            return @{ Mode = 'nonempty'; Args = @('iam', 'get-policy', '--policy-arn', $arn, '--query', 'Policy.PolicyName', '--output', 'text') }
        }
        'log-group' { return @{ Mode = 'nonempty'; Args = @('logs', 'describe-log-groups', '--log-group-name-prefix', $id, '--query', "logGroups[?logGroupName=='$id'].logGroupName", '--output', 'text') } }
        'lambda-function' { return @{ Mode = 'nonempty'; Args = @('lambda', 'get-function', '--function-name', $id, '--query', 'Configuration.FunctionName', '--output', 'text') } }
        'eventbridge-rule' { return @{ Mode = 'nonempty'; Args = @('events', 'describe-rule', '--name', $id, '--query', 'Name', '--output', 'text') } }
        'sns-topic' { return @{ Mode = 'nonempty'; Args = @('sns', 'get-topic-attributes', '--topic-arn', (Get-LabTopicArn -Name $id), '--query', 'Attributes.TopicArn', '--output', 'text') } }
        'cloudwatch-alarm' { return @{ Mode = 'nonempty'; Args = @('cloudwatch', 'describe-alarms', '--alarm-names', $id, '--query', 'MetricAlarms[].AlarmName', '--output', 'text') } }
        'cloudtrail-trail' { return @{ Mode = 'nonempty'; Args = @('cloudtrail', 'describe-trails', '--trail-name-list', $id, '--query', 'trailList[].Name', '--output', 'text') } }
        'guardduty-detector' { return @{ Mode = 'nonempty'; Args = @('guardduty', 'get-detector', '--detector-id', $id, '--query', 'Status', '--output', 'text') } }
        'kms-key' { return @{ Mode = 'notpending'; Args = @('kms', 'describe-key', '--key-id', $id, '--query', 'KeyMetadata.KeyState', '--output', 'text') } }
        'codecommit-repo' { return @{ Mode = 'nonempty'; Args = @('codecommit', 'get-repository', '--repository-name', $id, '--query', 'repositoryMetadata.repositoryName', '--output', 'text') } }
        'logs-metric-filter' {
            $p = $id -split '\|', 2
            if ($p.Count -ne 2) { return $null }
            return @{ Mode = 'nonempty'; Args = @('logs', 'describe-metric-filters', '--log-group-name', $p[0], '--filter-name-prefix', $p[1], '--query', "metricFilters[?filterName=='$($p[1])'].filterName", '--output', 'text') }
        }
        'sns-subscription' {
            $p = $id -split '\|'
            if ($p.Count -lt 3) { return $null }
            return @{ Mode = 'confirmedsub'; Args = @('sns', 'list-subscriptions-by-topic', '--topic-arn', $p[0], '--query', "Subscriptions[?Endpoint=='$($p[2])'].SubscriptionArn", '--output', 'text') }
        }
        'iam-access-key' {
            $u = Resolve-LabAccessKey -Id $id
            if (-not $u) { return $null }
            return @{ Mode = 'nonempty'; Args = @('iam', 'list-access-keys', '--user-name', $u.User, '--query', "AccessKeyMetadata[?AccessKeyId=='$($u.Key)'].AccessKeyId", '--output', 'text') }
        }
        default { return $null }
    }
}

function Resolve-LabAccessKey {
    <# Accepts "user|AKIA..", "user/AKIA..", "user:AKIA.." or a bare access key id (resolved through last-used). #>
    param([string]$Id)
    if ($Id -match '^([\w+=,.@-]+)[|/:]((?:AKIA|ASIA)[A-Z0-9]+)$') { return [pscustomobject]@{ User = $Matches[1]; Key = $Matches[2] } }
    if ($Id -match '^(?:AKIA|ASIA)[A-Z0-9]+$') {
        $r = Invoke-LabCli -CliArgs @('iam', 'get-access-key-last-used', '--access-key-id', $Id, '--query', 'UserName', '--output', 'text')
        $u = "$($r.Output)".Trim()
        if ($r.ExitCode -eq 0 -and $u -and $u -ne 'None') { return [pscustomobject]@{ User = $u; Key = $Id } }
    }
    return $null
}

function Test-LabItemExists {
    <# Returns 'yes', 'no' or 'unknown'. Unknown is treated as present by callers (fail safe: never claim "gone" on doubt). #>
    param($Item)
    $spec = Get-LabExistsSpec -Item $Item
    if ($null -eq $spec) { return 'unknown' }
    $r = Invoke-LabCli -CliArgs $spec.Args
    $out = "$($r.Output)".Trim()
    if ($r.ExitCode -ne 0) {
        if (Test-LabNotFound $r) { return 'no' }
        return 'unknown'
    }
    switch ($spec.Mode) {
        'exit' { return 'yes' }
        'notpending' { if ($out -match 'Pending') { return 'no' } else { return 'yes' } }
        'confirmedsub' { if (-not $out -or $out -eq 'None' -or $out -match 'PendingConfirmation') { return 'no' } else { return 'yes' } }
        default { if (-not $out -or $out -eq 'None' -or $out -eq '[]') { return 'no' } else { return 'yes' } }
    }
}

# ---------------------------------------------------------------------------
# Billable risk-class scan
# ---------------------------------------------------------------------------

function Get-LabBillableScan {
    <#
    Lists, in the lab Region, every resource of the billable risk classes: EC2 instances, EBS
    volumes, snapshots, RDS instances and snapshots, Elastic IPs, NAT gateways, load
    balancers, CloudWatch log groups, S3 buckets, Secrets Manager secrets, KMS keys,
    CloudTrail trails, GuardDuty detectors, Lambda functions, SNS topics and VPCs.
    Each result says whether it is tagged (inline tags, tagging-API index, or manifest).
    Read-only. A failed query is recorded in Errors; callers must NOT claim "nothing
    remaining" when Errors is not empty.
    #>
    param([hashtable]$Index, [hashtable]$ManifestKeys)
    $items = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList

    function Add-ScanRow {
        param([string]$Class, [string]$Type, [string]$Id, $Tags, [string]$Arn = '')
        $key = "$Type|$Id"
        $tagged = (Test-LabTagged -Tags $Tags)
        $tm = ConvertTo-LabTagMap $Tags
        if (-not $tagged -and $Index.ContainsKey($key)) { $tagged = $true; $tm = $Index[$key].Tags }
        $inMan = $ManifestKeys.ContainsKey($key)
        $it = New-LabItem -Type $Type -Id $Id -Region $script:LabRegion -Tags $tm -Arn $Arn -Source 'scan' -Tagged:$tagged -InManifest:$inMan
        $it.Billable = $true
        $it.Class = $Class
        [void]$items.Add($it)
    }

    function Invoke-ScanList {
        param([string]$Class, [string]$Type, [string[]]$CliArgs, [string]$IdField = 'id')
        $q = Invoke-LabQuery -CliArgs $CliArgs
        if (-not $q.Ok) { [void]$errors.Add("$Class query failed: $(Get-LabErrorLine $q)"); return }
        foreach ($row in @(ConvertTo-LabList $q.Data)) {
            if ($row -is [string]) { Add-ScanRow -Class $Class -Type $Type -Id $row -Tags $null; continue }
            $tags = $null
            if ($row.PSObject.Properties['tags']) { $tags = $row.tags }
            $arn = ''
            if ($row.PSObject.Properties['arn']) { $arn = "$($row.arn)" }
            Add-ScanRow -Class $Class -Type $Type -Id "$($row.$IdField)" -Tags $tags -Arn $arn
        }
    }

    Invoke-ScanList -Class 'EC2 instances' -Type 'ec2-instance' -CliArgs @('ec2', 'describe-instances', '--filters', 'Name=instance-state-name,Values=pending,running,stopping,stopped', '--query', 'Reservations[].Instances[].{id:InstanceId,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'EBS volumes' -Type 'ebs-volume' -CliArgs @('ec2', 'describe-volumes', '--query', 'Volumes[].{id:VolumeId,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'EBS snapshots' -Type 'ebs-snapshot' -CliArgs @('ec2', 'describe-snapshots', '--owner-ids', 'self', '--query', 'Snapshots[].{id:SnapshotId,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'RDS instances' -Type 'rds-instance' -CliArgs @('rds', 'describe-db-instances', '--query', 'DBInstances[].{id:DBInstanceIdentifier,tags:TagList}', '--output', 'json')
    Invoke-ScanList -Class 'RDS snapshots' -Type 'rds-snapshot' -CliArgs @('rds', 'describe-db-snapshots', '--query', 'DBSnapshots[].{id:DBSnapshotIdentifier,tags:TagList}', '--output', 'json')
    Invoke-ScanList -Class 'Elastic IPs' -Type 'elastic-ip' -CliArgs @('ec2', 'describe-addresses', '--query', 'Addresses[].{id:AllocationId,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'NAT gateways' -Type 'nat-gateway' -CliArgs @('ec2', 'describe-nat-gateways', '--filter', 'Name=state,Values=pending,available', '--query', 'NatGateways[].{id:NatGatewayId,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'Load balancers' -Type 'load-balancer' -CliArgs @('elbv2', 'describe-load-balancers', '--query', 'LoadBalancers[].{id:LoadBalancerName,arn:LoadBalancerArn}', '--output', 'json')
    Invoke-ScanList -Class 'Load balancers' -Type 'load-balancer' -CliArgs @('elb', 'describe-load-balancers', '--query', 'LoadBalancerDescriptions[].{id:LoadBalancerName}', '--output', 'json')
    Invoke-ScanList -Class 'CloudWatch log groups' -Type 'log-group' -CliArgs @('logs', 'describe-log-groups', '--query', 'logGroups[].{id:logGroupName}', '--output', 'json')
    Invoke-ScanList -Class 'Secrets Manager secrets' -Type 'secret' -CliArgs @('secretsmanager', 'list-secrets', '--query', 'SecretList[].{id:Name,tags:Tags}', '--output', 'json')
    Invoke-ScanList -Class 'CloudTrail trails' -Type 'cloudtrail-trail' -CliArgs @('cloudtrail', 'describe-trails', '--no-include-shadow-trails', '--query', 'trailList[].{id:Name}', '--output', 'json')
    Invoke-ScanList -Class 'GuardDuty detectors' -Type 'guardduty-detector' -CliArgs @('guardduty', 'list-detectors', '--query', 'DetectorIds', '--output', 'json')
    Invoke-ScanList -Class 'Lambda functions' -Type 'lambda-function' -CliArgs @('lambda', 'list-functions', '--query', 'Functions[].{id:FunctionName}', '--output', 'json')
    # SNS topics: the list returns ARNs; the id is the topic name.
    $sns = Invoke-LabQuery -CliArgs @('sns', 'list-topics', '--query', 'Topics[].TopicArn', '--output', 'json')
    if (-not $sns.Ok) { [void]$errors.Add("SNS topics query failed: $(Get-LabErrorLine $sns)") } else {
        foreach ($a in @(ConvertTo-LabList $sns.Data)) { Add-ScanRow -Class 'SNS topics' -Type 'sns-topic' -Id (("$a" -split ':')[-1]) -Tags $null -Arn "$a" }
    }
    # VPCs: the default VPC always exists and is free, so it is not a pending item.
    Invoke-ScanList -Class 'VPCs' -Type 'vpc' -CliArgs @('ec2', 'describe-vpcs', '--query', 'Vpcs[?IsDefault==`false`].{id:VpcId,tags:Tags}', '--output', 'json')

    # S3 buckets in the lab Region.
    $b = Invoke-LabQuery -CliArgs @('s3api', 'list-buckets', '--query', 'Buckets[].Name', '--output', 'json')
    if (-not $b.Ok) { [void]$errors.Add("S3 buckets query failed: $(Get-LabErrorLine $b)") } else {
        foreach ($n in @(ConvertTo-LabList $b.Data)) {
            $name = "$n"
            if (-not $Index.ContainsKey("s3-bucket|$name")) {
                $loc = Invoke-LabCli -CliArgs @('s3api', 'get-bucket-location', '--bucket', $name, '--query', 'LocationConstraint', '--output', 'text')
                if ($loc.ExitCode -ne 0) { [void]$errors.Add("S3 bucket '$name' location query failed: $(Get-LabErrorLine $loc)"); continue }
                $where = "$($loc.Output)".Trim()
                if (-not $where -or $where -eq 'None') { $where = 'us-east-1' } elseif ($where -eq 'EU') { $where = 'eu-west-1' }
                if ($where -ne $script:LabRegion) { continue }
            }
            Add-ScanRow -Class 'S3 buckets' -Type 's3-bucket' -Id $name -Tags $null
        }
    }

    # KMS customer-managed keys that are not scheduled for deletion.
    $k = Invoke-LabQuery -CliArgs @('kms', 'list-keys', '--query', 'Keys[].KeyId', '--output', 'json')
    if (-not $k.Ok) { [void]$errors.Add("KMS keys query failed: $(Get-LabErrorLine $k)") } else {
        foreach ($kid in @(ConvertTo-LabList $k.Data)) {
            $d = Invoke-LabQuery -CliArgs @('kms', 'describe-key', '--key-id', "$kid", '--query', 'KeyMetadata.{s:KeyState,m:KeyManager}', '--output', 'json')
            if (-not $d.Ok) { [void]$errors.Add("KMS key '$kid' describe failed: $(Get-LabErrorLine $d)"); continue }
            if ($d.Data -and "$($d.Data.m)" -eq 'CUSTOMER' -and "$($d.Data.s)" -notmatch 'Pending') {
                Add-ScanRow -Class 'KMS keys' -Type 'kms-key' -Id "$kid" -Tags $null
            }
        }
    }
    return [pscustomobject]@{ Items = $items.ToArray(); Errors = $errors.ToArray() }
}

# ---------------------------------------------------------------------------
# Inventory: tag:GetResources + manifest + scan, existence-checked
# ---------------------------------------------------------------------------

function Get-LabIamTagged {
    <#
    Service query for IAM (global), filtered by lab tag. IAM list calls do not return tags, so
    each user, customer role, instance profile and customer policy is tag-checked. Capped at
    200 objects per kind; a capped listing is reported in Errors (never silently truncated).
    #>
    $found = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    $kinds = @(
        @{ Type = 'iam-user'; List = @('iam', 'list-users', '--query', 'Users[].UserName', '--output', 'json'); Tags = { param($n) @('iam', 'list-user-tags', '--user-name', $n, '--query', 'Tags', '--output', 'json') } },
        @{ Type = 'iam-role'; List = @('iam', 'list-roles', '--query', "Roles[?!starts_with(Path,'/aws-service-role/')].RoleName", '--output', 'json'); Tags = { param($n) @('iam', 'list-role-tags', '--role-name', $n, '--query', 'Tags', '--output', 'json') } },
        @{ Type = 'instance-profile'; List = @('iam', 'list-instance-profiles', '--query', 'InstanceProfiles[].InstanceProfileName', '--output', 'json'); Tags = { param($n) @('iam', 'list-instance-profile-tags', '--instance-profile-name', $n, '--query', 'Tags', '--output', 'json') } }
    )
    foreach ($k in $kinds) {
        $l = Invoke-LabQuery -CliArgs $k.List
        if (-not $l.Ok) { [void]$errors.Add("IAM $($k.Type) listing failed: $(Get-LabErrorLine $l)"); continue }
        $names = @(ConvertTo-LabList $l.Data)
        if ($names.Count -gt 200) { [void]$errors.Add("IAM $($k.Type) listing has $($names.Count) entries; only the first 200 were tag-checked"); $names = $names | Select-Object -First 200 }
        foreach ($n in $names) {
            $targs = & $k.Tags "$n"
            $t = Invoke-LabQuery -CliArgs $targs
            if ($t.Ok -and (Test-LabTagged -Tags $t.Data)) {
                [void]$found.Add((New-LabItem -Type $k.Type -Id "$n" -Region 'global' -Tags $t.Data -Source 'iam-query' -Tagged))
            }
        }
    }
    $pl = Invoke-LabQuery -CliArgs @('iam', 'list-policies', '--scope', 'Local', '--query', 'Policies[].{n:PolicyName,a:Arn}', '--output', 'json')
    if (-not $pl.Ok) { [void]$errors.Add("IAM policy listing failed: $(Get-LabErrorLine $pl)") } else {
        foreach ($p in @(ConvertTo-LabList $pl.Data | Select-Object -First 200)) {
            $t = Invoke-LabQuery -CliArgs @('iam', 'list-policy-tags', '--policy-arn', "$($p.a)", '--query', 'Tags', '--output', 'json')
            if ($t.Ok -and (Test-LabTagged -Tags $t.Data)) {
                [void]$found.Add((New-LabItem -Type 'iam-policy' -Id "$($p.n)" -Region 'global' -Tags $t.Data -Arn "$($p.a)" -Source 'iam-query' -Tagged))
            }
        }
    }
    return [pscustomobject]@{ Items = $found.ToArray(); Errors = $errors.ToArray() }
}

function Get-LabTaggedMappings {
    <# tag:GetResources for the lab tag in the lab Region (and IAM through us-east-1). #>
    param([string]$Region)
    $regions = New-Object System.Collections.ArrayList
    [void]$regions.Add($Region)
    if ($Region -ne $script:LabGlobalRegion) { [void]$regions.Add($script:LabGlobalRegion) }
    $found = New-Object System.Collections.ArrayList
    $errors = New-Object System.Collections.ArrayList
    foreach ($rg in $regions) {
        $isPrimary = ($rg -eq $Region)
        $q = Use-LabRegion -Region $rg -Script {
            Invoke-LabQuery -CliArgs @('resourcegroupstaggingapi', 'get-resources', '--tag-filters', "Key=$($script:LabTagKey),Values=$($script:LabTagValue)", '--query', 'ResourceTagMappingList[].{a:ResourceARN,t:Tags}', '--output', 'json')
        }
        if (-not $q.Ok) {
            if ($isPrimary) { Stop-Lab -Code 1 -Message "Tag discovery failed (tag:GetResources in $rg): $(Get-LabErrorLine $q). No changes were made." }
            [void]$errors.Add("tag:GetResources in $rg (global IAM) failed: $(Get-LabErrorLine $q)")
            continue
        }
        foreach ($m in @(ConvertTo-LabList $q.Data)) {
            $p = ConvertFrom-LabArn -Arn "$($m.a)"
            if ($null -eq $p) { continue }
            # The secondary (us-east-1) call only contributes global IAM resources.
            if (-not $isPrimary -and $p.Service -ne 'iam') { continue }
            $region = $p.Region
            if (-not $region) { $region = $rg }
            if ($p.Service -eq 'iam') { $region = 'global' }
            $it = New-LabItem -Type $p.Type -Id $p.Id -Region $region -Tags $m.t -Arn "$($m.a)" -Source 'tag' -Tagged
            [void]$found.Add($it)
        }
    }
    return [pscustomobject]@{ Items = $found.ToArray(); Errors = $errors.ToArray() }
}

function Get-LabInventory {
    <#
    Builds the set of lab-owned resources that currently EXIST.
      Sources: tag:GetResources (lab tag), the lab manifest, and the lab tag-tagged hits of the
      billable scan. Untagged billable resources that are not in the manifest are returned in
      Unmarked and are never part of Items.
    -RunId limits Items to that run (items of other runs are only counted in OtherRun).
    -SkipScan skips the billable scan (used for the cheap second look after a deletion pass).
    #>
    param([string]$Region, [string]$RunId, [string]$ManifestPath, [switch]$SkipScan)
    $table = @{}
    $errors = New-Object System.Collections.ArrayList
    $stale = 0

    $tag = Get-LabTaggedMappings -Region $Region
    foreach ($e in $tag.Errors) { [void]$errors.Add($e) }
    foreach ($it in $tag.Items) { Merge-LabItem -Table $table -Item $it }
    $iam = Get-LabIamTagged
    foreach ($e in $iam.Errors) { [void]$errors.Add($e) }
    foreach ($it in $iam.Items) { Merge-LabItem -Table $table -Item $it }
    $index = @{}
    foreach ($k in @($table.Keys)) { $index[$k] = $table[$k] }

    $manifestKeys = @{}
    foreach ($m in @(Read-LabManifestEntries -ManifestPath $ManifestPath)) {
        if ($m.Region -and $m.Region -ne $Region -and $m.Region -ne 'global') { continue }
        if ($m.Type -eq 'nacl-entry') { continue }   # removed together with its (tagged) network ACL
        $mReg = $m.Region
        if (-not $mReg) { $mReg = $Region }
        $mi = New-LabItem -Type $m.Type -Id $m.Id -Region $mReg -Tags @{} -RunId $m.RunId -Source 'manifest' -InManifest
        if ($m.Component) { $mi.Component = $m.Component }
        if ($m.Reused) { $mi.Reused = $true }
        Merge-LabItem -Table $table -Item $mi
        $manifestKeys[$mi.Key] = $true
    }

    $unmarked = @()
    $scanErrors = @()
    if (-not $SkipScan) {
        $scan = Get-LabBillableScan -Index $index -ManifestKeys $manifestKeys
        $scanErrors = @($scan.Errors)
        foreach ($s in $scan.Items) {
            if ($s.Tagged -or $s.InManifest) { Merge-LabItem -Table $table -Item $s }
            else { $unmarked += $s }
        }
    }

    # Existence check for everything that did not come from a live listing.
    $present = New-Object System.Collections.ArrayList
    foreach ($k in @($table.Keys | Sort-Object)) {
        $it = $table[$k]
        if (($it.Sources -notcontains 'scan') -and ($it.Sources -notcontains 'iam-query')) {
            $ex = Test-LabItemExists -Item $it
            if ($ex -eq 'no') { $stale++; continue }
            if ($ex -eq 'unknown' -and $it.Type -notlike 'unsupported:*') { $it.Detail = 'existence could not be confirmed' }
        }
        # Class labels for billable types found via tag/manifest (so verify can group them).
        $it.Phase = Get-LabItemPhase -Item $it
        if (-not $it.Evidence -and $it.Component -eq 'evidence') { $it.Evidence = 'true' }
        [void]$present.Add($it)
    }

    # Derived items: undo NACL deny entries and open ingress rules on lab security groups.
    foreach ($it in @($present.ToArray())) {
        if ($it.Type -eq 'network-acl') {
            $n = Invoke-LabQuery -CliArgs @('ec2', 'describe-network-acls', '--network-acl-ids', $it.Id, '--query', 'NetworkAcls[0].Entries', '--output', 'json')
            if ($n.Ok) {
                foreach ($en in @(ConvertTo-LabList $n.Data)) {
                    if (-not $en.Egress -and "$($en.RuleAction)" -eq 'deny' -and [int]$en.RuleNumber -ge 100 -and [int]$en.RuleNumber -le 199) {
                        $d = New-LabItem -Type 'nacl-block-entry' -Id "$($it.Id)/$($en.RuleNumber)" -Region $it.Region -Tags @{} -RunId $it.RunId -Source 'derived' -Tagged
                        $d.Detail = "deny $($en.CidrBlock)"; $d.Phase = 10
                        [void]$present.Add($d)
                    }
                }
            }
        } elseif ($it.Type -eq 'security-group') {
            $g = Invoke-LabQuery -CliArgs @('ec2', 'describe-security-groups', '--group-ids', $it.Id, '--query', 'SecurityGroups[0].IpPermissions', '--output', 'json')
            if ($g.Ok) {
                $perms = @(ConvertTo-LabList $g.Data)
                if ($perms.Count -gt 0) {
                    $d = New-LabItem -Type 'sg-ingress-rule' -Id "$($it.Id)" -Region $it.Region -Tags @{} -RunId $it.RunId -Source 'derived' -Tagged
                    $d.Detail = "$($perms.Count) ingress permission(s) to revoke"; $d.Phase = 12
                    [void]$present.Add($d)
                }
            }
        }
    }

    # Run filter. Resources the lab only reused (recorded with ownership "reused") are split off:
    # they are reported as kept and never reach a removal plan or the pending list.
    $items = New-Object System.Collections.ArrayList
    $reusedItems = New-Object System.Collections.ArrayList
    $otherRun = 0
    foreach ($it in $present) {
        if ($it.Reused) { [void]$reusedItems.Add($it); continue }
        if ($RunId -and "$($it.RunId)" -ne $RunId) { $otherRun++; continue }
        [void]$items.Add($it)
    }
    $sorted = @($items.ToArray() | Sort-Object -Property @{ Expression = { $_.Phase } }, @{ Expression = { $_.Type } }, @{ Expression = { $_.Id } })
    return [pscustomobject]@{
        Items = $sorted; Reused = @($reusedItems.ToArray()); Unmarked = @($unmarked); Errors = @($errors.ToArray()); ScanErrors = $scanErrors
        Stale = $stale; OtherRun = $otherRun; Index = $index
    }
}

# ---------------------------------------------------------------------------
# Evidence: tagging as preserved and the monthly cost of keeping it
# ---------------------------------------------------------------------------

function Set-LabEvidencePreserved {
    <# Tags an evidence resource evidence=preserved. Returns $true on success. #>
    param($Item)
    switch ($Item.Type) {
        'ebs-snapshot' {
            $r = Invoke-LabCli -Mutating -CliArgs @('ec2', 'create-tags', '--resources', $Item.Id, '--tags', 'Key=evidence,Value=preserved')
            return ($r.ExitCode -eq 0)
        }
        'rds-snapshot' {
            $arn = "arn:aws:rds:$($script:LabRegion):$(Get-LabAccountId):snapshot:$($Item.Id)"
            $r = Invoke-LabCli -Mutating -CliArgs @('rds', 'add-tags-to-resource', '--resource-name', $arn, '--tags', 'Key=evidence,Value=preserved')
            return ($r.ExitCode -eq 0)
        }
        's3-bucket' {
            $cur = Invoke-LabQuery -CliArgs @('s3api', 'get-bucket-tagging', '--bucket', $Item.Id, '--query', 'TagSet', '--output', 'json')
            $set = New-Object System.Collections.ArrayList
            if ($cur.Ok) {
                foreach ($t in @(ConvertTo-LabList $cur.Data)) { if ("$($t.Key)" -ne 'evidence') { [void]$set.Add([ordered]@{ Key = "$($t.Key)"; Value = "$($t.Value)" }) } }
            }
            [void]$set.Add([ordered]@{ Key = 'evidence'; Value = 'preserved' })
            $json = ([ordered]@{ TagSet = $set.ToArray() }) | ConvertTo-Json -Depth 5 -Compress
            $r = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-bucket-tagging', '--bucket', $Item.Id, '--tagging', (New-LabTempFile -Text $json))
            return ($r.ExitCode -eq 0)
        }
        default { return $false }
    }
}

function Get-LabEvidenceCost {
    <# Estimated monthly cost (USD) of keeping one evidence resource; $null when the size cannot be read. #>
    param($Item)
    switch ($Item.Type) {
        'ebs-snapshot' {
            $q = Invoke-LabCli -CliArgs @('ec2', 'describe-snapshots', '--snapshot-ids', $Item.Id, '--query', 'Snapshots[0].VolumeSize', '--output', 'text')
            $gb = 0.0
            if ($q.ExitCode -eq 0 -and [double]::TryParse("$($q.Output)".Trim(), [ref]$gb)) { return [math]::Round($gb * $script:LabPriceEbsSnapshotGbMonth, 4) }
            return $null
        }
        'rds-snapshot' {
            $q = Invoke-LabCli -CliArgs @('rds', 'describe-db-snapshots', '--db-snapshot-identifier', $Item.Id, '--query', 'DBSnapshots[0].AllocatedStorage', '--output', 'text')
            $gb = 0.0
            if ($q.ExitCode -eq 0 -and [double]::TryParse("$($q.Output)".Trim(), [ref]$gb)) { return [math]::Round($gb * $script:LabPriceRdsSnapshotGbMonth, 4) }
            return $null
        }
        's3-bucket' {
            $q = Invoke-LabQuery -CliArgs @('s3api', 'list-object-versions', '--bucket', $Item.Id, '--query', '{v:Versions[].Size}', '--output', 'json')
            if (-not $q.Ok) { return $null }
            $bytes = 0.0
            if ($q.Data -and $q.Data.v) { foreach ($s in @(ConvertTo-LabList $q.Data.v)) { $bytes += [double]$s } }
            return [math]::Round(($bytes / 1GB) * $script:LabPriceS3StandardGbMonth, 4)
        }
        default { return $null }
    }
}

# ---------------------------------------------------------------------------
# Removal (used by full-teardown.ps1 only)
# ---------------------------------------------------------------------------

function New-LabResult {
    param([string]$Status, [string]$Detail = '', [string]$RetainUntil = '')
    return [pscustomobject]@{ Status = $Status; Detail = $Detail; RetainUntil = $RetainUntil }
}

function Invoke-LabRm {
    <# One mutating call. 'absent' when the resource is already gone; retries dependency errors. #>
    param([string[]]$CliArgs, [int]$Retries = 0)
    $attempt = 0
    while ($true) {
        $attempt++
        $r = Invoke-LabCli -Mutating -CliArgs $CliArgs
        if ($r.ExitCode -eq 0) { return (New-LabResult 'removed') }
        if (Test-LabNotFound $r) { return (New-LabResult 'absent') }
        if ($attempt -le $Retries -and "$($r.Output)" -match 'DependencyViolation|has dependencies|InvalidDBSubnetGroupStateFault|InvalidDBInstanceState|IncorrectState|VolumeInUse|is in use|in use') {
            if ($script:LabRetryDelay -gt 0) { Start-Sleep -Seconds $script:LabRetryDelay }
            continue
        }
        return (New-LabResult 'failed' (Get-LabErrorLine $r))
    }
}

function Invoke-LabTolerant {
    <# Preparation step whose failure is not an error by itself (the final delete decides). #>
    param([string[]]$CliArgs)
    $null = Invoke-LabCli -Mutating -CliArgs $CliArgs
}

function Remove-LabBucket {
    <#
    Empties (all versions and delete markers) and deletes an S3 bucket. If S3 Object Lock
    retention blocks version deletions the bucket is kept and the result is 'retention',
    carrying the latest retain-until date found.
    #>
    param([string]$Bucket)
    $lock = Invoke-LabCli -CliArgs @('s3api', 'get-object-lock-configuration', '--bucket', $Bucket, '--output', 'json')
    if ($lock.ExitCode -ne 0 -and (Test-LabNotFound $lock) -and "$($lock.Output)" -match 'NoSuchBucket|404') { return (New-LabResult 'absent') }
    $lockEnabled = ($lock.ExitCode -eq 0)

    $v = Invoke-LabQuery -CliArgs @('s3api', 'list-object-versions', '--bucket', $Bucket, '--query', '{v:Versions[].{Key:Key,VersionId:VersionId},m:DeleteMarkers[].{Key:Key,VersionId:VersionId}}', '--output', 'json')
    if (-not $v.Ok) {
        if ("$($v.Output)" -match 'NoSuchBucket|404') { return (New-LabResult 'absent') }
        return (New-LabResult 'failed' (Get-LabErrorLine $v))
    }
    $objs = New-Object System.Collections.ArrayList
    if ($v.Data) {
        foreach ($o in @(ConvertTo-LabList $v.Data.v)) { [void]$objs.Add([ordered]@{ Key = "$($o.Key)"; VersionId = "$($o.VersionId)" }) }
        foreach ($o in @(ConvertTo-LabList $v.Data.m)) { [void]$objs.Add([ordered]@{ Key = "$($o.Key)"; VersionId = "$($o.VersionId)" }) }
    }

    $blocked = New-Object System.Collections.ArrayList
    $other = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $objs.Count; $i += 500) {
        $n = [math]::Min(500, $objs.Count - $i)
        $batch = $objs.GetRange($i, $n)
        $body = ([ordered]@{ Objects = $batch.ToArray(); Quiet = $true }) | ConvertTo-Json -Depth 5 -Compress
        $args2 = @('s3api', 'delete-objects', '--bucket', $Bucket, '--delete', (New-LabTempFile -Text $body), '--output', 'json')
        if ($lockEnabled) { $args2 += '--bypass-governance-retention' }
        $d = Invoke-LabCli -Mutating -CliArgs $args2
        if ($d.ExitCode -ne 0) {
            if ("$($d.Output)" -match 'AccessDenied' -and $lockEnabled) { foreach ($o in $batch) { [void]$blocked.Add($o) } }
            else { [void]$other.Add((Get-LabErrorLine $d)) }
            continue
        }
        $res = ConvertFrom-LabJson -Text "$($d.Output)"
        if ($res -and $res.PSObject.Properties['Errors']) {
            foreach ($er in @(ConvertTo-LabList $res.Errors)) {
                if ("$($er.Code)" -eq 'AccessDenied' -and "$($er.Message)" -match '(?i)object lock|retention|legal hold|protected') {
                    [void]$blocked.Add([ordered]@{ Key = "$($er.Key)"; VersionId = "$($er.VersionId)" })
                } else { [void]$other.Add("$($er.Code) $($er.Key)") }
            }
        }
    }

    if ($blocked.Count -gt 0) {
        $latest = $null
        $checked = 0
        foreach ($o in $blocked) {
            if ($checked -ge 50) { break }
            $checked++
            $rt = Invoke-LabCli -CliArgs @('s3api', 'get-object-retention', '--bucket', $Bucket, '--key', $o.Key, '--version-id', $o.VersionId, '--query', 'Retention.RetainUntilDate', '--output', 'text')
            $dt = [datetime]::MinValue
            if ($rt.ExitCode -eq 0 -and [datetime]::TryParse("$($rt.Output)".Trim(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
                if ($null -eq $latest -or $dt -gt $latest) { $latest = $dt }
            }
        }
        $when = 'unknown (a legal hold or an unreadable retention is in place)'
        if ($null -ne $latest) { $when = $latest.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture) }
        return (New-LabResult 'retention' "$($blocked.Count) object version(s) under Object Lock" $when)
    }
    if ($other.Count -gt 0) { return (New-LabResult 'failed' ("could not delete objects: " + ($other[0]))) }
    return (Invoke-LabRm -CliArgs @('s3api', 'delete-bucket', '--bucket', $Bucket))
}

function Remove-LabIamUser {
    param([string]$User)
    $chk = Invoke-LabCli -CliArgs @('iam', 'get-user', '--user-name', $User, '--query', 'User.UserName', '--output', 'text')
    if ($chk.ExitCode -ne 0 -and (Test-LabNotFound $chk)) { return (New-LabResult 'absent') }
    $problems = New-Object System.Collections.ArrayList

    $keys = Invoke-LabQuery -CliArgs @('iam', 'list-access-keys', '--user-name', $User, '--query', 'AccessKeyMetadata[].AccessKeyId', '--output', 'json')
    foreach ($kid in @(ConvertTo-LabList $keys.Data)) {
        Invoke-LabTolerant -CliArgs @('iam', 'update-access-key', '--user-name', $User, '--access-key-id', "$kid", '--status', 'Inactive')
        $d = Invoke-LabRm -CliArgs @('iam', 'delete-access-key', '--user-name', $User, '--access-key-id', "$kid")
        if ($d.Status -eq 'failed') { [void]$problems.Add("access key $kid : $($d.Detail)") }
    }
    $pol = Invoke-LabQuery -CliArgs @('iam', 'list-user-policies', '--user-name', $User, '--query', 'PolicyNames', '--output', 'json')
    foreach ($pn in @(ConvertTo-LabList $pol.Data)) {
        $d = Invoke-LabRm -CliArgs @('iam', 'delete-user-policy', '--user-name', $User, '--policy-name', "$pn")
        if ($d.Status -eq 'failed') { [void]$problems.Add("inline policy $pn : $($d.Detail)") }
    }
    $att = Invoke-LabQuery -CliArgs @('iam', 'list-attached-user-policies', '--user-name', $User, '--query', 'AttachedPolicies[].PolicyArn', '--output', 'json')
    foreach ($pa in @(ConvertTo-LabList $att.Data)) {
        $d = Invoke-LabRm -CliArgs @('iam', 'detach-user-policy', '--user-name', $User, '--policy-arn', "$pa")
        if ($d.Status -eq 'failed') { [void]$problems.Add("attached policy $pa : $($d.Detail)") }
    }
    $grp = Invoke-LabQuery -CliArgs @('iam', 'list-groups-for-user', '--user-name', $User, '--query', 'Groups[].GroupName', '--output', 'json')
    foreach ($gn in @(ConvertTo-LabList $grp.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'remove-user-from-group', '--user-name', $User, '--group-name', "$gn") }
    Invoke-LabTolerant -CliArgs @('iam', 'delete-login-profile', '--user-name', $User)
    if ($problems.Count -gt 0) { return (New-LabResult 'failed' ($problems -join '; ')) }
    return (Invoke-LabRm -CliArgs @('iam', 'delete-user', '--user-name', $User))
}

function Remove-LabIamRole {
    param([string]$Role)
    $chk = Invoke-LabCli -CliArgs @('iam', 'get-role', '--role-name', $Role, '--query', 'Role.RoleName', '--output', 'text')
    if ($chk.ExitCode -ne 0 -and (Test-LabNotFound $chk)) { return (New-LabResult 'absent') }
    $pr = Invoke-LabQuery -CliArgs @('iam', 'list-instance-profiles-for-role', '--role-name', $Role, '--query', 'InstanceProfiles[].InstanceProfileName', '--output', 'json')
    foreach ($ip in @(ConvertTo-LabList $pr.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'remove-role-from-instance-profile', '--instance-profile-name', "$ip", '--role-name', $Role) }
    $ap = Invoke-LabQuery -CliArgs @('iam', 'list-attached-role-policies', '--role-name', $Role, '--query', 'AttachedPolicies[].PolicyArn', '--output', 'json')
    foreach ($a in @(ConvertTo-LabList $ap.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'detach-role-policy', '--role-name', $Role, '--policy-arn', "$a") }
    $ip2 = Invoke-LabQuery -CliArgs @('iam', 'list-role-policies', '--role-name', $Role, '--query', 'PolicyNames', '--output', 'json')
    foreach ($n in @(ConvertTo-LabList $ip2.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'delete-role-policy', '--role-name', $Role, '--policy-name', "$n") }
    return (Invoke-LabRm -CliArgs @('iam', 'delete-role', '--role-name', $Role))
}

function Remove-LabItem {
    <#
    Removes ONE inventory item. Refuses (throws) when the item is neither tagged nor in the
    manifest: this is the last line of defence against removing anything the lab does not own.
    #>
    param($Item)
    if (-not ($Item.Tagged -or $Item.InManifest)) {
        throw "Refusing to remove $($Item.Type) '$($Item.Id)': it has neither lab tag nor a manifest entry."
    }
    $id = "$($Item.Id)"
    switch -Exact ($Item.Type) {
        'nacl-block-entry' {
            $p = $id -split '/'
            return (Invoke-LabRm -CliArgs @('ec2', 'delete-network-acl-entry', '--network-acl-id', $p[0], '--rule-number', $p[1], '--ingress'))
        }
        'sg-ingress-rule' {
            $g = Invoke-LabQuery -CliArgs @('ec2', 'describe-security-groups', '--group-ids', $id, '--query', 'SecurityGroups[0].IpPermissions', '--output', 'json')
            if (-not $g.Ok) { if (Test-LabNotFound (@{ ExitCode = $g.ExitCode; Output = $g.Output })) { return (New-LabResult 'absent') }; return (New-LabResult 'failed' "could not read ingress rules of $id") }
            if (@(ConvertTo-LabList $g.Data).Count -eq 0) { return (New-LabResult 'absent') }
            return (Invoke-LabRm -CliArgs @('ec2', 'revoke-security-group-ingress', '--group-id', $id, '--ip-permissions', (New-LabTempFile -Text ($g.Output.Trim()))))
        }
        'eventbridge-rule' {
            $t = Invoke-LabQuery -CliArgs @('events', 'list-targets-by-rule', '--rule', $id, '--query', 'Targets[].Id', '--output', 'json')
            $tids = @(ConvertTo-LabList $t.Data | ForEach-Object { "$_" })
            if ($tids.Count -gt 0) { Invoke-LabTolerant -CliArgs (@('events', 'remove-targets', '--rule', $id, '--ids') + $tids) }
            return (Invoke-LabRm -CliArgs @('events', 'delete-rule', '--name', $id))
        }
        'lambda-function' { return (Invoke-LabRm -CliArgs @('lambda', 'delete-function', '--function-name', $id)) }
        'cloudwatch-alarm' { return (Invoke-LabRm -CliArgs @('cloudwatch', 'delete-alarms', '--alarm-names', $id)) }
        'logs-metric-filter' {
            $p = $id -split '\|', 2
            return (Invoke-LabRm -CliArgs @('logs', 'delete-metric-filter', '--log-group-name', $p[0], '--filter-name', $p[1]))
        }
        'flow-log' { return (Invoke-LabRm -CliArgs @('ec2', 'delete-flow-logs', '--flow-log-ids', $id)) }
        'log-group' { return (Invoke-LabRm -CliArgs @('logs', 'delete-log-group', '--log-group-name', $id)) }
        'cloudtrail-trail' {
            Invoke-LabTolerant -CliArgs @('cloudtrail', 'stop-logging', '--name', $id)
            return (Invoke-LabRm -CliArgs @('cloudtrail', 'delete-trail', '--name', $id))
        }
        'guardduty-detector' { return (Invoke-LabRm -CliArgs @('guardduty', 'delete-detector', '--detector-id', $id)) }
        'sns-subscription' {
            $p = $id -split '\|'
            $s = Invoke-LabQuery -CliArgs @('sns', 'list-subscriptions-by-topic', '--topic-arn', $p[0], '--query', "Subscriptions[?Endpoint=='$($p[2])'].SubscriptionArn", '--output', 'json')
            $any = $false
            foreach ($sa in @(ConvertTo-LabList $s.Data)) {
                if ("$sa" -notmatch '^arn:') { continue }
                $any = $true
                $d = Invoke-LabRm -CliArgs @('sns', 'unsubscribe', '--subscription-arn', "$sa")
                if ($d.Status -eq 'failed') { return $d }
            }
            if ($any) { return (New-LabResult 'removed') }
            return (New-LabResult 'absent')
        }
        'sns-topic' { return (Invoke-LabRm -CliArgs @('sns', 'delete-topic', '--topic-arn', (Get-LabTopicArn -Name $id))) }
        'ec2-instance' {
            $d = Invoke-LabRm -CliArgs @('ec2', 'terminate-instances', '--instance-ids', $id)
            if ($d.Status -eq 'removed') {
                $w = Invoke-LabCli -Mutating -CliArgs @('ec2', 'wait', 'instance-terminated', '--instance-ids', $id)
                if ($w.ExitCode -ne 0) { return (New-LabResult 'failed' 'instance did not reach the terminated state in time') }
            }
            return $d
        }
        'nat-gateway' {
            $d = Invoke-LabRm -CliArgs @('ec2', 'delete-nat-gateway', '--nat-gateway-id', $id)
            if ($d.Status -eq 'removed') { Invoke-LabTolerant -CliArgs @('ec2', 'wait', 'nat-gateway-deleted', '--nat-gateway-ids', $id) }
            return $d
        }
        'elastic-ip' { return (Invoke-LabRm -Retries 3 -CliArgs @('ec2', 'release-address', '--allocation-id', $id)) }
        'ebs-volume' { return (Invoke-LabRm -Retries 4 -CliArgs @('ec2', 'delete-volume', '--volume-id', $id)) }
        'key-pair' { return (Invoke-LabRm -CliArgs @('ec2', 'delete-key-pair', '--key-pair-id', $id)) }
        'rds-instance' {
            $d = Invoke-LabRm -CliArgs @('rds', 'delete-db-instance', '--db-instance-identifier', $id, '--skip-final-snapshot', '--delete-automated-backups')
            if ($d.Status -eq 'removed') {
                $w = Invoke-LabCli -Mutating -CliArgs @('rds', 'wait', 'db-instance-deleted', '--db-instance-identifier', $id)
                if ($w.ExitCode -ne 0) { return (New-LabResult 'failed' 'RDS instance did not finish deleting in time') }
            }
            return $d
        }
        'db-subnet-group' { return (Invoke-LabRm -Retries 3 -CliArgs @('rds', 'delete-db-subnet-group', '--db-subnet-group-name', $id)) }
        'rds-snapshot' { return (Invoke-LabRm -CliArgs @('rds', 'delete-db-snapshot', '--db-snapshot-identifier', $id)) }
        'secret' { return (Invoke-LabRm -CliArgs @('secretsmanager', 'delete-secret', '--secret-id', $id, '--force-delete-without-recovery')) }
        's3-bucket' { return (Remove-LabBucket -Bucket $id) }
        'codecommit-repo' { return (Invoke-LabRm -CliArgs @('codecommit', 'delete-repository', '--repository-name', $id)) }
        'instance-profile' {
            $g = Invoke-LabQuery -CliArgs @('iam', 'get-instance-profile', '--instance-profile-name', $id, '--query', 'InstanceProfile.Roles[].RoleName', '--output', 'json')
            foreach ($rn in @(ConvertTo-LabList $g.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'remove-role-from-instance-profile', '--instance-profile-name', $id, '--role-name', "$rn") }
            return (Invoke-LabRm -CliArgs @('iam', 'delete-instance-profile', '--instance-profile-name', $id))
        }
        'iam-role' { return (Remove-LabIamRole -Role $id) }
        'iam-policy' {
            $arn = "$($Item.Arn)"
            if (-not $arn) { return (New-LabResult 'failed' 'policy ARN unknown') }
            $ents = Invoke-LabQuery -CliArgs @('iam', 'list-entities-for-policy', '--policy-arn', $arn, '--output', 'json')
            if ($ents.Data) {
                foreach ($u in @(ConvertTo-LabList $ents.Data.PolicyUsers)) { Invoke-LabTolerant -CliArgs @('iam', 'detach-user-policy', '--user-name', "$($u.UserName)", '--policy-arn', $arn) }
                foreach ($r in @(ConvertTo-LabList $ents.Data.PolicyRoles)) { Invoke-LabTolerant -CliArgs @('iam', 'detach-role-policy', '--role-name', "$($r.RoleName)", '--policy-arn', $arn) }
                foreach ($g in @(ConvertTo-LabList $ents.Data.PolicyGroups)) { Invoke-LabTolerant -CliArgs @('iam', 'detach-group-policy', '--group-name', "$($g.GroupName)", '--policy-arn', $arn) }
            }
            $vers = Invoke-LabQuery -CliArgs @('iam', 'list-policy-versions', '--policy-arn', $arn, '--query', 'Versions[?IsDefaultVersion==`false`].VersionId', '--output', 'json')
            foreach ($vv in @(ConvertTo-LabList $vers.Data)) { Invoke-LabTolerant -CliArgs @('iam', 'delete-policy-version', '--policy-arn', $arn, '--version-id', "$vv") }
            return (Invoke-LabRm -CliArgs @('iam', 'delete-policy', '--policy-arn', $arn))
        }
        'security-group' { return (Invoke-LabRm -Retries 6 -CliArgs @('ec2', 'delete-security-group', '--group-id', $id)) }
        'subnet' { return (Invoke-LabRm -Retries 6 -CliArgs @('ec2', 'delete-subnet', '--subnet-id', $id)) }
        'network-acl' { return (Invoke-LabRm -Retries 3 -CliArgs @('ec2', 'delete-network-acl', '--network-acl-id', $id)) }
        'route-table' { return (Invoke-LabRm -Retries 3 -CliArgs @('ec2', 'delete-route-table', '--route-table-id', $id)) }
        'internet-gateway' {
            $a = Invoke-LabQuery -CliArgs @('ec2', 'describe-internet-gateways', '--internet-gateway-ids', $id, '--query', 'InternetGateways[0].Attachments[].VpcId', '--output', 'json')
            foreach ($vp in @(ConvertTo-LabList $a.Data)) { Invoke-LabTolerant -CliArgs @('ec2', 'detach-internet-gateway', '--internet-gateway-id', $id, '--vpc-id', "$vp") }
            return (Invoke-LabRm -Retries 3 -CliArgs @('ec2', 'delete-internet-gateway', '--internet-gateway-id', $id))
        }
        'vpc' { return (Invoke-LabRm -Retries 3 -CliArgs @('ec2', 'delete-vpc', '--vpc-id', $id)) }
        'kms-key' { return (Invoke-LabRm -CliArgs @('kms', 'schedule-key-deletion', '--key-id', $id, '--pending-window-in-days', '7')) }
        'ebs-snapshot' { return (Invoke-LabRm -CliArgs @('ec2', 'delete-snapshot', '--snapshot-id', $id)) }
        'iam-access-key' {
            $u = Resolve-LabAccessKey -Id $id
            if (-not $u) { return (New-LabResult 'failed' 'could not resolve the owner of this access key') }
            Invoke-LabTolerant -CliArgs @('iam', 'update-access-key', '--user-name', $u.User, '--access-key-id', $u.Key, '--status', 'Inactive')
            return (Invoke-LabRm -CliArgs @('iam', 'delete-access-key', '--user-name', $u.User, '--access-key-id', $u.Key))
        }
        'iam-user' { return (Remove-LabIamUser -User $id) }
        default { return (New-LabResult 'failed' "no removal routine for resource type '$($Item.Type)' (left untouched)") }
    }
}
