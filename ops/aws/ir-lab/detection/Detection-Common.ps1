<#
.SYNOPSIS
    Shared helpers for the AWS detection stack scripts (ops/aws/ir-lab/detection).

.DESCRIPTION
    Dot-source it from each script:
        . "$PSScriptRoot\Detection-Common.ps1"

    What it provides:
      - Resource names derived from the cloud config through Get-AwsLabNames
        (ops/aws/AwsLabNames.ps1), exposed as $script:Lab* variables and as the
        $script:LabNames table. No resource name is typed in this file.
      - Invoke-LabCli: the single seam through which every AWS CLI call goes.
        * Mutating calls are only echoed (not executed) when -WhatIf is active.
        * Every executed command is echoed before it runs, with secrets masked.
        * Tests can intercept all calls by setting $global:LabCliHandler to a
          scriptblock that receives the full argument array (region included)
          and returns an object with ExitCode and Output. No AWS call is made
          while the handler is set.
      - Lab tag helpers built on Get-LabTags (lab, run-id, component) and run ids
        built on New-RunId, both from ops/lib/Common.ps1.
      - Manifest access through Add-LabManifestEntry (ops/lib/Common.ps1).
      - Alert e-mail through Resolve-LabAlertEmail and region through
        Resolve-LabRegion (both from ops/lib/Common.ps1).
      - Output masking through Hide-LabSecrets (ops/lib/Common.ps1).

    Configuration is read with Get-CloudConfig -Cloud Aws -Modality ec2 from
    ops/cloud.config.ps1. Set LAB_CONFIG_PATH to use another config file.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

. (Join-Path $PSScriptRoot '..\..\..\lib\Common.ps1')
. (Join-Path $PSScriptRoot '..\..\AwsLabNames.ps1')
. (Join-Path $PSScriptRoot '..\..\..\lib\LabPermissions.ps1')
. (Join-Path $PSScriptRoot '..\..\..\lib\LabPreflight.ps1')

# The test seam must be readable under strict mode even when no test set it.
if (-not (Test-Path -LiteralPath 'variable:global:LabCliHandler')) { $global:LabCliHandler = $null }

# Exit codes shared by the lab scripts:
#   0 success, 1 failure, 2 missing or invalid configuration,
#   3 permission missing (Stop-LabForPermission), 4 precondition or quota blocked.
# True only while the preflight reads run, so a denied read is reported as "unknown state"
# (Blocked) by Resolve-ResourceDecision instead of stopping the script inside Invoke-LabCli.
$script:LabPassDenied = $false
$script:LabStepName = 'detection'

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

function Get-LabConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($env:LAB_CONFIG_PATH)) { return $env:LAB_CONFIG_PATH }
    return (Join-Path $PSScriptRoot '..\..\..\cloud.config.ps1')
}

$script:LabConfig = $null
try {
    $script:LabConfig = Get-CloudConfig -ConfigPath (Get-LabConfigPath) -Cloud 'Aws' -Modality 'ec2'
} catch {
    Stop-Lab -Code 2 -Message "Could not load the lab configuration. $($_.Exception.Message)"
}

# Names shared by the enable/disable pairs (deterministic, so re-runs find the same resources).
$script:LabNames = Get-AwsLabNames -Config $script:LabConfig
$script:LabTagKey = 'lab'
$script:LabTagValue = [string]$script:LabNames['LabTag']
$script:LabComponent = 'detection'
$script:LabRegion = ''
$script:LabAccountId = $null
$script:LabTempFiles = New-Object System.Collections.ArrayList

$script:LabTrailName = [string]$script:LabNames['TrailName']
$script:LabAppLogGroup = [string]$script:LabNames['AppLogGroup']
$script:LabFlowLogGroup = [string]$script:LabNames['FlowLogGroup']
$script:LabFlowRoleName = [string]$script:LabNames['FlowRoleName']
$script:LabTopicName = [string]$script:LabNames['TopicName']
$script:LabFilterName = [string]$script:LabNames['FilterName']
$script:LabAlarmName = [string]$script:LabNames['AlarmName']
$script:LabMetricNamespace = [string]$script:LabNames['MetricNamespace']
$script:LabMetricName = [string]$script:LabNames['MetricName']
# Matches the access log schema of the application (event=auth_login, result=failure).
$script:LabFilterPattern = [string]$script:LabNames['FilterPattern']

function Protect-LabText {
    <# Masks secrets in text that is about to be printed (secrets must never reach the console). #>
    param([string]$Text)
    return [string](Hide-LabSecrets -Text $Text)
}

function Initialize-Lab {
    <# Resolves the region (parameter, then the config) and checks that the AWS CLI exists (unless a test handler is set). #>
    param([string]$Region)
    $script:LabRegion = Resolve-LabRegion -Region $Region -Config $script:LabConfig
    $caller = @(Get-PSCallStack | Where-Object { $_.ScriptName -and ((Split-Path -Leaf $_.ScriptName) -ne 'Detection-Common.ps1') } | Select-Object -First 1)
    if ($caller.Count -gt 0) { $script:LabStepName = [System.IO.Path]::GetFileNameWithoutExtension($caller[0].ScriptName) }
    if (-not $global:LabCliHandler) {
        if (-not (Get-Command aws -CommandType Application -ErrorAction SilentlyContinue)) {
            Stop-Lab -Code 1 -Message 'AWS CLI is not installed or not in PATH'
        }
    }
}

function Get-LabRunId {
    <# Returns the run id: the provided value, then $env:LAB_RUN_ID, then a new one from New-RunId. #>
    param([string]$RunId)
    $value = $null
    if (-not [string]::IsNullOrWhiteSpace($RunId)) { $value = $RunId.Trim() }
    elseif (-not [string]::IsNullOrWhiteSpace($env:LAB_RUN_ID)) { $value = $env:LAB_RUN_ID.Trim() }
    if ($null -eq $value) { return (New-RunId) }
    if ($value -cnotmatch '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$') {
        Stop-Lab -Code 2 -Message "Invalid run id '$value'. Expected yyyyMMddTHHmmssZ-xxxx; omit it to generate one."
    }
    return $value
}

function Invoke-LabCli {
    <#
    .SYNOPSIS
        Thin wrapper around the AWS CLI (the seam used by tests).
    .DESCRIPTION
        Returns an object with ExitCode and Output. -Mutating marks calls that
        change AWS state: they are echoed as "What if" and skipped under -WhatIf.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$CliArgs,
        [switch]$Mutating
    )
    $full = @('--region', $script:LabRegion) + $CliArgs
    $shown = Protect-LabText -Text ('aws ' + ($full -join ' '))

    if ($Mutating -and $WhatIfPreference) {
        Write-Host "What if: $shown"
        return [pscustomobject]@{ ExitCode = 0; Output = ''; Skipped = $true }
    }
    Write-Host "+ $shown"
    if ($global:LabCliHandler) {
        $r = & $global:LabCliHandler $full
        if ($null -eq $r) { $r = [pscustomobject]@{ ExitCode = 0; Output = '' } }
        return (Resolve-LabCliFailure -Result $r -CliArgs $CliArgs)
    }
    $native = $full
    if ($PSVersionTable.PSVersion -lt [version]'7.3') {
        # Older PowerShell strips embedded double quotes from native arguments.
        $native = @($full | ForEach-Object { $_ -replace '"', '\"' })
    }
    $text = (& aws @native 2>&1 | Out-String)
    $result = [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $text }
    return (Resolve-LabCliFailure -Result $result -CliArgs $CliArgs)
}

function Stop-LabForQuota {
    <# Prints the quota message for a LimitExceeded error and exits with code 4. Grants and changes nothing. #>
    param([string]$Service, [string]$Action, [string]$Step = $script:LabStepName)
    Write-Host "BLOCKED: quota reached in step '$Step' ($Service $Action returned LimitExceeded)." -ForegroundColor Red
    Write-Host '  Cause       : the account or region already holds the maximum number of this resource.' -ForegroundColor Red
    Write-Host '  Fix         : remove or reuse one of the existing resources, or ask for a quota increase. The lab changes none of them.' -ForegroundColor Red
    Write-Host '  Next        : run this same script again. Resources already created are detected and reused.' -ForegroundColor Red
    $global:LASTEXITCODE = 4
    exit 4
}

function Resolve-LabCliFailure {
    <#
    .SYNOPSIS
        Turns a denied or over-quota CLI result into a clear stop.
    .DESCRIPTION
        An access denied text stops with the permission message and exit code 3
        (Stop-LabForPermission). A LimitExceeded text on a policy call stops with
        Stop-LabForPolicyQuota (code 3); on any other call it stops with code 4.
        Other failures are returned unchanged for the caller to handle. While the
        preflight reads run ($script:LabPassDenied) the result is always returned as is.
    #>
    param($Result, [string[]]$CliArgs)
    if ($script:LabPassDenied) { return $Result }
    if ($null -eq $Result -or -not $Result.PSObject.Properties['ExitCode'] -or [int]$Result.ExitCode -eq 0) { return $Result }
    $text = "$($Result.Output)"
    $service = if ($CliArgs.Count -gt 0) { $CliArgs[0] } else { 'unknown' }
    $operation = if ($CliArgs.Count -gt 1) { $CliArgs[1] } else { 'unknown' }
    if (Test-LabAccessDenied -Text $text) {
        $denied = Get-LabDeniedAction -Text $text
        $hintAction = if ($denied) { $denied } else { $operation }
        $hint = Get-LabPermissionHint -Cloud Aws -Service $service -Action $hintAction
        Stop-LabForPermission -Hint $hint -Step $script:LabStepName
    }
    if (Test-LabPolicyQuotaExceeded -Text $text) {
        if ($service -eq 'iam' -and $operation -match 'policy') { Stop-LabForPolicyQuota -Step $script:LabStepName }
        Stop-LabForQuota -Service $service -Action $operation
    }
    return $Result
}

function ConvertFrom-LabJson {
    <# Parses CLI JSON output; returns $null for blank or invalid text. #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return (ConvertFrom-Json -InputObject $Text) } catch { return $null }
}

function Get-LabAccountId {
    if ($script:LabAccountId) { return $script:LabAccountId }
    $r = Invoke-LabCli -CliArgs @('sts', 'get-caller-identity', '--query', 'Account', '--output', 'text')
    $id = "$($r.Output)".Trim()
    if ($r.ExitCode -ne 0 -or $id -notmatch '^\d{12}$') {
        Stop-Lab -Code 3 -Message 'AWS credentials are missing, invalid or expired. No changes were made.'
    }
    $script:LabAccountId = $id
    return $id
}

function Get-LabTagSet {
    <# The lab tags (lab, run-id, component) as an ordered hashtable, built by Get-LabTags. #>
    param([string]$RunId, [string]$Component)
    if ([string]::IsNullOrWhiteSpace($Component)) { $Component = $script:LabComponent }
    return (Get-LabTags -Lab $script:LabTagValue -RunId $RunId -Component $Component)
}

function Get-LabTagPairs {
    <# Lab tags as "Key=..,Value=.." items (CloudTrail, SNS, CloudWatch, IAM, GuardDuty-style lists). #>
    param([string]$RunId, [string]$Component)
    $set = Get-LabTagSet -RunId $RunId -Component $Component
    return @($set.Keys | ForEach-Object { "Key=$_,Value=$($set[$_])" })
}

function Get-LabTagMap {
    <# Lab tags as "k=v,k=v" (CloudWatch Logs, Lambda and GuardDuty map syntax). #>
    param([string]$RunId, [string]$Component)
    $set = Get-LabTagSet -RunId $RunId -Component $Component
    return (($set.Keys | ForEach-Object { "$_=$($set[$_])" }) -join ',')
}

function Get-LabTagJsonList {
    <# Lab tags as a JSON list of Key/Value objects (S3 tagging, EC2 tag specifications, IAM files). #>
    param([string]$RunId, [string]$Component)
    $set = Get-LabTagSet -RunId $RunId -Component $Component
    return ('[' + ((@($set.Keys | ForEach-Object { '{"Key":"' + $_ + '","Value":"' + $set[$_] + '"}' })) -join ',') + ']')
}

function Test-LabTagged {
    <# $true when a tag list ([{Key,Value}]) or tag map ({k:v}) contains the lab tag. #>
    param($Tags)
    if ($null -eq $Tags) { return $false }
    foreach ($t in @($Tags)) {
        if ($null -eq $t) { continue }
        $p = $t.PSObject.Properties
        if ($p['Key'] -and $p['Value']) {
            if ("$($p['Key'].Value)" -eq $script:LabTagKey -and "$($p['Value'].Value)" -eq $script:LabTagValue) { return $true }
        } elseif ($p[$script:LabTagKey]) {
            if ("$($p[$script:LabTagKey].Value)" -eq $script:LabTagValue) { return $true }
        }
    }
    return $false
}

function New-LabTempFile {
    <# Writes text to a temp file and returns "file://<path>" for CLI arguments (avoids shell quoting issues). #>
    param([string]$Text)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("lab-{0}.json" -f [guid]::NewGuid().ToString('N'))
    [System.IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding($false)))
    [void]$script:LabTempFiles.Add($path)
    return 'file://' + ($path -replace '\\', '/')
}

function Clear-LabTempFiles {
    foreach ($f in @($script:LabTempFiles)) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -WhatIf:$false -ErrorAction SilentlyContinue }
    }
    $script:LabTempFiles.Clear()
}

function Add-LabResource {
    <#
    .SYNOPSIS
        Records a resource that cannot carry tags in the lab manifest.
    .DESCRIPTION
        Thin call into Add-LabManifestEntry (ops/lib/Common.ps1) with this lab's
        region, component and name. Does nothing under -WhatIf.
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$RunId,
        [ValidateSet('created', 'reused')][string]$Ownership = 'created'
    )
    if ($WhatIfPreference) {
        Write-Host "What if: record $Type '$Id' in the lab manifest"
        return
    }
    Add-LabManifestEntry -Type $Type -Id $Id -Region $script:LabRegion -RunId $RunId `
        -Component $script:LabComponent -Ownership $Ownership -Lab $script:LabTagValue
    Write-LabInfo "Recorded $Type in the lab manifest."
}

function Read-LabManifest {
    <# Entries of the lab manifest written by Add-LabManifestEntry (empty when there is none). #>
    $path = Get-LabManifestPath -Lab $script:LabTagValue
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $obj = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($path))
        if ($obj -and $obj.PSObject.Properties['resources'] -and $obj.resources) { return @($obj.resources) }
    }
    return @()
}

function Remove-LabManifestEntry {
    <# Drops one entry (type, id, region) from the lab manifest; the file is replaced atomically. #>
    param([string]$Type, [string]$Id)
    if ($WhatIfPreference) {
        Write-Host "What if: remove $Type '$Id' from the lab manifest"
        return
    }
    $path = Get-LabManifestPath -Lab $script:LabTagValue
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $doc = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($path))
    if (-not $doc -or -not $doc.PSObject.Properties['resources']) { return }
    $all = @($doc.resources)
    $keep = @($all | Where-Object { -not ($_.type -eq $Type -and $_.id -eq $Id -and $_.region -eq $script:LabRegion) })
    if ($keep.Count -eq $all.Count) { return }
    $doc.resources = $keep
    $tmp = "$path.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $doc -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Confirm-LabUntaggedRefusal {
    <# Standard refusal for a same-named resource that lacks the lab tag. Exits with code 1. #>
    param([string]$Kind, [string]$Name, [string]$Hint = '')
    Stop-Lab -Code 1 -Message "$Kind '$Name' exists but does not carry the tag $($script:LabTagKey)=$($script:LabTagValue). It was left unchanged. $Hint".Trim()
}

function Test-LabLogGroupExists {
    param([string]$Name)
    $r = Invoke-LabCli -CliArgs @('logs', 'describe-log-groups', '--log-group-name-prefix', $Name, '--query', 'logGroups[].logGroupName', '--output', 'json')
    if ($r.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not describe log group '$Name'. $($r.Output)" }
    $names = @(ConvertFrom-LabJson -Text $r.Output)
    return ($names -contains $Name)
}

function Test-LabLogGroupTagged {
    param([string]$Name)
    $arn = 'arn:aws:logs:{0}:{1}:log-group:{2}' -f $script:LabRegion, (Get-LabAccountId), $Name
    $r = Invoke-LabCli -CliArgs @('logs', 'list-tags-for-resource', '--resource-arn', $arn, '--query', 'tags', '--output', 'json')
    if ($r.ExitCode -ne 0) { return $false }
    return (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $r.Output))
}

function Confirm-LabLogGroup {
    <# Creates the log group with the lab tag and a short retention if it does not exist; refuses an untagged one unless adopted. #>
    param([string]$Name, [string]$RunId, [int]$RetentionDays = 7, [switch]$Adopt)
    if (Test-LabLogGroupExists -Name $Name) {
        if (Test-LabLogGroupTagged -Name $Name) {
            Write-LabInfo "Log group '$Name' already exists with the lab tag. Nothing to do."
            return 'existing'
        }
        $arn = 'arn:aws:logs:{0}:{1}:log-group:{2}' -f $script:LabRegion, (Get-LabAccountId), $Name
        if (Test-LabManifestCreated -Type 'log-group' -Id $Name) {
            # Created by the lab in an interrupted run before the tags were applied: complete them, never recreate.
            $r = Invoke-LabCli -Mutating -CliArgs @('logs', 'tag-resource', '--resource-arn', $arn, '--tags', (Get-LabTagMap -RunId $RunId))
            if ($r.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of log group '$Name'. $($r.Output)" }
            Write-LabInfo "Log group '$Name' was created by the lab without tags. Completed the tags."
            return 'existing'
        }
        # A log group the lab did not create: use it as it is. No tag, no retention change, never removed by the lab.
        if ($Adopt) { Write-LabWarn "-AdoptExisting is ignored for log group '$Name': the lab does not tag resources it did not create." }
        Write-LabKept -Kind 'Log group' -Name $Name
        Add-LabReusedResource -Type 'log-group' -Id $Name -RunId $RunId
        return 'reused'
    }
    $r = Invoke-LabCli -Mutating -CliArgs @('logs', 'create-log-group', '--log-group-name', $Name, '--tags', (Get-LabTagMap -RunId $RunId))
    if ($r.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create log group '$Name'. $($r.Output)" }
    Add-LabResource -Type 'log-group' -Id $Name -RunId $RunId
    $r = Invoke-LabCli -Mutating -CliArgs @('logs', 'put-retention-policy', '--log-group-name', $Name, '--retention-in-days', "$RetentionDays")
    if ($r.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not set retention on '$Name'. $($r.Output)" }
    Write-LabInfo "Created log group '$Name' (retention $RetentionDays days)."
    return 'created'
}

function Remove-LabLogGroup {
    <# Deletes the log group only when it carries the lab tag. #>
    param([string]$Name)
    if (-not (Test-LabLogGroupExists -Name $Name)) {
        Write-LabInfo "Log group '$Name' not found. Nothing to do."
        return
    }
    if (-not (Test-LabLogGroupTagged -Name $Name)) {
        Write-LabWarn "Log group '$Name' does not carry the lab tag: kept (not created by the lab). Left unchanged."
        return
    }
    $r = Invoke-LabCli -Mutating -CliArgs @('logs', 'delete-log-group', '--log-group-name', $Name)
    if ($r.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete log group '$Name'. $($r.Output)" }
    Write-LabInfo "Deleted log group '$Name'."
}

function Get-LabTopicArn {
    param([string]$Name)
    return ('arn:aws:sns:{0}:{1}:{2}' -f $script:LabRegion, (Get-LabAccountId), $Name)
}

function Get-LabPreflightSnapshot {
    <#
    .SYNOPSIS
        Reads the existing detection resources (read verbs only) through Get-LabAccountSnapshot.
    .DESCRIPTION
        Runs before any mutating call. A denied read does not stop here: the type becomes
        Blocked and Resolve-LabDecision stops the script with the permission message when
        (and only when) the script needs that type.
    #>
    param([string]$LogGroup, [string]$Topic)
    if (-not $LogGroup) { $LogGroup = $script:LabAppLogGroup }
    if (-not $Topic) { $Topic = $script:LabTopicName }
    $script:LabPassDenied = $true
    try {
        return (Get-LabAccountSnapshot -Cloud Aws -LabTag $script:LabTagValue -LabNames @{ LogGroup = $LogGroup; Topic = $Topic })
    } finally {
        $script:LabPassDenied = $false
    }
}

function Resolve-LabDecision {
    <#
    .SYNOPSIS
        Resolve-ResourceDecision (prints one line) plus the stop rules for an unreadable type.
    .DESCRIPTION
        Blocked because the read was denied: stops with Stop-LabForPermission (exit 3).
        Blocked because the read failed: stops with exit 1. In both cases nothing of that
        type is created, so a missing permission never produces a duplicate.
    #>
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$Type,
        [string]$ExpectedName,
        [switch]$Singleton
    )
    $d = Resolve-ResourceDecision -Snapshot $Snapshot -Type $Type -ExpectedName $ExpectedName -Singleton:$Singleton
    if ($d.Decision -ne 'Blocked') { return $d }
    if ($d.Reasons -contains 'read denied') {
        $service = if ($d.Service) { $d.Service } else { 'sts' }
        $action = if ($d.Error -and (Get-LabDeniedAction -Text $d.Error)) { Get-LabDeniedAction -Text $d.Error } elseif ($d.Action) { $d.Action } else { 'get-caller-identity' }
        Stop-LabForPermission -Hint (Get-LabPermissionHint -Cloud Aws -Service $service -Action $action) -Step $script:LabStepName
    }
    Stop-Lab -Code 1 -Message "Could not read the existing $Type state, so nothing of that kind was created. $($d.Error)".Trim()
}

function Test-LabManifestCreated {
    <# True when the lab manifest records this resource as created by the lab (an entry without ownership counts as created). #>
    param([string]$Type, [string]$Id)
    foreach ($e in @(Read-LabManifest)) {
        if ("$($e.type)" -ceq $Type -and "$($e.id)" -ceq $Id) {
            $own = if ($e.PSObject.Properties['ownership']) { "$($e.ownership)" } else { 'created' }
            return ($own -ne 'reused')
        }
    }
    return $false
}

function Resolve-LabAppBucket {
    <#
    .SYNOPSIS
        Returns the app bucket name: the given value, then the lab config, then the lab manifest.
    .DESCRIPTION
        The config derivation is the one ops/aws/ec2/deploy.ps1 uses (Aws.Ec2.BucketBase + '-' +
        UniqueSuffix, exposed as AppBucket by Get-AwsLabNames). The manifest fallback reads the
        s3-bucket entry recorded by the deploy component. Returns an empty string when none is
        available; the caller decides whether that is an error. Read only.
    #>
    param([string]$LabBucket)
    if (-not [string]::IsNullOrWhiteSpace($LabBucket)) { return $LabBucket.Trim() }
    $fromConfig = [string]$script:LabNames['AppBucket']
    if (-not [string]::IsNullOrWhiteSpace($fromConfig)) {
        Write-LabInfo "-LabBucket not given: using app bucket '$fromConfig' from the lab config (Aws.Ec2.BucketBase + UniqueSuffix)."
        return $fromConfig
    }
    $fromManifest = Find-LabManifestResourceId -Type 's3-bucket' -Lab $script:LabTagValue -Component 'deploy' -Region $script:LabRegion
    if (-not [string]::IsNullOrWhiteSpace($fromManifest)) {
        Write-LabInfo "-LabBucket not given: using app bucket '$fromManifest' from the lab manifest."
        return $fromManifest
    }
    return ''
}

function Resolve-LabInstanceId {
    <#
    .SYNOPSIS
        Returns the deployment instance id: the given value, then the lab manifest, then describe-instances.
    .DESCRIPTION
        The manifest fallback reads the ec2-instance entry recorded by the deploy component. The
        describe-instances fallback filters on the lab Name tag and the lab tag and only accepts
        exactly one non-terminated instance. Returns an empty string when none is found; more than
        one match stops the script with exit code 2 (ambiguous). Read only.
    #>
    param([string]$InstanceId)
    if (-not [string]::IsNullOrWhiteSpace($InstanceId)) { return $InstanceId.Trim() }
    $fromManifest = Find-LabManifestResourceId -Type 'ec2-instance' -Lab $script:LabTagValue -Component 'deploy' -Region $script:LabRegion
    if (-not [string]::IsNullOrWhiteSpace($fromManifest)) {
        Write-LabInfo "-InstanceId not given: using instance '$fromManifest' from the lab manifest."
        return $fromManifest
    }
    $r = Invoke-LabCli -CliArgs @('ec2', 'describe-instances',
        '--filters', "Name=tag:Name,Values=$($script:LabNames['Ec2Name'])", "Name=tag:$($script:LabTagKey),Values=$($script:LabTagValue)",
        'Name=instance-state-name,Values=pending,running,stopping,stopped',
        '--query', 'Reservations[].Instances[].InstanceId', '--output', 'json')
    if ($r.ExitCode -ne 0) { return '' }
    $ids = @(ConvertFrom-LabJson -Text $r.Output | Where-Object { $_ })
    if ($ids.Count -eq 1) {
        Write-LabInfo "-InstanceId not given: using instance '$($ids[0])' found by the lab Name and lab tags."
        return "$($ids[0])"
    }
    if ($ids.Count -gt 1) {
        Stop-Lab -Code 2 -Message "More than one lab instance matches ($($ids -join ', ')). Pass -InstanceId to choose one."
    }
    return ''
}

function Test-LabManifestHas {
    param([string]$Type, [string]$Id)
    foreach ($e in @(Read-LabManifest)) {
        if ("$($e.type)" -ceq $Type -and "$($e.id)" -ceq $Id) { return $true }
    }
    return $false
}

function Add-LabReusedResource {
    <#
    .SYNOPSIS
        Records a resource the lab did not create with ownership reused (no tags, no delete block).
    .DESCRIPTION
        A resource the manifest already lists as created keeps that entry, so a re-run never
        downgrades or hides something the lab owns.
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$RunId
    )
    if (Test-LabManifestCreated -Type $Type -Id $Id) { return }
    Add-LabResource -Type $Type -Id $Id -RunId $RunId -Ownership 'reused'
}

function Write-LabKept {
    <# The standard line for a resource the lab reuses and will not change or remove. #>
    param([string]$Kind, [string]$Name)
    Write-LabInfo "kept (not created by the lab): $Kind '$Name'. The lab does not modify, tag or remove it."
}
