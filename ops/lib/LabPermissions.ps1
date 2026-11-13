<#
.SYNOPSIS
    Permission-error handling for the lab scripts (AWS and Azure).

.DESCRIPTION
    Dot-sourced by the lab scripts under ops/. Provides:

      Test-LabAccessDenied         True when a CLI error text means "not authorized".
      Test-LabPolicyQuotaExceeded  True when attaching a policy hit the per-user quota.
      Get-LabDeniedAction          Extracts the denied IAM action from an error text.
      Get-LabPermissionHint        Looks up the exact managed policies (AWS) or
                                   built-in roles (Azure) that fix a denied call.
      Format-LabPermissionMessage  Builds the BLOCKED message lines (no exit).
      Stop-LabForPermission        Prints the BLOCKED message and exits with code 3.
      Stop-LabForPolicyQuota       Prints the quota message and exits with code 3.

    Safety rule: this library never grants anything. It calls no IAM verb at all
    (no attach, put, create or add-user-to-group). It only reads text, prints, and
    exits. The operator fixes the account and runs the same script again.

    Every policy and role name below was checked against the AWS managed policy
    reference and the Azure built-in roles reference before being fixed here.
    The hint tables are the single source for the console message and the READMEs.

    Windows PowerShell 5.1 compatible (no newer syntax).
#>

Set-StrictMode -Version Latest

# Exit codes shared by the lab scripts: 2 = missing or invalid configuration,
# 3 = permission missing, 4 = step precondition blocked.
$script:LabPermissionExitCode = 3

# ---------------------------------------------------------------------------
# AWS table: CLI service name -> IAM prefix, managed policies, note.
# Source: AWS managed policy reference (docs.aws.amazon.com/aws-managed-policy).
#
# Read versus write: Policies cover the read actions (Get*, Describe*, List*) and, for
# services whose managed policy is FullAccess/ReadWrite/PowerUser, the write actions too.
# A service whose Policies are read only has WritePolicies, WriteScoped and WriteNote, which
# Get-LabPermissionHint uses for any other action. Reviewed services: events and lambda
# (FullAccess, read and write covered), iam (scoped template for both), ssm (read only
# managed policy, so it has the write override).
# ---------------------------------------------------------------------------
$script:LabAwsPermissionTable = [ordered]@{
    'ec2'                      = @{ Prefix = 'ec2';            Policies = @('AmazonEC2FullAccess');                Note = 'Covers network, AMI and flow logs of EC2.' }
    's3'                       = @{ Prefix = 's3';             Policies = @('AmazonS3FullAccess');                 Note = 'Application bucket and trail bucket.' }
    's3api'                    = @{ Prefix = 's3';             Policies = @('AmazonS3FullAccess');                 Note = 'Application bucket and trail bucket.' }
    'rds'                      = @{ Prefix = 'rds';            Policies = @('AmazonRDSFullAccess');                Note = 'Lab database.' }
    'logs'                     = @{ Prefix = 'logs';           Policies = @('CloudWatchLogsFullAccess');           Note = 'Log groups and metric filter.' }
    'cloudwatch'               = @{ Prefix = 'cloudwatch';     Policies = @('CloudWatchFullAccessV2');             Note = 'Alarms.' }
    'sns'                      = @{ Prefix = 'sns';            Policies = @('AmazonSNSFullAccess');                Note = 'Topic and subscription.' }
    'cloudtrail'               = @{ Prefix = 'cloudtrail';     Policies = @('AWSCloudTrail_FullAccess');           Note = 'Trail.' }
    'guardduty'                = @{ Prefix = 'guardduty';      Policies = @('AmazonGuardDutyFullAccess_v2');       Note = 'Detector.' }
    'events'                   = @{ Prefix = 'events';         Policies = @('AmazonEventBridgeFullAccess');        Note = 'Rule of the blocker.' }
    'lambda'                   = @{ Prefix = 'lambda';         Policies = @('AWSLambda_FullAccess');               Note = 'Function of the blocker.' }
    'ssm'                      = @{ Prefix = 'ssm';            Policies = @('AmazonSSMReadOnlyAccess');            Note = 'Read actions (Get, Describe, List) only. The lab has an AMI fallback that works without SSM.'
                                    WritePolicies = @('AmazonSSMFullAccess'); WriteScoped = 'lab-core.json'
                                    WriteNote = 'Write actions such as SendCommand are not in AmazonSSMReadOnlyAccess. lab-core.json grants ssm:SendCommand (preferred, scoped); AmazonSSMFullAccess is the broad managed alternative.' }
    'secretsmanager'           = @{ Prefix = 'secretsmanager'; Policies = @('SecretsManagerReadWrite');            Note = 'Database secret.' }
    'kms'                      = @{ Prefix = 'kms';            Policies = @('AWSKeyManagementServicePowerUser');   Note = 'Keys used by RDS and secrets.' }
    'iam'                      = @{ Prefix = 'iam';            Policies = @();                                     Note = 'No managed policy fits without excess. Use lab-iam-scoped.json from the lab group (ops/aws/iam/lab-iam-scoped.json).'; Scoped = 'lab-iam-scoped.json' }
    'resourcegroupstaggingapi' = @{ Prefix = 'tag';            Policies = @();                                     Note = 'No managed policy needed beyond lab-core.json (tag and identity reads).'; Scoped = 'lab-core.json' }
    'sts'                      = @{ Prefix = 'sts';            Policies = @();                                     Note = 'No managed policy needed beyond lab-core.json (tag and identity reads).'; Scoped = 'lab-core.json' }
}

# ---------------------------------------------------------------------------
# Azure table: az command group -> built-in RBAC roles, note.
# Source: Azure built-in roles reference (learn.microsoft.com, Azure RBAC).
# ---------------------------------------------------------------------------
$script:LabAzurePermissionTable = [ordered]@{
    'group'          = @{ Roles = @('Contributor');                                                              Note = 'Assign at the lab resource group scope.' }
    'vm'             = @{ Roles = @('Virtual Machine Contributor');                                              Note = 'Assign at the lab resource group scope.' }
    'network'        = @{ Roles = @('Network Contributor');                                                      Note = 'Virtual network, NSG and public IP. Assign at the lab resource group scope.' }
    'storage'        = @{ Roles = @('Storage Account Contributor');                                              Note = 'Evidence and trail storage. Assign at the lab resource group scope.' }
    'postgres'       = @{ Roles = @('Contributor');                                                              Note = 'No narrower built-in role covers PostgreSQL flexible server. Assign at the lab resource group scope.' }
    'keyvault'       = @{ Roles = @('Key Vault Contributor', 'Key Vault Secrets Officer');                       Note = 'Vault management plus secrets. Assign at the lab resource group scope.' }
    'identity'       = @{ Roles = @('Managed Identity Contributor');                                             Note = 'User-assigned managed identity. Assign at the lab resource group scope.' }
    'acr'            = @{ Roles = @('Contributor');                                                              Note = 'Container registry. Assign at the lab resource group scope.' }
    'aks'            = @{ Roles = @('Contributor');                                                              Note = 'Kubernetes cluster. Assign at the lab resource group scope.' }
    'container'      = @{ Roles = @('Contributor');                                                              Note = 'Container instances. Assign at the lab resource group scope.' }
    'monitor'        = @{ Roles = @('Monitoring Contributor');                                                   Note = 'Action groups, alert rules and diagnostic settings.' }
    'loganalytics'   = @{ Roles = @('Log Analytics Contributor');                                                Note = 'Log Analytics workspace.' }
    'sentinel'       = @{ Roles = @('Microsoft Sentinel Contributor');                                           Note = 'Sentinel analytics rules.' }
    'logic'          = @{ Roles = @('Logic App Contributor');                                                    Note = 'Logic App of the blocker.' }
    'policy'         = @{ Roles = @('Resource Policy Contributor');                                              Note = 'Azure Policy definitions and assignments.' }
    'role'           = @{ Roles = @('Role Based Access Control Administrator', 'User Access Administrator');     Note = 'Role assignments of the blocker. Assign either role at the lab resource group scope, never at subscription scope.' }
    'security'       = @{ Roles = @('Security Admin');                                                           Note = 'Defender for Cloud pricing plans. Assign at the subscription scope.' }
    'account'        = @{ Roles = @('Reader');                                                                   Note = 'Subscription and resource reads.' }
}

# Azure resource provider namespace -> az command group key above.
$script:LabAzureProviderAlias = @{
    'microsoft.resources'           = 'group'
    'microsoft.compute'             = 'vm'
    'microsoft.network'             = 'network'
    'microsoft.storage'             = 'storage'
    'microsoft.dbforpostgresql'     = 'postgres'
    'microsoft.keyvault'            = 'keyvault'
    'microsoft.managedidentity'     = 'identity'
    'microsoft.containerregistry'   = 'acr'
    'microsoft.containerservice'    = 'aks'
    'microsoft.containerinstance'   = 'container'
    'microsoft.insights'            = 'monitor'
    'microsoft.operationalinsights' = 'loganalytics'
    'microsoft.securityinsights'    = 'sentinel'
    'microsoft.logic'               = 'logic'
    'microsoft.authorization'       = 'role'
    'vnet'                          = 'network'
    'nsg'                           = 'network'
    'log-analytics'                 = 'loganalytics'
    'logic-app'                     = 'logic'
}

function Test-LabAccessDenied {
    <#
    .SYNOPSIS
        Returns $true when a CLI error text means the caller is not authorized.
    .DESCRIPTION
        Recognizes AccessDenied, AccessDeniedException, UnauthorizedOperation,
        AuthorizationError, AuthorizationFailed, "not authorized to perform",
        "is not authorized" and HTTP 403. Blank or null text returns $false.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    $pattern = '(?i)(' +
        'AccessDeniedException|AccessDenied|UnauthorizedOperation|AuthorizationError|AuthorizationFailed' +
        '|not\s+authorized\s+to\s+perform|is\s+not\s+authorized' +
        '|HTTP[/ ]*[0-9.]*\s*403|status(\s*code)?\W{0,3}403|\(403\)|\b403\s+Forbidden' +
        ')'
    return [bool]($Text -match $pattern)
}

function Test-LabPolicyQuotaExceeded {
    <#
    .SYNOPSIS
        Returns $true when the text is the IAM quota error for attached managed policies.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return [bool]($Text -match '(?i)LimitExceeded')
}

function ConvertTo-LabIamActionName {
    # 'create-topic' or 'createTopic' -> 'CreateTopic'. 'sns:CreateTopic' is kept as is.
    param([string] $Action)

    if ([string]::IsNullOrWhiteSpace($Action)) { return '' }
    if ($Action.Contains(':')) { return $Action.Substring($Action.IndexOf(':') + 1) }
    $parts = $Action -split '[-_ ]+' | Where-Object { $_.Length -gt 0 }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in $parts) {
        [void]$sb.Append($p.Substring(0, 1).ToUpperInvariant())
        if ($p.Length -gt 1) { [void]$sb.Append($p.Substring(1)) }
    }
    return $sb.ToString()
}

function Get-LabDeniedAction {
    <#
    .SYNOPSIS
        Extracts the denied IAM action (for example sns:CreateTopic) from an error text.
    .DESCRIPTION
        Reads the "not authorized to perform: <action>" part that AWS prints. Returns
        $null when the text does not carry it. The account ID is never returned.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(?i)not\s+authorized\s+to\s+perform:?\s+([A-Za-z0-9-]+:[A-Za-z0-9*]+)')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($Text, "(?i)does not have permission to perform action\s+'?([A-Za-z0-9./]+)'?")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-LabPermissionHint {
    <#
    .SYNOPSIS
        Returns the exact managed policies (AWS) or built-in roles (Azure) for a denied call.
    .DESCRIPTION
        Service is the AWS CLI service ('sns', 's3api', ...) or, for Azure, the az command
        group ('monitor', 'vm', ...) or the resource provider namespace
        ('Microsoft.Network'). Action is the operation ('create-topic', 'CreateTopic' or
        'sns:CreateTopic').

        Returns a [pscustomobject] with: Cloud, Service, Action, IamAction,
        ManagedPolicies (AWS names), BuiltInRoles (Azure names), ScopedTemplate (minimum
        policy file or $null), Note and Known. For a service that is not in the table,
        Known is $false and the lists are empty, so the caller still prints a useful
        message. Nothing here calls the cloud.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Aws', 'Azure')][string] $Cloud,
        [Parameter(Mandatory)][string] $Service,
        [Parameter(Mandatory)][string] $Action
    )

    $key = $Service.Trim().ToLowerInvariant()
    $actionName = ConvertTo-LabIamActionName -Action $Action

    if ($Cloud -eq 'Aws') {
        $entry = $null
        if ($script:LabAwsPermissionTable.Contains($key)) { $entry = $script:LabAwsPermissionTable[$key] }
        $prefix = if ($entry) { $entry.Prefix } else { $key }
        $iamAction = if ($Action.Contains(':')) { $Action } else { "${prefix}:${actionName}" }

        $policies = @()
        $scoped = $null
        $note = 'This service is not in the lab permission table. Review the denied action and ask for the narrowest permission that allows it.'
        if ($entry) {
            $policies = @($entry.Policies)
            $note = $entry.Note
            if ($entry.ContainsKey('Scoped')) { $scoped = $entry.Scoped }
            # Read only managed policy: any action that is not a read needs the write path.
            $isRead = ($actionName -match '^(Get|Describe|List|BatchGet|Search)')
            if ((-not $isRead) -and $entry.ContainsKey('WritePolicies')) {
                $policies = @($entry.WritePolicies)
                $note = $entry.WriteNote
                if ($entry.ContainsKey('WriteScoped')) { $scoped = $entry.WriteScoped }
            }
        }
        return [pscustomobject]@{
            Cloud           = 'Aws'
            Service         = $Service
            Action          = $Action
            IamAction       = $iamAction
            ManagedPolicies = $policies
            BuiltInRoles    = @()
            ScopedTemplate  = $scoped
            Note            = $note
            Known           = [bool]$entry
        }
    }

    # Azure
    if ($script:LabAzureProviderAlias.ContainsKey($key)) { $key = $script:LabAzureProviderAlias[$key] }
    $entry = $null
    if ($script:LabAzurePermissionTable.Contains($key)) { $entry = $script:LabAzurePermissionTable[$key] }
    $roles = @()
    $note = 'This resource provider is not in the lab permission table. Review the denied action and ask for the narrowest built-in role that allows it.'
    if ($entry) { $roles = @($entry.Roles); $note = $entry.Note }
    return [pscustomobject]@{
        Cloud           = 'Azure'
        Service         = $Service
        Action          = $Action
        IamAction       = $Action
        ManagedPolicies = @()
        BuiltInRoles    = $roles
        ScopedTemplate  = $null
        Note            = $note
        Known           = [bool]$entry
    }
}

function Format-LabPermissionMessage {
    <#
    .SYNOPSIS
        Builds the BLOCKED message lines for a hint. Pure function, no output, no exit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Hint,
        [string] $Step = 'unknown'
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("BLOCKED: permission missing in step '$Step'.")

    if ($Hint.Cloud -eq 'Aws') {
        $lines.Add("  Denied call : $($Hint.Service) $($Hint.Action) ($($Hint.IamAction))")
        if ($Hint.ManagedPolicies.Count -gt 0 -and $Hint.ScopedTemplate) {
            $names = ($Hint.ManagedPolicies -join ', ')
            $lines.Add("  Fix         : apply the scoped template $($Hint.ScopedTemplate) to the lab IAM group (preferred) with")
            $lines.Add('                ops/aws/iam/ensure-lab-group.ps1 -WhatIf (review first), then run it without -WhatIf,')
            $lines.Add("                or attach the AWS managed policy $names as the broader alternative")
        }
        elseif ($Hint.ManagedPolicies.Count -gt 0) {
            $names = ($Hint.ManagedPolicies -join ', ')
            $lines.Add("  Fix         : attach the AWS managed policy $names to the lab IAM group,")
            $lines.Add('                or review the scoped alternative with ops/aws/iam/ensure-lab-group.ps1 -WhatIf')
        }
        elseif ($Hint.ScopedTemplate) {
            $lines.Add("  Fix         : no AWS managed policy fits without excess. Apply $($Hint.ScopedTemplate) to the lab IAM group")
            $lines.Add('                with ops/aws/iam/ensure-lab-group.ps1 -WhatIf (review first), then run it without -WhatIf')
        }
        else {
            $lines.Add("  Fix         : $($Hint.Note)")
        }
    }
    else {
        $lines.Add("  Denied call : az $($Hint.Service) $($Hint.Action)")
        if ($Hint.BuiltInRoles.Count -gt 0) {
            $names = ($Hint.BuiltInRoles -join ' or ')
            $lines.Add("  Fix         : assign the Azure built-in role $names to the operator at the lab resource group scope")
        }
        else {
            $lines.Add("  Fix         : $($Hint.Note)")
        }
    }

    if ($Hint.Known -and ($Hint.ManagedPolicies.Count -gt 0 -or $Hint.BuiltInRoles.Count -gt 0) -and $Hint.Note) {
        $lines.Add("  Note        : $($Hint.Note)")
    }
    $lines.Add('  Next        : run this same script again. Resources already created are detected and reused.')
    return $lines.ToArray()
}

function Stop-LabForPermission {
    <#
    .SYNOPSIS
        Prints the BLOCKED message for a permission error and exits with code 3.
    .DESCRIPTION
        Names the denied service and action, the exact managed policy or built-in role,
        and the instruction to run the same script again. Grants nothing and calls no
        IAM verb: the operator fixes the account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Hint,
        [string] $Step = 'unknown'
    )

    foreach ($line in (Format-LabPermissionMessage -Hint $Hint -Step $Step)) {
        Write-Host $line -ForegroundColor Red
    }
    $global:LASTEXITCODE = $script:LabPermissionExitCode
    exit $script:LabPermissionExitCode
}

function Stop-LabForPolicyQuota {
    <#
    .SYNOPSIS
        Prints the quota message for LimitExceeded on policy attachment and exits with code 3.
    .DESCRIPTION
        A user can have only a few managed policies attached directly. The message points
        to the lab IAM group and to ensure-lab-group.ps1. It does not attach anything.
    #>
    [CmdletBinding()]
    param([string] $Step = 'unknown')

    $lines = @(
        "BLOCKED: managed policy quota reached in step '$Step' (LimitExceeded).",
        '  Cause       : the IAM user already has the maximum number of managed policies attached directly.',
        '  Fix         : use the lab IAM group instead of direct attachments. Run',
        '                ops/aws/iam/ensure-lab-group.ps1 -WhatIf to review, then without -WhatIf to create the group,',
        '                and move the policy attachments from the user to the group.',
        '  Next        : run this same script again. Resources already created are detected and reused.'
    )
    foreach ($line in $lines) { Write-Host $line -ForegroundColor Red }
    $global:LASTEXITCODE = $script:LabPermissionExitCode
    exit $script:LabPermissionExitCode
}
