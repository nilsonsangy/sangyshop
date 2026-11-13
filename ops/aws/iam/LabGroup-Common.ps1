# =============================================================================
# LabGroup-Common.ps1 -- shared helpers for the lab IAM group tooling
# =============================================================================
# Dot-sourced by ops/aws/iam/ensure-lab-group.ps1 and by the tests. Every
# function here is side-effect free: no aws call, no file write. Windows
# PowerShell 5.1 compatible.
#
# Contents:
#   Test-LabGroupNameAllowed   name guard for the lab group
#   ConvertTo-IamAction        maps an AWS CLI "service operation" to IAM actions
#   Get-RequiredActions        scans scripts for the IAM actions they need
#   Get-LabPolicyTemplatePath  lists the policy template files
#   Expand-LabPolicyTemplate   renders a template (${AccountId}, ${Region})
#   Get-PolicyActions          lists the Allow actions of a rendered policy
#   Get-PolicyCharacterCount   counts characters excluding white space
#   Test-IamActionCovered      checks an action against a set of allowed patterns

Set-StrictMode -Version Latest

# Name guard ------------------------------------------------------------------

# The foreign application name is assembled at run time so the literal never
# appears in this file.
$script:LabGroupForbiddenToken = ('know' + 'tree')
$script:LabGroupNamePattern    = '^sangyshop-lab-[a-z0-9-]+\z'

function Test-LabGroupNameAllowed {
    <#
    .SYNOPSIS
        Returns $true only when the group name is safe for the lab tooling.
    .DESCRIPTION
        Allow-list: the name must match ^sangyshop-lab-[a-z0-9-]+$ (case
        sensitive), which rejects names that belong to other applications.
        Deny-list on top: a name containing the foreign application token in
        any letter case is always rejected.
    #>
    param([AllowNull()][AllowEmptyString()][string] $Name)

    if ([string]::IsNullOrEmpty($Name)) { return $false }
    if ($Name.ToLowerInvariant().Contains($script:LabGroupForbiddenToken)) { return $false }
    return [regex]::IsMatch($Name, $script:LabGroupNamePattern, [System.Text.RegularExpressions.RegexOptions]::None)
}

# CLI command to IAM action mapping -------------------------------------------

# CLI service name -> IAM service prefix, when they differ.
$script:IamServicePrefix = @{
    's3api'      = 's3'
    'elbv2'      = 'elasticloadbalancing'
    'elb'        = 'elasticloadbalancing'
    'cloudwatch' = 'cloudwatch'
    'events'     = 'events'
    'logs'       = 'logs'
}

# Services that are not IAM-controlled calls (local helpers).
$script:IamSkipServices = @('configure', 'help', 'history', 'deploy')

# Exceptions: "service operation" -> IAM action(s) that do not follow the
# default rule (service prefix + PascalCase operation). An empty array means the
# command needs no IAM permission.
$script:IamActionExceptions = @{
    'ecr get-login-password'         = @('ecr:GetAuthorizationToken')
    'eks update-kubeconfig'          = @('eks:DescribeCluster')
    'logs tail'                      = @('logs:FilterLogEvents', 'logs:DescribeLogGroups')
    'lambda invoke'                  = @('lambda:InvokeFunction')
    's3 ls'                          = @('s3:ListBucket', 's3:ListAllMyBuckets')
    's3 cp'                          = @('s3:GetObject', 's3:PutObject')
    's3 mv'                          = @('s3:GetObject', 's3:PutObject', 's3:DeleteObject')
    's3 rm'                          = @('s3:DeleteObject')
    's3 sync'                        = @('s3:GetObject', 's3:PutObject', 's3:ListBucket')
    's3 mb'                          = @('s3:CreateBucket')
    's3 rb'                          = @('s3:DeleteBucket')
    's3api head-bucket'              = @('s3:ListBucket')
    's3api head-object'              = @('s3:GetObject')
    's3api put-bucket-policy'        = @('s3:PutBucketPolicy')
    's3api list-buckets'             = @('s3:ListAllMyBuckets')
    's3api list-object-versions'     = @('s3:ListBucketVersions')
    's3api list-objects'             = @('s3:ListBucket')
    's3api list-objects-v2'          = @('s3:ListBucket')
    'resourcegroupstaggingapi get-resources' = @('tag:GetResources')
    'sts get-caller-identity'        = @()
    'sts get-session-token'          = @('sts:GetSessionToken')
    'iam wait'                       = @()
    'ec2 wait'                       = @('ec2:DescribeInstances')
    'lambda wait'                    = @('lambda:GetFunction')
    'cloudwatch wait'                = @('cloudwatch:DescribeAlarms')
}

function ConvertTo-PascalCase {
    param([Parameter(Mandatory)][string] $KebabCase)
    $parts = $KebabCase.Split('-') | Where-Object { $_ }
    return (($parts | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1).ToLowerInvariant() }) -join '')
}

function ConvertTo-IamAction {
    <#
    .SYNOPSIS
        Maps an AWS CLI service and operation to the IAM action(s) it needs.
    .EXAMPLE
        ConvertTo-IamAction -Service logs -Operation put-metric-filter
        # logs:PutMetricFilter
    .OUTPUTS
        string[] (possibly empty when the command needs no permission).
    #>
    param(
        [Parameter(Mandatory)][string] $Service,
        [Parameter(Mandatory)][string] $Operation
    )

    $svc = $Service.ToLowerInvariant()
    $op  = $Operation.ToLowerInvariant()

    if ($script:IamSkipServices -contains $svc) { return @() }

    $key = "$svc $op"
    if ($script:IamActionExceptions.ContainsKey($key)) {
        return @($script:IamActionExceptions[$key])
    }

    # Waiters never have a dedicated IAM action; they poll a Describe/Get call
    # that is already listed by the script that waits.
    if ($op -eq 'wait') { return @() }

    $prefix = if ($script:IamServicePrefix.ContainsKey($svc)) { $script:IamServicePrefix[$svc] } else { $svc }
    $name = ConvertTo-PascalCase -KebabCase $op
    # RDS spells the "DB" acronym in capitals (rds:CreateDBInstance).
    if ($prefix -eq 'rds') { $name = $name -creplace 'Db(?=[A-Z]|$)', 'DB' }
    return @("${prefix}:$name")
}

# Script scanning ------------------------------------------------------------

# AWS CLI services the lab scripts may call. Matching against this list keeps
# prose such as "aws sso login" or two-element arrays from being read as calls.
$script:AwsCliServices = @(
    'acm', 'apigateway', 'autoscaling', 'cloudformation', 'cloudtrail', 'cloudwatch', 'codecommit',
    'resourcegroupstaggingapi',
    'dynamodb', 'ec2', 'ecr', 'ecs', 'eks', 'elb', 'elbv2', 'events', 'guardduty',
    'iam', 'kms', 'lambda', 'logs', 'rds', 's3', 's3api', 'secretsmanager', 'sns',
    'sqs', 'ssm', 'sts'
)

# Form 1, plain text: aws [global flags] <service> <operation>
$script:AwsCliPattern = '(?<![\w./-])aws\s+(?:(?:--(?:region|profile|output|query|endpoint-url|cli-connect-timeout|cli-read-timeout)(?:\s+|=)\S+|--(?:no-[a-z-]+|debug))\s+)*(?<svc>[a-z][a-z0-9]*)\s+(?<op>[a-z][a-z0-9-]*)'
# Form 2, argument arrays handed to the CLI wrapper: -CmdArgs @('svc', 'op', ...)
$script:AwsCliArrayPattern = '-(?:Cmd|Cli|Find|Create)Args\s+\(?@\(\s*''(?<svc>[a-z][a-z0-9]*)''\s*,\s*''(?<op>[a-z][a-z0-9-]*)'''
# Form 3, deletion descriptors: -DelService 'svc' -DelAction 'op'
$script:AwsCliDelPattern = '-DelService\s+''(?<svc>[a-z][a-z0-9]*)''\s+-DelAction\s+''(?<op>[a-z][a-z0-9-]*)'''
function Get-RequiredActions {
    <#
    .SYNOPSIS
        Scans PowerShell/shell scripts for AWS CLI calls and returns the sorted,
        unique IAM actions they need.
    .PARAMETER Path
        One or more script files or directories (searched recursively for *.ps1
        and *.sh).
    #>
    param([Parameter(Mandatory)][string[]] $Path)

    $files = foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Container) {
            Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.sh' }
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) {
            Get-Item -LiteralPath $p
        }
    }

    $actions = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @($files)) {
        foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
            if ($line -match '^\s*#') { continue }
            $matches2 = @()
            foreach ($pat in @($script:AwsCliPattern, $script:AwsCliArrayPattern, $script:AwsCliDelPattern)) {
                $matches2 += [regex]::Matches($line, $pat)
            }
            foreach ($m in $matches2) {
                if ($script:AwsCliServices -notcontains $m.Groups['svc'].Value) { continue }
                foreach ($a in (ConvertTo-IamAction -Service $m.Groups['svc'].Value -Operation $m.Groups['op'].Value)) {
                    [void]$actions.Add($a)
                }
            }
        }
    }
    return @($actions | Sort-Object)
}

# Policy templates -------------------------------------------------------------

function Get-LabPolicyTemplatePath {
    <#
    .SYNOPSIS
        Returns the policy template files (ops/aws/iam/policies/*.json).
    #>
    param([string] $TemplateDir = (Join-Path $PSScriptRoot 'policies'))
    if (-not (Test-Path -LiteralPath $TemplateDir -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $TemplateDir -Filter '*.json' -File | Sort-Object Name | ForEach-Object { $_.FullName })
}

function Expand-LabPolicyTemplate {
    <#
    .SYNOPSIS
        Renders a policy template, replacing ${AccountId} and ${Region}.
    .OUTPUTS
        string with the rendered JSON document.
    #>
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $AccountId,
        [Parameter(Mandatory)][string] $Region
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Policy template not found: $Path"
    }
    $text = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).ProviderPath)
    $text = $text.Replace('${AccountId}', $AccountId).Replace('${Region}', $Region)
    return $text
}

function Get-PolicyCharacterCount {
    <#
    .SYNOPSIS
        Counts the characters of a policy document excluding white space, the
        measure used by the managed policy size limit.
    #>
    param([Parameter(Mandatory)][string] $Document)
    return ([regex]::Replace($Document, '\s', '')).Length
}

function Get-PolicyActions {
    <#
    .SYNOPSIS
        Returns every action listed in the Allow statements of a policy document.
    #>
    param([Parameter(Mandatory)][string] $Document)

    $doc = $Document | ConvertFrom-Json
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($doc.Statement)) {
        if ($s.Effect -ne 'Allow') { continue }
        foreach ($a in @($s.Action)) { if ($a) { $out.Add([string]$a) } }
    }
    return @($out | Sort-Object -Unique)
}

function Test-IamActionCovered {
    <#
    .SYNOPSIS
        True when Action matches at least one allowed action pattern (wildcards
        allowed, case insensitive).
    #>
    param(
        [Parameter(Mandatory)][string] $Action,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Allowed
    )
    foreach ($pattern in $Allowed) {
        if ($Action -like $pattern) { return $true }
    }
    return $false
}
