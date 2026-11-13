<#
.SYNOPSIS
    Creates or updates the lab IAM group and its managed policies, additively.
.DESCRIPTION
    An IAM user can have only a few managed policies attached directly, so the
    lab permissions live in a group. This script renders the templates in
    ops/aws/iam/policies/*.json, makes sure one managed policy per template
    exists and is current, makes sure the policies are attached to the lab
    group, and optionally adds a user to the group.

    Safety rules:
      * The group name is checked first, before any AWS call. Only names that
        pass Test-LabGroupNameAllowed (sangyshop-lab-*) are accepted.
      * The script only reads, creates or changes that one group and the
        managed policies named sangyshop-<template name>. It never lists other
        groups, never detaches or deletes anything from the group and never
        touches users except to add the user named with -AddUser.
      * An existing group is adopted as it is: nothing about it is changed other
        than attaching the missing lab policies.
      * Idempotent: a policy is compared to its current default version using a
        normalized document. When they match, no call is made. When they differ,
        a new default version is created. If the policy already has five
        versions, the oldest non-default version is deleted first.
      * All changes are applied only after one explicit confirmation
        (ShouldProcess, high confirm impact) that comes before the first
        mutating call. -WhatIf prints the plan and changes nothing. -Describe
        prints the current state and changes nothing.
      * Every AWS call goes through Invoke-LabCli, so tests can replace the CLI
        with $global:LabCliHandler.

    Exit codes: 0 success, 1 unexpected failure, 2 configuration error (bad
    group name, user name or missing region), 3 permission missing, 4 precondition
    not met (the group would exceed its managed policy quota).

    Required IAM actions:
      iam:GetGroup, iam:CreateGroup, iam:ListAttachedGroupPolicies,
      iam:AttachGroupPolicy, iam:AddUserToGroup, iam:GetPolicy,
      iam:GetPolicyVersion, iam:ListPolicyVersions, iam:CreatePolicy,
      iam:CreatePolicyVersion, iam:DeletePolicyVersion
.PARAMETER GroupName
    Name of the lab group. Default: sangyshop-lab-group.
.PARAMETER AddUser
    IAM user names to add to the group. Never done unless named here.
.PARAMETER Describe
    Print the current state of the group and policies. Changes nothing.
.PARAMETER Region
    AWS region used to fill ${Region} in the templates. Falls back to
    AWS_REGION, then AWS_DEFAULT_REGION. Without any, the script exits with code 2.
.PARAMETER TemplateDir
    Folder with the policy templates. Default: policies next to this script.
.EXAMPLE
    ./ops/aws/iam/ensure-lab-group.ps1 -WhatIf
.EXAMPLE
    ./ops/aws/iam/ensure-lab-group.ps1 -AddUser my-iam-user
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]   $GroupName = 'sangyshop-lab-group',
    [string[]] $AddUser = @(),
    [switch]   $Describe,
    [string]   $Region,
    [string]   $TemplateDir = (Join-Path $PSScriptRoot 'policies')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'LabGroup-Common.ps1')

# Name guard: first thing, before any other work and before any AWS call.
if (-not (Test-LabGroupNameAllowed -Name $GroupName)) {
    [Console]::Error.WriteLine("Error: group name '$GroupName' is not allowed. Only names matching sangyshop-lab-* are accepted. No AWS call was made.")
    exit 2
}

$script:GuardedGroup = $GroupName
$script:MaxGroupPolicies = 10
$script:MaxPolicyVersions = 5
$script:UserNamePattern = '^[\w+=,.@-]{1,64}$'

foreach ($u in @($AddUser)) {
    if ([string]::IsNullOrWhiteSpace($u) -or $u -notmatch $script:UserNamePattern) {
        [Console]::Error.WriteLine("Error: '$u' is not a valid IAM user name. No AWS call was made.")
        exit 2
    }
}

. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

# Region (only used to render templates; IAM itself is global).
if ([string]::IsNullOrWhiteSpace($Region)) { $Region = $env:AWS_REGION }
if ([string]::IsNullOrWhiteSpace($Region)) { $Region = $env:AWS_DEFAULT_REGION }
$Region = Resolve-LabRegion -Region $Region
$script:LabRegion = $Region

# CLI seam -----------------------------------------------------------------------

# The test seam must be readable under strict mode even when no test set it.
if (-not (Test-Path -LiteralPath 'variable:global:LabCliHandler')) { $global:LabCliHandler = $null }

if (-not (Get-Command Invoke-LabCli -CommandType Function -ErrorAction SilentlyContinue)) {
    function Invoke-LabCli {
        <# Wrapper around the AWS CLI. $global:LabCliHandler replaces it in tests. #>
        param(
            [Parameter(Mandatory = $true)][string[]] $CliArgs,
            [switch] $Mutating
        )
        $full = @('--region', $script:LabRegion) + $CliArgs
        $shown = 'aws ' + ($full -join ' ')
        if ($Mutating -and $WhatIfPreference) {
            Write-Host "What if: $shown"
            return [pscustomobject]@{ ExitCode = 0; Output = ''; Skipped = $true }
        }
        Write-Host "+ $shown"
        if ($global:LabCliHandler) {
            $r = & $global:LabCliHandler $full
            if ($null -eq $r) { $r = [pscustomobject]@{ ExitCode = 0; Output = '' } }
            return $r
        }
        $native = $full
        if ($PSVersionTable.PSVersion -lt [version]'7.3') {
            $native = @($full | ForEach-Object { $_ -replace '"', '\"' })
        }
        $text = (& aws @native 2>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $text }
    }
}

# Operations this script may ever issue. Anything else is a programming error.
$script:AllowedOperations = @(
    'sts get-caller-identity',
    'iam get-group', 'iam create-group', 'iam list-attached-group-policies',
    'iam attach-group-policy', 'iam add-user-to-group',
    'iam get-policy', 'iam get-policy-version', 'iam list-policy-versions',
    'iam create-policy', 'iam create-policy-version', 'iam delete-policy-version'
)

function Invoke-GroupCli {
    <# Single door for every AWS call: allow-list of operations and group guard. #>
    param(
        [Parameter(Mandatory)][string[]] $CliArgs,
        [switch] $Mutating
    )
    $op = "$($CliArgs[0]) $($CliArgs[1])"
    if ($script:AllowedOperations -notcontains $op) {
        throw "Operation '$op' is not allowed in this script."
    }
    for ($i = 0; $i -lt $CliArgs.Count; $i++) {
        if ($CliArgs[$i] -eq '--group-name') {
            if ($i + 1 -ge $CliArgs.Count -or $CliArgs[$i + 1] -ne $script:GuardedGroup) {
                throw 'Refusing to touch a group other than the guarded lab group.'
            }
        }
    }
    return (Invoke-LabCli -CliArgs $CliArgs -Mutating:$Mutating)
}

function Stop-OnCliError {
    param($Result, [string] $Step)
    if ($Result.ExitCode -eq 0) { return }
    $text = "$($Result.Output)"
    if ($text -match '(?i)AccessDenied|not authorized|UnauthorizedOperation|\b403\b') {
        [Console]::Error.WriteLine("BLOCKED: permission missing in step '$Step'. Grant the IAM action shown by the error, then run this script again. Nothing was granted automatically.")
        [Console]::Error.WriteLine($text.Trim())
        exit 3
    }
    [Console]::Error.WriteLine("Error: step '$Step' failed.")
    [Console]::Error.WriteLine($text.Trim())
    exit 1
}

function Test-NoSuchEntity {
    param($Result)
    return ($Result.ExitCode -ne 0 -and "$($Result.Output)" -match 'NoSuchEntity')
}

# Normalized policy documents ------------------------------------------------------

$script:ListKeys = @('Action', 'NotAction', 'Resource', 'NotResource', 'Statement')

function ConvertTo-CanonicalJson {
    <# Deterministic text for a parsed policy document: sorted keys, scalar-or-list keys as lists. #>
    param($Node, [string] $Key = '')

    if ($null -eq $Node) { return 'null' }

    $asList = $script:ListKeys -contains $Key
    if ($asList -and -not ($Node -is [System.Array])) { $Node = @($Node) }

    if ($Node -is [System.Array]) {
        $items = @($Node | ForEach-Object { ConvertTo-CanonicalJson -Node $_ })
        if ($Key -ne 'Statement') { $items = @($items | Sort-Object -CaseSensitive) }
        return '[' + ($items -join ',') + ']'
    }
    if ($Node -is [pscustomobject]) {
        $parts = foreach ($p in ($Node.PSObject.Properties | Sort-Object Name)) {
            '"' + $p.Name + '":' + (ConvertTo-CanonicalJson -Node $p.Value -Key $p.Name)
        }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($Node -is [bool]) { return $Node.ToString().ToLowerInvariant() }
    if ($Node -is [string]) { return (ConvertTo-Json -InputObject $Node -Compress) }
    return [string]$Node
}

function Get-NormalizedDocument {
    param($Document)
    if ($Document -is [string]) { $Document = $Document | ConvertFrom-Json }
    return (ConvertTo-CanonicalJson -Node $Document)
}

function ConvertTo-CompactDocument {
    param([Parameter(Mandatory)][string] $Text)
    $obj = $Text | ConvertFrom-Json
    return (ConvertTo-Json -InputObject $obj -Depth 32 -Compress)
}

function ConvertFrom-CliJson {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

# Read phase (no mutating call) ------------------------------------------------------

$templates = @(Get-LabPolicyTemplatePath -TemplateDir $TemplateDir)
if ($templates.Count -eq 0) {
    [Console]::Error.WriteLine("Error: no policy templates found in '$TemplateDir'.")
    exit 2
}

$id = Invoke-GroupCli -CliArgs @('sts', 'get-caller-identity', '--query', 'Account', '--output', 'text')
$accountId = "$($id.Output)".Trim()
if ($id.ExitCode -ne 0 -or $accountId -notmatch '^\d{12}$') {
    [Console]::Error.WriteLine('BLOCKED: AWS credentials are missing, invalid or expired. No changes were made.')
    exit 3
}

# The group.
$groupExists = $false
$memberNames = @()
$g = Invoke-GroupCli -CliArgs @('iam', 'get-group', '--group-name', $GroupName, '--output', 'json')
if (Test-NoSuchEntity -Result $g) {
    $groupExists = $false
}
else {
    Stop-OnCliError -Result $g -Step 'get-group'
    $groupExists = $true
    $gj = ConvertFrom-CliJson -Text "$($g.Output)"
    if ($null -ne $gj -and $gj.PSObject.Properties['Users']) {
        $memberNames = @($gj.Users | ForEach-Object { [string]$_.UserName })
    }
}

# Policies attached to the group.
$attachedArns = @()
if ($groupExists) {
    $la = Invoke-GroupCli -CliArgs @('iam', 'list-attached-group-policies', '--group-name', $GroupName, '--output', 'json')
    Stop-OnCliError -Result $la -Step 'list-attached-group-policies'
    $laj = ConvertFrom-CliJson -Text "$($la.Output)"
    if ($null -ne $laj -and $laj.PSObject.Properties['AttachedPolicies']) {
        $attachedArns = @($laj.AttachedPolicies | ForEach-Object { [string]$_.PolicyArn })
    }
}

# Plan, one entry per change.
$plan = New-Object System.Collections.Generic.List[object]
$report = New-Object System.Collections.Generic.List[string]

if (-not $groupExists) {
    $plan.Add([pscustomobject]@{
            Text = "create group $GroupName"
            Args = @('iam', 'create-group', '--group-name', $GroupName)
        })
}

$missingAttachments = 0
foreach ($tpl in $templates) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($tpl)
    $policyName = "sangyshop-$base"
    $arn = "arn:aws:iam::${accountId}:policy/$policyName"
    $rendered = Expand-LabPolicyTemplate -Path $tpl -AccountId $accountId -Region $Region
    $wanted = Get-NormalizedDocument -Document $rendered
    $compact = ConvertTo-CompactDocument -Text $rendered

    $gp = Invoke-GroupCli -CliArgs @('iam', 'get-policy', '--policy-arn', $arn, '--output', 'json')
    if (Test-NoSuchEntity -Result $gp) {
        $report.Add("policy ${policyName}: missing")
        $plan.Add([pscustomobject]@{
                Text = "create policy $policyName"
                Args = @('iam', 'create-policy', '--policy-name', $policyName, '--policy-document', $compact)
            })
    }
    else {
        Stop-OnCliError -Result $gp -Step "get-policy $policyName"
        $gpj = ConvertFrom-CliJson -Text "$($gp.Output)"
        $defaultVersion = [string]$gpj.Policy.DefaultVersionId

        $gv = Invoke-GroupCli -CliArgs @('iam', 'get-policy-version', '--policy-arn', $arn, '--version-id', $defaultVersion, '--output', 'json')
        Stop-OnCliError -Result $gv -Step "get-policy-version $policyName"
        $gvj = ConvertFrom-CliJson -Text "$($gv.Output)"
        $current = Get-NormalizedDocument -Document $gvj.PolicyVersion.Document

        if ($current -eq $wanted) {
            $report.Add("policy ${policyName}: up to date")
        }
        else {
            $report.Add("policy ${policyName}: differs from the template")
            $lv = Invoke-GroupCli -CliArgs @('iam', 'list-policy-versions', '--policy-arn', $arn, '--output', 'json')
            Stop-OnCliError -Result $lv -Step "list-policy-versions $policyName"
            $lvj = ConvertFrom-CliJson -Text "$($lv.Output)"
            $versions = @($lvj.Versions)
            if ($versions.Count -ge $script:MaxPolicyVersions) {
                $oldest = @($versions | Where-Object { -not $_.IsDefaultVersion } |
                        Sort-Object @{ Expression = { ([datetime]$_.CreateDate).ToUniversalTime() } }, @{ Expression = { [int](([string]$_.VersionId) -replace '\D', '') } } |
                        Select-Object -First 1)
                if ($oldest.Count -eq 1) {
                    $plan.Add([pscustomobject]@{
                            Text = "delete oldest version $($oldest[0].VersionId) of policy $policyName (five versions in use)"
                            Args = @('iam', 'delete-policy-version', '--policy-arn', $arn, '--version-id', [string]$oldest[0].VersionId)
                        })
                }
            }
            $plan.Add([pscustomobject]@{
                    Text = "create new default version of policy $policyName"
                    Args = @('iam', 'create-policy-version', '--policy-arn', $arn, '--policy-document', $compact, '--set-as-default')
                })
        }
    }

    if ($attachedArns -contains $arn) {
        $report.Add("attachment ${policyName}: present")
    }
    else {
        $report.Add("attachment ${policyName}: missing")
        $missingAttachments++
        $plan.Add([pscustomobject]@{
                Text = "attach policy $policyName to $GroupName"
                Args = @('iam', 'attach-group-policy', '--group-name', $GroupName, '--policy-arn', $arn)
            })
    }
}

# Quota check before anything is changed.
if (($attachedArns.Count + $missingAttachments) -gt $script:MaxGroupPolicies) {
    [Console]::Error.WriteLine("Error: the group would have more than $($script:MaxGroupPolicies) managed policies attached ($($attachedArns.Count) now, $missingAttachments to add). Nothing was changed.")
    exit 4
}

foreach ($u in @($AddUser)) {
    if ($memberNames -contains $u) {
        $report.Add("member ${u}: already in group")
    }
    else {
        $report.Add("member ${u}: not in group")
        $plan.Add([pscustomobject]@{
                Text = "add user $u to $GroupName"
                Args = @('iam', 'add-user-to-group', '--group-name', $GroupName, '--user-name', $u)
            })
    }
}

# Report ----------------------------------------------------------------------------

Write-Host ''
Write-Host "Lab group: $GroupName ($(if ($groupExists) { 'exists, adopted as is' } else { 'does not exist yet' }))"
foreach ($line in $report) { Write-Host "  $line" }

if ($plan.Count -eq 0) {
    Write-Host 'Nothing to change.'
    exit 0
}

Write-Host ''
Write-Host 'Planned changes:'
foreach ($p in $plan) { Write-Host "  - $($p.Text)" }

if ($Describe) {
    Write-Host ''
    Write-Host 'Describe only: nothing was changed.'
    exit 0
}

# Apply phase -----------------------------------------------------------------------

# One explicit confirmation, before the first mutating call. -WhatIf stops here.
if (-not $PSCmdlet.ShouldProcess("IAM group $GroupName", 'Apply the planned changes listed above')) {
    exit 0
}

foreach ($p in $plan) {
    $r = Invoke-GroupCli -CliArgs $p.Args -Mutating
    if ($r.ExitCode -ne 0 -and $p.Args[1] -eq 'attach-group-policy' -and "$($r.Output)" -match 'LimitExceeded') {
        [Console]::Error.WriteLine('Error: the group reached its managed policy quota. Nothing else was changed.')
        exit 4
    }
    Stop-OnCliError -Result $r -Step $p.Args[1]
}

Write-Host ''
Write-Host 'Done. Run this script again with -Describe to confirm the final state.'
exit 0
