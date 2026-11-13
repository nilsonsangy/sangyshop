<#
.SYNOPSIS
    Removes the auto-block mechanism: EventBridge rule, Lambda, IAM role and (optionally) the NACL deny entries.

.DESCRIPTION
    Reverse order of deploy-blocker.ps1. Only resources that carry the lab tag
    are deleted; untagged same-named resources are left unchanged
    with a warning. Missing resources are not an error, so it can run repeatedly.
    When -NaclId is given, inbound deny entries numbered 100-199 are deleted from that
    NACL (the range reserved for the blocker) unless -KeepBlocks is set.
    Supports -WhatIf.


    Required IAM actions:
      ec2:DeleteNetworkAclEntry
      ec2:DescribeNetworkAcls
      events:DeleteRule
      events:DescribeRule
      events:ListTagsForResource
      events:RemoveTargets
      iam:DeleteRole
      iam:DeleteRolePolicy
      iam:GetRole
      lambda:DeleteFunction
      lambda:GetFunction
      logs:DeleteLogGroup
      logs:DescribeLogGroups
      logs:ListTagsForResource

.EXAMPLE
    .\remove-blocker.ps1 -Region us-east-1 -NaclId acl-0123456789abcdef0 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$RunId,
    [string]$NaclId,
    [switch]$KeepBlocks
)
. "$PSScriptRoot\Blocker-Common.ps1"
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
if ($NaclId -and -not (Test-BlockerNaclId -Id $NaclId)) { Stop-Lab -Code 2 -Message 'Invalid -NaclId (expected acl-xxxxxxxx)' }
$account = Get-LabAccountId

$fn = $script:BlockerFunctionName
$role = $script:BlockerRoleName
$ruleName = $script:BlockerRuleName

try {
    # 1. EventBridge rule (targets first)
    $ruleArn = "arn:aws:events:$($script:LabRegion):${account}:rule/$ruleName"
    $e = Invoke-LabCli -CliArgs @('events', 'describe-rule', '--name', $ruleName, '--query', 'Arn', '--output', 'text')
    if ($e.ExitCode -ne 0) {
        Write-LabInfo "EventBridge rule '$ruleName' not found. Nothing to do."
    } else {
        $t = Invoke-LabCli -CliArgs @('events', 'list-tags-for-resource', '--resource-arn', $ruleArn, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            Write-LabWarn "EventBridge rule '$ruleName' does not carry the lab tag. Left unchanged (untagged resource)."
        } else {
            $null = Invoke-LabCli -Mutating -CliArgs @('events', 'remove-targets', '--rule', $ruleName, '--ids', 'blocker')
            $d = Invoke-LabCli -Mutating -CliArgs @('events', 'delete-rule', '--name', $ruleName)
            if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the EventBridge rule. $($d.Output)" }
            Write-LabInfo "Deleted EventBridge rule '$ruleName'."
        }
    }

    # 2. Lambda (its resource policy goes with it)
    $g = Invoke-LabCli -CliArgs @('lambda', 'get-function', '--function-name', $fn, '--query', 'Tags', '--output', 'json')
    if ($g.ExitCode -ne 0) {
        Write-LabInfo "Lambda '$fn' not found. Nothing to do."
    } elseif (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $g.Output))) {
        Write-LabWarn "Lambda '$fn' does not carry the lab tag. Left unchanged (untagged resource)."
    } else {
        $d = Invoke-LabCli -Mutating -CliArgs @('lambda', 'delete-function', '--function-name', $fn)
        if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the Lambda. $($d.Output)" }
        Write-LabInfo "Deleted Lambda '$fn'."
    }

    # 2b. The Lambda's own log group (deleted only when it carries the lab tag)
    Remove-LabLogGroup -Name "/aws/lambda/$fn"

    # 3. IAM role (inline policy first)
    $r = Invoke-LabCli -CliArgs @('iam', 'get-role', '--role-name', $role, '--query', 'Role.Tags', '--output', 'json')
    if ($r.ExitCode -ne 0) {
        Write-LabInfo "IAM role '$role' not found. Nothing to do."
    } elseif (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $r.Output))) {
        Write-LabWarn "IAM role '$role' does not carry the lab tag. Left unchanged (untagged resource)."
    } else {
        $null = Invoke-LabCli -Mutating -CliArgs @('iam', 'delete-role-policy', '--role-name', $role, '--policy-name', $script:BlockerRolePolicyName)
        $d = Invoke-LabCli -Mutating -CliArgs @('iam', 'delete-role', '--role-name', $role)
        if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the IAM role. $($d.Output)" }
        Write-LabInfo "Deleted IAM role '$role'."
    }

    # 4. NACL deny entries created by the blocker (range 100-199, inbound, deny)
    if ($NaclId -and -not $KeepBlocks) {
        $n = Invoke-LabCli -CliArgs @('ec2', 'describe-network-acls', '--network-acl-ids', $NaclId, '--query', 'NetworkAcls[0].{t:Tags,e:Entries}', '--output', 'json')
        $acl = if ($n.ExitCode -eq 0) { ConvertFrom-LabJson -Text $n.Output } else { $null }
        if (-not $acl) {
            Write-LabInfo "NACL '$NaclId' not found. Nothing to do."
        } elseif (-not (Test-LabTagged -Tags $acl.t)) {
            Write-LabWarn "NACL '$NaclId' does not carry the lab tag. Entries left unchanged (untagged resource)."
        } else {
            $mine = @($acl.e | Where-Object {
                    $_ -and -not $_.Egress -and $_.RuleAction -eq 'deny' -and
                    $_.RuleNumber -ge $script:BlockerRuleMin -and $_.RuleNumber -le $script:BlockerRuleMax })
            if ($mine.Count -eq 0) { Write-LabInfo 'No blocker deny entries on the NACL. Nothing to do.' }
            foreach ($entry in $mine) {
                $d = Invoke-LabCli -Mutating -CliArgs @('ec2', 'delete-network-acl-entry', '--network-acl-id', $NaclId, '--rule-number', "$($entry.RuleNumber)", '--ingress')
                if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete NACL entry $($entry.RuleNumber). $($d.Output)" }
                Write-LabInfo "Deleted NACL deny entry $($entry.RuleNumber) ($($entry.CidrBlock))."
            }
        }
    } elseif (-not $NaclId) {
        Write-LabInfo 'No -NaclId given: NACL deny entries (if any) were not touched.'
    }
} finally {
    Clear-LabTempFiles
}
exit 0
