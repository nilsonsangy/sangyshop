<#
.SYNOPSIS
    Disables the lab VPC Flow Logs and removes their log group and IAM role (idempotent).

.DESCRIPTION
    Finds flow logs by lab_tag (no hand-typed IDs), deletes them, then deletes the
    /sangyshop/vpcflow log group and the delivery role when they carry lab tag.
    Use -KeepLogGroup to keep the collected flow records. Re-running when everything is
    gone exits 0. Supports -WhatIf.


    Required IAM actions:
      ec2:DeleteFlowLogs
      ec2:DescribeFlowLogs
      iam:DeleteRole
      iam:DeleteRolePolicy
      iam:GetRole
      iam:ListRoleTags
      logs:DeleteLogGroup
      logs:DescribeLogGroups
      logs:ListTagsForResource

.EXAMPLE
    .\disable-flowlogs.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$LogGroup,
    [switch]$KeepLogGroup
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $LogGroup) { $LogGroup = $script:LabFlowLogGroup }
Initialize-Lab -Region $Region
$null = Get-LabAccountId
$roleName = $script:LabFlowRoleName

try {
    # Flow logs
    $fl = Invoke-LabCli -CliArgs @('ec2', 'describe-flow-logs', '--filter', "Name=tag:$($script:LabTagKey),Values=$($script:LabTagValue)", '--query', 'FlowLogs[].FlowLogId', '--output', 'json')
    $ids = @()
    if ($fl.ExitCode -eq 0) { $ids = @(ConvertFrom-LabJson -Text $fl.Output) }
    if ($ids.Count -eq 0) {
        Write-LabInfo 'No lab VPC flow logs found. Nothing to remove.'
    } else {
        $d = Invoke-LabCli -Mutating -CliArgs (@('ec2', 'delete-flow-logs', '--flow-log-ids') + @($ids | ForEach-Object { "$_" }))
        if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete the flow logs. $($d.Output)" }
        Write-LabInfo "Deleted flow log(s): $($ids -join ', ')."
    }

    # Log group
    if ($KeepLogGroup) {
        Write-LabInfo "Keeping log group '$LogGroup' (-KeepLogGroup). It keeps costing storage until removed."
    } else {
        Remove-LabLogGroup -Name $LogGroup
    }

    # Delivery role
    $g = Invoke-LabCli -CliArgs @('iam', 'get-role', '--role-name', $roleName, '--query', 'Role.Arn', '--output', 'text')
    if ($g.ExitCode -ne 0) {
        Write-LabInfo "IAM role '$roleName' not found. Nothing to remove."
    } else {
        $rt = Invoke-LabCli -CliArgs @('iam', 'list-role-tags', '--role-name', $roleName, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $rt.Output))) {
            Write-LabWarn "IAM role '$roleName' does not carry the lab tag: kept (not created by the lab). Left unchanged."
        } else {
            $p = Invoke-LabCli -Mutating -CliArgs @('iam', 'delete-role-policy', '--role-name', $roleName, '--policy-name', 'flowlogs-delivery')
            if ($p.ExitCode -ne 0 -and "$($p.Output)" -notmatch 'NoSuchEntity') { Stop-Lab -Code 1 -Message "Could not delete the role policy. $($p.Output)" }
            $d = Invoke-LabCli -Mutating -CliArgs @('iam', 'delete-role', '--role-name', $roleName)
            if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete IAM role '$roleName'. $($d.Output)" }
            Write-LabInfo "Deleted IAM role '$roleName'."
        }
    }
} finally {
    Clear-LabTempFiles
}
exit 0
