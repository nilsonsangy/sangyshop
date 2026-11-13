<#
.SYNOPSIS
    Enables VPC Flow Logs to a CloudWatch Logs group (idempotent, optional and billable).

.DESCRIPTION
    Creates log group /sangyshop/vpcflow, the IAM delivery role 'sangyshop-lab-flowlogs-role'
    (both tagged with lab tag) and one flow log on the lab VPC. When -VpcId is omitted the
    script looks for exactly one VPC that carries lab tag. A VPC that already has a lab flow
    log is left alone. Re-running creates nothing new. Supports -WhatIf.


    Required IAM actions:
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      ec2:CreateFlowLogs
      ec2:CreateTags
      ec2:DescribeFlowLogs
      ec2:DescribeVpcs
      guardduty:GetDetector
      guardduty:ListDetectors
      iam:CreateRole
      iam:GetRole
      iam:ListRoleTags
      iam:PassRole
      iam:PutRolePolicy
      iam:TagRole
      logs:CreateLogGroup
      logs:DescribeLogGroups
      logs:ListTagsForResource
      logs:PutRetentionPolicy
      logs:TagResource
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics

.EXAMPLE
    .\enable-flowlogs.ps1 -Region us-east-1 -VpcId vpc-0123456789abcdef0 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$VpcId,
    [string]$RunId,
    [string]$LogGroup,
    [int]$RetentionDays = 3,
    [switch]$AdoptExisting
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $LogGroup) { $LogGroup = $script:LabFlowLogGroup }
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
$account = Get-LabAccountId
$roleName = $script:LabFlowRoleName
$roleArn = "arn:aws:iam::${account}:role/$roleName"

# Preflight: read what exists (read verbs only) before any change.
$snapshot = Get-LabPreflightSnapshot -LogGroup $LogGroup
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'loggroup' -ExpectedName $LogGroup

try {
    # Resolve the VPC
    if ([string]::IsNullOrWhiteSpace($VpcId)) {
        $v = Invoke-LabCli -CliArgs @('ec2', 'describe-vpcs', '--filters', "Name=tag:$($script:LabTagKey),Values=$($script:LabTagValue)", '--query', 'Vpcs[].VpcId', '--output', 'json')
        $vpcs = @()
        if ($v.ExitCode -eq 0) { $vpcs = @(ConvertFrom-LabJson -Text $v.Output) }
        if ($vpcs.Count -ne 1) {
            Stop-Lab -Code 2 -Message "Could not pick the lab VPC automatically ($($vpcs.Count) VPCs carry the lab tag). Pass -VpcId."
        }
        $VpcId = "$($vpcs[0])"
    }
    if ($VpcId -notmatch '^vpc-[0-9a-f]+$') { Stop-Lab -Code 2 -Message "Invalid -VpcId '$VpcId'" }

    # Already enabled?
    $fl = Invoke-LabCli -CliArgs @('ec2', 'describe-flow-logs', '--filter', "Name=resource-id,Values=$VpcId", "Name=tag:$($script:LabTagKey),Values=$($script:LabTagValue)", '--query', 'FlowLogs[].FlowLogId', '--output', 'json')
    $flowIds = @()
    if ($fl.ExitCode -eq 0) { $flowIds = @(ConvertFrom-LabJson -Text $fl.Output) }
    if ($flowIds.Count -gt 0) {
        Write-LabInfo "VPC $VpcId already has a lab flow log ($($flowIds -join ', ')). Nothing to create."
    } else {
        # Log group
        $null = Confirm-LabLogGroup -Name $LogGroup -RunId $RunId -RetentionDays $RetentionDays -Adopt:$AdoptExisting

        # Delivery role
        $createdRole = $false
        $g = Invoke-LabCli -CliArgs @('iam', 'get-role', '--role-name', $roleName, '--query', 'Role.Arn', '--output', 'text')
        if ($g.ExitCode -eq 0) {
            $rt = Invoke-LabCli -CliArgs @('iam', 'list-role-tags', '--role-name', $roleName, '--query', 'Tags', '--output', 'json')
            if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $rt.Output))) {
                if (-not (Test-LabManifestCreated -Type 'iam-role' -Id $roleName)) {
                    Confirm-LabUntaggedRefusal -Kind 'IAM role' -Name $roleName
                }
                $tr = Invoke-LabCli -Mutating -CliArgs (@('iam', 'tag-role', '--role-name', $roleName, '--tags') + (Get-LabTagPairs -RunId $RunId))
                if ($tr.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of IAM role '$roleName'. $($tr.Output)" }
                Write-LabInfo "IAM role '$roleName' was created by the lab without tags. Completed the tags."
            }
            Write-LabInfo "IAM role '$roleName' already exists with the lab tag."
        } else {
            $trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"vpc-flow-logs.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            $c = Invoke-LabCli -Mutating -CliArgs (@('iam', 'create-role', '--role-name', $roleName, '--assume-role-policy-document', (New-LabTempFile -Text $trust), '--tags') + (Get-LabTagPairs -RunId $RunId))
            if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create IAM role '$roleName'. $($c.Output)" }
            Add-LabResource -Type 'iam-role' -Id $roleName -RunId $RunId
            $createdRole = $true
            Write-LabInfo "Created IAM role '$roleName'."
        }
        # The inline policy is re-applied every time (put-role-policy is idempotent).
        $logArn = "arn:aws:logs:${script:LabRegion}:${account}:log-group:${LogGroup}:*"
        $policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogStreams"],"Resource":"' + $logArn + '"}]}'
        $p = Invoke-LabCli -Mutating -CliArgs @('iam', 'put-role-policy', '--role-name', $roleName, '--policy-name', 'flowlogs-delivery', '--policy-document', (New-LabTempFile -Text $policy))
        if ($p.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not attach the delivery policy. $($p.Output)" }
        if ($createdRole -and -not $WhatIfPreference) {
            Write-LabInfo 'Waiting 10 seconds for IAM propagation.'
            Start-Sleep -Seconds 10
        }

        # Flow log
        $tagSpec = 'ResourceType=vpc-flow-log,Tags=[{Key=' + $script:LabTagKey + ',Value=' + $script:LabTagValue + '},{Key=run-id,Value=' + $RunId + '}]'
        $c = Invoke-LabCli -Mutating -CliArgs @(
            'ec2', 'create-flow-logs', '--resource-type', 'VPC', '--resource-ids', $VpcId,
            '--traffic-type', 'ALL', '--log-destination-type', 'cloud-watch-logs',
            '--log-group-name', $LogGroup, '--deliver-logs-permission-arn', $roleArn,
            '--max-aggregation-interval', '60', '--tag-specifications', $tagSpec, '--query', 'FlowLogIds', '--output', 'json')
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the VPC flow log. $($c.Output)" }
        foreach ($flId in @(ConvertFrom-LabJson -Text $c.Output | Where-Object { $_ })) {
            Add-LabResource -Type 'flow-log' -Id "$flId" -RunId $RunId
        }
        Write-LabInfo "VPC Flow Logs enabled for $VpcId -> $LogGroup (billable per GB ingested)."
    }
} finally {
    Clear-LabTempFiles
}
exit 0
