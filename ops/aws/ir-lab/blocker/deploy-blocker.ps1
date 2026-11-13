<#
.SYNOPSIS
    Deploys the auto-block mechanism: IAM role, Lambda, EventBridge rule and invoke permission (idempotent).

.DESCRIPTION
    Chain: the lab CloudWatch alarm (see AlarmName in AwsLabNames.ps1) enters ALARM -> EventBridge rule
    -> blocker Lambda -> Logs Insights query on the application log group ->
    inbound NACL deny entries (rule numbers 100-199) for IPs with >= Threshold failures.
    Private, loopback and link-local ranges are never blocked.

    Resources carry the lab tag (lab, run-id, component). A same-named resource without the
    tag is left unchanged and the script stops with exit 1. Re-running updates the code,
    configuration and policy in place and creates nothing twice. Supports -WhatIf.

    NOTE: NACLs evaluate rules in ascending order. The deny entries (100-199) only work
    if the allow rules of the NACL have numbers above 199.


    Required IAM actions:
      ec2:DescribeNetworkAcls
      events:DescribeRule
      events:ListTagsForResource
      events:PutRule
      events:PutTargets
      events:TagResource
      iam:CreateRole
      iam:GetRole
      iam:PassRole
      iam:PutRolePolicy
      iam:TagRole
      lambda:AddPermission
      lambda:CreateFunction
      lambda:GetFunction
      lambda:GetPolicy
      lambda:TagResource
      lambda:UpdateFunctionCode
      lambda:UpdateFunctionConfiguration
      logs:CreateLogGroup
      logs:DescribeLogGroups
      logs:ListTagsForResource
      logs:PutRetentionPolicy
      logs:TagResource

.EXAMPLE
    .\deploy-blocker.ps1 -Region us-east-1 -NaclId acl-0123456789abcdef0 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$RunId,
    [string]$NaclId,
    [string]$TopicArn,
    [int]$Threshold = 10,
    [int]$WindowMinutes = 5,
    [string]$LogGroup
)
. "$PSScriptRoot\Blocker-Common.ps1"
if (-not $LogGroup) { $LogGroup = $script:LabAppLogGroup }
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
if ([string]::IsNullOrWhiteSpace($NaclId) -or -not (Test-BlockerNaclId -Id $NaclId)) {
    Stop-Lab -Code 2 -Message 'Missing or invalid -NaclId (expected acl-xxxxxxxx of the lab subnet NACL)'
}
if ($Threshold -lt 1) { Stop-Lab -Code 2 -Message '-Threshold must be 1 or greater' }
if ($WindowMinutes -lt 1 -or $WindowMinutes -gt 60) { Stop-Lab -Code 2 -Message '-WindowMinutes must be between 1 and 60' }
$account = Get-LabAccountId
if (-not $TopicArn) { $TopicArn = Get-LabTopicArn -Name $script:LabTopicName }
if ($TopicArn -notmatch '^arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+$') { Stop-Lab -Code 2 -Message "Invalid -TopicArn: $TopicArn" }

$fn = $script:BlockerFunctionName
$role = $script:BlockerRoleName
$ruleName = $script:BlockerRuleName
$values = @{
    REGION = $script:LabRegion; ACCOUNT_ID = $account; NACL_ID = $NaclId; LOG_GROUP = $LogGroup
    TOPIC_ARN = $TopicArn; FUNCTION_NAME = $fn; ALARM_NAME = $script:LabAlarmName
}

try {
    # 0. The NACL must exist and carry the lab tag (never touch a NACL that is not ours).
    $n = Invoke-LabCli -CliArgs @('ec2', 'describe-network-acls', '--network-acl-ids', $NaclId, '--query', 'NetworkAcls[0].Tags', '--output', 'json')
    if ($n.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "NACL '$NaclId' was not found in $($script:LabRegion). $($n.Output)" }
    if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $n.Output))) {
        Confirm-LabUntaggedRefusal -Kind 'Network ACL' -Name $NaclId
    }

    # 1. IAM role (trust + inline least-privilege policy)
    $roleCreated = $false
    $r = Invoke-LabCli -CliArgs @('iam', 'get-role', '--role-name', $role, '--query', 'Role.Tags', '--output', 'json')
    if ($r.ExitCode -eq 0) {
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $r.Output))) { Confirm-LabUntaggedRefusal -Kind 'IAM role' -Name $role }
        Write-LabInfo "IAM role '$role' already exists with the lab tag."
    } elseif (Test-BlockerAwsNotFound -Result $r) {
        $trust = New-LabTempFile -Text (Get-BlockerPolicyText -File 'lambda-trust-policy.json' -Values $values)
        $c = Invoke-LabCli -Mutating -CliArgs (@('iam', 'create-role', '--role-name', $role, '--assume-role-policy-document', $trust,
                '--description', 'Lab auto-block Lambda role', '--tags') + (Get-LabTagPairs -RunId $RunId))
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create IAM role. $($c.Output)" }
        $roleCreated = $true
        Write-LabInfo "Created IAM role '$role'."
    } else {
        Stop-Lab -Code 1 -Message "Could not read IAM role '$role'. $($r.Output)"
    }
    $policy = New-LabTempFile -Text (Get-BlockerPolicyText -File 'lambda-execution-role.json' -Values $values)
    $p = Invoke-LabCli -Mutating -CliArgs @('iam', 'put-role-policy', '--role-name', $role, '--policy-name', $script:BlockerRolePolicyName, '--policy-document', $policy)
    if ($p.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not attach the inline policy. $($p.Output)" }
    Write-LabInfo "Inline policy '$($script:BlockerRolePolicyName)' is in place."
    if ($roleCreated -and -not $WhatIfPreference -and -not $global:LabCliHandler) {
        Write-LabInfo 'Waiting 10 seconds for IAM propagation...'
        Start-Sleep -Seconds 10
    }
    $roleArn = "arn:aws:iam::${account}:role/$role"

    # 2a. The Lambda's own log group. Created here (tagged) so Lambda does not auto-create
    #     an untagged one on first invoke. An existing untagged one is adopted (it is ours).
    Confirm-LabLogGroup -Name "/aws/lambda/$fn" -RunId $RunId -Adopt

    # 2. Lambda package and function
    $zip = Join-Path ([System.IO.Path]::GetTempPath()) ("lab-blocker-{0}.zip" -f [guid]::NewGuid().ToString('N'))
    [void]$script:LabTempFiles.Add($zip)
    Compress-Archive -LiteralPath (Join-Path $PSScriptRoot 'lambda_function.py') -DestinationPath $zip -Force -WhatIf:$false
    $zipArg = 'fileb://' + ($zip -replace '\\', '/')
    $envJson = New-LabTempFile -Text (([ordered]@{ Variables = [ordered]@{
                    NACL_ID = $NaclId; LOG_GROUP = $LogGroup; TOPIC_ARN = $TopicArn
                    THRESHOLD = "$Threshold"; WINDOW_MINUTES = "$WindowMinutes" } }) | ConvertTo-Json -Depth 4 -Compress)

    $g = Invoke-LabCli -CliArgs @('lambda', 'get-function', '--function-name', $fn, '--query', 'Tags', '--output', 'json')
    if ($g.ExitCode -eq 0) {
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $g.Output))) { Confirm-LabUntaggedRefusal -Kind 'Lambda function' -Name $fn }
        $u = Invoke-LabCli -Mutating -CliArgs @('lambda', 'update-function-code', '--function-name', $fn, '--zip-file', $zipArg)
        if ($u.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not update the function code. $($u.Output)" }
        $null = Invoke-LabCli -CliArgs @('lambda', 'wait', 'function-updated-v2', '--function-name', $fn)
        $u = Invoke-LabCli -Mutating -CliArgs @('lambda', 'update-function-configuration', '--function-name', $fn, '--role', $roleArn,
            '--timeout', '60', '--memory-size', '128', '--environment', $envJson)
        if ($u.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not update the function configuration. $($u.Output)" }
        Write-LabInfo "Updated Lambda '$fn' (code and configuration)."
    } elseif (Test-BlockerAwsNotFound -Result $g) {
        $created = $false
        for ($i = 1; $i -le 3 -and -not $created; $i++) {
            $c = Invoke-LabCli -Mutating -CliArgs @('lambda', 'create-function', '--function-name', $fn, '--runtime', 'python3.12',
                '--handler', 'lambda_function.handler', '--role', $roleArn, '--zip-file', $zipArg,
                '--timeout', '60', '--memory-size', '128', '--environment', $envJson,
                '--description', 'Lab auto-block (NACL deny by IP)', '--tags', (Get-LabTagMap -RunId $RunId))
            if ($c.ExitCode -eq 0) { $created = $true; break }
            if ("$($c.Output)" -match 'cannot be assumed' -and $i -lt 3 -and -not $global:LabCliHandler) {
                Write-LabWarn 'Role not propagated yet. Retrying in 5 seconds.'
                Start-Sleep -Seconds 5
            } else {
                Stop-Lab -Code 1 -Message "Could not create the Lambda function. $($c.Output)"
            }
        }
        $null = Invoke-LabCli -CliArgs @('lambda', 'wait', 'function-active-v2', '--function-name', $fn)
        Write-LabInfo "Created Lambda '$fn'."
    } else {
        Stop-Lab -Code 1 -Message "Could not read Lambda '$fn'. $($g.Output)"
    }
    $fnArn = "arn:aws:lambda:$($script:LabRegion):${account}:function:$fn"

    # 3. EventBridge rule (alarm -> ALARM) and target
    $ruleArn = "arn:aws:events:$($script:LabRegion):${account}:rule/$ruleName"
    $e = Invoke-LabCli -CliArgs @('events', 'describe-rule', '--name', $ruleName, '--query', 'Arn', '--output', 'text')
    if ($e.ExitCode -eq 0) {
        $t = Invoke-LabCli -CliArgs @('events', 'list-tags-for-resource', '--resource-arn', $ruleArn, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) { Confirm-LabUntaggedRefusal -Kind 'EventBridge rule' -Name $ruleName }
        $putTags = @()
    } elseif (Test-BlockerAwsNotFound -Result $e) {
        $putTags = @('--tags') + (Get-LabTagPairs -RunId $RunId)
    } else {
        Stop-Lab -Code 1 -Message "Could not read EventBridge rule '$ruleName'. $($e.Output)"
    }
    $pattern = New-LabTempFile -Text (Get-BlockerPolicyText -File 'eventbridge-rule-pattern.json' -Values $values)
    $pr = Invoke-LabCli -Mutating -CliArgs (@('events', 'put-rule', '--name', $ruleName, '--event-pattern', $pattern, '--state', 'ENABLED',
            '--description', "Alarm $($script:LabAlarmName) in ALARM triggers the auto-block Lambda") + $putTags)
    if ($pr.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the EventBridge rule. $($pr.Output)" }
    $targets = New-LabTempFile -Text ('[{"Id":"blocker","Arn":"' + $fnArn + '"}]')
    $pt = Invoke-LabCli -Mutating -CliArgs @('events', 'put-targets', '--rule', $ruleName, '--targets', $targets)
    if ($pt.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not set the rule target. $($pt.Output)" }
    Write-LabInfo "EventBridge rule '$ruleName' targets the Lambda."

    # 4. Permission for EventBridge to invoke the function (only this rule)
    $pol = Invoke-LabCli -CliArgs @('lambda', 'get-policy', '--function-name', $fn, '--query', 'Policy', '--output', 'text')
    if ($pol.ExitCode -eq 0 -and "$($pol.Output)" -match [regex]::Escape($script:BlockerStatementId)) {
        Write-LabInfo 'Invoke permission already exists. Nothing to create.'
    } else {
        $a = Invoke-LabCli -Mutating -CliArgs @('lambda', 'add-permission', '--function-name', $fn, '--statement-id', $script:BlockerStatementId,
            '--action', 'lambda:InvokeFunction', '--principal', 'events.amazonaws.com', '--source-arn', $ruleArn)
        if ($a.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not add the invoke permission. $($a.Output)" }
        Write-LabInfo 'Added the EventBridge invoke permission.'
    }
    Write-LabInfo "Auto-block ready: threshold $Threshold failures in $WindowMinutes min, NACL $NaclId, rules $($script:BlockerRuleMin)-$($script:BlockerRuleMax)."
} finally {
    Clear-LabTempFiles
}
exit 0
