<#
.SYNOPSIS
    Creates the lab alert SNS topic and an e-mail subscription (idempotent).

.DESCRIPTION
    Creates topic 'sangyshop-lab-alerts' tagged with lab_tag (lab=sangyshop-lab-aws) and
    run-id, then subscribes an e-mail address. The subscription cannot carry tags, so it
    is recorded in the lab manifest. The user must confirm the subscription from the
    e-mail AWS sends. Re-running creates nothing new. Supports -WhatIf.

    A topic with this name that the lab did not create is reused as it is (not tagged, not
    changed, recorded with ownership reused); only the e-mail subscription is added. A topic
    the lab created without tags (interrupted run) gets the missing tags. Exit codes: 0 done,
    1 failure, 2 invalid e-mail, 3 permission missing (fix it and run the script again),
    4 quota reached.

    The e-mail address is resolved in this order (Resolve-LabAlertEmail, Detection-Common.ps1):
      1. -Email, if passed.
      2. $env:LAB_ALERT_EMAIL, read from a .env file at the repository root if present
         (copy .env.example to .env and set LAB_ALERT_EMAIL there; .env is git-ignored).
      3. An interactive prompt (skipped, exit code 2, when -NonInteractive is set).
    No real e-mail address is ever hardcoded in this script.


    Required IAM actions:
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      guardduty:GetDetector
      guardduty:ListDetectors
      logs:DescribeLogGroups
      logs:ListTagsForResource
      sns:CreateTopic
      sns:GetTopicAttributes
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics
      sns:Subscribe
      sns:TagResource

.EXAMPLE
    .\enable-sns.ps1 -Region us-east-1 -Email user@example.com -WhatIf

.EXAMPLE
    # LAB_ALERT_EMAIL set in .env at the repository root:
    .\enable-sns.ps1 -Region us-east-1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$Email,
    [string]$RunId,
    [string]$TopicName,
    [switch]$NonInteractive
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $TopicName) { $TopicName = $script:LabTopicName }
Initialize-Lab -Region $Region
$Email = Resolve-LabAlertEmail -Email $Email -NonInteractive:$NonInteractive
if ($Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
    Stop-Lab -Code 2 -Message "Invalid e-mail address: '$Email'"
}
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabAccountId
$topicArn = Get-LabTopicArn -Name $TopicName

# Preflight: read what exists (read verbs only) before any change.
$snapshot = Get-LabPreflightSnapshot
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'topic' -ExpectedName $TopicName
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'subscription' -ExpectedName $Email
$topicForeign = $false

try {
    # 1. Topic: the lab topic is reused and completed, a topic the lab did not create is reused untouched.
    $r = Invoke-LabCli -CliArgs @('sns', 'get-topic-attributes', '--topic-arn', $topicArn, '--query', 'Attributes.TopicArn', '--output', 'text')
    if ($r.ExitCode -eq 0) {
        $t = Invoke-LabCli -CliArgs @('sns', 'list-tags-for-resource', '--resource-arn', $topicArn, '--query', 'Tags', '--output', 'json')
        if (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output)) {
            Write-LabInfo "SNS topic '$TopicName' already exists with the lab tag. Nothing to create."
        } elseif (Test-LabManifestCreated -Type 'sns-topic' -Id $TopicName) {
            # Created by the lab in an interrupted run: add the missing tags, never recreate.
            $tag = Invoke-LabCli -Mutating -CliArgs (@('sns', 'tag-resource', '--resource-arn', $topicArn, '--tags') + (Get-LabTagPairs -RunId $RunId))
            if ($tag.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of SNS topic '$TopicName'. $($tag.Output)" }
            Write-LabInfo "SNS topic '$TopicName' was created by the lab without tags. Added the missing tags."
        } else {
            $topicForeign = $true
            Write-LabKept -Kind 'SNS topic' -Name $TopicName
            Write-LabInfo 'Only the lab e-mail subscription is added to it.'
            Add-LabReusedResource -Type 'sns-topic' -Id $TopicName -RunId $RunId
        }
    } else {
        $createArgs = @('sns', 'create-topic', '--name', $TopicName, '--tags') + (Get-LabTagPairs -RunId $RunId) + @('--query', 'TopicArn', '--output', 'text')
        $c = Invoke-LabCli -Mutating -CliArgs $createArgs
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create SNS topic '$TopicName'. $($c.Output)" }
        Add-LabResource -Type 'sns-topic' -Id $TopicName -RunId $RunId
        Write-LabInfo "Created SNS topic '$TopicName'."
    }

    # 2. Subscription: skip when this endpoint is already subscribed.
    $s = Invoke-LabCli -CliArgs @('sns', 'list-subscriptions-by-topic', '--topic-arn', $topicArn, '--query', 'Subscriptions[].Endpoint', '--output', 'json')
    $endpoints = @()
    if ($s.ExitCode -eq 0) { $endpoints = @(ConvertFrom-LabJson -Text $s.Output) }
    $subId = "$topicArn|email|$Email"
    if ($endpoints -contains $Email) {
        Write-LabInfo 'The e-mail subscription already exists. Nothing to subscribe.'
        if ($topicForeign -and -not (Test-LabManifestCreated -Type 'sns-subscription' -Id $subId)) {
            # A subscription on a topic the lab did not create, made before the lab: keep it.
            Add-LabReusedResource -Type 'sns-subscription' -Id $subId -RunId $RunId
        } else {
            Add-LabResource -Type 'sns-subscription' -Id $subId -RunId $RunId
        }
    } else {
        $sub = Invoke-LabCli -Mutating -CliArgs @('sns', 'subscribe', '--topic-arn', $topicArn, '--protocol', 'email', '--notification-endpoint', $Email, '--return-subscription-arn')
        if ($sub.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not subscribe the e-mail address. $($sub.Output)" }
        Add-LabResource -Type 'sns-subscription' -Id $subId -RunId $RunId
        Write-LabInfo 'Subscription requested. Open the AWS confirmation e-mail and confirm it to receive alerts.'
    }
} finally {
    Clear-LabTempFiles
}
exit 0
