<#
.SYNOPSIS
    Removes the lab alert SNS topic and its subscriptions (idempotent).

.DESCRIPTION
    Deletes topic 'sangyshop-lab-alerts' (this also removes its subscriptions) only when
    it carries lab tag. A same-named topic without the tag is left unchanged.
    Re-running when the topic is gone exits 0. Supports -WhatIf.


    Required IAM actions:
      sns:DeleteTopic
      sns:GetTopicAttributes
      sns:ListTagsForResource

.EXAMPLE
    .\disable-sns.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$TopicName
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $TopicName) { $TopicName = $script:LabTopicName }
Initialize-Lab -Region $Region
$null = Get-LabAccountId
$topicArn = Get-LabTopicArn -Name $TopicName

try {
    $r = Invoke-LabCli -CliArgs @('sns', 'get-topic-attributes', '--topic-arn', $topicArn, '--query', 'Attributes.TopicArn', '--output', 'text')
    if ($r.ExitCode -ne 0) {
        Write-LabInfo "SNS topic '$TopicName' not found. Nothing to remove."
    } else {
        $t = Invoke-LabCli -CliArgs @('sns', 'list-tags-for-resource', '--resource-arn', $topicArn, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            Write-LabWarn "SNS topic '$TopicName' does not carry the lab tag: kept (not created by the lab). Left unchanged."
        } else {
            $d = Invoke-LabCli -Mutating -CliArgs @('sns', 'delete-topic', '--topic-arn', $topicArn)
            if ($d.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete SNS topic '$TopicName'. $($d.Output)" }
            Write-LabInfo "Deleted SNS topic '$TopicName' and its subscriptions."
        }
    }
    foreach ($e in @(Read-LabManifest | Where-Object { $_.type -eq 'sns-subscription' -and $_.region -eq $script:LabRegion -and "$($_.id)".StartsWith("$topicArn|") })) {
        Remove-LabManifestEntry -Type $e.type -Id $e.id
    }
} finally {
    Clear-LabTempFiles
}
exit 0
