<#
.SYNOPSIS
    Enables the GuardDuty detector for the lab account and region (idempotent, billable after the 30-day trial).

.DESCRIPTION
    GuardDuty allows one detector per region. If one exists with lab tag it is reused (and
    re-enabled when suspended). If one exists that the lab did not create, it is
    reused as it is: not tagged, not changed, recorded in the lab manifest with ownership
    reused, and never removed by the lab (-AdoptExisting no longer tags it). A detector the
    lab created without tags (interrupted run) gets the missing tags. Otherwise a detector
    is created with lab tag and run-id and recorded in the manifest. Supports -WhatIf.

    Exit codes: 0 done or reused, 1 failure, 3 permission missing (the message names the
    policy; fix it and run the script again), 4 quota reached.


    Required IAM actions:
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      guardduty:CreateDetector
      guardduty:GetDetector
      guardduty:ListDetectors
      guardduty:ListTagsForResource
      guardduty:TagResource
      guardduty:UpdateDetector
      logs:DescribeLogGroups
      logs:ListTagsForResource
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics

.EXAMPLE
    .\enable-guardduty.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$RunId,
    [switch]$AdoptExisting
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId
$account = Get-LabAccountId

# Preflight: read what exists (read verbs only) before any change.
$snapshot = Get-LabPreflightSnapshot
$null = Resolve-LabDecision -Snapshot $snapshot -Type 'detector' -ExpectedName 'detector' -Singleton

try {
    $l = Invoke-LabCli -CliArgs @('guardduty', 'list-detectors', '--query', 'DetectorIds', '--output', 'json')
    if ($l.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not list GuardDuty detectors. $($l.Output)" }
    $detectors = @(ConvertFrom-LabJson -Text $l.Output)
    if ($detectors.Count -gt 0) {
        $id = "$($detectors[0])"
        $arn = "arn:aws:guardduty:${script:LabRegion}:${account}:detector/$id"
        $t = Invoke-LabCli -CliArgs @('guardduty', 'list-tags-for-resource', '--resource-arn', $arn, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            if (Test-LabManifestCreated -Type 'guardduty-detector' -Id $id) {
                # Created by the lab in an interrupted run before the tags were applied: complete them, never recreate.
                $tag = Invoke-LabCli -Mutating -CliArgs @('guardduty', 'tag-resource', '--resource-arn', $arn, '--tags', (Get-LabTagMap -RunId $RunId))
                if ($tag.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of the detector. $($tag.Output)" }
                Write-LabInfo "Detector $id was created by the lab without tags. Completed the tags."
            } else {
                # A detector the lab did not create (only one is allowed per region): use it as it is.
                if ($AdoptExisting) { Write-LabWarn '-AdoptExisting is ignored: the lab does not tag resources it did not create.' }
                Write-LabKept -Kind 'GuardDuty detector' -Name $id
                Add-LabReusedResource -Type 'guardduty-detector' -Id $id -RunId $RunId
                $st = Invoke-LabCli -CliArgs @('guardduty', 'get-detector', '--detector-id', $id, '--query', 'Status', '--output', 'text')
                if ("$($st.Output)".Trim() -eq 'DISABLED') { Write-LabWarn "Detector $id is disabled. The lab does not change its settings; enable it yourself if you want GuardDuty findings." }
                exit 0
            }
        }
        $s = Invoke-LabCli -CliArgs @('guardduty', 'get-detector', '--detector-id', $id, '--query', 'Status', '--output', 'text')
        if ("$($s.Output)".Trim() -eq 'DISABLED') {
            $u = Invoke-LabCli -Mutating -CliArgs @('guardduty', 'update-detector', '--detector-id', $id, '--enable')
            if ($u.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not re-enable the detector. $($u.Output)" }
            Write-LabInfo "Re-enabled GuardDuty detector $id."
        } else {
            Write-LabInfo "GuardDuty detector $id already exists and is enabled. Nothing to create."
        }
    } else {
        $c = Invoke-LabCli -Mutating -CliArgs @('guardduty', 'create-detector', '--enable', '--finding-publishing-frequency', 'FIFTEEN_MINUTES', '--tags', (Get-LabTagMap -RunId $RunId), '--query', 'DetectorId', '--output', 'text')
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the GuardDuty detector. $($c.Output)" }
        $newId = "$($c.Output)".Trim()
        if ($newId) { Add-LabResource -Type 'guardduty-detector' -Id $newId -RunId $RunId }
        Write-LabInfo 'Created the GuardDuty detector (30-day free trial per region on first activation, then billable).'
    }
} finally {
    Clear-LabTempFiles
}
exit 0
