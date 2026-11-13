<#
.SYNOPSIS
    Deletes the lab GuardDuty detector (idempotent).

.DESCRIPTION
    Deletes the detector in the region only when it carries lab tag. An untagged detector is
    left unchanged. Re-running when no detector exists exits 0. Supports -WhatIf.


    Required IAM actions:
      guardduty:DeleteDetector
      guardduty:ListDetectors
      guardduty:ListTagsForResource

.EXAMPLE
    .\disable-guardduty.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Region $Region
$account = Get-LabAccountId

try {
    $l = Invoke-LabCli -CliArgs @('guardduty', 'list-detectors', '--query', 'DetectorIds', '--output', 'json')
    if ($l.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not list GuardDuty detectors. $($l.Output)" }
    $detectors = @(ConvertFrom-LabJson -Text $l.Output)
    if ($detectors.Count -eq 0) {
        Write-LabInfo 'No GuardDuty detector found. Nothing to remove.'
    }
    foreach ($d in $detectors) {
        $id = "$d"
        $arn = "arn:aws:guardduty:${script:LabRegion}:${account}:detector/$id"
        $t = Invoke-LabCli -CliArgs @('guardduty', 'list-tags-for-resource', '--resource-arn', $arn, '--query', 'Tags', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $t.Output))) {
            Write-LabWarn "GuardDuty detector $id does not carry the lab tag: kept (not created by the lab). Left unchanged."
            continue
        }
        $x = Invoke-LabCli -Mutating -CliArgs @('guardduty', 'delete-detector', '--detector-id', $id)
        if ($x.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete detector $id. $($x.Output)" }
        Write-LabInfo "Deleted GuardDuty detector $id."
    }
} finally {
    Clear-LabTempFiles
}
exit 0
