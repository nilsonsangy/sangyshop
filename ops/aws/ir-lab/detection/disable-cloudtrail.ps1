<#
.SYNOPSIS
    Stops and deletes the lab CloudTrail trail and, by default, its log bucket (idempotent).

.DESCRIPTION
    The trail and the bucket are removed only when they carry lab tag. Use -KeepTrailBucket
    to keep the collected trail logs (the bucket keeps costing storage until removed).
    Re-running when everything is gone exits 0. Supports -WhatIf.


    Required IAM actions:
      cloudtrail:DeleteTrail
      cloudtrail:DescribeTrails
      cloudtrail:ListTags
      cloudtrail:StopLogging
      s3:DeleteBucket
      s3:DeleteObject
      s3:GetBucketTagging
      s3:ListBucket

.EXAMPLE
    .\disable-cloudtrail.ps1 -Region us-east-1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$TrailName,
    [string]$TrailBucket,
    [switch]$KeepTrailBucket
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $TrailName) { $TrailName = $script:LabTrailName }
Initialize-Lab -Region $Region
$account = Get-LabAccountId
# A trail the manifest records as reused (for example 'management-events') is never stopped or deleted.
$trailReused = $false
foreach ($e in @(Read-LabManifest)) {
    if ("$($e.type)" -ceq 'cloudtrail-trail' -and "$($e.id)" -ceq $TrailName -and $e.PSObject.Properties['ownership'] -and "$($e.ownership)" -eq 'reused') { $trailReused = $true }
}
if (-not $TrailBucket) { $TrailBucket = "sangyshop-lab-trail-$account-$($script:LabRegion)" }

try {
    # Trail
    $d = Invoke-LabCli -CliArgs @('cloudtrail', 'describe-trails', '--trail-name-list', $TrailName, '--query', 'trailList[].TrailARN', '--output', 'json')
    $arns = @()
    if ($d.ExitCode -eq 0) { $arns = @(ConvertFrom-LabJson -Text $d.Output) }
    if ($trailReused) {
        Write-LabKept -Kind 'Trail' -Name $TrailName
    } elseif ($arns.Count -eq 0) {
        Write-LabInfo "Trail '$TrailName' not found. Nothing to remove."
    } else {
        $tt = Invoke-LabCli -CliArgs @('cloudtrail', 'list-tags', '--resource-id-list', "$($arns[0])", '--query', 'ResourceTagList[0].TagsList', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $tt.Output))) {
            Write-LabWarn "Trail '$TrailName' does not carry the lab tag: kept (not created by the lab). Left unchanged."
        } else {
            $s = Invoke-LabCli -Mutating -CliArgs @('cloudtrail', 'stop-logging', '--name', $TrailName)
            if ($s.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not stop logging. $($s.Output)" }
            $x = Invoke-LabCli -Mutating -CliArgs @('cloudtrail', 'delete-trail', '--name', $TrailName)
            if ($x.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete trail '$TrailName'. $($x.Output)" }
            Write-LabInfo "Deleted trail '$TrailName'."
        }
    }

    # Trail log bucket
    if ($KeepTrailBucket) {
        Write-LabInfo "Keeping trail bucket '$TrailBucket' (-KeepTrailBucket). It keeps costing storage until removed."
    } else {
        $h = Invoke-LabCli -CliArgs @('s3api', 'head-bucket', '--bucket', $TrailBucket)
        if ($h.ExitCode -ne 0) {
            Write-LabInfo "Trail bucket '$TrailBucket' not found. Nothing to remove."
        } else {
            $bt = Invoke-LabCli -CliArgs @('s3api', 'get-bucket-tagging', '--bucket', $TrailBucket, '--query', 'TagSet', '--output', 'json')
            if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $bt.Output))) {
                Write-LabWarn "Bucket '$TrailBucket' does not carry the lab tag: kept (not created by the lab). Left unchanged."
            } else {
                $rb = Invoke-LabCli -Mutating -CliArgs @('s3', 'rb', "s3://$TrailBucket", '--force')
                if ($rb.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete trail bucket '$TrailBucket'. $($rb.Output)" }
                Write-LabInfo "Deleted trail bucket '$TrailBucket'."
            }
        }
    }
} finally {
    Clear-LabTempFiles
}
exit 0
