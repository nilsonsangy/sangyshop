<#
.SYNOPSIS
    Enables a CloudTrail trail with management events and S3 data events for the lab bucket (idempotent).

.DESCRIPTION
    Creates (when missing) a private, tagged S3 bucket for the trail logs, the trail
    'sangyshop-lab-trail' (single region, tagged with lab tag and run-id), event selectors
    for management events plus S3 data events of -LabBucket, and starts logging.
    Use -SkipDataEvents to log management events only (cheaper; -LabBucket is then not used).
    -LabBucket is optional: when omitted it defaults to the app bucket that
    ops/aws/ec2/deploy.ps1 creates (Aws.Ec2.BucketBase + '-' + UniqueSuffix from the config),
    or to the s3-bucket entry of the deploy component in the lab manifest. The script exits
    with code 2 only when neither is available.
    Re-running creates nothing new. Supports -WhatIf.

    Preflight and reuse: before any change the script reads the trails of the region. A trail
    that is multi-region, logging and records read and write management events is reused as
    it is (the lab bucket, trail, selectors and logging are all skipped). The lab does not
    modify, tag, stop or remove a reused trail; it is recorded in the lab manifest with
    ownership reused. If no trail qualifies, the reason is printed, the existing trails are
    left unchanged, and the lab trail is created only when the trail quota of the region
    allows it.

    Exit codes: 0 done or reused, 1 failure, 2 invalid parameter, 3 permission missing
    (the message names the policy to attach; fix it and run the script again), 4 trail
    quota reached.


    Required IAM actions:
      cloudtrail:AddTags
      cloudtrail:CreateTrail
      cloudtrail:DescribeTrails
      cloudtrail:GetEventSelectors
      cloudtrail:GetTrailStatus
      cloudtrail:ListTags
      cloudtrail:PutEventSelectors
      cloudtrail:StartLogging
      guardduty:GetDetector
      guardduty:ListDetectors
      logs:DescribeLogGroups
      logs:ListTagsForResource
      s3:CreateBucket
      s3:GetBucketTagging
      s3:ListBucket
      s3:PutBucketPolicy
      s3:PutBucketPublicAccessBlock
      s3:PutBucketTagging
      sns:ListSubscriptionsByTopic
      sns:ListTagsForResource
      sns:ListTopics

.EXAMPLE
    .\enable-cloudtrail.ps1 -Region us-east-1 -LabBucket sangyshop-lab-app-123456789012 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$LabBucket,
    [string]$RunId,
    [string]$TrailName,
    [string]$TrailBucket,
    [switch]$SkipDataEvents
)
. "$PSScriptRoot\Detection-Common.ps1"
if (-not $TrailName) { $TrailName = $script:LabTrailName }
Initialize-Lab -Region $Region
if (-not $SkipDataEvents) {
    $LabBucket = Resolve-LabAppBucket -LabBucket $LabBucket
    if ([string]::IsNullOrWhiteSpace($LabBucket)) {
        Stop-Lab -Code 2 -Message 'Missing required parameter: -LabBucket, and no app bucket was found in the lab config (Aws.Ec2.BucketBase + UniqueSuffix) or the lab manifest. Pass -LabBucket, or pass -SkipDataEvents to log management events only'
    }
}
$RunId = Get-LabRunId -RunId $RunId
$account = Get-LabAccountId
if (-not $TrailBucket) { $TrailBucket = "sangyshop-lab-trail-$account-$($script:LabRegion)" }
$trailArn = "arn:aws:cloudtrail:$($script:LabRegion):${account}:trail/$TrailName"

# Preflight: read the existing trails (read verbs only) before any change.
$snapshot = Get-LabPreflightSnapshot
$decision = Resolve-LabDecision -Snapshot $snapshot -Type 'trail' -ExpectedName $TrailName

$reuse = $null
if ($decision.Decision -eq 'ReuseForeign') { $reuse = $decision.Item }
elseif ($decision.Decision -eq 'ReuseLabOwned' -and $decision.Classification -eq 'LabNamedUntagged' -and -not (Test-LabManifestCreated -Type 'cloudtrail-trail' -Id $TrailName)) {
    # A trail with the lab name that the lab never recorded as created is not the lab's: reuse it only when it qualifies.
    if ($null -ne (Find-ReusableTrail -Trails @($decision.Item) -LabTrailName $TrailName)) { $reuse = $decision.Item }
}
if ($null -ne $reuse) {
    $why = if ($decision.Reasons.Count -gt 0) { $decision.Reasons } else { @('multi-region', 'logging', 'management events for reads and writes') }
    Write-LabInfo "Reusing existing trail '$($reuse.Name)' instead of creating one."
    Write-LabInfo "Reasons: $($why -join '; ')."
    Write-LabInfo "kept (not created by the lab): the lab neither modifies nor removes trail '$($reuse.Name)'. No bucket, selector or logging change is made."
    Add-LabReusedResource -Type 'cloudtrail-trail' -Id "$($reuse.Name)" -RunId $RunId
    exit 0
}
if ($decision.Decision -eq 'Create') {
    foreach ($why in $decision.Reasons) { Write-LabInfo "No existing trail was reused: $why. Existing trails are left unchanged." }
    # Create the lab trail only when the regional trail quota allows it (5 trails per region).
    $q = Invoke-LabCli -CliArgs @('cloudtrail', 'describe-trails', '--no-include-shadow-trails', '--query', 'trailList[].Name', '--output', 'json')
    $trailCount = 0
    if ($q.ExitCode -eq 0) { $trailCount = @(ConvertFrom-LabJson -Text $q.Output | Where-Object { $_ }).Count }
    if ($trailCount -ge 5) {
        [Console]::Error.WriteLine("Error: the region already has $trailCount trails, the CloudTrail quota. The lab trail was not created and the existing trails were left unchanged. Remove an unused trail or reuse one, then run this script again.")
        exit 4
    }
}

try {
    # 1. Trail log bucket
    $h = Invoke-LabCli -CliArgs @('s3api', 'head-bucket', '--bucket', $TrailBucket)
    if ($h.ExitCode -eq 0) {
        $bt = Invoke-LabCli -CliArgs @('s3api', 'get-bucket-tagging', '--bucket', $TrailBucket, '--query', 'TagSet', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $bt.Output))) {
            if (-not (Test-LabManifestCreated -Type 's3-bucket' -Id $TrailBucket)) {
                Confirm-LabUntaggedRefusal -Kind 'S3 bucket' -Name $TrailBucket
            }
            # Created by the lab in an interrupted run before the tags were applied: complete them.
            $tg = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-bucket-tagging', '--bucket', $TrailBucket, '--tagging', (New-LabTempFile -Text ('{"TagSet":' + (Get-LabTagJsonList -RunId $RunId) + '}')))
            if ($tg.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of trail bucket '$TrailBucket'. $($tg.Output)" }
            $pa = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-public-access-block', '--bucket', $TrailBucket, '--public-access-block-configuration', 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true')
            if ($pa.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not block public access on trail bucket. $($pa.Output)" }
            Write-LabInfo "Trail bucket '$TrailBucket' was created by the lab without tags. Completed the tags."
        }
        Write-LabInfo "Trail bucket '$TrailBucket' already exists with the lab tag."
    } else {
        $createArgs = @('s3api', 'create-bucket', '--bucket', $TrailBucket)
        if ($script:LabRegion -ne 'us-east-1') { $createArgs += @('--create-bucket-configuration', "LocationConstraint=$($script:LabRegion)") }
        $c = Invoke-LabCli -Mutating -CliArgs $createArgs
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create trail bucket '$TrailBucket'. $($c.Output)" }
        Add-LabResource -Type 's3-bucket' -Id $TrailBucket -RunId $RunId
        $tg = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-bucket-tagging', '--bucket', $TrailBucket, '--tagging', (New-LabTempFile -Text ('{"TagSet":' + (Get-LabTagJsonList -RunId $RunId) + '}')))
        if ($tg.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not tag trail bucket. $($tg.Output)" }
        $pa = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-public-access-block', '--bucket', $TrailBucket, '--public-access-block-configuration', 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true')
        if ($pa.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not block public access on trail bucket. $($pa.Output)" }
        Write-LabInfo "Created private trail bucket '$TrailBucket'."
    }
    # The bucket policy lets CloudTrail (only this trail) write; re-applying it is idempotent.
    $policy = '{"Version":"2012-10-17","Statement":[' +
        '{"Sid":"AWSCloudTrailAclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::' + $TrailBucket + '","Condition":{"StringEquals":{"aws:SourceArn":"' + $trailArn + '"}}},' +
        '{"Sid":"AWSCloudTrailWrite","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::' + $TrailBucket + '/AWSLogs/' + $account + '/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control","aws:SourceArn":"' + $trailArn + '"}}}]}'
    $bp = Invoke-LabCli -Mutating -CliArgs @('s3api', 'put-bucket-policy', '--bucket', $TrailBucket, '--policy', (New-LabTempFile -Text $policy))
    if ($bp.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not apply the trail bucket policy. $($bp.Output)" }

    # 2. Trail
    $d = Invoke-LabCli -CliArgs @('cloudtrail', 'describe-trails', '--trail-name-list', $TrailName, '--query', 'trailList[].TrailARN', '--output', 'json')
    $arns = @()
    if ($d.ExitCode -eq 0) { $arns = @(ConvertFrom-LabJson -Text $d.Output) }
    if ($arns.Count -gt 0) {
        $tt = Invoke-LabCli -CliArgs @('cloudtrail', 'list-tags', '--resource-id-list', "$($arns[0])", '--query', 'ResourceTagList[0].TagsList', '--output', 'json')
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $tt.Output))) {
            if (-not (Test-LabManifestCreated -Type 'cloudtrail-trail' -Id $TrailName)) {
                Confirm-LabUntaggedRefusal -Kind 'CloudTrail trail' -Name $TrailName -Hint 'It does not qualify for reuse, so the lab left it unchanged.'
            }
            $at = Invoke-LabCli -Mutating -CliArgs (@('cloudtrail', 'add-tags', '--resource-id', "$($arns[0])", '--tags-list') + (Get-LabTagPairs -RunId $RunId))
            if ($at.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not complete the tags of trail '$TrailName'. $($at.Output)" }
            Write-LabInfo "Trail '$TrailName' was created by the lab without tags. Completed the tags."
        }
        Write-LabInfo "Trail '$TrailName' already exists with the lab tag. Nothing to create."
    } else {
        $createTrail = @('cloudtrail', 'create-trail', '--name', $TrailName, '--s3-bucket-name', $TrailBucket, '--tags-list') + (Get-LabTagPairs -RunId $RunId)
        $c = Invoke-LabCli -Mutating -CliArgs $createTrail
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create trail '$TrailName'. $($c.Output)" }
        Add-LabResource -Type 'cloudtrail-trail' -Id $TrailName -RunId $RunId
        Write-LabInfo "Created trail '$TrailName'."
    }

    # 3. Event selectors (put is idempotent): management events, plus S3 data events of the lab bucket.
    if ($SkipDataEvents) {
        $selectors = '[{"ReadWriteType":"All","IncludeManagementEvents":true}]'
        Write-LabInfo 'Skipping S3 data events (-SkipDataEvents): management events only.'
    } else {
        $selectors = '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::' + $LabBucket + '/"]}]}]'
    }
    $es = Invoke-LabCli -Mutating -CliArgs @('cloudtrail', 'put-event-selectors', '--trail-name', $TrailName, '--event-selectors', (New-LabTempFile -Text $selectors))
    if ($es.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not set event selectors. $($es.Output)" }

    # 4. Logging (start-logging is a no-op when already logging)
    $sl = Invoke-LabCli -Mutating -CliArgs @('cloudtrail', 'start-logging', '--name', $TrailName)
    if ($sl.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not start logging. $($sl.Output)" }
    Write-LabInfo "CloudTrail logging is on for '$TrailName'."
} finally {
    Clear-LabTempFiles
}
exit 0
