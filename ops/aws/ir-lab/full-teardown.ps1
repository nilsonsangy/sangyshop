<#
.SYNOPSIS
    Full teardown (AWS): removes EVERYTHING the AWS incident response lab created in the account.

.DESCRIPTION
    Discovery is by lab tag (lab=<app>-lab-aws) through the Resource Groups Tagging API
    (tag:GetResources), by per-service queries filtered by the tag, and by the lab manifest
    for resources that cannot carry tags (access keys, SNS subscriptions, metric filters).
    No resource name typed by hand is used as a selection criterion.

    A resource that has neither lab tag nor a manifest entry is a unmarked resource: it is
    listed and left unchanged, always.

    Order (reverse of the dependencies):
      1. block / isolation   NACL deny entries 100-199, open ingress rules of lab security groups
      2. blocker             EventBridge rule, Lambda, blocker IAM role
      3. detection stack     alarms, metric filters, flow logs, log groups, trail + bucket,
                             GuardDuty, SNS subscriptions and topic, flow-log role
      4. deploy              ops\aws\ec2\teardown.ps1 (next to this folder) runs here;
                             then a lab tag sweep removes whatever it left (EC2, EBS, RDS, secrets,
                             app bucket, role/profile, network)
      5. evidence            EBS/RDS snapshots and the evidence bucket (see -PreserveEvidence)
      6. credentials         access keys, deny policy, lab IAM user (last)
    A failure never stops the independent steps. A final sweep re-discovers and retries what is left.

    Exit codes: 0 done / simulation / nothing to do, 1 a resource could not be removed,
    2 invalid parameter, 3 credentials missing or expired, 4 manifest unreadable,
    5 cancelled by the operator or S3 Object Lock retention blocked the deletion.

    Idempotent: after a successful run, a re-run finds nothing, says so and exits 0.
    Always follow with verify-zero-cost.ps1.


    Required IAM actions:
      cloudtrail:DeleteTrail
      cloudtrail:DescribeTrails
      cloudtrail:StopLogging
      cloudwatch:DeleteAlarms
      cloudwatch:DescribeAlarms
      ec2:CreateTags
      ec2:DeleteFlowLogs
      ec2:DeleteInternetGateway
      ec2:DeleteKeyPair
      ec2:DeleteNatGateway
      ec2:DeleteNetworkAcl
      ec2:DeleteNetworkAclEntry
      ec2:DeleteRouteTable
      ec2:DeleteSecurityGroup
      ec2:DeleteSnapshot
      ec2:DeleteSubnet
      ec2:DeleteVolume
      ec2:DeleteVpc
      ec2:DescribeAddresses
      ec2:DescribeFlowLogs
      ec2:DescribeInstances
      ec2:DescribeInternetGateways
      ec2:DescribeKeyPairs
      ec2:DescribeNatGateways
      ec2:DescribeNetworkAcls
      ec2:DescribeRouteTables
      ec2:DescribeSecurityGroups
      ec2:DescribeSnapshots
      ec2:DescribeSubnets
      ec2:DescribeVolumes
      ec2:DescribeVpcs
      ec2:DetachInternetGateway
      ec2:ReleaseAddress
      ec2:RevokeSecurityGroupIngress
      ec2:TerminateInstances
      elasticloadbalancing:DescribeLoadBalancers
      events:DeleteRule
      events:DescribeRule
      events:ListTargetsByRule
      events:RemoveTargets
      guardduty:DeleteDetector
      guardduty:GetDetector
      guardduty:ListDetectors
      iam:DeleteAccessKey
      iam:DeleteInstanceProfile
      iam:DeleteLoginProfile
      iam:DeletePolicy
      iam:DeletePolicyVersion
      iam:DeleteRole
      iam:DeleteRolePolicy
      iam:DeleteUser
      iam:DeleteUserPolicy
      iam:DetachGroupPolicy
      iam:DetachRolePolicy
      iam:DetachUserPolicy
      iam:GetAccessKeyLastUsed
      iam:GetInstanceProfile
      iam:GetPolicy
      iam:GetRole
      iam:GetUser
      iam:ListAccessKeys
      iam:ListAttachedRolePolicies
      iam:ListAttachedUserPolicies
      iam:ListEntitiesForPolicy
      iam:ListGroupsForUser
      iam:ListInstanceProfiles
      iam:ListInstanceProfilesForRole
      iam:ListInstanceProfileTags
      iam:ListPolicies
      iam:ListPolicyTags
      iam:ListPolicyVersions
      iam:ListRolePolicies
      iam:ListRoles
      iam:ListRoleTags
      iam:ListUserPolicies
      iam:ListUsers
      iam:ListUserTags
      iam:RemoveRoleFromInstanceProfile
      iam:RemoveUserFromGroup
      iam:UpdateAccessKey
      kms:DescribeKey
      kms:ListKeys
      kms:ScheduleKeyDeletion
      lambda:DeleteFunction
      lambda:GetFunction
      lambda:ListFunctions
      logs:DeleteLogGroup
      logs:DeleteMetricFilter
      logs:DescribeLogGroups
      logs:DescribeMetricFilters
      rds:AddTagsToResource
      rds:DeleteDBInstance
      rds:DeleteDBSnapshot
      rds:DeleteDBSubnetGroup
      rds:DescribeDBInstances
      rds:DescribeDBSnapshots
      rds:DescribeDBSubnetGroups
      s3:BypassGovernanceRetention
      s3:DeleteBucket
      s3:DeleteObject
      s3:DeleteObjectVersion
      s3:GetBucketLocation
      s3:GetBucketTagging
      s3:GetObjectLockConfiguration
      s3:GetObjectRetention
      s3:ListAllMyBuckets
      s3:ListBucket
      s3:ListBucketVersions
      s3:PutBucketTagging
      secretsmanager:DeleteSecret
      secretsmanager:DescribeSecret
      secretsmanager:ListSecrets
      sns:DeleteTopic
      sns:GetTopicAttributes
      sns:ListSubscriptionsByTopic
      sns:ListTopics
      sns:Unsubscribe
      tag:GetResources

.PARAMETER Region
    The single lab region. Default: Aws.Region from the config file.

.PARAMETER RunId
    Only remove resources whose run-id tag/manifest entry equals this value.

.PARAMETER AllRuns
    Remove every run (also the behaviour when neither -RunId nor -AllRuns is given).

.PARAMETER NonInteractive
    Do not ask for confirmation (the explicit second flag for preserved evidence is still required).

.PARAMETER PreserveEvidence
    Keep evidence snapshots/bucket: they are tagged evidence=preserved and the monthly cost of
    keeping them is printed in USD and BRL with the price date.

.PARAMETER ConfirmPreservedEvidenceRemoval
    Required, together with a second typed confirmation (unless -NonInteractive), to remove
    resources already tagged evidence=preserved.


.PARAMETER ManifestPath
    Explicit lab manifest file (default: the standard locations under ~/.sangyshop-lab).

.PARAMETER UsdBrlRate
    USD to BRL rate used in the cost estimate of preserved evidence (default 5.60, project rate).

.EXAMPLE
    .\full-teardown.ps1 -Region us-east-1 -WhatIf

.EXAMPLE
    .\full-teardown.ps1 -Region us-east-1 -AllRuns -PreserveEvidence
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$RunId,
    [switch]$AllRuns,
    [switch]$NonInteractive,
    [switch]$PreserveEvidence,
    [switch]$ConfirmPreservedEvidenceRemoval,
    [string]$ManifestPath,
    [double]$UsdBrlRate = 5.60
)
. "$PSScriptRoot\LabTeardown-Common.ps1"

# ---- parameter validation (exit 2) -----------------------------------------
if ($RunId -and $AllRuns) { Stop-Lab -Code 2 -Message '-RunId and -AllRuns cannot be used together' }
if ($RunId -and $RunId -notmatch '^[A-Za-z0-9._-]{1,64}$') { Stop-Lab -Code 2 -Message 'Invalid -RunId (use letters, digits, dot, underscore or hyphen, up to 64 characters)' }
if ($PreserveEvidence -and $ConfirmPreservedEvidenceRemoval) { Stop-Lab -Code 2 -Message '-PreserveEvidence and -ConfirmPreservedEvidenceRemoval contradict each other' }
if ($UsdBrlRate -le 0) { Stop-Lab -Code 2 -Message '-UsdBrlRate must be positive' }
Initialize-Lab -Region $Region
$wi = [bool]$WhatIfPreference
$account = Get-LabAccountId      # exit 3 when credentials are missing or expired
$RunId = if ($RunId) { $RunId.Trim() } else { '' }
$scopeText = if ($RunId) { "run-id $RunId" } else { 'all runs' }
# The deployment teardown lives next to this folder: ops\aws\ec2\teardown.ps1.
$deployTeardownScript = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\ec2\teardown.ps1'))
$deployConfigPath = Get-LabConfigPath
$deployTeardownAvailable = (Test-Path -LiteralPath $deployTeardownScript -PathType Leaf) -or [bool]$global:LabDeployTeardownHandler

$results = New-Object System.Collections.ArrayList     # {Item, Result}
$retention = @{}                                        # Key -> Result (S3 Object Lock blocks)

function Get-TeardownPlan {
    <# Splits an inventory into the removal plan and the evidence that stays. Kept never reaches Remove-LabItem. #>
    param($Items)
    $plan = New-Object System.Collections.ArrayList
    $kept = New-Object System.Collections.ArrayList
    foreach ($it in $Items) {
        $evidenceType = ($it.Type -in @('ebs-snapshot', 'rds-snapshot', 's3-bucket'))
        $keep = $false
        if ($evidenceType -and $it.Evidence -eq 'preserved' -and -not $ConfirmPreservedEvidenceRemoval) { $keep = $true }
        if ($evidenceType -and $it.Evidence -eq 'true' -and $PreserveEvidence) { $keep = $true }
        if ($keep) { $it.Kept = $true; [void]$kept.Add($it) } else { [void]$plan.Add($it) }
    }
    return [pscustomobject]@{ Plan = $plan.ToArray(); Kept = $kept.ToArray() }
}

function Write-TeardownTable {
    param($Items, [string]$Title)
    Write-Host ''
    Write-Host $Title
    $i = 0
    foreach ($it in $Items) {
        $i++
        $src = ($it.Sources -join '+')
        $extra = ''
        if ($it.Detail) { $extra = "  ($($it.Detail))" }
        if ($it.Phase -ge 999) { $extra = '  (unsupported type: will be reported, not removed)' }
        Write-Host ('  {0,3}. [{1,-15}] {2,-20} {3}  region={4}  via={5}{6}' -f $i, (Get-LabPhaseGroup $it.Phase), $it.Type, $it.Id, $it.Region, $src, $extra)
    }
}

function Invoke-Removals {
    param($Items)
    foreach ($it in $Items) {
        if ($retention.ContainsKey($it.Key)) { continue }
        Write-LabInfo "Removing $($it.Type) '$($it.Id)'"
        $res = $null
        try { $res = Remove-LabItem -Item $it } catch { $res = New-LabResult 'failed' $_.Exception.Message }
        [void]$results.Add([pscustomobject]@{ Item = $it; Result = $res })
        switch ($res.Status) {
            'removed' { Write-LabInfo "  removed: $($it.Type) $($it.Id)" }
            'absent' { Write-LabInfo "  already gone: $($it.Type) $($it.Id)" }
            'retention' { $retention[$it.Key] = $res; Write-LabWarn "  kept by Object Lock until $($res.RetainUntil): $($it.Type) $($it.Id)" }
            default { Write-LabWarn "  FAILED: $($it.Type) $($it.Id): $($res.Detail)" }
        }
    }
}

function Invoke-DeployTeardown {
    <# Runs ops\aws\ec2\teardown.ps1 -Force in a child process. Returns its exit code. #>
    if ($global:LabDeployTeardownHandler) { return [int](& $global:LabDeployTeardownHandler $deployTeardownScript) }
    $exe = (Get-Process -Id $PID).Path
    Write-Host "+ $exe -NoProfile -File $deployTeardownScript -ConfigPath $deployConfigPath -Force"
    & $exe -NoProfile -ExecutionPolicy Bypass -File $deployTeardownScript -ConfigPath $deployConfigPath -Force
    return [int]$LASTEXITCODE
}

# ---- discovery --------------------------------------------------------------
Write-LabInfo "Full teardown of the AWS incident response lab: account $account, region $($script:LabRegion), scope: $scopeText."
Write-LabInfo 'Discovering lab resources (tag:GetResources + lab tag service queries + lab manifest). Read-only.'
$inv = Get-LabInventory -Region $script:LabRegion -RunId $RunId -ManifestPath $ManifestPath
foreach ($e in @($inv.Errors) + @($inv.ScanErrors)) { Write-LabWarn "Discovery note: $e" }
if ($inv.OtherRun -gt 0) { Write-LabInfo "$($inv.OtherRun) lab resource(s) belong to other runs and are outside -RunId $RunId (left unchanged)." }
if ($inv.Stale -gt 0) { Write-LabInfo "$($inv.Stale) listed resource(s) no longer exist (stale tag index or manifest entry); ignored." }
foreach ($ru in @($inv.Reused)) { Write-LabInfo "kept (not created by the lab): $($ru.Type) $($ru.Id)" }

$split = Get-TeardownPlan -Items $inv.Items
$plan = @($split.Plan)
$kept = @($split.Kept)

function Write-UnmarkedReport {
    param($Unmarked)
    if (@($Unmarked).Count -eq 0) { return }
    Write-Host ''
    Write-Host 'Unmarked resources (billable, no lab tag, not in the manifest). NOT touched; decide manually:'
    foreach ($u in $Unmarked) { Write-Host ("  - {0} {1}  region={2}  class={3}" -f $u.Type, $u.Id, $u.Region, $u.Class) }
}

function Write-EvidenceCost {
    param($Items)
    $Items = @(ConvertTo-LabList $Items)
    if ($Items.Count -eq 0) { return }
    Write-Host ''
    Write-Host 'Evidence kept (evidence=preserved). Estimated monthly cost of keeping it:'
    $total = 0.0; $unknown = 0
    foreach ($it in $Items) {
        $c = Get-LabEvidenceCost -Item $it
        if ($null -eq $c) { $unknown++; Write-Host ("  - {0} {1}: size unknown, cost not estimated" -f $it.Type, $it.Id); continue }
        $total += $c
        Write-Host ("  - {0} {1}: US$ {2:N4}/month  (R$ {3:N4})" -f $it.Type, $it.Id, $c, ($c * $UsdBrlRate))
    }
    Write-Host ("  Total: US$ {0:N4}/month  (R$ {1:N4} at R$ {2:N2}/US$)" -f $total, ($total * $UsdBrlRate), $UsdBrlRate)
    Write-Host ("  Indicative list prices as of {0} (EBS snapshot {1}/GB-month, RDS snapshot {2}/GB-month, S3 Standard {3}/GB-month); confirm current prices before relying on them." -f $script:LabPriceDate, $script:LabPriceEbsSnapshotGbMonth, $script:LabPriceRdsSnapshotGbMonth, $script:LabPriceS3StandardGbMonth)
    if ($unknown -gt 0) { Write-Host "  $unknown item(s) could not be sized; the total is a lower bound." }
}

# ---- nothing to do ----------------------------------------------------------
if ($plan.Count -eq 0) {
    if ($kept.Count -gt 0) {
        Write-Host ''
        Write-Host "No lab resources to remove. $($kept.Count) evidence item(s) are kept on purpose (use -ConfirmPreservedEvidenceRemoval to remove evidence=preserved)."
        Write-EvidenceCost -Items $kept
    } else {
        Write-Host 'No lab resources remain. Nothing to remove.'
    }
    Write-UnmarkedReport -Unmarked $inv.Unmarked
    Write-Host "Next: .\verify-zero-cost.ps1 -Region $($script:LabRegion)"
    exit 0
}

Write-TeardownTable -Items $plan -Title "Resources to remove ($($plan.Count)):"
if ($kept.Count -gt 0) { Write-TeardownTable -Items $kept -Title "Evidence kept ($($kept.Count)):" }
$deployInPlan = @($plan | Where-Object { $_.Phase -ge $script:LabDeployPhaseMin -and $_.Phase -le $script:LabDeployPhaseMax })
$delegate = ($deployInPlan.Count -gt 0 -and $deployTeardownAvailable -and -not $RunId)
Write-Host ''
if ($delegate) { Write-Host "Deploy group: the EC2 deployment teardown will run first ($deployTeardownScript), then a lab tag sweep removes what it leaves." }
elseif ($deployInPlan.Count -gt 0 -and $RunId) { Write-Host 'Deploy group: removed directly by tag (the EC2 deployment teardown is not run-scoped, so it is skipped with -RunId).' }
elseif ($deployInPlan.Count -gt 0) { Write-Host "Deploy group: the EC2 deployment teardown was not found at $deployTeardownScript; removed directly by tag." }
Write-UnmarkedReport -Unmarked $inv.Unmarked

# ---- simulation -------------------------------------------------------------
if ($wi) {
    if ($PreserveEvidence) { Write-Host "What if: tag the evidence items above as evidence=preserved and keep them." }
    Write-EvidenceCost -Items ($kept | Where-Object { $_.Evidence -eq 'preserved' })
    Write-Host ''
    Write-Host "What if: $($plan.Count) resource(s) would be removed. No changes were made to the account."
    exit 0
}

# ---- confirmation -----------------------------------------------------------
$preservedInPlan = @($plan | Where-Object { $_.Evidence -eq 'preserved' -and ($_.Type -in @('ebs-snapshot', 'rds-snapshot', 's3-bucket')) })
if (-not $NonInteractive) {
    $ans = Read-LabConfirmation "Type 'yes' to PERMANENTLY remove the $($plan.Count) resource(s) above from account $account (region $($script:LabRegion))"
    if ($ans.Trim() -ne 'yes') {
        Write-Host 'Cancelled by the operator. No changes were made.'
        exit 5
    }
    if ($preservedInPlan.Count -gt 0) {
        Write-Host ''
        Write-Host "EXTRA CONFIRMATION: $($preservedInPlan.Count) item(s) are tagged evidence=preserved and will be destroyed."
        $ans2 = Read-LabConfirmation "Type 'remove preserved evidence' to delete preserved evidence"
        if ($ans2.Trim() -ne 'remove preserved evidence') {
            Write-Host 'Cancelled: preserved evidence was not confirmed. No changes were made.'
            exit 5
        }
    }
} elseif ($preservedInPlan.Count -gt 0) {
    Write-LabWarn "-NonInteractive with -ConfirmPreservedEvidenceRemoval: $($preservedInPlan.Count) preserved evidence item(s) will be removed."
}

# ---- preserve evidence (tag before anything is deleted) ----------------------
$tagFailures = New-Object System.Collections.ArrayList
if ($PreserveEvidence) {
    foreach ($it in ($kept | Where-Object { $_.Evidence -eq 'true' })) {
        if (Set-LabEvidencePreserved -Item $it) { $it.Evidence = 'preserved'; Write-LabInfo "Tagged evidence=preserved: $($it.Type) $($it.Id)" }
        else { [void]$tagFailures.Add($it); Write-LabWarn "Could not tag $($it.Type) '$($it.Id)' as preserved; it is still kept (not removed)." }
    }
}
Write-EvidenceCost -Items $kept

# ---- execution ---------------------------------------------------------------
try {
    $pre = @($plan | Where-Object { $_.Phase -lt $script:LabDeployPhaseMin })
    $post = @($plan | Where-Object { $_.Phase -ge $script:LabDeployPhaseMin })

    Write-Host ''
    Write-LabInfo '=== block, blocker and detection stack ==='
    Invoke-Removals -Items $pre

    if ($delegate) {
        Write-Host ''
        Write-LabInfo '=== deploy group: EC2 deployment teardown ==='
        $code = Invoke-DeployTeardown
        if ($code -ne 0) { Write-LabWarn "The EC2 deployment teardown exited with code $code; the lab tag sweep will handle what is left." }
        $again = Get-LabInventory -Region $script:LabRegion -RunId $RunId -ManifestPath $ManifestPath -SkipScan
        $split2 = Get-TeardownPlan -Items $again.Items
        $post = @($split2.Plan | Where-Object { $_.Phase -ge $script:LabDeployPhaseMin })
    }

    Write-Host ''
    Write-LabInfo '=== deploy leftovers (lab tag sweep), evidence and credentials ==='
    Invoke-Removals -Items $post

    # Final sweep: re-discover and retry anything still there (dependencies may have drained meanwhile).
    Write-Host ''
    Write-LabInfo '=== final lab tag sweep ==='
    $sweep = Get-LabInventory -Region $script:LabRegion -RunId $RunId -ManifestPath $ManifestPath -SkipScan
    $sweepPlan = @((Get-TeardownPlan -Items $sweep.Items).Plan)
    if ($sweepPlan.Count -gt 0) {
        Write-LabInfo "$($sweepPlan.Count) resource(s) still present; retrying once."
        Invoke-Removals -Items $sweepPlan
    }
    $final = Get-LabInventory -Region $script:LabRegion -RunId $RunId -ManifestPath $ManifestPath -SkipScan
} finally {
    Clear-LabTempFiles
}

# ---- report ------------------------------------------------------------------
$finalSplit = Get-TeardownPlan -Items $final.Items
$left = @($finalSplit.Plan)
$removedCount = @($results | Where-Object { $_.Result.Status -eq 'removed' }).Count
Write-Host ''
Write-Host "Removed $removedCount resource(s) in this run."
Write-UnmarkedReport -Unmarked $inv.Unmarked

$retentionLeft = @($left | Where-Object { $retention.ContainsKey($_.Key) })
$otherLeft = @($left | Where-Object { -not $retention.ContainsKey($_.Key) })

foreach ($it in $retentionLeft) {
    $r = $retention[$it.Key]
    [Console]::Error.WriteLine("Error: S3 Object Lock retention prevents deleting bucket '$($it.Id)' ($($r.Detail)). Retention lasts until $($r.RetainUntil). Repeat full-teardown.ps1 after that date.")
}
foreach ($it in $otherLeft) {
    $why = ''
    $last = @($results | Where-Object { $_.Item.Key -eq $it.Key -and $_.Result.Status -eq 'failed' }) | Select-Object -Last 1
    if ($last) { $why = " ($($last.Result.Detail))" }
    elseif ($it.Phase -ge 999) { $why = ' (unsupported type, not removed)' }
    [Console]::Error.WriteLine("Error: resource remains: $($it.Type) $($it.Id) region=$($it.Region)$why")
}
foreach ($it in $tagFailures) { [Console]::Error.WriteLine("Error: evidence could not be tagged as preserved (kept untouched): $($it.Type) $($it.Id)") }

if ($otherLeft.Count -gt 0 -or $tagFailures.Count -gt 0) {
    Write-Host "Teardown incomplete: $($otherLeft.Count) resource(s) could not be removed. Fix the cause and re-run."
    exit 1
}
if ($retentionLeft.Count -gt 0) {
    Write-Host "Teardown incomplete: $($retentionLeft.Count) bucket(s) are locked by S3 Object Lock retention. Everything else was removed."
    exit 5
}
if ($kept.Count -gt 0) { Write-Host "Teardown complete. $($kept.Count) evidence item(s) were kept on purpose (billable until removed)." }
else { Write-Host 'Teardown complete: no lab resources remain.' }
Write-Host "Next: .\verify-zero-cost.ps1 -Region $($script:LabRegion)"
exit 0
