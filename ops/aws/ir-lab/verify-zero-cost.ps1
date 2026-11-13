<#
.SYNOPSIS
    Zero-cost verification (AWS): lists everything that still exists and could cost money.

.DESCRIPTION
    Read-only. It NEVER deletes or changes anything. In the lab region and the global services it
    lists what still exists, by lab tag (lab=<app>-lab-aws) and by the billable risk classes:
    EC2 instances, EBS volumes, snapshots, RDS instances and snapshots, Elastic
    IPs, NAT gateways, load balancers, CloudWatch log groups, S3 buckets, Secrets Manager secrets,
    KMS keys, CloudTrail trails, GuardDuty detectors, Lambda functions, SNS topics and VPCs.
    It also lists any lab IAM user that remains and checks that its access-key list is empty.

    A billable resource WITHOUT the lab tag and not in the manifest is an unmarked resource: it is
    reported as "unmarked" for a manual decision and is never deleted by this or any other script.

    Output: "nothing billable remaining" and exit 0, or the list of pending items (class, type, id,
    region, reason, tagged|unmarked) and exit 1. If a query fails the answer is "inconclusive"
    (exit 1): the script never claims a clean account when it could not look.
    -Json prints one JSON document on stdout (echoed commands and notes go to stderr).

    Exit codes: 0 clean, 1 pending or inconclusive, 2 invalid parameter, 3 credentials, 4 manifest.

.PARAMETER Region
    The single lab region. Default: Aws.Region from the config file.


.PARAMETER Json
    Machine-readable report.

.PARAMETER ManifestPath
    Explicit lab manifest file (default: the standard locations under ~/.sangyshop-lab).

.PARAMETER AllowPreserved
    Evidence deliberately kept with evidence=preserved is listed under "preserved" and does not
    make the result fail.

.EXAMPLE
    .\verify-zero-cost.ps1 -Region us-east-1

.EXAMPLE
    .\verify-zero-cost.ps1 -Region us-east-1 -Json
#>
[CmdletBinding()]
param(
    [string]$Region,
    [switch]$Json,
    [string]$ManifestPath,
    [switch]$AllowPreserved
)
. "$PSScriptRoot\LabTeardown-Common.ps1"

if ($Json) {
    # Keep stdout clean for the JSON document: every Write-Host (including echoed commands) goes to stderr.
    function Write-Host {
        [CmdletBinding()]
        param([Parameter(Position = 0, ValueFromRemainingArguments = $true)]$Object, $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator)
        [Console]::Error.WriteLine((@($Object) -join ' '))
    }
}

Initialize-Lab -Region $Region
$account = Get-LabAccountId      # exit 3

$billableClass = @{
    'ec2-instance' = 'EC2 instances'; 'ebs-volume' = 'EBS volumes'; 'ebs-snapshot' = 'EBS snapshots'
    'rds-instance' = 'RDS instances'; 'rds-snapshot' = 'RDS snapshots'; 'elastic-ip' = 'Elastic IPs'
    'nat-gateway' = 'NAT gateways'; 'load-balancer' = 'Load balancers'; 'log-group' = 'CloudWatch log groups'
    's3-bucket' = 'S3 buckets'; 'secret' = 'Secrets Manager secrets'; 'kms-key' = 'KMS keys'
    'cloudtrail-trail' = 'CloudTrail trails'; 'guardduty-detector' = 'GuardDuty detectors'
    'lambda-function' = 'Lambda functions'; 'sns-topic' = 'SNS topics'; 'vpc' = 'VPCs'
}
$evidenceTypes = @('ebs-snapshot', 'rds-snapshot', 's3-bucket')

Write-LabInfo "Zero-cost verification: account $account, region $($script:LabRegion). Read-only."
$inv = Get-LabInventory -Region $script:LabRegion -ManifestPath $ManifestPath

$pending = New-Object System.Collections.ArrayList
$preserved = New-Object System.Collections.ArrayList

function New-Row {
    param([string]$Class, [string]$Type, [string]$Id, [string]$Region, [string]$Reason, [string]$Marking)
    return [ordered]@{
        class = $Class; type = $Type; id = $Id; region = $Region; reason = $Reason
        marking = $Marking; billable = [bool]$billableClass.ContainsKey($Type)
    }
}

foreach ($it in $inv.Items) {
    $class = 'lab-tagged'
    if ($billableClass.ContainsKey($it.Type)) { $class = $billableClass[$it.Type] }
    $marking = 'tagged'
    $reason = 'carries lab tag and still exists'
    if (-not $it.Tagged -and $it.InManifest) { $reason = 'listed in the lab manifest and still exists' }
    if ($it.Type -eq 'nacl-block-entry') { $reason = 'blocker deny entry still present on a lab network ACL' }
    if ($it.Type -eq 'sg-ingress-rule') { $reason = 'lab security group still has ingress rules' }
    if ($it.Detail -match 'could not be confirmed') { $reason = 'could not confirm whether it still exists (treated as present)' }
    $row = New-Row -Class $class -Type $it.Type -Id $it.Id -Region $it.Region -Reason $reason -Marking $marking
    if ($it.Evidence -eq 'preserved' -and ($evidenceTypes -contains $it.Type)) {
        $row['reason'] = 'preserved evidence kept on purpose (evidence=preserved); billable until removed'
        [void]$preserved.Add($row)
    } else {
        [void]$pending.Add($row)
    }
}
foreach ($u in $inv.Unmarked) {
    [void]$pending.Add((New-Row -Class $u.Class -Type $u.Type -Id $u.Id -Region $u.Region -Marking 'unmarked' `
            -Reason 'billable resource without lab tag and not in the manifest; manual decision, never auto-deleted'))
}

# A lab IAM user must not remain, and its access-key list must be empty.
$extraErrors = New-Object System.Collections.ArrayList
foreach ($it in ($inv.Items | Where-Object { $_.Type -eq 'iam-user' })) {
    $k = Invoke-LabQuery -CliArgs @('iam', 'list-access-keys', '--user-name', $it.Id, '--query', 'AccessKeyMetadata[].AccessKeyId', '--output', 'json')
    if (-not $k.Ok) { [void]$extraErrors.Add("access keys of '$($it.Id)' could not be listed: $(Get-LabErrorLine $k)"); continue }
    foreach ($kid in @(ConvertTo-LabList $k.Data)) {
        [void]$pending.Add((New-Row -Class 'IAM access keys' -Type 'iam-access-key' -Id "$($it.Id)|$kid" -Region 'global' -Marking 'tagged' `
                -Reason 'aws iam list-access-keys is not empty for the lab user'))
    }
}

$problems = @($inv.Errors) + @($inv.ScanErrors) + @($extraErrors.ToArray())
$failing = $pending.Count
if (-not $AllowPreserved) { $failing += $preserved.Count }
$status = 'clean'
if ($problems.Count -gt 0) { $status = 'inconclusive' }
elseif ($failing -gt 0) { $status = 'pending' }

if ($Json) {
    $doc = [ordered]@{
        status = $status
        region = $script:LabRegion
        account = $account
        checkedAtUtc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        pending = $pending.ToArray()
        preserved = $preserved.ToArray()
        keptNotCreatedByLab = @($inv.Reused | ForEach-Object { [ordered]@{ type = $_.Type; id = $_.Id; region = $_.Region } })
        errors = $problems
    }
    Write-Output (ConvertTo-Json -InputObject $doc -Depth 6)
} else {
    Write-Host ''
    if ($status -eq 'clean') {
        Write-Host 'nothing billable remaining'
        foreach ($r in @($inv.Reused)) { Write-Host ('kept (not created by the lab): {0} {1}  region={2}' -f $r.Type, $r.Id, $r.Region) }
        if ($preserved.Count -gt 0) {
            Write-Host "($($preserved.Count) preserved evidence item(s) kept on purpose are not counted because of -AllowPreserved)"
        }
    } else {
        if ($pending.Count -gt 0) {
            Write-Host "Pending items ($($pending.Count)):"
            foreach ($r in $pending) {
                Write-Host ('  - [{0}] {1} {2}  region={3}  {4}  | {5}' -f $r.marking, $r.type, $r.id, $r.region, $r.class, $r.reason)
            }
        }
        if ($preserved.Count -gt 0) {
            Write-Host "Preserved evidence ($($preserved.Count)):"
            foreach ($r in $preserved) { Write-Host ('  - {0} {1}  region={2}  | {3}' -f $r.type, $r.id, $r.region, $r.reason) }
        }
        if (@($inv.Reused).Count -gt 0) {
            Write-Host 'Kept (not created by the lab, not counted as pending):'
            foreach ($r in @($inv.Reused)) { Write-Host ('  - {0} {1}  region={2}' -f $r.Type, $r.Id, $r.Region) }
        }
        if ($problems.Count -gt 0) {
            Write-Host 'The check is INCONCLUSIVE because some queries failed:'
            foreach ($p in $problems) { Write-Host "  - $p" }
        }
        Write-Host ''
        Write-Host 'Unmarked items are only reported. Nothing was deleted by this script.'
    }
}
if ($status -eq 'clean') { exit 0 }
exit 1
