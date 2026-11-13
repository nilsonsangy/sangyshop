<#
.SYNOPSIS
    Demonstrates what an attacker could enumerate with the leaked lab
    credential, using at most 10 AWS API calls.

.DESCRIPTION
    This script is the one that actually CALLS AWS with the credential found
    by the attack script's credential-discovery step (out/exposed-credential.json) or with the lab's own
    plant-leaked-credential.ps1 output. The attack script itself
    never calls a real cloud API; that call is made here, by a script
    specific to this lab.

    For each AWS API call attempted, this script prints ONLY the API name and
    the resulting status (ok, denied or error). It NEVER prints response
    content: no object keys, no bucket listing, no account details, no ARNs
    beyond what is required to name the call. This mirrors what an analyst
    reading CloudTrail would see: that the credential was used, and for what,
    without re-exposing whatever the attacker could read.

    At most 10 API calls are made in total, matching the least-privilege
    policy attached to the credential (s3:ListBucket and s3:GetObject on the
    app bucket only): every other AWS call is expected, and
    reported, as 'denied'.

    The credential is read from a local leaked-credential JSON file (the same
    shape produced by plant-leaked-credential.ps1 and by the attack script's
    credential-discovery step), never typed on the command line, never
    echoed, and never written to any output.

    Supports -WhatIf: prints the planned calls without making them and exits 0.

.PARAMETER CredentialPath
    Path to the leaked-credential JSON file (fields: access_key_id,
    secret_access_key, region). Default: .\out\exposed-credential.json
    relative to the current directory, matching the attack script's default
    output path when run from the sangyshop repository.

.PARAMETER LabBucket
    Name of the SangyShop app S3 bucket. Optional: defaults to Aws.Ec2.BucketBase +
    '-' + UniqueSuffix from the config (as ops/aws/ec2/deploy.ps1 derives it), then to
    the s3-bucket entry of the deploy component in the lab manifest. Exit code 2 only
    when none is available. The credential is only authorized to list and read
    objects in this bucket.

.PARAMETER Region
    AWS region to call. Default: Aws.Region from the config file (ops\cloud.config.ps1,
    or the file named by LAB_CONFIG_PATH). Should match the credential's region.

.PARAMETER MaxCalls
    Maximum number of AWS API calls to attempt. Default and hard ceiling: 10.

.EXAMPLE
    # Bucket and region default from the config:
    .\use-leaked-credential.ps1 -CredentialPath .\out\exposed-credential.json -WhatIf

.EXAMPLE
    .\use-leaked-credential.ps1 -CredentialPath .\out\exposed-credential.json -LabBucket sangyshop-lab-abc12345 -Region us-east-1 -WhatIf

.EXAMPLE
    .\use-leaked-credential.ps1 -CredentialPath .\out\exposed-credential.json -LabBucket sangyshop-lab-abc12345 -Region us-east-1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$CredentialPath = (Join-Path (Get-Location) 'out\exposed-credential.json'),
    [string]$LabBucket,
    [string]$Region,
    [int]$MaxCalls = 10
)

. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')
. (Join-Path $PSScriptRoot '..\AwsLabNames.ps1')
Set-StrictMode -Off

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" }

function Stop-Use {
    param([string]$Message, [int]$Code = 1)
    [Console]::Error.WriteLine("Error: $Message")
    exit $Code
}

if ($MaxCalls -lt 1 -or $MaxCalls -gt 10) {
    Stop-Use -Code 2 -Message '-MaxCalls must be between 1 and 10 (hard ceiling for this script).'
}
$useConfig = $null
$configPath = $env:LAB_CONFIG_PATH
if ([string]::IsNullOrWhiteSpace($configPath)) { $configPath = Join-Path $PSScriptRoot '..\..\cloud.config.ps1' }
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    try { $useConfig = Get-CloudConfig -ConfigPath $configPath -Cloud 'Aws' -Modality 'ec2' } catch { $useConfig = $null }
}
if ([string]::IsNullOrWhiteSpace($Region)) {
    $Region = Resolve-LabRegion -Region $Region -Config $useConfig   # exits with code 2 when neither is available
}
if ([string]::IsNullOrWhiteSpace($LabBucket)) {
    # Same derivation as ops/aws/ec2/deploy.ps1 (BucketBase + '-' + UniqueSuffix), then the lab manifest.
    $useNames = $null
    if ($useConfig) { $useNames = Get-AwsLabNames -Config $useConfig }
    if ($useNames -and -not [string]::IsNullOrWhiteSpace([string]$useNames['AppBucket'])) {
        $LabBucket = [string]$useNames['AppBucket']
        Write-Info "-LabBucket not given: using app bucket '$LabBucket' from the lab config (Aws.Ec2.BucketBase + UniqueSuffix)."
    } else {
        $labTag = if ($useNames) { [string]$useNames['LabTag'] } else { 'sangyshop-lab-aws' }
        $fromManifest = Find-LabManifestResourceId -Type 's3-bucket' -Lab $labTag -Component 'deploy' -Region $Region
        if (-not [string]::IsNullOrWhiteSpace($fromManifest)) {
            $LabBucket = $fromManifest
            Write-Info "-LabBucket not given: using app bucket '$LabBucket' from the lab manifest."
        }
    }
}
if ([string]::IsNullOrWhiteSpace($LabBucket)) {
    Stop-Use -Code 2 -Message 'Missing required parameter: -LabBucket (not found in the lab config or the lab manifest either)'
}
if (-not (Test-Path -LiteralPath $CredentialPath)) {
    Stop-Use -Code 3 -Message "Leaked credential file not found: $CredentialPath. Run plant-leaked-credential.ps1 or the attack script's credential-discovery step first."
}

# The credential is parsed but NEVER echoed, logged or re-printed below.
$raw = Get-Content -LiteralPath $CredentialPath -Raw
try {
    $credential = ConvertFrom-Json -InputObject $raw
} catch {
    Stop-Use -Code 3 -Message "Leaked credential file is not valid JSON: $CredentialPath"
}
if (-not $credential.access_key_id -or -not $credential.secret_access_key) {
    Stop-Use -Code 3 -Message "Leaked credential file is missing 'access_key_id' or 'secret_access_key': $CredentialPath"
}

# Calls attempted, in order. Only ListBucket and GetObject on the lab app
# bucket are expected to succeed; everything else exercises what an attacker
# would find denied, which is itself useful evidence when triaging the identity.
$calls = @(
    @{ Name = 's3:ListBucket (lab app bucket)'; Args = @('s3api', 'list-objects-v2', '--bucket', $LabBucket, '--max-items', '1') }
    @{ Name = 's3:GetBucketLocation (lab app bucket)'; Args = @('s3api', 'get-bucket-location', '--bucket', $LabBucket) }
    @{ Name = 's3:ListAllMyBuckets'; Args = @('s3api', 'list-buckets') }
    @{ Name = 'sts:GetCallerIdentity'; Args = @('sts', 'get-caller-identity') }
    @{ Name = 'iam:ListUsers'; Args = @('iam', 'list-users') }
    @{ Name = 'iam:GetUser (self)'; Args = @('iam', 'get-user') }
    @{ Name = 'ec2:DescribeInstances'; Args = @('ec2', 'describe-instances', '--region', $Region) }
    @{ Name = 'secretsmanager:ListSecrets'; Args = @('secretsmanager', 'list-secrets') }
    @{ Name = 'rds:DescribeDBInstances'; Args = @('rds', 'describe-db-instances') }
    @{ Name = 'cloudtrail:LookupEvents'; Args = @('cloudtrail', 'lookup-events', '--max-results', '1') }
)

if ($calls.Count -gt $MaxCalls) { $calls = $calls[0..($MaxCalls - 1)] }

Write-Info "Using the leaked credential against AWS in $Region (at most $($calls.Count) API call(s); API names and status only, no response content is printed)."

# The credential is passed through environment variables for this process
# only: it is never written to the default AWS CLI profile or to any shared
# credentials file location.
$env:AWS_ACCESS_KEY_ID = "$($credential.access_key_id)"
$env:AWS_SECRET_ACCESS_KEY = "$($credential.secret_access_key)"
$env:AWS_DEFAULT_REGION = $Region
$env:AWS_REGION = $Region

try {
    $callNumber = 0
    foreach ($call in $calls) {
        $callNumber++
        if ($WhatIfPreference) {
            Write-Host "What if: [$callNumber/$($calls.Count)] $($call.Name)"
            continue
        }
        $full = @('--region', $Region) + $call.Args
        $output = (& aws @full --output json 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
        $status = if ($exitCode -eq 0) {
            'ok'
        } elseif ($output -match 'AccessDenied|UnauthorizedOperation|is not authorized to perform') {
            'denied'
        } else {
            'error'
        }
        Write-Host ("[{0}/{1}] {2}: {3}" -f $callNumber, $calls.Count, $call.Name, $status)
    }
} finally {
    # -WhatIf:$false: always clear the credential from the environment, even
    # during a dry run, so it never lingers in this process.
    Remove-Item Env:\AWS_ACCESS_KEY_ID, Env:\AWS_SECRET_ACCESS_KEY -ErrorAction SilentlyContinue -WhatIf:$false
}

Write-Info "Done. Only the s3:ListBucket and s3:GetObject calls on '$LabBucket' are expected to return 'ok'; everything else should show 'denied', demonstrating the least-privilege policy of the leaked identity."
Write-Info 'This is the evidence to use when triaging the IAM identity: identify the calls made by this identity, the source IP, and the time of the first call, via CloudTrail.'
exit 0
