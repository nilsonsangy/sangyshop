<#
.SYNOPSIS
    Creates the leaked lab credential: a least-privilege IAM user and the
    "forgotten" /lab/leaked.json file on the EC2 deployment instance (idempotent).

.DESCRIPTION
    The credential planted here is deliberately a low-privilege, separate
    identity, never the operator's own credential.

        1. IAM user named by the LeakedUser entry of Get-AwsLabNames (no console
           access, no password).
        2. Inline policy granting ONLY 's3:ListBucket' and 's3:GetObject' on
           the app bucket (-LabBucket), nothing else, no wildcard resource.
        3. One access key for the user. If the user already has key(s) but their
           secret is not available locally (for example a previous run failed after
           create-access-key), this user's existing key(s) are deleted (only because the
           user carries the lab tag) and one fresh key is created, so the file always
           holds a real secret. The manifest drops the old key id and records the new one.
        4. The access key id and secret are written to /lab/leaked.json on the
           EC2 deployment instance (-InstanceId) through SSM Send-Command, matching
           how src/routes/lab.js's GET /debug/config reads LAB_LEAKED_FILE
           (default /lab/leaked.json) in the sangyshop repository. The command
           document and its parameters are never echoed with the secret value.

    The IAM user carries the lab tag (lab=<app>-lab-aws) and is recorded in the
    lab manifest through Add-LabManifestEntry (ownership: created). The access
    key itself cannot be tagged, so it is also recorded in the manifest (type
    'iam-access-key') for the full teardown and zero-cost verification to find.

    Re-running: an existing tagged user is reused and the policy is re-applied in
    place. Its access key is reused only when the secret is available locally in
    -LeakedFilePath; otherwise the key is rotated (see 3) and the remote file is
    re-written with the new secret. A same-named, untagged IAM user stops
    the script (exit 1) without any change, following unmarked resource.

    The attack simulation only reads the placeholder
    credential from GET /debug/config; it never calls a
    real AWS API. This script is the one that plants that credential, and
    use-leaked-credential.ps1 (also in this folder) is the one that calls AWS
    with it.

    Supports -WhatIf: prints every planned AWS CLI call and the planned SSM
    command without executing them, creates nothing, writes no manifest entry,
    and exits 0.

    Windows PowerShell 5.1 compatible.


    Required IAM actions:
      iam:CreateAccessKey
      iam:CreateUser
      iam:DeleteAccessKey
      iam:GetUser
      iam:ListAccessKeys
      iam:PutUserPolicy
      iam:TagUser
      ssm:GetCommandInvocation
      ssm:SendCommand

.PARAMETER Region
    AWS region. Default: Aws.Region from the config file (set LAB_CONFIG_PATH to use another
    config). Must match the EC2 deployment region.


.PARAMETER LabBucket
    Name of the SangyShop app S3 bucket created by EC2 deployment. Optional: defaults
    to Aws.Ec2.BucketBase + '-' + UniqueSuffix from the config (as ops/aws/ec2/deploy.ps1
    derives it), then to the s3-bucket entry of the deploy component in the lab manifest.
    Exit code 2 only when none is available.
    The leaked user's policy is restricted to this bucket only.

.PARAMETER InstanceId
    Instance id of the EC2 deployment instance (i-xxxxxxxxxxxxxxxxx). Optional:
    defaults to the ec2-instance entry of the deploy component in the lab manifest,
    then to describe-instances filtered by the lab Name and lab tags (exactly one
    non-terminated match). Not needed when -LeakedFilePath is given instead
    (local-only smoke test). Exit code 2 when none is found.

.PARAMETER LeakedFilePath
    When given instead of -InstanceId, writes /lab/leaked.json content to this
    local path instead of using SSM. Intended for smoke tests and for
    manual setups that do not use SSM.

.PARAMETER UserName
    IAM user name for the leaked credential. Default: the LeakedUser name from Get-AwsLabNames.

.PARAMETER RunId
    Run identifier used in the run-id tag and the manifest entries. Default:
    Get-LabRunId (new UTC timestamp, or $env:LAB_RUN_ID).

.EXAMPLE
    # Bucket and instance default from the config and the lab manifest:
    .\plant-leaked-credential.ps1 -WhatIf

.EXAMPLE
    .\plant-leaked-credential.ps1 -Region us-east-1 -LabBucket sangyshop-lab-abc12345 -InstanceId i-0123456789abcdef0 -WhatIf

.EXAMPLE
    .\plant-leaked-credential.ps1 -Region us-east-1 -LabBucket sangyshop-lab-abc12345 -InstanceId i-0123456789abcdef0
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Region,
    [string]$LabBucket,
    [string]$InstanceId,
    [string]$LeakedFilePath,
    [string]$UserName,
    [string]$RunId
)
. "$PSScriptRoot\detection\Detection-Common.ps1"
# The shared libraries enable strict mode, which this script was not written for, so it is switched
# off again after loading. Names, region and tags come from Detection-Common (Get-AwsLabNames).
Set-StrictMode -Off
$script:LabComponent = 'credential'

function Test-LeakedAwsNotFound {
    <# True when CLI output says the resource does not exist (same check as Blocker-Common.ps1). #>
    param($Result)
    return ($Result.ExitCode -ne 0 -and "$($Result.Output)" -match 'NoSuchEntity|ResourceNotFoundException|NotFound|does not exist')
}

if ([string]::IsNullOrWhiteSpace($UserName)) { $UserName = [string]$script:LabNames['LeakedUser'] }
Initialize-Lab -Region $Region
$RunId = Get-LabRunId -RunId $RunId

$LabBucket = Resolve-LabAppBucket -LabBucket $LabBucket
if ([string]::IsNullOrWhiteSpace($LabBucket)) {
    Stop-Lab -Code 2 -Message 'Missing required parameter: -LabBucket (the app bucket created by EC2 deployment). It was not found in the lab config (Aws.Ec2.BucketBase + UniqueSuffix) or the lab manifest either'
}
if ([string]::IsNullOrWhiteSpace($InstanceId) -and [string]::IsNullOrWhiteSpace($LeakedFilePath)) {
    $InstanceId = Resolve-LabInstanceId -InstanceId $InstanceId
}
if ([string]::IsNullOrWhiteSpace($InstanceId) -and [string]::IsNullOrWhiteSpace($LeakedFilePath)) {
    Stop-Lab -Code 2 -Message 'Missing required parameter: -InstanceId (or -LeakedFilePath for a local-only smoke test). No lab instance was found in the lab manifest or by the lab Name and lab tags either'
}
if (-not [string]::IsNullOrWhiteSpace($InstanceId) -and $InstanceId -notmatch '^i-[0-9a-f]{8,17}$') {
    Stop-Lab -Code 2 -Message "Invalid -InstanceId: $InstanceId (expected i-xxxxxxxx)"
}

$account = Get-LabAccountId
$policyName = [string]$script:LabNames['LeakedPolicy']

try {
    # 1. IAM user (no console access, no password is ever set by this script).
    $g = Invoke-LabCli -CliArgs @('iam', 'get-user', '--user-name', $UserName, '--query', 'User.Tags', '--output', 'json')
    if ($g.ExitCode -eq 0) {
        if (-not (Test-LabTagged -Tags (ConvertFrom-LabJson -Text $g.Output))) {
            Confirm-LabUntaggedRefusal -Kind 'IAM user' -Name $UserName
        }
        Write-LabInfo "IAM user '$UserName' already exists with the lab tag."
    } elseif (Test-LeakedAwsNotFound -Result $g) {
        $c = Invoke-LabCli -Mutating -CliArgs (@('iam', 'create-user', '--user-name', $UserName,
                '--tags') + (Get-LabTagPairs -RunId $RunId))
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create IAM user '$UserName'. $(Hide-LabSecrets $c.Output)" }
        Add-LabResource -Type 'iam-user' -Id $UserName -RunId $RunId
        Write-LabInfo "Created IAM user '$UserName' (leaked lab credential, no console access)."
    } else {
        Stop-Lab -Code 1 -Message "Could not read IAM user '$UserName'. $(Hide-LabSecrets $g.Output)"
    }

    # 2. Minimal inline policy: ListBucket + GetObject on the app bucket ONLY.
    $policyDoc = @{
        Version   = '2012-10-17'
        Statement = @(
            @{
                Sid      = 'ListLabAppBucketOnly'
                Effect   = 'Allow'
                Action   = 's3:ListBucket'
                Resource = "arn:aws:s3:::$LabBucket"
            },
            @{
                Sid      = 'ReadLabAppBucketObjectsOnly'
                Effect   = 'Allow'
                Action   = 's3:GetObject'
                Resource = "arn:aws:s3:::$LabBucket/*"
            }
        )
    } | ConvertTo-Json -Depth 5 -Compress
    $policyFile = New-LabTempFile -Text $policyDoc
    $p = Invoke-LabCli -Mutating -CliArgs @('iam', 'put-user-policy', '--user-name', $UserName,
        '--policy-name', $policyName, '--policy-document', $policyFile)
    if ($p.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not attach the inline policy. $(Hide-LabSecrets $p.Output)" }
    Write-LabInfo "Inline policy '$policyName' grants only s3:ListBucket and s3:GetObject on '$LabBucket'."

    # 3. Access key: reuse one if the user already has a key, else create exactly one.
    $lk = Invoke-LabCli -CliArgs @('iam', 'list-access-keys', '--user-name', $UserName, '--query', 'AccessKeyMetadata[].AccessKeyId', '--output', 'json')
    if ($lk.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not list access keys for '$UserName'. $(Hide-LabSecrets $lk.Output)" }
    $existingKeys = @(ConvertFrom-LabJson -Text $lk.Output)

    $accessKeyId = $null
    $secretAccessKey = $null

    # A secret is only available locally when -LeakedFilePath already holds a real (non-placeholder)
    # secret for one of the user's existing keys. AWS never returns a secret again after creation.
    $usableLocal = $false
    if ($existingKeys.Count -gt 0 -and $LeakedFilePath -and (Test-Path -LiteralPath $LeakedFilePath -PathType Leaf)) {
        try {
            $prev = ConvertFrom-LabJson -Text ([System.IO.File]::ReadAllText($LeakedFilePath))
            if ($prev -and $prev.access_key_id -and $prev.secret_access_key -and ($existingKeys -contains "$($prev.access_key_id)") -and "$($prev.secret_access_key)" -notmatch '^EXAMPLE-') {
                $usableLocal = $true
                $accessKeyId = "$($prev.access_key_id)"
                $secretAccessKey = "$($prev.secret_access_key)"
            }
        } catch { $usableLocal = $false }
    }

    if ($usableLocal) {
        Write-LabInfo "Reusing existing access key '$accessKeyId' for '$UserName': its secret is available in '$LeakedFilePath'."
    } else {
        if ($existingKeys.Count -gt 0) {
            # The user is lab-tagged here (an untagged same-named user stopped the script above), so
            # only this user's keys are rotated: delete them, then create one fresh key with a real secret.
            Write-LabInfo "Access key(s) of lab user '$UserName' exist but their secret is not available, so a placeholder would break the leaked-credential exercise. Rotating: deleting this user's existing key(s) and creating a fresh one."
            foreach ($oldKey in $existingKeys) {
                $dk = Invoke-LabCli -Mutating -CliArgs @('iam', 'delete-access-key', '--user-name', $UserName, '--access-key-id', "$oldKey")
                if ($dk.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not delete access key '$oldKey' of '$UserName'. $(Hide-LabSecrets $dk.Output)" }
                Remove-LabManifestEntry -Type 'iam-access-key' -Id "$UserName/$oldKey"
                Write-LabInfo "Deleted old access key '$oldKey' of '$UserName' and removed it from the lab manifest."
            }
        }
        $ck = Invoke-LabCli -Mutating -CliArgs @('iam', 'create-access-key', '--user-name', $UserName, '--output', 'json')
        if ($ck.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create an access key for '$UserName'. $(Hide-LabSecrets $ck.Output)" }
        if (-not $WhatIfPreference) {
            $created = ConvertFrom-LabJson -Text $ck.Output
            if ($created -and $created.AccessKey) {
                $accessKeyId = $created.AccessKey.AccessKeyId
                $secretAccessKey = $created.AccessKey.SecretAccessKey
            }
        } else {
            $accessKeyId = 'AKIAIOSFODNN7EXAMPLE'
        }
        Add-LabResource -Type 'iam-access-key' -Id "$UserName/$accessKeyId" -RunId $RunId
        Write-LabInfo "Created access key '$accessKeyId' for '$UserName'. The secret is never echoed or logged."
    }

    if (-not $accessKeyId) {
        Stop-Lab -Code 1 -Message "Could not determine an access key id for '$UserName'."
    }

    # 4. Leaked file content: a realistic-looking JSON, matching the shape
    #    used by the attack simulation's credential-discovery step.
    #    The secret is always real here: a key without a known secret was rotated above.
    #    Only -WhatIf (nothing was created) writes a clearly fake value, and -WhatIf writes no file.
    if (-not $secretAccessKey -and -not $WhatIfPreference) {
        Stop-Lab -Code 1 -Message "No secret is available for access key '$accessKeyId' of '$UserName', so /lab/leaked.json was not written."
    }
    $secretForFile = if ($secretAccessKey) { $secretAccessKey } else { 'EXAMPLE-SECRET-WHATIF-ONLY' }
    $leakedContent = [ordered]@{
        cloud             = 'aws'
        access_key_id     = $accessKeyId
        secret_access_key = $secretForFile
        region            = $script:LabRegion
        note              = 'placeholder lab credential, not a real AWS key once rotated for a training run'
    } | ConvertTo-Json -Depth 3

    if ($LeakedFilePath) {
        if ($WhatIfPreference) {
            Write-Host "What if: write /lab/leaked.json content to local path '$LeakedFilePath'"
        } else {
            $dir = Split-Path -Parent $LeakedFilePath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [System.IO.File]::WriteAllText($LeakedFilePath, $leakedContent, (New-Object System.Text.UTF8Encoding($false)))
            Write-LabInfo "Wrote the leaked credential file to local path '$LeakedFilePath' (secret value not echoed)."
        }
    } else {
        $remoteScript = @(
            'set -e'
            'mkdir -p /lab'
            'cat > /lab/leaked.json <<''LEAKED_JSON_EOF''' 
            $leakedContent
            'LEAKED_JSON_EOF'
            'chmod 644 /lab/leaked.json'
        ) -join "`n"

        if ($WhatIfPreference) {
            Write-Host "What if: aws ssm send-command --instance-ids $InstanceId --document-name AWS-RunShellScript --parameters commands=[<write /lab/leaked.json, secret value redacted>]"
        } else {
            $paramsFile = New-LabTempFile -Text (@{ commands = @($remoteScript) } | ConvertTo-Json -Depth 3 -Compress)
            $sc = Invoke-LabCli -Mutating -CliArgs @('ssm', 'send-command', '--instance-ids', $InstanceId,
                '--document-name', 'AWS-RunShellScript', '--parameters', $paramsFile, '--query', 'Command.CommandId', '--output', 'text')
            if ($sc.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not send the SSM command to '$InstanceId'. $(Hide-LabSecrets $sc.Output)" }
            $commandId = "$($sc.Output)".Trim()
            Write-LabInfo "Sent SSM command '$commandId' to write /lab/leaked.json on '$InstanceId' (secret value not echoed)."

            $wait = Invoke-LabCli -CliArgs @('ssm', 'wait', 'command-executed', '--command-id', $commandId, '--instance-id', $InstanceId)
            if ($wait.ExitCode -ne 0) {
                Write-LabWarn "Could not confirm SSM command completion for '$commandId'. Check 'aws ssm get-command-invocation --command-id $commandId --instance-id $InstanceId'."
            } else {
                Write-LabInfo "/lab/leaked.json is in place on '$InstanceId'."
            }
        }
    }

    Write-LabInfo "Leaked credential ready: IAM user '$UserName', access key '$accessKeyId', scoped to s3:ListBucket/s3:GetObject on '$LabBucket' only."
    Write-LabInfo 'This credential is billable only while it exists (IAM users and keys have no AWS charge by themselves); remember to disable it during containment and remove it with full-teardown.ps1.'
} finally {
    Clear-LabTempFiles
}
exit 0
