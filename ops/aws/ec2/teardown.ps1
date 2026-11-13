<#
.SYNOPSIS
    Remove everything deploy.ps1 created for the EC2 + RDS lab (EC2 deployment).

.DESCRIPTION
    Removes the resources in the inverse order of creation, looking each one up
    first so a re-run after a successful teardown skips what is already gone,
    prints that no resource remains and exits 0 quickly (no waiting).

        1. EC2 instance (terminate, wait)
        2. RDS instance (skip final snapshot, wait) and the DB subnet group
        3. Secrets Manager secret (force delete, no recovery window)
        4. S3 application bucket (emptied, then removed)
        5. IAM instance profile, inline/managed policies and role
        6. CodeCommit repository (if one was created)
        7. CloudWatch Logs group created by the awslogs driver
        8. Network: security groups, subnets, NACL, route table, internet
           gateway, VPC

    Fail-but-continue: if a resource cannot be removed, its type and identifier
    are listed on stderr, the remaining independent resources are still removed
    and the script exits non-zero. Exit 0 only when no EC2 deployment resource
    remains.

    The detection stack, evidence, snapshots and exposed credentials are NOT
    handled here: the account-wide full AWS teardown is the recommended command
    to remove the whole lab and prevails over this script.

    Every external command is echoed before it runs. -WhatIf lists the commands
    that would run and removes nothing. Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1 (default: ops/cloud.config.ps1).

.PARAMETER Force
    Skip the interactive confirmation prompt.

.PARAMETER WhatIf
    Dry run: print the planned command list, delete nothing, exit 0.

.EXAMPLE
    .\teardown.ps1 -Force
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [switch] $Force,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0
$script:removed         = New-Object System.Collections.Generic.List[string]
$script:failures        = New-Object System.Collections.Generic.List[string]

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs
    )

    $displayParts = @($Exe)
    foreach ($a in $CmdArgs) {
        if ($null -eq $a -or $a -eq '') { $displayParts += '""' }
        elseif ($a -match '[\s"]') { $displayParts += ('"' + ($a -replace '"', '\"') + '"') }
        else { $displayParts += $a }
    }
    $display = $displayParts -join ' '

    if ($WhatIf) {
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Always tolerate a non-zero exit so the caller can classify it.
    $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

function Get-Scalar {
    param($Value)
    if ($null -eq $Value) { return '' }
    $lines = @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return '' }
    return $lines[$lines.Count - 1].Trim()
}

function Write-StderrLine {
    param([string] $Text)
    [Console]::Error.WriteLine($Text)
}

# Look a resource up. Returns $null when it does not exist (always $null in a
# dry run, where the planned delete commands use placeholders).
function Find-LabId {
    param([string[]] $FindArgs, [switch] $ByExit, [string] $KnownId)
    $out = Invoke-Cli -Exe 'aws' -CmdArgs $FindArgs
    if ($WhatIf) { return $null }
    if ($script:LastCliExit -ne 0) { return $null }
    if ($ByExit) { return $KnownId }
    $s = Get-Scalar $out
    if ([string]::IsNullOrWhiteSpace($s) -or $s -eq 'None') { return $null }
    return $s
}

# Run one removal and classify the outcome. "Already gone" is success.
function Remove-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Type,
        [Parameter(Mandatory)][string]   $Identifier,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [int] $Retries = 0
    )
    $label = "$Type $Identifier"
    $attempt = 0
    while ($true) {
        $attempt++
        $output = Invoke-Cli -Exe 'aws' -CmdArgs $CmdArgs
        if ($WhatIf) { Write-Host "    would remove: $label" -ForegroundColor DarkGray; return }
        if ($script:LastCliExit -eq 0) {
            $script:removed.Add($label)
            Write-Host "    removed: $label" -ForegroundColor Green
            return
        }
        $text = if ($null -ne $output) { ($output | Out-String) } else { '' }
        if ($text -match '(?i)(not\s*found|notfound|does\s*not\s*exist|no\s*such|nosuchbucket|NoSuchEntity|InvalidGroup\.NotFound|InvalidVpcID\.NotFound|InvalidSubnetID\.NotFound|DBInstanceNotFound|DBSubnetGroupNotFound|ResourceNotFoundException|RepositoryDoesNotExistException)') {
            $script:removed.Add("$label (already absent)")
            Write-Host "    already absent (skipped): $label" -ForegroundColor DarkGray
            return
        }
        if ($attempt -le $Retries -and $text -match '(?i)(DependencyViolation|has dependencies|InvalidDBSubnetGroupStateFault|in use)') {
            Write-Host "    dependency still draining, retrying in 15 s ($attempt/$Retries)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 15
            continue
        }
        $script:failures.Add($label)
        Write-StderrLine "ERROR: failed to remove $label (CLI exit $($script:LastCliExit))."
        return
    }
}

# ---------------------------------------------------------------------------
# Config and derived names (identical to deploy.ps1).
# ---------------------------------------------------------------------------
try {
    Write-Step "Loading configuration (cloud: Aws, modality: ec2)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws' -Modality 'ec2'
}
catch {
    Write-StderrLine "ERROR: $($_.Exception.Message)"
    exit 1
}

$region      = [string]$cfg.Aws.Region
$suffix      = [string]$cfg.UniqueSuffix
$appName     = [string]$cfg.Common.AppName
$lab         = 'sangyshop-lab-aws'
$prefix      = "$appName-lab"
$vpcName     = "$prefix-vpc"
$igwName     = "$prefix-igw"
$pubName     = "$prefix-public"
$privAName   = "$prefix-private-a"
$privBName   = "$prefix-private-b"
$rtName      = "$prefix-public-rt"
$naclName    = "$prefix-public-nacl"
$appSgName   = "$prefix-app-sg"
$dbSgName    = "$prefix-db-sg"
$roleName    = "$appName-ec2-role"
$profileName = "$appName-ec2-profile"
$bucket      = ([string]$cfg.Aws.Ec2.BucketBase + '-' + $suffix)
$secretName  = "$appName/ec2/db_password"
$dbSubnetGrp = "$prefix-db-subnets"
$rdsId       = "$prefix-pg"
$ec2Name     = "$prefix-ec2"
$logGroup    = '/sangyshop/app'
$repoName    = $appName
$rg          = @('--region', $region)

function Get-TagFilters {
    param([string] $Name)
    return @('--filters', "Name=tag:Name,Values=$Name", "Name=tag:lab,Values=$lab")
}

if (-not $WhatIf -and -not $Force) {
    Write-Host ""
    Write-Host "This will PERMANENTLY DELETE the EC2 lab resources (region '$region'):" -ForegroundColor Yellow
    Write-Host "  EC2 $ec2Name, RDS $rdsId (no final snapshot), secret $secretName," -ForegroundColor Yellow
    Write-Host "  S3 bucket $bucket (and its objects), IAM role/profile $roleName, log group $logGroup," -ForegroundColor Yellow
    Write-Host "  security groups, subnets, NACL, route table, internet gateway and VPC $vpcName." -ForegroundColor Yellow
    $answer = Read-Host "Type 'yes' to proceed (or re-run with -Force to skip this prompt)"
    if ($answer -ne 'yes') {
        Write-Host "Teardown aborted; nothing was deleted." -ForegroundColor Cyan
        exit 0
    }
}
if ($WhatIf) {
    Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
}

# Auth check (fail-closed).
Write-Step "Checking AWS authentication via sts get-caller-identity"
Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
if ($script:LastCliExit -ne 0) {
    Write-StderrLine ("ERROR: AWS authentication/CLI check failed (aws sts get-caller-identity). " +
        "Install the AWS CLI v2 and authenticate as the lab operator ('aws configure' or 'aws sso login'), then re-run.")
    exit 1
}

# ---------------------------------------------------------------------------
# 1. EC2 instance.
# ---------------------------------------------------------------------------
Write-Step "Removing EC2 instance '$ec2Name'"
$instanceId = Find-LabId -FindArgs (@('ec2', 'describe-instances') + $rg + (Get-TagFilters $ec2Name) + @('Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down', '--query', 'Reservations[0].Instances[0].InstanceId', '--output', 'text'))
if ($WhatIf) { $instanceId = '<instance-id>' }
if ($instanceId) {
    Remove-Resource -Type 'ec2-instance' -Identifier $instanceId -CmdArgs (@('ec2', 'terminate-instances') + $rg + @('--instance-ids', $instanceId))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'wait', 'instance-terminated') + $rg + @('--instance-ids', $instanceId)) | Out-Null
}
else { Write-Host "  no EC2 instance found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 2. RDS instance and DB subnet group.
# ---------------------------------------------------------------------------
Write-Step "Removing RDS instance '$rdsId' and DB subnet group '$dbSubnetGrp'"
$rdsFound = Find-LabId -ByExit -KnownId $rdsId -FindArgs (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].DBInstanceIdentifier', '--output', 'text'))
if ($WhatIf) { $rdsFound = $rdsId }
if ($rdsFound) {
    Remove-Resource -Type 'rds-instance' -Identifier $rdsId -CmdArgs (@('rds', 'delete-db-instance') + $rg + @('--db-instance-identifier', $rdsId, '--skip-final-snapshot', '--delete-automated-backups'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'wait', 'db-instance-deleted') + $rg + @('--db-instance-identifier', $rdsId)) | Out-Null
}
else { Write-Host "  no RDS instance found" -ForegroundColor DarkGray }
$sgrpFound = Find-LabId -ByExit -KnownId $dbSubnetGrp -FindArgs (@('rds', 'describe-db-subnet-groups') + $rg + @('--db-subnet-group-name', $dbSubnetGrp, '--query', 'DBSubnetGroups[0].DBSubnetGroupName', '--output', 'text'))
if ($WhatIf) { $sgrpFound = $dbSubnetGrp }
if ($sgrpFound) {
    Remove-Resource -Type 'db-subnet-group' -Identifier $dbSubnetGrp -Retries 3 -CmdArgs (@('rds', 'delete-db-subnet-group') + $rg + @('--db-subnet-group-name', $dbSubnetGrp))
}

# ---------------------------------------------------------------------------
# 3. Secret.
# ---------------------------------------------------------------------------
Write-Step "Removing Secrets Manager secret '$secretName'"
$secretFound = Find-LabId -ByExit -KnownId $secretName -FindArgs (@('secretsmanager', 'describe-secret') + $rg + @('--secret-id', $secretName, '--query', 'Name', '--output', 'text'))
if ($WhatIf) { $secretFound = $secretName }
if ($secretFound) {
    Remove-Resource -Type 'secret' -Identifier $secretName -CmdArgs (@('secretsmanager', 'delete-secret') + $rg + @('--secret-id', $secretName, '--force-delete-without-recovery'))
}
else { Write-Host "  no secret found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 4. S3 application bucket.
# ---------------------------------------------------------------------------
Write-Step "Removing S3 bucket '$bucket'"
$bucketFound = Find-LabId -ByExit -KnownId $bucket -FindArgs (@('s3api', 'head-bucket') + $rg + @('--bucket', $bucket))
if ($WhatIf) { $bucketFound = $bucket }
if ($bucketFound) {
    Remove-Resource -Type 's3-bucket' -Identifier $bucket -CmdArgs (@('s3', 'rb', "s3://$bucket", '--force') + $rg)
}
else { Write-Host "  no bucket found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 5. IAM instance profile and role.
# ---------------------------------------------------------------------------
Write-Step "Removing IAM instance profile '$profileName' and role '$roleName'"
$profFound = Find-LabId -ByExit -KnownId $profileName -FindArgs @('iam', 'get-instance-profile', '--instance-profile-name', $profileName, '--query', 'InstanceProfile.InstanceProfileName', '--output', 'text')
if ($WhatIf) { $profFound = $profileName }
if ($profFound) {
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'remove-role-from-instance-profile', '--instance-profile-name', $profileName, '--role-name', $roleName) | Out-Null
    Remove-Resource -Type 'instance-profile' -Identifier $profileName -CmdArgs @('iam', 'delete-instance-profile', '--instance-profile-name', $profileName)
}
$roleFound = Find-LabId -ByExit -KnownId $roleName -FindArgs @('iam', 'get-role', '--role-name', $roleName, '--query', 'Role.RoleName', '--output', 'text')
if ($WhatIf) { $roleFound = $roleName }
if ($roleFound) {
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'detach-role-policy', '--role-name', $roleName, '--policy-arn', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore') | Out-Null
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'delete-role-policy', '--role-name', $roleName, '--policy-name', 'sangyshop-ec2-inline') | Out-Null
    Remove-Resource -Type 'iam-role' -Identifier $roleName -CmdArgs @('iam', 'delete-role', '--role-name', $roleName)
}
if (-not $profFound -and -not $roleFound) { Write-Host "  no IAM role or instance profile found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 6. CodeCommit repository (only exists when deploy ran with -Repo codecommit).
# ---------------------------------------------------------------------------
Write-Step "Removing CodeCommit repository '$repoName' (if created by deploy)"
$ccFound = Find-LabId -ByExit -KnownId $repoName -FindArgs (@('codecommit', 'get-repository') + $rg + @('--repository-name', $repoName, '--query', 'repositoryMetadata.repositoryName', '--output', 'text'))
if ($WhatIf) { $ccFound = $repoName }
if ($ccFound) {
    Remove-Resource -Type 'codecommit-repo' -Identifier $repoName -CmdArgs (@('codecommit', 'delete-repository') + $rg + @('--repository-name', $repoName))
}
else { Write-Host "  no CodeCommit repository found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 7. CloudWatch Logs group created by the awslogs driver.
# ---------------------------------------------------------------------------
Write-Step "Removing CloudWatch Logs group '$logGroup'"
$lgOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('logs', 'describe-log-groups') + $rg + @('--log-group-name-prefix', $logGroup, '--query', "logGroups[?logGroupName=='$logGroup'].logGroupName | [0]", '--output', 'text'))
$lgFound = if ($WhatIf) { $logGroup } else { Get-Scalar $lgOut }
if ($lgFound -and $lgFound -ne 'None') {
    Remove-Resource -Type 'log-group' -Identifier $logGroup -CmdArgs (@('logs', 'delete-log-group') + $rg + @('--log-group-name', $logGroup))
}
else { Write-Host "  no log group found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# 8. Network, inverse order of creation.
# ---------------------------------------------------------------------------
Write-Step "Removing network resources of '$vpcName'"
$vpcId = Find-LabId -FindArgs (@('ec2', 'describe-vpcs') + $rg + (Get-TagFilters $vpcName) + @('--query', 'Vpcs[0].VpcId', '--output', 'text'))
if ($WhatIf) { $vpcId = '<vpc-id>' }

foreach ($sgName in @($dbSgName, $appSgName)) {
    $sgId = if ($vpcId) { Find-LabId -FindArgs (@('ec2', 'describe-security-groups') + $rg + @('--filters', "Name=group-name,Values=$sgName", "Name=vpc-id,Values=$vpcId", '--query', 'SecurityGroups[0].GroupId', '--output', 'text')) } else { $null }
    if ($WhatIf) { $sgId = "<$sgName-id>" }
    if ($sgId) { Remove-Resource -Type 'security-group' -Identifier "$sgName ($sgId)" -Retries 6 -CmdArgs (@('ec2', 'delete-security-group') + $rg + @('--group-id', $sgId)) }
}
foreach ($subName in @($pubName, $privAName, $privBName)) {
    $subId = Find-LabId -FindArgs (@('ec2', 'describe-subnets') + $rg + (Get-TagFilters $subName) + @('--query', 'Subnets[0].SubnetId', '--output', 'text'))
    if ($WhatIf) { $subId = "<$subName-id>" }
    if ($subId) { Remove-Resource -Type 'subnet' -Identifier "$subName ($subId)" -Retries 6 -CmdArgs (@('ec2', 'delete-subnet') + $rg + @('--subnet-id', $subId)) }
}
$naclId = Find-LabId -FindArgs (@('ec2', 'describe-network-acls') + $rg + (Get-TagFilters $naclName) + @('--query', 'NetworkAcls[0].NetworkAclId', '--output', 'text'))
if ($WhatIf) { $naclId = '<nacl-id>' }
if ($naclId) { Remove-Resource -Type 'network-acl' -Identifier "$naclName ($naclId)" -Retries 3 -CmdArgs (@('ec2', 'delete-network-acl') + $rg + @('--network-acl-id', $naclId)) }

$rtId = Find-LabId -FindArgs (@('ec2', 'describe-route-tables') + $rg + (Get-TagFilters $rtName) + @('--query', 'RouteTables[0].RouteTableId', '--output', 'text'))
if ($WhatIf) { $rtId = '<route-table-id>' }
if ($rtId) { Remove-Resource -Type 'route-table' -Identifier "$rtName ($rtId)" -Retries 3 -CmdArgs (@('ec2', 'delete-route-table') + $rg + @('--route-table-id', $rtId)) }

$igwId = Find-LabId -FindArgs (@('ec2', 'describe-internet-gateways') + $rg + (Get-TagFilters $igwName) + @('--query', 'InternetGateways[0].InternetGatewayId', '--output', 'text'))
if ($WhatIf) { $igwId = '<igw-id>' }
if ($igwId) {
    if ($vpcId) { Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'detach-internet-gateway') + $rg + @('--internet-gateway-id', $igwId, '--vpc-id', $vpcId)) | Out-Null }
    Remove-Resource -Type 'internet-gateway' -Identifier "$igwName ($igwId)" -Retries 3 -CmdArgs (@('ec2', 'delete-internet-gateway') + $rg + @('--internet-gateway-id', $igwId))
}
if ($vpcId) { Remove-Resource -Type 'vpc' -Identifier "$vpcName ($vpcId)" -Retries 3 -CmdArgs (@('ec2', 'delete-vpc') + $rg + @('--vpc-id', $vpcId)) }
else { Write-Host "  no VPC found" -ForegroundColor DarkGray }

# ---------------------------------------------------------------------------
# Dry run ends here.
# ---------------------------------------------------------------------------
if ($WhatIf) {
    Write-Step "Dry run (-WhatIf): planned command list (no command was executed)"
    $i = 0
    foreach ($c in $script:PlannedCommands) {
        $i++
        Write-Host ("  {0,3}. {1}" -f $i, $c)
    }
    Write-Host ""
    Write-Host "Dry run complete: $($script:PlannedCommands.Count) command(s) planned, none executed."
    exit 0
}

# ---------------------------------------------------------------------------
# Final verification: nothing from ec2_deployment may remain.
# ---------------------------------------------------------------------------
Write-Step "Verifying that no EC2 deployment resource remains"
$checks = @(
    @{ Type = 'ec2-instance'; Id = $ec2Name; Args = (@('ec2', 'describe-instances') + $rg + (Get-TagFilters $ec2Name) + @('Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down', '--query', 'Reservations[0].Instances[0].InstanceId', '--output', 'text')); ByExit = $false },
    @{ Type = 'rds-instance'; Id = $rdsId; Args = (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].DBInstanceIdentifier', '--output', 'text')); ByExit = $true },
    @{ Type = 'secret'; Id = $secretName; Args = (@('secretsmanager', 'describe-secret') + $rg + @('--secret-id', $secretName, '--query', 'Name', '--output', 'text')); ByExit = $true },
    @{ Type = 's3-bucket'; Id = $bucket; Args = (@('s3api', 'head-bucket') + $rg + @('--bucket', $bucket)); ByExit = $true },
    @{ Type = 'iam-role'; Id = $roleName; Args = @('iam', 'get-role', '--role-name', $roleName, '--query', 'Role.RoleName', '--output', 'text'); ByExit = $true },
    @{ Type = 'vpc'; Id = $vpcName; Args = (@('ec2', 'describe-vpcs') + $rg + (Get-TagFilters $vpcName) + @('--query', 'Vpcs[0].VpcId', '--output', 'text')); ByExit = $false }
)
$remaining = New-Object System.Collections.Generic.List[string]
foreach ($c in $checks) {
    $found = if ($c.ByExit) { Find-LabId -ByExit -KnownId $c.Id -FindArgs $c.Args } else { Find-LabId -FindArgs $c.Args }
    if ($found) { $remaining.Add("$($c.Type) $($c.Id)") }
}
foreach ($f in $script:failures) { if (-not ($remaining -contains $f)) { $remaining.Add($f) } }

if ($remaining.Count -gt 0) {
    Write-StderrLine "ERROR: the following resources remain and must be removed (re-run teardown.ps1 once dependencies drain, or remove them manually):"
    foreach ($r in $remaining) { Write-StderrLine "  - $r" }
    exit 1
}

Write-Host ""
if ($script:removed.Count -eq 0) {
    Write-Host "Teardown complete: no EC2 deployment resources remain (nothing to remove)." -ForegroundColor Green
}
else {
    Write-Host "Teardown complete: no EC2 deployment resources remain." -ForegroundColor Green
}
exit 0
