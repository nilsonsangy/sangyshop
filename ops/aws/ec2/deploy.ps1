<#
.SYNOPSIS
    Deploy the VULNERABLE SangyShop on AWS EC2 + RDS PostgreSQL (Deploy_EC2, lab 24).

.DESCRIPTION
    Provisions the incident-response lab environment in a single region (us-east-1
    by default), in this order. Every external CLI call is echoed before it runs
    (shared Invoke-Echoed helper in ops/lib/Common.ps1, via Invoke-Cli below).

        1. Auth check ('aws sts get-caller-identity')
        2. Network: VPC, internet gateway, 1 public + 2 private subnets, route
           table, and a dedicated NACL on the public subnet (the detection stack
           later adds DENY entries to it)
        3. Security groups: instance SG (app port 3000 from the allowed /32 ONLY),
           database SG (5432 from the instance SG ONLY, no CIDR rule)
        4. IAM: role 'sangyshop-ec2-role' + instance profile (S3 app bucket RW,
           secretsmanager:GetSecretValue on the DB secret, CloudWatch Logs,
           AmazonSSMManagedInstanceCore)
        5. S3 application bucket (Block Public Access on)
        6. Secrets Manager secret holding a generated 32-char DB password
        7. RDS PostgreSQL (private subnets, not publicly accessible)
        8. Optional CodeCommit repository (-Repo codecommit; GitHub otherwise)
        9. EC2 instance (IMDSv2 required, hop limit 2, no key pair, SSM access)
           running the userdata.sh.tpl template: Docker, awslogs log driver,
           /lab volume, APP_MODE=vulnerable, DB_BACKEND=pg

    Every resource carries the lab tags (lab, run-id, component) built by
    Get-LabTags, and is also recorded in the Manifesto_Lab through
    Add-LabManifestEntry (a JSON file outside the repository).

    Safety:
      * -AllowedSourceRanges is REQUIRED and must be single IPv4 hosts in /32
        form. 0.0.0.0/0, ::/0, missing values and any non-/32 range stop the
        script (exit 1, message on stderr) BEFORE any external command runs.
      * The DB password is never written to a versioned file, a log, or an echoed
        command line. It reaches the CLI only through a transient file:// temp
        file that is wiped afterwards.
      * -WhatIf prints the ordered command list and executes NO external command,
        creates no resource and writes no manifest entry, then exits 0.
      * If any creation fails the script exits non-zero, names the failed resource
        on stderr and lists the resources already created (remove them with
        teardown.ps1).

    Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1 (default: ops/cloud.config.ps1). Needs Aws.Region,
    Aws.AccountId and the Aws.Ec2 section (InstanceType, DbInstanceClass,
    BucketBase, VolumeGb).

.PARAMETER AllowedSourceRanges
    REQUIRED. One or more single-host IPv4 CIDRs (for example 203.0.113.10/32)
    allowed to reach the application port.

.PARAMETER WhatIf
    Dry run. Print the planned command list, execute nothing, exit 0.

.PARAMETER RunId
    Run identifier (yyyyMMddTHHmmssZ-xxxx) used in the run-id tag. Default: New-RunId.

.PARAMETER Repo
    Where the instance fetches the SangyShop code: 'github' (default) or
    'codecommit'. If the CodeCommit repository cannot be created the script falls
    back to GitHub once, without retrying.

.PARAMETER NoLabMode
    Do not set LAB_MODE=1 (disables the lab marker and /debug/config routes).

.EXAMPLE
    .\deploy.ps1 -AllowedSourceRanges 203.0.113.10/32 -WhatIf

.EXAMPLE
    .\deploy.ps1 -AllowedSourceRanges 203.0.113.10/32 -Repo codecommit
#>
[CmdletBinding()]
param(
    [string]   $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [string[]] $AllowedSourceRanges,
    [switch]   $WhatIf,
    [string]   $RunId,
    [ValidateSet('github', 'codecommit')]
    [string]   $Repo = 'github',
    [switch]   $NoLabMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0
$script:LastExisted     = $false
$script:CurrentResource = 'startup'
$script:Created         = New-Object System.Collections.Generic.List[string]
$script:TempFiles       = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# WhatIf-aware command runner. Every external CLI call goes through Invoke-Cli.
# ---------------------------------------------------------------------------
function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
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

    if ($AllowFail) { $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail) }
    else            { $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs) }
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

# Transient file for file:// arguments (policies, user-data, password).
function New-TempFile {
    param([string] $Content, [string] $Extension = '.tmp')
    if ($WhatIf) { return '<temp-file>' }
    $p = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + $Extension))
    [System.IO.File]::WriteAllText($p, $Content, (New-Object System.Text.UTF8Encoding($false)))
    $script:TempFiles.Add($p)
    return $p
}

function Remove-TempFiles {
    foreach ($p in $script:TempFiles) {
        if (Test-Path -LiteralPath $p) {
            try {
                $len = (Get-Item -LiteralPath $p).Length
                if ($len -gt 0) { [System.IO.File]::WriteAllBytes($p, (New-Object byte[] $len)) }
            }
            catch { }
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
    $script:TempFiles.Clear()
}

# ---------------------------------------------------------------------------
# 0. Validate the allowed source set BEFORE anything else (no external command
#    has run yet). Assert-AllowedSource32 rejects empty, 0.0.0.0/0, ::/0 and
#    anything that is not a strict single-host IPv4 /32.
# ---------------------------------------------------------------------------
try {
    Write-Step "Validating allowed ingress source set (/32 only)"
    $ranges = @()
    if ($AllowedSourceRanges) {
        $ranges = @($AllowedSourceRanges | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    }
    if ($ranges.Count -eq 0) {
        throw "-AllowedSourceRanges is required. Expected one or more single-host IPv4 CIDRs in /32 form, for example 203.0.113.10/32. Open-to-internet sources (0.0.0.0/0, ::/0) are forbidden."
    }
    foreach ($r in $ranges) {
        if ($r -ceq '0.0.0.0/0' -or $r -ceq '::/0') {
            throw "Forbidden source '$r': a source open to the internet is not allowed. Expected a single-host IPv4 CIDR in /32 form, for example 203.0.113.10/32."
        }
    }
    Assert-AllowedSource32 -Ranges $ranges
}
catch {
    Write-StderrLine "ERROR: $($_.Exception.Message)"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = New-RunId }

$exitCode = 0
try {
    # -----------------------------------------------------------------------
    # 1. Load + validate config.
    # -----------------------------------------------------------------------
    Write-Step "Loading configuration (cloud: Aws, modality: ec2)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws' -Modality 'ec2'

    $region    = [string]$cfg.Aws.Region
    $accountId = [string]$cfg.Aws.AccountId
    $suffix    = [string]$cfg.UniqueSuffix
    $appName   = [string]$cfg.Common.AppName
    $dbName    = [string]$cfg.Common.DbName
    $dbUser    = [string]$cfg.Common.DbUser
    $ec2Cfg    = $cfg.Aws.Ec2
    $instType  = [string]$ec2Cfg.InstanceType
    $dbClass   = [string]$ec2Cfg.DbInstanceClass
    $volumeGb  = [string]$ec2Cfg.VolumeGb

    # Derived names (teardown.ps1, stop-lab.ps1 and start-lab.ps1 mirror these).
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
    $bucket      = ([string]$ec2Cfg.BucketBase + '-' + $suffix)
    $secretName  = "$appName/ec2/db_password"
    $dbSubnetGrp = "$prefix-db-subnets"
    $rdsId       = "$prefix-pg"
    $ec2Name     = "$prefix-ec2"
    $logGroup    = '/sangyshop/app'
    $repoName    = $appName
    $appPort     = '3000'
    $dbPort      = '5432'
    $vpcCidr     = '10.20.0.0/16'
    $pubCidr     = '10.20.1.0/24'
    $privACidr   = '10.20.2.0/24'
    $privBCidr   = '10.20.3.0/24'
    $azA         = "${region}a"
    $azB         = "${region}b"
    $githubUrl   = 'https://github.com/nilsonsangy/sangyshop.git'

    $labTags = Get-LabTags -Lab $lab -RunId $RunId -Component 'deploy'
    $rg      = @('--region', $region)

    # Tag helpers.
    function Get-TagSpec {
        param([string] $ResourceType, [string] $Name)
        $pairs = @("{Key=Name,Value=$Name}")
        foreach ($k in $labTags.Keys) { $pairs += "{Key=$k,Value=$($labTags[$k])}" }
        return "ResourceType=$ResourceType,Tags=[" + ($pairs -join ',') + "]"
    }
    function Get-TagPairs {
        $pairs = @()
        foreach ($k in $labTags.Keys) { $pairs += "Key=$k,Value=$($labTags[$k])" }
        return $pairs
    }
    function Get-TagFilters {
        param([string] $Name)
        return @('--filters', "Name=tag:Name,Values=$Name", "Name=tag:lab,Values=$lab")
    }

    # Manifest helper (skipped under -WhatIf: a dry run writes nothing).
    function Register-LabResource {
        param([string] $Type, [string] $Id, [string] $Component = 'deploy',
              [string] $DelService, [string] $DelAction, [string] $DelArg, [string] $Extra)
        if ([string]::IsNullOrWhiteSpace($Id)) { return }
        if ($WhatIf) {
            Write-Host "  [manifest] would record $Type $Id" -ForegroundColor DarkGray
            return
        }
        $hint = $null
        if ($DelService) {
            $hint = @{ service = $DelService; action = $DelAction; args = @{ $DelArg = $Id } }
        }
        $p = @{ Type = $Type; Id = $Id; Region = $region; RunId = $RunId; Component = $Component; Lab = $lab }
        if ($hint) { $p['DeleteHint'] = $hint }
        Add-LabManifestEntry @p
    }

    # Describe-or-create. Returns the resource id (placeholder under -WhatIf).
    function Initialize-LabResource {
        param(
            [Parameter(Mandatory)][string]   $Type,
            [Parameter(Mandatory)][string]   $Name,
            [Parameter(Mandatory)][string[]] $FindArgs,
            [Parameter(Mandatory)][string[]] $CreateArgs,
            [string] $Placeholder = '<id>',
            [string] $KnownId,
            [string] $DelService, [string] $DelAction, [string] $DelArg
        )
        $script:CurrentResource = "$Type '$Name'"
        $script:LastExisted = $false
        $id = $null

        $found = Invoke-Cli -Exe 'aws' -CmdArgs $FindArgs -AllowFail
        if (-not $WhatIf -and $script:LastCliExit -eq 0) {
            $s = Get-Scalar $found
            if ($KnownId) { $id = $KnownId }
            elseif ($s -and $s -ne 'None') { $id = $s }
        }

        if ($id) {
            $script:LastExisted = $true
            Write-Host "  reusing existing $Type '$Name' ($id)" -ForegroundColor DarkGray
        }
        else {
            $out = Invoke-Cli -Exe 'aws' -CmdArgs $CreateArgs
            if ($WhatIf) {
                $id = if ($KnownId) { $KnownId } else { $Placeholder }
            }
            else {
                $id = if ($KnownId) { $KnownId } else { Get-Scalar $out }
                if ([string]::IsNullOrWhiteSpace($id) -or $id -eq 'None') {
                    throw "Creation of $Type '$Name' returned no identifier."
                }
                $script:Created.Add("$Type $id")
            }
        }
        Register-LabResource -Type $Type -Id $id -DelService $DelService -DelAction $DelAction -DelArg $DelArg
        return $id
    }

    if ($WhatIf) {
        Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
    }
    Write-Host "Run id: $RunId   Region: $region   Repo: $Repo"

    # -----------------------------------------------------------------------
    # Auth check.
    # -----------------------------------------------------------------------
    $script:CurrentResource = 'AWS authentication'
    Write-Step "Checking AWS authentication via sts get-caller-identity"
    try {
        Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
    }
    catch {
        throw ("AWS authentication/CLI check failed: $($_.Exception.Message) " +
               "Install the AWS CLI v2 (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) " +
               "and authenticate as the lab operator ('aws configure' or 'aws sso login').")
    }

    # -----------------------------------------------------------------------
    # 2. Network.
    # -----------------------------------------------------------------------
    Write-Step "Network: VPC '$vpcName' ($vpcCidr)"
    $vpcId = Initialize-LabResource -Type 'vpc' -Name $vpcName -Placeholder '<vpc-id>' `
        -DelService 'ec2' -DelAction 'delete-vpc' -DelArg 'VpcId' `
        -FindArgs (@('ec2', 'describe-vpcs') + $rg + (Get-TagFilters $vpcName) + @('--query', 'Vpcs[0].VpcId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-vpc') + $rg + @('--cidr-block', $vpcCidr, '--tag-specifications', (Get-TagSpec 'vpc' $vpcName), '--query', 'Vpc.VpcId', '--output', 'text'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'modify-vpc-attribute') + $rg + @('--vpc-id', $vpcId, '--enable-dns-hostnames', 'Value=true')) | Out-Null

    Write-Step "Network: internet gateway '$igwName'"
    $igwId = Initialize-LabResource -Type 'internet-gateway' -Name $igwName -Placeholder '<igw-id>' `
        -DelService 'ec2' -DelAction 'delete-internet-gateway' -DelArg 'InternetGatewayId' `
        -FindArgs (@('ec2', 'describe-internet-gateways') + $rg + (Get-TagFilters $igwName) + @('--query', 'InternetGateways[0].InternetGatewayId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-internet-gateway') + $rg + @('--tag-specifications', (Get-TagSpec 'internet-gateway' $igwName), '--query', 'InternetGateway.InternetGatewayId', '--output', 'text'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'attach-internet-gateway') + $rg + @('--internet-gateway-id', $igwId, '--vpc-id', $vpcId)) -AllowFail | Out-Null

    Write-Step "Network: subnets (public + 2 private)"
    $pubSubnet = Initialize-LabResource -Type 'subnet' -Name $pubName -Placeholder '<public-subnet-id>' `
        -DelService 'ec2' -DelAction 'delete-subnet' -DelArg 'SubnetId' `
        -FindArgs (@('ec2', 'describe-subnets') + $rg + (Get-TagFilters $pubName) + @('--query', 'Subnets[0].SubnetId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-subnet') + $rg + @('--vpc-id', $vpcId, '--cidr-block', $pubCidr, '--availability-zone', $azA, '--tag-specifications', (Get-TagSpec 'subnet' $pubName), '--query', 'Subnet.SubnetId', '--output', 'text'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'modify-subnet-attribute') + $rg + @('--subnet-id', $pubSubnet, '--map-public-ip-on-launch')) | Out-Null
    $privASubnet = Initialize-LabResource -Type 'subnet' -Name $privAName -Placeholder '<private-subnet-a-id>' `
        -DelService 'ec2' -DelAction 'delete-subnet' -DelArg 'SubnetId' `
        -FindArgs (@('ec2', 'describe-subnets') + $rg + (Get-TagFilters $privAName) + @('--query', 'Subnets[0].SubnetId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-subnet') + $rg + @('--vpc-id', $vpcId, '--cidr-block', $privACidr, '--availability-zone', $azA, '--tag-specifications', (Get-TagSpec 'subnet' $privAName), '--query', 'Subnet.SubnetId', '--output', 'text'))
    $privBSubnet = Initialize-LabResource -Type 'subnet' -Name $privBName -Placeholder '<private-subnet-b-id>' `
        -DelService 'ec2' -DelAction 'delete-subnet' -DelArg 'SubnetId' `
        -FindArgs (@('ec2', 'describe-subnets') + $rg + (Get-TagFilters $privBName) + @('--query', 'Subnets[0].SubnetId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-subnet') + $rg + @('--vpc-id', $vpcId, '--cidr-block', $privBCidr, '--availability-zone', $azB, '--tag-specifications', (Get-TagSpec 'subnet' $privBName), '--query', 'Subnet.SubnetId', '--output', 'text'))

    Write-Step "Network: public route table '$rtName'"
    $rtId = Initialize-LabResource -Type 'route-table' -Name $rtName -Placeholder '<route-table-id>' `
        -DelService 'ec2' -DelAction 'delete-route-table' -DelArg 'RouteTableId' `
        -FindArgs (@('ec2', 'describe-route-tables') + $rg + (Get-TagFilters $rtName) + @('--query', 'RouteTables[0].RouteTableId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-route-table') + $rg + @('--vpc-id', $vpcId, '--tag-specifications', (Get-TagSpec 'route-table' $rtName), '--query', 'RouteTable.RouteTableId', '--output', 'text'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'create-route') + $rg + @('--route-table-id', $rtId, '--destination-cidr-block', '0.0.0.0/0', '--gateway-id', $igwId)) -AllowFail | Out-Null
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'associate-route-table') + $rg + @('--route-table-id', $rtId, '--subnet-id', $pubSubnet)) -AllowFail | Out-Null

    Write-Step "Network: dedicated NACL '$naclName' on the public subnet"
    $naclId = Initialize-LabResource -Type 'network-acl' -Name $naclName -Placeholder '<nacl-id>' `
        -DelService 'ec2' -DelAction 'delete-network-acl' -DelArg 'NetworkAclId' `
        -FindArgs (@('ec2', 'describe-network-acls') + $rg + (Get-TagFilters $naclName) + @('--query', 'NetworkAcls[0].NetworkAclId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-network-acl') + $rg + @('--vpc-id', $vpcId, '--tag-specifications', (Get-TagSpec 'network-acl' $naclName), '--query', 'NetworkAcl.NetworkAclId', '--output', 'text'))
    # Rule 900 allows traffic so the Security Group stays the real ingress control.
    # Rules 1-899 are reserved for the DENY entries added by the lab's blocker.
    foreach ($dir in @('ingress', 'egress')) {
        $dirFlag = if ($dir -eq 'egress') { '--egress' } else { '--ingress' }
        Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'create-network-acl-entry') + $rg + @('--network-acl-id', $naclId, '--rule-number', '900', '--protocol', '-1', '--rule-action', 'allow', '--cidr-block', '0.0.0.0/0', $dirFlag)) -AllowFail | Out-Null
        Register-LabResource -Type 'nacl-entry' -Id "$naclId/$dir/900"
    }
    $assocQuery = 'NetworkAcls[0].Associations[?SubnetId==`' + $pubSubnet + '`].NetworkAclAssociationId | [0]'
    $assocOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'describe-network-acls') + $rg + @('--filters', "Name=association.subnet-id,Values=$pubSubnet", '--query', $assocQuery, '--output', 'text'))
    $assocId = if ($WhatIf) { '<nacl-association-id>' } else { Get-Scalar $assocOut }
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'replace-network-acl-association') + $rg + @('--association-id', $assocId, '--network-acl-id', $naclId)) | Out-Null

    # -----------------------------------------------------------------------
    # 3. Security groups.
    # -----------------------------------------------------------------------
    Write-Step "Security group '$appSgName': port $appPort from $($ranges -join ', ') only"
    $appSgId = Initialize-LabResource -Type 'security-group' -Name $appSgName -Placeholder '<app-sg-id>' `
        -DelService 'ec2' -DelAction 'delete-security-group' -DelArg 'GroupId' `
        -FindArgs (@('ec2', 'describe-security-groups') + $rg + @('--filters', "Name=group-name,Values=$appSgName", "Name=vpc-id,Values=$vpcId", '--query', 'SecurityGroups[0].GroupId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-security-group') + $rg + @('--group-name', $appSgName, '--description', 'SangyShop lab instance: app port from allowed /32 only', '--vpc-id', $vpcId, '--tag-specifications', (Get-TagSpec 'security-group' $appSgName), '--query', 'GroupId', '--output', 'text'))
    foreach ($r in $ranges) {
        Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'authorize-security-group-ingress') + $rg + @('--group-id', $appSgId, '--protocol', 'tcp', '--port', $appPort, '--cidr', $r)) -AllowFail | Out-Null
    }

    Write-Step "Security group '$dbSgName': PostgreSQL $dbPort from the instance SG only"
    $dbSgId = Initialize-LabResource -Type 'security-group' -Name $dbSgName -Placeholder '<db-sg-id>' `
        -DelService 'ec2' -DelAction 'delete-security-group' -DelArg 'GroupId' `
        -FindArgs (@('ec2', 'describe-security-groups') + $rg + @('--filters', "Name=group-name,Values=$dbSgName", "Name=vpc-id,Values=$vpcId", '--query', 'SecurityGroups[0].GroupId', '--output', 'text')) `
        -CreateArgs (@('ec2', 'create-security-group') + $rg + @('--group-name', $dbSgName, '--description', 'SangyShop lab database: 5432 from the instance SG only', '--vpc-id', $vpcId, '--tag-specifications', (Get-TagSpec 'security-group' $dbSgName), '--query', 'GroupId', '--output', 'text'))
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'authorize-security-group-ingress') + $rg + @('--group-id', $dbSgId, '--protocol', 'tcp', '--port', $dbPort, '--source-group', $appSgId)) -AllowFail | Out-Null

    # -----------------------------------------------------------------------
    # 4. IAM role + instance profile.
    # -----------------------------------------------------------------------
    Write-Step "IAM: role '$roleName' and instance profile '$profileName'"
    $trust = [ordered]@{
        Version   = '2012-10-17'
        Statement = @([ordered]@{ Effect = 'Allow'; Principal = [ordered]@{ Service = 'ec2.amazonaws.com' }; Action = 'sts:AssumeRole' })
    }
    $secretArnPattern = "arn:aws:secretsmanager:${region}:${accountId}:secret:${secretName}-*"
    $statements = @(
        [ordered]@{ Sid = 'AppBucketRw'; Effect = 'Allow'; Action = @('s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:ListBucket'); Resource = @("arn:aws:s3:::$bucket", "arn:aws:s3:::$bucket/*") },
        [ordered]@{ Sid = 'ReadDbSecret'; Effect = 'Allow'; Action = 'secretsmanager:GetSecretValue'; Resource = $secretArnPattern },
        [ordered]@{ Sid = 'AppLogs'; Effect = 'Allow'; Action = @('logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents', 'logs:DescribeLogStreams'); Resource = @("arn:aws:logs:${region}:${accountId}:log-group:${logGroup}", "arn:aws:logs:${region}:${accountId}:log-group:${logGroup}:*") }
    )
    if ($Repo -eq 'codecommit') {
        $statements += [ordered]@{ Sid = 'CodeCommitPull'; Effect = 'Allow'; Action = 'codecommit:GitPull'; Resource = "arn:aws:codecommit:${region}:${accountId}:${repoName}" }
    }
    $policy = [ordered]@{ Version = '2012-10-17'; Statement = $statements }

    $trustFile  = New-TempFile -Content ($trust  | ConvertTo-Json -Depth 8) -Extension '.json'
    $policyFile = New-TempFile -Content ($policy | ConvertTo-Json -Depth 8) -Extension '.json'

    $null = Initialize-LabResource -Type 'iam-role' -Name $roleName -KnownId $roleName `
        -DelService 'iam' -DelAction 'delete-role' -DelArg 'RoleName' `
        -FindArgs @('iam', 'get-role', '--role-name', $roleName, '--query', 'Role.RoleName', '--output', 'text') `
        -CreateArgs (@('iam', 'create-role', '--role-name', $roleName, '--assume-role-policy-document', ('file://' + $trustFile), '--description', 'SangyShop lab EC2 role', '--tags') + (Get-TagPairs))
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'put-role-policy', '--role-name', $roleName, '--policy-name', 'sangyshop-ec2-inline', '--policy-document', ('file://' + $policyFile)) | Out-Null
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'attach-role-policy', '--role-name', $roleName, '--policy-arn', 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore') | Out-Null
    $null = Initialize-LabResource -Type 'instance-profile' -Name $profileName -KnownId $profileName `
        -DelService 'iam' -DelAction 'delete-instance-profile' -DelArg 'InstanceProfileName' `
        -FindArgs @('iam', 'get-instance-profile', '--instance-profile-name', $profileName, '--query', 'InstanceProfile.InstanceProfileName', '--output', 'text') `
        -CreateArgs (@('iam', 'create-instance-profile', '--instance-profile-name', $profileName, '--tags') + (Get-TagPairs))
    Invoke-Cli -Exe 'aws' -CmdArgs @('iam', 'add-role-to-instance-profile', '--instance-profile-name', $profileName, '--role-name', $roleName) -AllowFail | Out-Null
    if (-not $WhatIf) {
        Write-Host "Waiting 15 s for IAM propagation..."
        Start-Sleep -Seconds 15
    }

    # -----------------------------------------------------------------------
    # 5. S3 application bucket.
    # -----------------------------------------------------------------------
    Write-Step "S3: application bucket '$bucket' (Block Public Access on)"
    $bucketArgs = @('s3api', 'create-bucket') + $rg + @('--bucket', $bucket)
    if ($region -ne 'us-east-1') { $bucketArgs += @('--create-bucket-configuration', "LocationConstraint=$region") }
    $null = Initialize-LabResource -Type 's3-bucket' -Name $bucket -KnownId $bucket `
        -DelService 's3api' -DelAction 'delete-bucket' -DelArg 'Bucket' `
        -FindArgs (@('s3api', 'head-bucket') + $rg + @('--bucket', $bucket)) `
        -CreateArgs $bucketArgs
    Invoke-Cli -Exe 'aws' -CmdArgs (@('s3api', 'put-public-access-block') + $rg + @('--bucket', $bucket, '--public-access-block-configuration', 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true')) | Out-Null
    $tagSet = @()
    foreach ($k in $labTags.Keys) { $tagSet += "{Key=$k,Value=$($labTags[$k])}" }
    Invoke-Cli -Exe 'aws' -CmdArgs (@('s3api', 'put-bucket-tagging') + $rg + @('--bucket', $bucket, '--tagging', ('TagSet=[' + ($tagSet -join ',') + ']'))) | Out-Null

    # -----------------------------------------------------------------------
    # 6. Secrets Manager secret (generated password, 32 chars).
    # -----------------------------------------------------------------------
    Write-Step "Secrets Manager: '$secretName' (password generated, never echoed)"
    $dbPassword = if ($WhatIf) { '<generated-at-deploy-time>' } else { New-DbPassword -Length 32 }
    $pwFile = New-TempFile -Content $dbPassword
    $pwRef  = 'file://' + $(if ($WhatIf) { '<temp-file: db password (redacted)>' } else { $pwFile })
    $secretArn = Initialize-LabResource -Type 'secret' -Name $secretName -Placeholder "arn:aws:secretsmanager:${region}:${accountId}:secret:${secretName}-AbCdEf" `
        -DelService 'secretsmanager' -DelAction 'delete-secret' -DelArg 'SecretId' `
        -FindArgs (@('secretsmanager', 'describe-secret') + $rg + @('--secret-id', $secretName, '--query', 'ARN', '--output', 'text')) `
        -CreateArgs (@('secretsmanager', 'create-secret') + $rg + @('--name', $secretName, '--description', 'SangyShop lab DB password', '--secret-string', $pwRef, '--query', 'ARN', '--output', 'text', '--tags') + (Get-TagPairs))
    if ($script:LastExisted) {
        Invoke-Cli -Exe 'aws' -CmdArgs (@('secretsmanager', 'put-secret-value') + $rg + @('--secret-id', $secretName, '--secret-string', $pwRef)) | Out-Null
    }

    # -----------------------------------------------------------------------
    # 7. RDS PostgreSQL.
    # -----------------------------------------------------------------------
    Write-Step "RDS: subnet group '$dbSubnetGrp' and instance '$rdsId' ($dbClass)"
    $null = Initialize-LabResource -Type 'db-subnet-group' -Name $dbSubnetGrp -KnownId $dbSubnetGrp `
        -DelService 'rds' -DelAction 'delete-db-subnet-group' -DelArg 'DBSubnetGroupName' `
        -FindArgs (@('rds', 'describe-db-subnet-groups') + $rg + @('--db-subnet-group-name', $dbSubnetGrp, '--query', 'DBSubnetGroups[0].DBSubnetGroupName', '--output', 'text')) `
        -CreateArgs (@('rds', 'create-db-subnet-group') + $rg + @('--db-subnet-group-name', $dbSubnetGrp, '--db-subnet-group-description', 'SangyShop lab private subnets', '--subnet-ids', $privASubnet, $privBSubnet, '--tags') + (Get-TagPairs))

    $null = Initialize-LabResource -Type 'rds-instance' -Name $rdsId -KnownId $rdsId `
        -DelService 'rds' -DelAction 'delete-db-instance' -DelArg 'DBInstanceIdentifier' `
        -FindArgs (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].DBInstanceIdentifier', '--output', 'text')) `
        -CreateArgs (@('rds', 'create-db-instance') + $rg + @(
            '--db-instance-identifier', $rdsId,
            '--engine', 'postgres',
            '--db-instance-class', $dbClass,
            '--allocated-storage', '20',
            '--storage-type', 'gp3',
            '--db-name', $dbName,
            '--master-username', $dbUser,
            '--master-user-password', $pwRef,
            '--port', $dbPort,
            '--db-subnet-group-name', $dbSubnetGrp,
            '--vpc-security-group-ids', $dbSgId,
            '--no-publicly-accessible',
            '--no-multi-az',
            '--backup-retention-period', '0',
            '--tags') + (Get-TagPairs))
    if ($script:LastExisted) {
        # Re-assert the master password from the stored secret.
        Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'modify-db-instance') + $rg + @('--db-instance-identifier', $rdsId, '--master-user-password', $pwRef, '--vpc-security-group-ids', $dbSgId, '--apply-immediately')) | Out-Null
    }
    Write-Step "Waiting for RDS instance '$rdsId' to be available"
    Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'wait', 'db-instance-available') + $rg + @('--db-instance-identifier', $rdsId)) | Out-Null
    $dbEndpointOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('rds', 'describe-db-instances') + $rg + @('--db-instance-identifier', $rdsId, '--query', 'DBInstances[0].Endpoint.Address', '--output', 'text'))
    $dbHost = if ($WhatIf) { "$rdsId.<rds-endpoint>.$region.rds.amazonaws.com" } else { Get-Scalar $dbEndpointOut }

    # -----------------------------------------------------------------------
    # 8. Code repository.
    # -----------------------------------------------------------------------
    $repoKind = 'github'
    $repoUrl  = $githubUrl
    if ($Repo -eq 'codecommit') {
        Write-Step "CodeCommit: repository '$repoName'"
        try {
            $null = Initialize-LabResource -Type 'codecommit-repo' -Name $repoName -KnownId $repoName `
                -DelService 'codecommit' -DelAction 'delete-repository' -DelArg 'repositoryName' `
                -FindArgs (@('codecommit', 'get-repository') + $rg + @('--repository-name', $repoName, '--query', 'repositoryMetadata.repositoryName', '--output', 'text')) `
                -CreateArgs (@('codecommit', 'create-repository') + $rg + @('--repository-name', $repoName, '--repository-description', 'SangyShop lab code', '--tags', ((Get-TagPairs | ForEach-Object { ($_ -replace '^Key=', '') -replace ',Value=', '=' }) -join ',')))
            $repoKind = 'codecommit'
            $repoUrl  = "https://git-codecommit.$region.amazonaws.com/v1/repos/$repoName"
            Write-Host "NOTE: push the SangyShop code to '$repoName' BEFORE the instance boots, or the clone on the instance will find an empty repository." -ForegroundColor Yellow
        }
        catch {
            Write-Warning "CodeCommit repository could not be created ($($_.Exception.Message)). Falling back to GitHub ($githubUrl); not retrying."
        }
    }

    # -----------------------------------------------------------------------
    # 9. EC2 instance with the rendered user-data.
    # -----------------------------------------------------------------------
    Write-Step "EC2: instance '$ec2Name' ($instType, IMDSv2 required, hop limit 2)"
    $tplPath = Join-Path $PSScriptRoot 'userdata.sh.tpl'
    if (-not (Test-Path -LiteralPath $tplPath -PathType Leaf)) {
        throw "User-data template not found at '$tplPath'."
    }
    $tpl = [System.IO.File]::ReadAllText($tplPath)
    $labModeValue = if ($NoLabMode) { '0' } else { '1' }
    $tokens = [ordered]@{
        '@@REGION@@'    = $region
        '@@REPO_KIND@@' = $repoKind
        '@@REPO_URL@@'  = $repoUrl
        '@@SECRET_ID@@' = $secretName
        '@@DB_HOST@@'   = $dbHost
        '@@DB_NAME@@'   = $dbName
        '@@DB_USER@@'   = $dbUser
        '@@S3_BUCKET@@' = $bucket
        '@@LOG_GROUP@@' = $logGroup
        '@@LAB_MODE@@'  = $labModeValue
    }
    $userData = $tpl
    foreach ($k in $tokens.Keys) { $userData = $userData.Replace($k, [string]$tokens[$k]) }
    $userData = $userData -replace "`r`n", "`n"
    if ($userData -match '@@[A-Z_]+@@') {
        # Only the documentation lines of the header may mention @@TOKEN@@ literally.
        $left = [regex]::Matches($userData, '(?m)^[^#\r\n].*@@[A-Z_]+@@') | ForEach-Object { $_.Value }
        if ($left) { throw "Unreplaced placeholder(s) in user-data template: $($left -join '; ')" }
    }
    $udFile = New-TempFile -Content $userData -Extension '.sh'

    $amiOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('ssm', 'get-parameter') + $rg + @('--name', '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64', '--query', 'Parameter.Value', '--output', 'text'))
    $amiId = if ($WhatIf) { '<al2023-ami-id>' } else { Get-Scalar $amiOut }

    $runArgs = @('ec2', 'run-instances') + $rg + @(
        '--image-id', $amiId,
        '--instance-type', $instType,
        '--count', '1',
        '--subnet-id', $pubSubnet,
        '--security-group-ids', $appSgId,
        '--iam-instance-profile', "Name=$profileName",
        '--metadata-options', 'HttpTokens=required,HttpPutResponseHopLimit=2,HttpEndpoint=enabled',
        '--block-device-mappings', "DeviceName=/dev/xvda,Ebs={VolumeSize=$volumeGb,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}",
        '--user-data', ('file://' + $udFile),
        '--tag-specifications', (Get-TagSpec 'instance' $ec2Name), (Get-TagSpec 'volume' "$ec2Name-root"),
        '--query', 'Instances[0].InstanceId', '--output', 'text')
    $instanceId = Initialize-LabResource -Type 'ec2-instance' -Name $ec2Name -Placeholder '<instance-id>' `
        -DelService 'ec2' -DelAction 'terminate-instances' -DelArg 'InstanceIds' `
        -FindArgs (@('ec2', 'describe-instances') + $rg + (Get-TagFilters $ec2Name) + @('Name=instance-state-name,Values=pending,running,stopping,stopped', '--query', 'Reservations[0].Instances[0].InstanceId', '--output', 'text')) `
        -CreateArgs $runArgs
    Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'wait', 'instance-running') + $rg + @('--instance-ids', $instanceId)) | Out-Null
    $ipOut = Invoke-Cli -Exe 'aws' -CmdArgs (@('ec2', 'describe-instances') + $rg + @('--instance-ids', $instanceId, '--query', 'Reservations[0].Instances[0].PublicIpAddress', '--output', 'text'))
    $publicIp = if ($WhatIf) { '<instance-public-ip>' } else { Get-Scalar $ipOut }

    # -----------------------------------------------------------------------
    # Dry run ends here.
    # -----------------------------------------------------------------------
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

    Write-Host ""
    Write-Step "Deployment complete (run id $RunId)"
    Write-Host "Application URL: http://${publicIp}:$appPort   (first boot takes a few minutes: Docker install + image build)"
    Write-Host "Access: AWS Systems Manager Session Manager (no SSH port is open)."
    Write-Host ""
    Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
    Write-Host "  * SangyShop is DELIBERATELY VULNERABLE. Use an isolated, throwaway AWS account only." -ForegroundColor Yellow
    Write-Host "  * Ingress to port $appPort is limited to: $($ranges -join ', ')." -ForegroundColor Yellow
    Write-Host "  * Stop the lab at the end of each day: ops/aws/ec2/stop-lab.ps1" -ForegroundColor Yellow
    Write-Host "  * REMOVE EVERYTHING WHEN FINISHED: ops/aws/ec2/teardown.ps1" -ForegroundColor Yellow
}
catch {
    $exitCode = 1
    Write-StderrLine "ERROR: failed to create resource: $($script:CurrentResource)"
    Write-StderrLine "Reason: $($_.Exception.Message)"
    if ($script:Created.Count -gt 0) {
        Write-StderrLine "Resources already created (remove them with ops/aws/ec2/teardown.ps1):"
        foreach ($c in $script:Created) { Write-StderrLine "  - $c" }
    }
    else {
        Write-StderrLine "No resources had been created yet."
    }
}
finally {
    Remove-TempFiles
}

exit $exitCode
