<#
.SYNOPSIS
    Deploys the VULNERABLE SangyShop variant to an Azure VM (Azure VM deployment) for the
    Azure incident-response lab.

.DESCRIPTION
    Creates, inside the lab resource group (lab resource group), in this order:

      1. Validates -AllowedSourceRanges (single IPv4 /32 only) BEFORE anything else.
      2. Checks `az account show` (fail-closed) and prints the active subscription.
      3. Lab and Evidence resource groups (both carry the lab tag).
      4. Virtual network, subnet, Network Security Group (app port + SSH only from
         the allowed /32 ranges) and a static public IP.
      5. User-assigned managed identity for the VM.
      6. Key Vault (Azure RBAC mode) and the generated DB password (>= 20 chars,
         32 by default) stored ONLY there.
      7. Azure Database for PostgreSQL Flexible Server (firewall: the VM IP only).
      8. Storage Account (no shared-key access) and the app Blob container.
      9. Azure RBAC for the managed identity: Storage Blob Data Contributor on the
         container, Key Vault Secrets User on the vault.
     10. Log Analytics workspace, custom table SangyShopApp_CL and the Data
         Collection Rule (DCR) for the app log file.
     11. The VM (Ubuntu, cloud-init from cloud-init.yaml.tpl: Docker, SangyShop with
         `--log-driver syslog`, rsyslog), then the Azure Monitor Agent extension and
         the DCR association.

    Every external CLI call goes through Invoke-Echoed (echo-before-exec). The DB
    password is NEVER passed as a CLI argument, echoed, logged or committed: it
    travels to Key Vault / PostgreSQL by file (`--file`, `@file`) and the VM reads it
    from Key Vault at boot with its managed identity.

    Every resource that accepts tags gets the lab_tag (lab, run-id, component) and
    EVERY resource is also recorded in the lab_manifest (Add-LabManifestEntry).

    On failure the script exits non-zero, writes (to stderr, in English) the name of
    the resource that failed plus the list of resources already created, and tells
    you to run teardown.ps1.

    SECURITY WARNING: SangyShop is deliberately vulnerable. Use a throwaway
    subscription, keep ingress locked to your own /32 and run teardown.ps1 when done
    (these resources are billable).

    Windows PowerShell 5.1 compatible. No bash/sh is invoked on the operator machine.

.PARAMETER AllowedSourceRanges
    REQUIRED. One or more single-host IPv4 CIDRs in /32 form (e.g. 203.0.113.10/32).
    0.0.0.0/0, ::/0, '*', 'Internet', 'Any', missing values and non-/32 values abort
    the script with a non-zero exit code before any resource is created.

.PARAMETER ConfigPath
    Path to cloud.config.ps1 (needs Azure.Location and the Azure.Vm section).
    Defaults to ops/cloud.config.ps1.

.PARAMETER WhatIf
    Dry run: prints the ordered list of external commands that WOULD run, creates and
    removes nothing, writes no manifest, and exits 0.

.PARAMETER ReuseExisting
    Allow re-running against an existing lab resource group. Without it, deploy
    aborts if the lab resource group already exists.

.PARAMETER RunId
    Run identifier (yyyyMMddTHHmmssZ-xxxx). Defaults to New-RunId.

.PARAMETER Repo
    Where the VM clones the SangyShop source from: 'github' (default) or 'azure-repos'.

.PARAMETER RepoUrl
    Clone URL. Defaults to the public SangyShop GitHub URL when -Repo github.
    REQUIRED when -Repo azure-repos (must be reachable by the VM, no embedded token).

.PARAMETER SshPublicKeyPath
    Optional SSH public key file for the VM admin user. When omitted the Azure CLI
    generates a key pair under ~/.ssh if none exists (--generate-ssh-keys).

.PARAMETER NoLabMode
    Starts the app WITHOUT LAB_MODE=1 (no lab marker / leaked-config routes).

.EXAMPLE
    .\deploy.ps1 -AllowedSourceRanges '203.0.113.10/32'

.EXAMPLE
    .\deploy.ps1 -AllowedSourceRanges '203.0.113.10/32' -WhatIf
#>
[CmdletBinding()]
param(
    [string[]] $AllowedSourceRanges,
    [string]   $ConfigPath,
    [switch]   $WhatIf,
    [switch]   $ReuseExisting,
    [string]   $RunId,
    [ValidateSet('github', 'azure-repos')]
    [string]   $Repo = 'github',
    [string]   $RepoUrl,
    [string]   $SshPublicKeyPath,
    [switch]   $NoLabMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = (Join-Path $scriptDir '..\..\cloud.config.ps1')
}

. (Join-Path $scriptDir '..\..\lib\Common.ps1')
. (Join-Path $scriptDir 'VmNames.ps1')

# =============================================================================
# Single gate for every external command: echo-only in -WhatIf, Invoke-Echoed
# (echo-before-exec) otherwise.
# =============================================================================
$script:PlanOrdinal = 0
function Invoke-Planned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
    )
    if ($WhatIf) {
        $script:PlanOrdinal++
        $display = (@($Exe) + $CmdArgs) -join ' '
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        return $null
    }
    return (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail:$AllowFail)
}
function Az    { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A }
function AzTry { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az' -CmdArgs $A -AllowFail }

# Runs an az query that returns one value. In -WhatIf prints the command and
# returns the placeholder. Ignores stderr/warning records (only string lines count).
function Get-AzValue {
    param([Parameter(Mandatory)][string[]] $CmdArgs, [Parameter(Mandatory)][string] $Placeholder)
    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs | Out-Null
        return $Placeholder
    }
    $out = Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs
    $lines = @($out | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { return '' }
    return ([string]$lines[$lines.Count - 1]).Trim()
}

# Returns $true when `az ... show` succeeds (real run). Always $false in -WhatIf so
# the full create path is listed.
function Test-AzExists {
    param([Parameter(Mandatory)][string[]] $CmdArgs)
    if ($WhatIf) {
        Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs | Out-Null
        return $false
    }
    $null = Invoke-Planned -Exe 'az' -CmdArgs $CmdArgs -AllowFail
    return ($LASTEXITCODE -eq 0)
}

function Write-StdErr { param([string] $Message) [Console]::Error.WriteLine($Message) }

# =============================================================================
# Failure bookkeeping and lab manifest registration.
# =============================================================================
$script:Current = $null
$script:Created = New-Object System.Collections.Generic.List[string]

function Start-Resource { param([Parameter(Mandatory)][string] $Name) $script:Current = $Name }

function Complete-Resource {
    param(
        [Parameter(Mandatory)][string] $Type,
        [Parameter(Mandatory)][string] $Id,
        [string]    $Component = 'deploy',
        [hashtable] $DeleteHint
    )
    $script:Created.Add("$Type $Id")
    $script:Current = $null
    if ($WhatIf) {
        Write-Host ("     [manifest] {0} {1} ({2})" -f $Type, $Id, $Component) -ForegroundColor DarkGray
        return
    }
    $p = @{
        Type      = $Type
        Id        = $Id
        Region    = $script:Location
        RunId     = $RunId
        Component = $Component
        Lab       = $script:VmLabName
    }
    if ($PSBoundParameters.ContainsKey('DeleteHint') -and $null -ne $DeleteHint) { $p['DeleteHint'] = $DeleteHint }
    Add-LabManifestEntry @p
}

function Get-TagArgs {
    param([ValidateSet('deploy', 'detection', 'blocker', 'evidence', 'credential')][string] $Component = 'deploy')
    $t = Get-LabTags -Lab $script:VmLabName -RunId $RunId -Component $Component
    return @($t.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
}

function Wait-Seconds {
    param([int] $Seconds)
    if (-not $WhatIf) { Start-Sleep -Seconds $Seconds }
}

# =============================================================================
# Main
# =============================================================================
$tempFiles = New-Object System.Collections.Generic.List[string]
try {
    # --- 1. Validate the allowed sources BEFORE anything else. ---
    Write-Step "Validating -AllowedSourceRanges (single IPv4 /32 only)"
    # Explicit guard for a missing value: Assert-AllowedSource32 fails with an opaque
    # strict-mode error on $null under Windows PowerShell 5.1.
    if ($null -eq $AllowedSourceRanges -or @($AllowedSourceRanges).Count -eq 0) {
        throw "-AllowedSourceRanges is required. Provide at least one single-host IPv4 CIDR in /32 form (for example 203.0.113.10/32). Sources open to the internet (0.0.0.0/0, ::/0, '*', 'Internet', 'Any') are forbidden."
    }
    Assert-AllowedSource32 -Ranges $AllowedSourceRanges
    $allowed = @($AllowedSourceRanges | ForEach-Object { ([string]$_).Trim() })

    if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = New-RunId }

    Write-Step "Loading and validating configuration (Azure, VM modality)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure' -Modality 'vm'
    $names    = Get-VmLabNames -Config $cfg
    $location = $names['Location']
    $script:Location = $location
    $rg       = $names['LabGroup']
    $rgEv     = $names['EvidenceGroup']
    $common   = $cfg['Common']
    $vmCfg    = $cfg['Azure']['Vm']
    $dbName   = [string]$common['DbName']
    $dbUser   = [string]$common['DbUser']
    $appPort  = [int]$names['AppPort']
    $pgFqdn   = ($names['PgServer'] + '.postgres.database.azure.com')

    # Repo selection (Req design: -Repo github|azure-repos).
    if ([string]::IsNullOrWhiteSpace($RepoUrl)) {
        if ($Repo -eq 'github') { $RepoUrl = 'https://github.com/nilsonsangy/sangyshop' }
        else { throw "-RepoUrl is required with -Repo azure-repos (for example https://dev.azure.com/<org>/<project>/_git/sangyshop)." }
    }
    if ($RepoUrl -match '://[^/@]+@') {
        throw "-RepoUrl must not embed credentials (found user info in the URL). Use a URL the VM can clone without a token."
    }
    if (-not [string]::IsNullOrWhiteSpace($SshPublicKeyPath) -and -not (Test-Path -LiteralPath $SshPublicKeyPath -PathType Leaf)) {
        throw "SSH public key file not found: '$SshPublicKeyPath'."
    }

    $tagDeploy   = Get-TagArgs 'deploy'
    $tagEvidence = Get-TagArgs 'evidence'

    $tplPath = Join-Path $scriptDir 'cloud-init.yaml.tpl'
    if (-not (Test-Path -LiteralPath $tplPath -PathType Leaf)) { throw "cloud-init template not found: '$tplPath'." }

    Write-Step "Target summary"
    Write-Host ("  Run id          : {0}" -f $RunId)
    Write-Host ("  Region          : {0}" -f $location)
    Write-Host ("  Lab group       : {0}" -f $rg)
    Write-Host ("  Evidence group  : {0}" -f $rgEv)
    Write-Host ("  VM              : {0} ({1})" -f $names['VmName'], $vmCfg['VmSize'])
    Write-Host ("  PostgreSQL      : {0} ({1}, {2} GB)" -f $names['PgServer'], $vmCfg['PgSku'], $vmCfg['PgStorageGb'])
    Write-Host ("  Key Vault       : {0}" -f $names['KeyVault'])
    Write-Host ("  Storage account : {0} / container {1}" -f $names['StorageAccount'], $names['StorageContainer'])
    Write-Host ("  Allowed ingress : {0}" -f ($allowed -join ', '))
    if ($WhatIf) { Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed." }

    # --- 2. Authentication / subscription check. ---
    Write-Step "Checking Azure CLI authentication and subscription"
    $subId = Get-AzValue -CmdArgs @('account', 'show', '--query', 'id', '--output', 'tsv') -Placeholder '<subscription-id>'
    if (-not $WhatIf) {
        if ([string]::IsNullOrWhiteSpace($subId)) {
            throw (@(
                "Azure authentication check failed (az account show).",
                "Install the Azure CLI:  winget install --exact --id Microsoft.AzureCLI",
                "Then run:  az login   and   az account set --subscription <your-subscription-id>"
            ) -join [Environment]::NewLine)
        }
        Write-Host ("  Active subscription: {0}" -f $subId)
    }

    # --- 3. Resource groups. ---
    Write-Step "Ensuring resource groups (lab resource group and evidence resource group)"
    $labExists = $false
    if (-not $WhatIf) {
        $labExists = ((Get-AzValue -CmdArgs @('group', 'exists', '--name', $rg) -Placeholder 'false') -eq 'true')
        if ($labExists -and -not $ReuseExisting) {
            throw "Resource group '$rg' already exists. Re-run with -ReuseExisting to converge on it, or run teardown.ps1 first."
        }
    }
    Start-Resource "resource group $rg"
    Az group create --name $rg --location $location --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:resource-group' -Id $rg -Component 'deploy' `
        -DeleteHint @{ service = 'az'; action = 'group delete'; args = @{ name = $rg } }

    Start-Resource "resource group $rgEv"
    Az group create --name $rgEv --location $location --tags @tagEvidence --output none
    Complete-Resource -Type 'azure:resource-group' -Id $rgEv -Component 'evidence' `
        -DeleteHint @{ service = 'az'; action = 'group delete'; args = @{ name = $rgEv } }

    # --- 4. Network: public IP, NSG (/32 only), VNet + subnet. ---
    Write-Step "Creating network resources (static public IP, NSG restricted to the allowed /32 ranges, VNet)"
    Start-Resource "public IP $($names['PublicIp'])"
    Az network public-ip create --name $names['PublicIp'] --resource-group $rg --location $location `
        --sku Standard --allocation-method Static --version IPv4 --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:public-ip' -Id ("$rg/" + $names['PublicIp'])
    $vmIp = Get-AzValue -CmdArgs @('network', 'public-ip', 'show', '--name', $names['PublicIp'], '--resource-group', $rg, '--query', 'ipAddress', '--output', 'tsv') -Placeholder '<vm-public-ip>'

    Start-Resource "network security group $($names['Nsg'])"
    Az network nsg create --name $names['Nsg'] --resource-group $rg --location $location --tags @tagDeploy --output none
    Az network nsg rule create --nsg-name $names['Nsg'] --resource-group $rg --name allow-app-from-user `
        --priority 100 --direction Inbound --access Allow --protocol Tcp `
        --source-address-prefixes @allowed --source-port-ranges '*' `
        --destination-address-prefixes '*' --destination-port-ranges $appPort --output none
    Az network nsg rule create --nsg-name $names['Nsg'] --resource-group $rg --name allow-ssh-from-user `
        --priority 110 --direction Inbound --access Allow --protocol Tcp `
        --source-address-prefixes @allowed --source-port-ranges '*' `
        --destination-address-prefixes '*' --destination-port-ranges 22 --output none
    Complete-Resource -Type 'azure:nsg' -Id ("$rg/" + $names['Nsg'])

    Start-Resource "virtual network $($names['Vnet'])"
    Az network vnet create --name $names['Vnet'] --resource-group $rg --location $location `
        --address-prefixes 10.20.0.0/16 --subnet-name $names['Subnet'] --subnet-prefixes 10.20.1.0/24 `
        --tags @tagDeploy --output none
    Az network vnet subnet update --name $names['Subnet'] --vnet-name $names['Vnet'] --resource-group $rg `
        --network-security-group $names['Nsg'] --output none
    Complete-Resource -Type 'azure:vnet' -Id ("$rg/" + $names['Vnet'])

    # --- 5. Managed identity (assigned to the VM). ---
    Write-Step "Creating the VM managed identity '$($names['Identity'])'"
    Start-Resource "managed identity $($names['Identity'])"
    Az identity create --name $names['Identity'] --resource-group $rg --location $location --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:managed-identity' -Id ("$rg/" + $names['Identity'])
    $idResourceId  = Get-AzValue -CmdArgs @('identity', 'show', '--name', $names['Identity'], '--resource-group', $rg, '--query', 'id', '--output', 'tsv') -Placeholder '<identity-resource-id>'
    $idPrincipalId = Get-AzValue -CmdArgs @('identity', 'show', '--name', $names['Identity'], '--resource-group', $rg, '--query', 'principalId', '--output', 'tsv') -Placeholder '<identity-principal-id>'
    $idClientId    = Get-AzValue -CmdArgs @('identity', 'show', '--name', $names['Identity'], '--resource-group', $rg, '--query', 'clientId', '--output', 'tsv') -Placeholder '<identity-client-id>'

    # --- 6. Key Vault + DB password (value never echoed, never an argument). ---
    Write-Step "Creating Key Vault '$($names['KeyVault'])' (Azure RBAC authorization)"
    Start-Resource "Key Vault $($names['KeyVault'])"
    $kvExists = Test-AzExists -CmdArgs @('keyvault', 'show', '--name', $names['KeyVault'], '--resource-group', $rg, '--output', 'none')
    if (-not $kvExists) {
        Az keyvault create --name $names['KeyVault'] --resource-group $rg --location $location `
            --enable-rbac-authorization true --retention-days 7 --tags @tagDeploy --output none
    }
    else { Write-Host "  Key Vault already exists; reusing." -ForegroundColor DarkGray }
    Complete-Resource -Type 'azure:keyvault' -Id ("$rg/" + $names['KeyVault']) `
        -DeleteHint @{ service = 'az'; action = 'keyvault purge'; args = @{ name = $names['KeyVault']; location = $location } }
    $kvId = Get-AzValue -CmdArgs @('keyvault', 'show', '--name', $names['KeyVault'], '--resource-group', $rg, '--query', 'id', '--output', 'tsv') -Placeholder '<key-vault-id>'

    # The operator needs data-plane write access to store the secret (RBAC mode).
    Start-Resource "role assignment Key Vault Secrets Officer (operator)"
    $operatorId = Get-AzValue -CmdArgs @('ad', 'signed-in-user', 'show', '--query', 'id', '--output', 'tsv') -Placeholder '<operator-object-id>'
    if ($WhatIf -or -not [string]::IsNullOrWhiteSpace($operatorId)) {
        Az role assignment create --assignee-object-id $operatorId --assignee-principal-type User `
            --role 'Key Vault Secrets Officer' --scope $kvId --output none
        Complete-Resource -Type 'azure:role-assignment' -Id "Key Vault Secrets Officer/$operatorId@$($names['KeyVault'])" `
            -DeleteHint @{ service = 'az'; action = 'role assignment delete'; args = @{ assignee = $operatorId; role = 'Key Vault Secrets Officer'; scope = $kvId } }
        Wait-Seconds 30
    }
    else {
        Write-Host "  Could not resolve the signed-in user object id; assuming it already has a Key Vault data role." -ForegroundColor Yellow
    }

    Write-Step "Generating the DB password and storing it in Key Vault (value never echoed)"
    $pwFile = $null
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        Start-Resource "Key Vault secret $($names['SecretName'])"
        $secretExists = $false
        if (-not $WhatIf) {
            $null = AzTry keyvault secret show --vault-name $names['KeyVault'] --name $names['SecretName'] --output none
            $secretExists = ($LASTEXITCODE -eq 0)
        }
        if ($WhatIf) {
            Az keyvault secret set --vault-name $names['KeyVault'] --name $names['SecretName'] --file '<generated-password-file>' --output none
        }
        elseif (-not $secretExists) {
            $dbPassword = New-DbPassword -Length 32
            $pwFile = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText($pwFile, $dbPassword, $utf8NoBom)
            Remove-Variable -Name dbPassword -ErrorAction SilentlyContinue
            $ok = $false
            for ($i = 1; $i -le 6 -and -not $ok; $i++) {
                $null = AzTry keyvault secret set --vault-name $names['KeyVault'] --name $names['SecretName'] --file $pwFile --output none
                $ok = ($LASTEXITCODE -eq 0)
                if (-not $ok) { Write-Host "  RBAC not propagated yet; retrying in 20 s ($i/6)" -ForegroundColor Yellow; Start-Sleep -Seconds 20 }
            }
            if (-not $ok) { throw "Could not store the DB password in Key Vault '$($names['KeyVault'])'." }
        }
        else {
            Write-Host "  Secret already present in Key Vault; reusing." -ForegroundColor DarkGray
        }
        if (-not $WhatIf -and $null -eq $pwFile) {
            $pwFile = [System.IO.Path]::GetTempFileName()
            $null = Az keyvault secret download --vault-name $names['KeyVault'] --name $names['SecretName'] --file $pwFile --encoding utf-8 --overwrite
            $tmp = ([System.IO.File]::ReadAllText($pwFile)).Trim()
            [System.IO.File]::WriteAllText($pwFile, $tmp, $utf8NoBom)
            Remove-Variable -Name tmp -ErrorAction SilentlyContinue
        }
        Complete-Resource -Type 'azure:keyvault-secret' -Id ($names['KeyVault'] + '/' + $names['SecretName']) -Component 'credential'

        # --- 7. PostgreSQL Flexible Server (password from the file via @file). ---
        Write-Step "Creating Azure Database for PostgreSQL Flexible Server '$($names['PgServer'])'"
        Start-Resource "PostgreSQL Flexible Server $($names['PgServer'])"
        $pgExists = Test-AzExists -CmdArgs @('postgres', 'flexible-server', 'show', '--name', $names['PgServer'], '--resource-group', $rg, '--output', 'none')
        $pwRef = if ($WhatIf) { '@<generated-password-file>' } else { '@' + $pwFile }
        if (-not $pgExists) {
            Az postgres flexible-server create --name $names['PgServer'] --resource-group $rg --location $location `
                --admin-user $dbUser --admin-password $pwRef `
                --tier Burstable --sku-name $vmCfg['PgSku'] --storage-size $vmCfg['PgStorageGb'] --version 16 `
                --public-access None --yes --tags @tagDeploy --output none
        }
        else {
            Az postgres flexible-server update --resource-group $rg --name $names['PgServer'] --admin-password $pwRef --output none
        }
        $dbExists = Test-AzExists -CmdArgs @('postgres', 'flexible-server', 'db', 'show', '--resource-group', $rg, '--server-name', $names['PgServer'], '--database-name', $dbName, '--output', 'none')
        if (-not $dbExists) {
            Az postgres flexible-server db create --resource-group $rg --server-name $names['PgServer'] --database-name $dbName --output none
        }
        # Port 5432 reachable ONLY from the VM public IP.
        Az postgres flexible-server firewall-rule create --resource-group $rg --name $names['PgServer'] `
            --rule-name allow-lab-vm --start-ip-address $vmIp --end-ip-address $vmIp --output none
        Complete-Resource -Type 'azure:postgres-flexible-server' -Id ("$rg/" + $names['PgServer'])
    }
    finally {
        if ($pwFile -and (Test-Path -LiteralPath $pwFile)) {
            [System.IO.File]::WriteAllText($pwFile, (' ' * 64))
            Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
        }
    }

    # --- 8. Storage account (no shared key) and the app container. ---
    Write-Step "Creating Storage Account '$($names['StorageAccount'])' and container '$($names['StorageContainer'])'"
    Start-Resource "storage account $($names['StorageAccount'])"
    Az storage account create --name $names['StorageAccount'] --resource-group $rg --location $location `
        --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 --allow-blob-public-access false `
        --allow-shared-key-access false --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:storage-account' -Id ("$rg/" + $names['StorageAccount'])
    Start-Resource "blob container $($names['StorageContainer'])"
    Az storage container-rm create --storage-account $names['StorageAccount'] --resource-group $rg `
        --name $names['StorageContainer'] --output none
    Complete-Resource -Type 'azure:blob-container' -Id ($names['StorageAccount'] + '/' + $names['StorageContainer'])
    $saId = Get-AzValue -CmdArgs @('storage', 'account', 'show', '--name', $names['StorageAccount'], '--resource-group', $rg, '--query', 'id', '--output', 'tsv') -Placeholder '<storage-account-id>'
    $containerScope = "$saId/blobServices/default/containers/$($names['StorageContainer'])"

    # --- 9. Azure RBAC for the VM identity. ---
    Write-Step "Assigning Azure RBAC to the VM managed identity (least privilege)"
    Start-Resource "role assignment Storage Blob Data Contributor"
    Az role assignment create --assignee-object-id $idPrincipalId --assignee-principal-type ServicePrincipal `
        --role 'Storage Blob Data Contributor' --scope $containerScope --output none
    Complete-Resource -Type 'azure:role-assignment' -Id ("Storage Blob Data Contributor/" + $names['Identity'] + '@' + $names['StorageContainer']) `
        -DeleteHint @{ service = 'az'; action = 'role assignment delete'; args = @{ assignee = $idPrincipalId; role = 'Storage Blob Data Contributor'; scope = $containerScope } }
    Start-Resource "role assignment Key Vault Secrets User"
    Az role assignment create --assignee-object-id $idPrincipalId --assignee-principal-type ServicePrincipal `
        --role 'Key Vault Secrets User' --scope $kvId --output none
    Complete-Resource -Type 'azure:role-assignment' -Id ("Key Vault Secrets User/" + $names['Identity'] + '@' + $names['KeyVault']) `
        -DeleteHint @{ service = 'az'; action = 'role assignment delete'; args = @{ assignee = $idPrincipalId; role = 'Key Vault Secrets User'; scope = $kvId } }

    # --- 10. Log Analytics workspace, custom table and DCR. ---
    Write-Step "Creating the Log Analytics workspace, table $($names['LogTable']) and the Data Collection Rule"
    Start-Resource "Log Analytics workspace $($names['Workspace'])"
    Az monitor log-analytics workspace create --resource-group $rg --workspace-name $names['Workspace'] --location $location `
        --quota 1 --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:log-analytics-workspace' -Id ("$rg/" + $names['Workspace'])
    $wsId = Get-AzValue -CmdArgs @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $rg, '--workspace-name', $names['Workspace'], '--query', 'id', '--output', 'tsv') -Placeholder '<workspace-id>'

    Start-Resource "Log Analytics table $($names['LogTable'])"
    $tblExists = Test-AzExists -CmdArgs @('monitor', 'log-analytics', 'workspace', 'table', 'show', '--resource-group', $rg, '--workspace-name', $names['Workspace'], '--name', $names['LogTable'], '--output', 'none')
    if (-not $tblExists) {
        Az monitor log-analytics workspace table create --resource-group $rg --workspace-name $names['Workspace'] `
            --name $names['LogTable'] --columns TimeGenerated=datetime RawData=string --output none
    }

    $stream = 'Custom-' + $names['LogTable']
    $dcrDef = [ordered]@{
        location   = $location
        kind       = 'Linux'
        properties = [ordered]@{
            streamDeclarations = @{ $stream = @{ columns = @(
                        @{ name = 'TimeGenerated'; type = 'datetime' },
                        @{ name = 'RawData'; type = 'string' }) } }
            dataSources        = @{ logFiles = @(@{
                        name         = 'sangyshopAppLog'
                        streams      = @($stream)
                        filePatterns = @('/var/log/sangyshop/app.log')
                        format       = 'text'
                        settings     = @{ text = @{ recordStartTimestampFormat = 'ISO 8601' } }
                    }) }
            destinations       = @{ logAnalytics = @(@{ name = 'lawDest'; workspaceResourceId = $wsId }) }
            dataFlows          = @(@{ streams = @($stream); destinations = @('lawDest'); transformKql = 'source'; outputStream = $stream })
        }
    }
    Start-Resource "Data Collection Rule $($names['Dcr'])"
    if ($WhatIf) {
        Az monitor data-collection rule create --name $names['Dcr'] --resource-group $rg --location $location `
            --rule-file '<generated-dcr.json>' --tags @tagDeploy --output none
    }
    else {
        $dcrFile = [System.IO.Path]::GetTempFileName()
        $tempFiles.Add($dcrFile)
        [System.IO.File]::WriteAllText($dcrFile, (ConvertTo-Json -InputObject $dcrDef -Depth 12), $utf8NoBom)
        Az monitor data-collection rule create --name $names['Dcr'] --resource-group $rg --location $location `
            --rule-file $dcrFile --tags @tagDeploy --output none
    }
    Complete-Resource -Type 'azure:data-collection-rule' -Id ("$rg/" + $names['Dcr']) -Component 'detection'
    $dcrId = Get-AzValue -CmdArgs @('monitor', 'data-collection', 'rule', 'show', '--name', $names['Dcr'], '--resource-group', $rg, '--query', 'id', '--output', 'tsv') -Placeholder '<dcr-id>'

    # --- 11. VM (cloud-init) + AMA extension + DCR association. ---
    Write-Step "Rendering cloud-init and creating the VM '$($names['VmName'])'"
    $tpl = [System.IO.File]::ReadAllText($tplPath)
    $labMode = if ($NoLabMode) { '0' } else { '1' }
    $tokens = [ordered]@{
        '@@PG_FQDN@@'            = $pgFqdn
        '@@DB_NAME@@'            = $dbName
        '@@DB_USER@@'            = $dbUser
        '@@APP_PORT@@'           = [string]$appPort
        '@@STORAGE_ACCOUNT@@'    = $names['StorageAccount']
        '@@STORAGE_CONTAINER@@'  = $names['StorageContainer']
        '@@IDENTITY_CLIENT_ID@@' = $idClientId
        '@@LAB_MODE@@'           = $labMode
        '@@KEY_VAULT_NAME@@'     = $names['KeyVault']
        '@@SECRET_NAME@@'        = $names['SecretName']
        '@@REPO_URL@@'           = $RepoUrl
    }
    $rendered = $tpl
    foreach ($k in $tokens.Keys) { $rendered = $rendered.Replace($k, [string]$tokens[$k]) }
    if ($rendered -match '@@[A-Z_]+@@') { throw "cloud-init template still contains an unresolved token: $($Matches[0])" }

    $customData = '<rendered-cloud-init.yaml>'
    if (-not $WhatIf) {
        $customData = [System.IO.Path]::GetTempFileName()
        $tempFiles.Add($customData)
        [System.IO.File]::WriteAllText($customData, $rendered.Replace("`r`n", "`n"), $utf8NoBom)
    }

    Start-Resource "virtual machine $($names['VmName'])"
    $sshArgs = @('--generate-ssh-keys')
    if (-not [string]::IsNullOrWhiteSpace($SshPublicKeyPath)) { $sshArgs = @('--ssh-key-values', $SshPublicKeyPath) }
    Az vm create --name $names['VmName'] --resource-group $rg --location $location `
        --image Ubuntu2204 --size $vmCfg['VmSize'] --admin-username azureuser @sshArgs `
        --os-disk-size-gb 32 --storage-sku StandardSSD_LRS `
        --vnet-name $names['Vnet'] --subnet $names['Subnet'] --nsg $names['Nsg'] `
        --public-ip-address $names['PublicIp'] --public-ip-sku Standard `
        --assign-identity $idResourceId --custom-data $customData `
        --tags @tagDeploy --output none
    Complete-Resource -Type 'azure:vm' -Id ("$rg/" + $names['VmName'])
    $vmId = Get-AzValue -CmdArgs @('vm', 'show', '--name', $names['VmName'], '--resource-group', $rg, '--query', 'id', '--output', 'tsv') -Placeholder '<vm-id>'

    Start-Resource "Azure Monitor Agent extension"
    $amaSettings = '<generated-ama-settings.json>'
    if (-not $WhatIf) {
        $amaSettings = [System.IO.Path]::GetTempFileName()
        $tempFiles.Add($amaSettings)
        $ama = @{ authentication = @{ managedIdentity = @{ 'identifier-name' = 'mi_res_id'; 'identifier-value' = $idResourceId } } }
        [System.IO.File]::WriteAllText($amaSettings, (ConvertTo-Json -InputObject $ama -Depth 6), $utf8NoBom)
    }
    Az vm extension set --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor `
        --vm-name $names['VmName'] --resource-group $rg --enable-auto-upgrade true --settings $amaSettings --output none
    Start-Resource "DCR association $($names['DcrAssociation'])"
    Az monitor data-collection rule association create --name $names['DcrAssociation'] --resource $vmId --rule-id $dcrId --output none
    Complete-Resource -Type 'azure:dcr-association' -Id ($names['VmName'] + '/' + $names['DcrAssociation']) -Component 'detection'

    # --- Done. ---
    Write-Step "Deploy finished"
    if ($WhatIf) {
        Write-Host ("DRY RUN complete: {0} command(s) listed; nothing was created." -f $script:PlanOrdinal) -ForegroundColor Green
        exit 0
    }
    Write-Host ("  SangyShop (vulnerable): http://{0}:{1}  (allow ~3-5 minutes for cloud-init)" -f $vmIp, $appPort) -ForegroundColor Green
    Write-Host ("  Manifest: {0}" -f (Get-LabManifestPath -Lab $script:VmLabName))
    Write-Host "  REMINDER: ingress is limited to your /32. Stop daily with stop-lab.ps1; remove everything with teardown.ps1." -ForegroundColor Yellow
    exit 0
}
catch {
    Write-StdErr ("ERROR: " + $_.Exception.Message)
    if ($script:Current) { Write-StdErr ("Failed resource: " + $script:Current) }
    if ($script:Created.Count -gt 0) {
        Write-StdErr "Resources already created (remove them with teardown.ps1):"
        foreach ($c in $script:Created) { Write-StdErr ("  - " + $c) }
    }
    exit 1
}
finally {
    foreach ($f in $tempFiles) {
        if ($f -and (Test-Path -LiteralPath $f)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }
}
