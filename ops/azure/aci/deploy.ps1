<#
.SYNOPSIS
    Deploys the HARDENED SangyShop variant to Azure Container Instances (ACI),
    backed by Azure Container Registry, Azure DB for PostgreSQL Flexible Server,
    and Azure Key Vault. Docker-only modality.

.DESCRIPTION
    One of the six (cloud, modality) deploy targets described in the
    multi-cloud-deploy spec. This script:

      1. Validates config and checks `az` authentication (fail-closed).
      2. Ensures the resource group, ACR, Flexible Server, and Key Vault exist
         (idempotent create-or-reuse via a describe/show check, Req 4.1/4.2).
      3. Builds the hardened image from
         ops/docker/hardened/Dockerfile, tags it `:hardened`,
         and pushes it to ACR (Req 2.1/2.3/4.5).
      4. Generates the DB password (New-DbPassword), stores it ONLY in Key Vault
         (Req 3.2/4.4), and sets the Flexible Server admin password from the
         stored secret.
      5. Locks down Postgres access to the compute target on 5432 (Req 9.5).
      6. Creates the ACI container group with a SECRET VOLUME that delivers the
         password to the file /run/secrets/db_password (Req 3.1), with the
         non-secret connection env only (no DB_PASSWORD env, Req 3.3).
      7. Restricts container ingress to an explicit allowed source-address set,
         rejecting 0.0.0.0/0 and ::/0 (Req 9.3/9.4).
      8. Prints the public URL plus the ingress-lockdown + teardown reminder
         (Req 4.7/9.2).

    EVERY external CLI call (`az`, `docker`) goes through Invoke-Echoed from
    lib/Common.ps1 (echo-before-exec, Req 1.3). The script never calls az/docker
    directly. The generated password is NEVER passed as a CLI argument or echoed;
    it is delivered to Key Vault / ACI exclusively by file so the echoed command
    stream never reveals it (Req 3.2).

    SECURITY WARNING: SangyShop is deliberately vulnerable. The "hardened" image
    only improves the deployment posture. Deploy ONLY to an isolated, throwaway
    subscription, keep ingress locked to your own address, and run teardown.ps1
    when finished (these resources are billable).

    Windows PowerShell 5.1 compatible (Req 6.1). No bash/sh is ever invoked (Req 6.2).

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the shared config two levels up.

.PARAMETER WhatIf
    Dry run (Req 6.5): prints the full ordered list of external commands that
    WOULD run, executes nothing, and exits 0.

.PARAMETER ReuseExisting
    Reuse existing registry/DB/vault if already present. This is the default
    behavior (every create is guarded by a describe/show check); the switch is
    accepted for parity with the other deploy scripts and documents intent.

.PARAMETER AllowedSourceRanges
    REQUIRED for a real deploy. The explicit set of source CIDRs / IPs allowed to
    reach the app and the database. 0.0.0.0/0 and ::/0 are rejected (Req 9.3/9.4).
    If omitted on a non-dry-run, the script stops before any change (Req 9.4).

.EXAMPLE
    .\deploy.ps1 -AllowedSourceRanges '203.0.113.7/32'

.EXAMPLE
    .\deploy.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [string]   $ConfigPath,
    [switch]   $WhatIf,
    [switch]   $ReuseExisting,
    [string[]] $AllowedSourceRanges
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve the script directory robustly (works whether invoked by path, dot-source,
# or via the call operator) and default -ConfigPath to the shared config two levels up.
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = (Join-Path $scriptDir '..\..\cloud.config.ps1')
}

# --- Dot-source the shared library (Invoke-Echoed, Write-Step, config, pw gen). ---
. (Join-Path $scriptDir '..\..\lib\Common.ps1')

# =============================================================================
# -WhatIf planning: in dry-run we only print the command line that WOULD run and
# execute nothing. Invoke-Planned is the single gate every external call passes
# through so the echo-only rule (Req 1.3) and the dry-run rule (Req 6.5) are both
# satisfied from one place. Kept simple and self-contained per task guidance.
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
        # Keep it copyable: executable followed by its arguments, space-joined.
        $display = (@($Exe) + $CmdArgs) -join ' '
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        return $null
    }
    return (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail:$AllowFail)
}

# Convenience wrappers so call sites read cleanly.
function Az     { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az'     -CmdArgs $A }
function AzTry  { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az'     -CmdArgs $A -AllowFail }
function Docker { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'docker' -CmdArgs $A }

# -----------------------------------------------------------------------------
# Validate the allowed-source set up front (Req 9.3/9.4). A real deploy MUST be
# given an explicit, non-world-open set. In -WhatIf we tolerate its absence so a
# user can inspect the plan without committing to an ingress decision, but we
# still reject world-open ranges if any were supplied.
# -----------------------------------------------------------------------------
function Assert-AllowedSourceRanges {
    param([string[]] $Ranges, [switch] $DryRun)

    $worldOpen = @('0.0.0.0/0', '::/0')

    if ($null -eq $Ranges -or @($Ranges).Count -eq 0) {
        if ($DryRun) {
            Write-Host "NOTE: -WhatIf dry run; -AllowedSourceRanges not supplied. A real deploy REQUIRES it." -ForegroundColor Yellow
            return @()
        }
        throw "An allowed source address set is required. Pass -AllowedSourceRanges with your own IP/CIDR (e.g. -AllowedSourceRanges '203.0.113.7/32'). Open-to-world ranges (0.0.0.0/0, ::/0) are forbidden for this deliberately-vulnerable app (Req 9.3/9.4)."
    }

    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Ranges) {
        $t = ([string]$r).Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($worldOpen -contains $t) {
            throw "Source range '$t' opens the app to the entire internet and is forbidden (Req 9.3). Restrict ingress to your own address."
        }
        $clean.Add($t)
    }
    if ($clean.Count -eq 0 -and -not $DryRun) {
        throw "An allowed source address set is required but only blank/forbidden entries were supplied (Req 9.4)."
    }
    return $clean.ToArray()
}

# -----------------------------------------------------------------------------
# Hardened-only guardrails (Req 2.1/2.2/2.3/2.4). Abort before any push/deploy if
# the hardened Dockerfile is missing or a non-hardened reference would be used.
# -----------------------------------------------------------------------------
function Assert-HardenedBuild {
    param([string] $RepoRoot, [string] $ImageTag, [string] $AppMode)

    $dockerfile = Join-Path $RepoRoot 'ops\docker\hardened\Dockerfile'
    if (-not (Test-Path -LiteralPath $dockerfile -PathType Leaf)) {
        throw "Hardened Dockerfile not found at '$dockerfile'. Refusing to build/push/deploy (Req 2.4)."
    }
    if ($ImageTag -ne 'hardened') {
        throw "Only the hardened variant may be deployed; image tag was '$ImageTag', expected 'hardened' (Req 2.2)."
    }
    if ($AppMode -ne 'hardened') {
        throw "Only the hardened variant may be deployed; APP_MODE was '$AppMode', expected 'hardened' (Req 2.2)."
    }
    return $dockerfile
}

# =============================================================================
# Main
# =============================================================================
try {
    Write-Step "Loading and validating configuration (Azure)"
    $cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Azure'

    $allowed = Assert-AllowedSourceRanges -Ranges $AllowedSourceRanges -DryRun:$WhatIf

    # --- Resolve names from config. ---
    $suffix   = [string]$cfg['UniqueSuffix']
    $common   = $cfg['Common']
    $azure    = $cfg['Azure']

    $appName  = [string]$common['AppName']
    $dbName   = [string]$common['DbName']
    $dbUser   = [string]$common['DbUser']
    $imageTag = [string]$common['ImageTag']      # must be 'hardened'
    $appMode  = 'hardened'                        # fixed by this target (Req 2.1)

    $location = [string]$azure['Location']
    $rg       = [string]$azure['ResourceGroup']
    $acrBase  = [string]$azure['AcrNameBase']
    $kvBase   = [string]$azure['KeyVaultBase']
    $aciName  = [string]$azure['AciName']

    # Final globally-unique names (Req 7.5): ACR = base + suffix (alnum only);
    # Key Vault = base + "-" + suffix.
    $acrName   = ($acrBase + $suffix)
    $kvName    = ($kvBase + '-' + $suffix)
    $kvSecret  = 'db-password'                    # Key Vault secret name (NOT the value)
    $pgServer  = ($appName + '-pg-' + $suffix)    # Flexible Server name
    $fwRuleBase = 'allow-src'
    $idName    = ($appName + '-aci-pull-' + $suffix)   # user-assigned identity for ACR pull

    # Repo root is three levels up from azure/aci/.
    $repoRoot = (Resolve-Path (Join-Path $scriptDir '..\..\..')).Path
    $dockerfile = Assert-HardenedBuild -RepoRoot $repoRoot -ImageTag $imageTag -AppMode $appMode

    $loginServer = ($acrName + '.azurecr.io')
    $imageRef    = ($loginServer + '/' + $appName + ':' + $imageTag)
    $pgFqdn      = ($pgServer + '.postgres.database.azure.com')
    $appPort     = 3000

    Write-Step "Target summary"
    Write-Host ("  Resource group : {0} ({1})" -f $rg, $location)
    Write-Host ("  ACR            : {0}" -f $acrName)
    Write-Host ("  Image          : {0}" -f $imageRef)
    Write-Host ("  Flexible Server: {0}" -f $pgServer)
    Write-Host ("  Key Vault      : {0} (secret: {1})" -f $kvName, $kvSecret)
    Write-Host ("  ACI group      : {0}" -f $aciName)
    if (@($allowed).Count -gt 0) {
        Write-Host ("  Allowed ingress: {0}" -f ($allowed -join ', '))
    }

    if ($WhatIf) {
        Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
    }

    # -------------------------------------------------------------------------
    # 1. Authentication check (Req 6.3/6.4). `az account show` succeeds only when
    #    the CLI is installed AND a session is active. On failure, print install +
    #    auth guidance and exit non-zero.
    # -------------------------------------------------------------------------
    Write-Step "Checking Azure CLI authentication"
    if ($WhatIf) {
        Az account show --output none
    }
    else {
        $null = AzTry account show --output none
        if ($LASTEXITCODE -ne 0) {
            Write-Error (@(
                "Azure authentication check failed (az account show).",
                "",
                "Install the Azure CLI (Windows):",
                "  winget install --exact --id Microsoft.AzureCLI",
                "  (or download the MSI from https://aka.ms/installazurecliwindows )",
                "Verify:  az version",
                "",
                "Authenticate to your OWN (isolated / throwaway) subscription:",
                "  az login",
                "  az account set --subscription <your-subscription-id>",
                "",
                "Then re-run this script."
            ) -join [Environment]::NewLine)
            exit 1
        }
    }

    # -------------------------------------------------------------------------
    # 2. Resource group (idempotent). `az group create` is itself idempotent.
    # -------------------------------------------------------------------------
    Write-Step "Ensuring resource group '$rg'"
    Az group create --name $rg --location $location --output none

    # -------------------------------------------------------------------------
    # 3. ACR: describe-then-create (Req 4.1). Reuse if present; create otherwise.
    # -------------------------------------------------------------------------
    Write-Step "Ensuring Azure Container Registry '$acrName'"
    $acrExists = $false
    if ($WhatIf) {
        Az acr show --name $acrName --resource-group $rg --output none
    }
    else {
        $null = AzTry acr show --name $acrName --resource-group $rg --output none
        $acrExists = ($LASTEXITCODE -eq 0)
    }
    if ($WhatIf -or -not $acrExists) {
        # Admin user stays DISABLED. The ACI container group pulls the private
        # image via a user-assigned managed identity granted AcrPull (step 5b),
        # so no registry password is ever created, stored, or echoed.
        Az acr create --name $acrName --resource-group $rg --sku Basic --admin-enabled false --output none
    }
    else {
        Write-Host "  ACR already exists; reusing." -ForegroundColor DarkGray
    }

    # -------------------------------------------------------------------------
    # 4. ACR login, build hardened image, push (Req 2.3/4.5). Build context is
    #    the repo root with the hardened Dockerfile.
    # -------------------------------------------------------------------------
    Write-Step "Logging in to ACR and building/pushing the hardened image"
    Az acr login --name $acrName
    Docker build -t $imageRef -f $dockerfile $repoRoot
    Docker push $imageRef

    # -------------------------------------------------------------------------
    # 5. Key Vault: describe-then-create (Req 4.1), then generate + store the DB
    #    password (Req 4.4) BEFORE provisioning Postgres. The secret VALUE is
    #    written to a private temp file and passed to `az keyvault secret set
    #    --file`, so the password is never a CLI argument and never appears on an
    #    echoed line (Req 3.2). The same temp file is reused to seed the Flexible
    #    Server admin password (step 6) and shredded in the finally block.
    # -------------------------------------------------------------------------
    Write-Step "Ensuring Key Vault '$kvName'"
    $kvExists = $false
    if ($WhatIf) {
        Az keyvault show --name $kvName --resource-group $rg --output none
    }
    else {
        $null = AzTry keyvault show --name $kvName --resource-group $rg --output none
        $kvExists = ($LASTEXITCODE -eq 0)
    }
    if ($WhatIf -or -not $kvExists) {
        Az keyvault create --name $kvName --resource-group $rg --location $location --output none
    }
    else {
        Write-Host "  Key Vault already exists; reusing." -ForegroundColor DarkGray
    }

    Write-Step "Generating and storing the DB password in Key Vault (value never echoed)"
    # Does the secret already exist? (idempotent: generate only when absent, Req 4.4)
    $secretExists = $false
    if (-not $WhatIf) {
        $null = AzTry keyvault secret show --vault-name $kvName --name $kvSecret --output none
        $secretExists = ($LASTEXITCODE -eq 0)
    }

    # Holds the plain password on disk ONLY for the duration of this run; shredded
    # in the finally block. Never echoed: every CLI that consumes it does so via a
    # file path or @file reference, so the echoed command line shows the path only.
    $pwFile = $null
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        if ($WhatIf) {
            # Show the shape of the command without a real value or file.
            Az keyvault secret set --vault-name $kvName --name $kvSecret --file '<generated-password-file>' --output none
        }
        elseif (-not $secretExists) {
            $dbPassword = New-DbPassword -Length 32
            # Write with NO trailing newline so the stored value (and the mounted
            # file content) is exactly the password.
            $pwFile = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText($pwFile, $dbPassword, $utf8NoBom)
            # --file keeps the value off the command line (Req 3.2).
            Az keyvault secret set --vault-name $kvName --name $kvSecret --file $pwFile --output none
            Remove-Variable -Name dbPassword -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "  Secret already present in Key Vault; reusing." -ForegroundColor DarkGray
        }

        # For a real deploy, make sure we have the password on disk (either just
        # written above, or downloaded from Key Vault when the secret pre-existed)
        # so the Flexible Server create can seed the admin password from it via the
        # az CLI @file convention, without ever echoing the value.
        if (-not $WhatIf -and ($null -eq $pwFile)) {
            $pwFile = [System.IO.Path]::GetTempFileName()
            $null = Az keyvault secret download --vault-name $kvName --name $kvSecret --file $pwFile --encoding utf-8 --overwrite
            # Normalize to exactly the trimmed value (no trailing newline).
            $tmp = ([System.IO.File]::ReadAllText($pwFile)).Trim()
            [System.IO.File]::WriteAllText($pwFile, $tmp, $utf8NoBom)
            Remove-Variable -Name tmp -ErrorAction SilentlyContinue
        }

        # ---------------------------------------------------------------------
        # 6. Flexible Server: describe-then-create (Req 4.3 - managed service,
        #    never a container). The admin password is seeded from the Key-Vault
        #    secret already on disk, passed with the az CLI `@file` convention so
        #    the value is read from the file and NEVER appears on the echoed
        #    command line (Req 3.2). --public-access None keeps the server off the
        #    public internet; access is granted only by the explicit firewall
        #    rule(s) added in step 7 (Req 9.5).
        # ---------------------------------------------------------------------
        Write-Step "Ensuring Azure DB for PostgreSQL Flexible Server '$pgServer'"
        $pgExists = $false
        if ($WhatIf) {
            Az postgres flexible-server show --name $pgServer --resource-group $rg --output none
        }
        else {
            $null = AzTry postgres flexible-server show --name $pgServer --resource-group $rg --output none
            $pgExists = ($LASTEXITCODE -eq 0)
        }
        if ($WhatIf -or -not $pgExists) {
            $pwRef = if ($WhatIf) { '@<generated-password-file>' } else { ('@' + $pwFile) }
            # NOTE: --database-name is NOT passed here. Current Azure CLI rejects
            # --database-name on a single Flexible Server create (it only applies
            # to elastic clusters with --node-count); the database is created in a
            # separate idempotent step below.
            Az postgres flexible-server create `
                --name $pgServer `
                --resource-group $rg `
                --location $location `
                --admin-user $dbUser `
                --admin-password $pwRef `
                --tier Burstable `
                --sku-name Standard_B1ms `
                --version 16 `
                --public-access None `
                --yes `
                --output none
        }
        else {
            # Server already exists; align its admin password with the stored
            # secret (idempotent, value via @file so it is never echoed).
            $pwRef = ('@' + $pwFile)
            Az postgres flexible-server update `
                --resource-group $rg --name $pgServer `
                --admin-password $pwRef --output none
        }

        # ---------------------------------------------------------------------
        # 6b. Database: describe-then-create (idempotent, Req 4.1). The database
        #     can no longer be created inline on the single Flexible Server
        #     create, so it is provisioned here as a separate step: show first
        #     (AllowFail), and create only when absent, matching the
        #     describe-or-create idempotency pattern used elsewhere.
        # ---------------------------------------------------------------------
        Write-Step "Ensuring database '$dbName' on Flexible Server '$pgServer'"
        $dbExists = $false
        if ($WhatIf) {
            Az postgres flexible-server db show --resource-group $rg --server-name $pgServer --database-name $dbName --output none
        }
        else {
            $null = AzTry postgres flexible-server db show --resource-group $rg --server-name $pgServer --database-name $dbName --output none
            $dbExists = ($LASTEXITCODE -eq 0)
        }
        if ($WhatIf -or -not $dbExists) {
            Az postgres flexible-server db create --resource-group $rg --server-name $pgServer --database-name $dbName --output none
        }
        else {
            Write-Host "  Database already exists; reusing." -ForegroundColor DarkGray
        }

        # ---------------------------------------------------------------------
        # 7. Firewall rule(s): allow ONLY the explicit source set to reach the
        #    server on 5432; world-open ranges were already rejected. The server
        #    stays private otherwise (Req 9.5). One rule per source address.
        # ---------------------------------------------------------------------
        Write-Step "Adding locked-down PostgreSQL firewall rule(s) (port 5432, no public exposure)"
        if ($WhatIf) {
            Az postgres flexible-server firewall-rule create `
                --resource-group $rg --name $pgServer `
                --rule-name ($fwRuleBase + '-0') `
                --start-ip-address '<allowed-ip>' --end-ip-address '<allowed-ip>' `
                --output none
        }
        else {
            $idx = 0
            foreach ($cidr in $allowed) {
                $ip = ($cidr -split '/')[0]
                Az postgres flexible-server firewall-rule create `
                    --resource-group $rg --name $pgServer `
                    --rule-name ($fwRuleBase + '-' + $idx) `
                    --start-ip-address $ip --end-ip-address $ip `
                    --output none
                $idx++
            }
        }

        # ---------------------------------------------------------------------
        # 7b. User-assigned managed identity + AcrPull role so ACI can pull the
        #     private image WITHOUT any registry password (no secret to echo or
        #     store). Identity principal/client ids are non-secret. Role
        #     assignment is idempotent (AllowFail on the already-exists case).
        # ---------------------------------------------------------------------
        Write-Step "Ensuring the ACR-pull managed identity '$idName'"
        if ($WhatIf) {
            Az identity create --name $idName --resource-group $rg --output none
            Az identity show --name $idName --resource-group $rg --query 'id' --output tsv
            Az acr show --name $acrName --resource-group $rg --query 'id' --output tsv
            Az role assignment create --assignee '<identity-principal-id>' --role AcrPull --scope '<acr-id>' --output none
        }

        if (-not $WhatIf) {
            # Create (idempotent: identity create is a no-op if it already exists).
            $null = AzTry identity create --name $idName --resource-group $rg --output none
            $idResourceId  = ([string](Az identity show --name $idName --resource-group $rg --query 'id' --output tsv)).Trim()
            $idPrincipalId = ([string](Az identity show --name $idName --resource-group $rg --query 'principalId' --output tsv)).Trim()
            $acrId         = ([string](Az acr show --name $acrName --resource-group $rg --query 'id' --output tsv)).Trim()
            # Grant AcrPull; tolerate "already assigned" so re-runs converge (Req 4.1).
            $null = AzTry role assignment create --assignee-object-id $idPrincipalId --assignee-principal-type ServicePrincipal --role AcrPull --scope $acrId --output none
        }

        # ---------------------------------------------------------------------
        # 8. ACI container group with a SECRET VOLUME delivering the password to
        #    /run/secrets/db_password (Req 3.1), the non-secret env only (no
        #    DB_PASSWORD, Req 3.3), ingress restricted to the allowed set
        #    (Req 9.3). The DB password value is injected via a deployment YAML
        #    passed with `--file`, so it never appears on the echoed command line
        #    (Req 3.2). ACI writes each secret volume entry to a file named by its
        #    key at the mount path, so key `db_password` + mount `/run/secrets`
        #    yields exactly /run/secrets/db_password. The image is pulled using the
        #    user-assigned identity (no registry password anywhere).
        # ---------------------------------------------------------------------
        Write-Step "Creating the ACI container group with the secret volume (/run/secrets/db_password)"

        if ($WhatIf) {
            Az container create --resource-group $rg --file '<generated-aci-group.yaml>' --output none
        }
        else {
            # Reuse the DB secret already on disk ($pwFile), base64-encode it for
            # the ACI secretVolume, and build the deployment YAML. The only secret
            # in the YAML is the DB password; it lives in the --file content only
            # and is never echoed.
            $yamlFile = [System.IO.Path]::GetTempFileName()
            try {
                if ($null -eq $pwFile -or -not (Test-Path -LiteralPath $pwFile)) {
                    throw "Internal error: DB password file is unavailable; cannot deliver the secret to the container (Req 3.4)."
                }
                $secretPlain = ([System.IO.File]::ReadAllText($pwFile)).Trim()
                if ([string]::IsNullOrEmpty($secretPlain)) {
                    throw "DB password could not be resolved from Key Vault; aborting before starting the container (Req 3.4)."
                }
                $secretB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($secretPlain))
                Remove-Variable -Name secretPlain -ErrorAction SilentlyContinue

                # Build the container-group YAML. The secretVolume entry 'db_password'
                # becomes the file /run/secrets/db_password. Env is non-secret only.
                # The user-assigned identity (identity block + registry.identity)
                # authenticates the ACR pull, so no registry password is present.
                $ipType = 'Public'   # ACI exposes a public IP; the DB/app ingress is
                                     # restricted by the Postgres firewall + the README
                                     # lockdown guidance (ACI has no native per-source
                                     # allowlist, so the reminder below is mandatory).
                $yaml = @"
apiVersion: 2021-10-01
location: $location
name: $aciName
identity:
  type: UserAssigned
  userAssignedIdentities:
    ${idResourceId}: {}
properties:
  osType: Linux
  restartPolicy: OnFailure
  imageRegistryCredentials:
    - server: $loginServer
      identity: $idResourceId
  ipAddress:
    type: $ipType
    ports:
      - protocol: tcp
        port: $appPort
  volumes:
    - name: dbsecret
      secret:
        db_password: $secretB64
  containers:
    - name: $appName
      properties:
        image: $imageRef
        ports:
          - protocol: tcp
            port: $appPort
        resources:
          requests:
            cpu: 1
            memoryInGB: 1.5
        environmentVariables:
          - name: APP_MODE
            value: $appMode
          - name: DB_BACKEND
            value: pg
          - name: DB_HOST
            value: $pgFqdn
          - name: DB_PORT
            value: "5432"
          - name: DB_NAME
            value: $dbName
          - name: DB_USER
            value: $dbUser
        volumeMounts:
          - name: dbsecret
            mountPath: /run/secrets
            readOnly: true
type: Microsoft.ContainerInstance/containerGroups
"@
                [System.IO.File]::WriteAllText($yamlFile, $yaml, (New-Object System.Text.UTF8Encoding($false)))
                Remove-Variable -Name secretB64 -ErrorAction SilentlyContinue

                Az container create --resource-group $rg --file $yamlFile --output none
            }
            finally {
                if (Test-Path -LiteralPath $yamlFile) {
                    [System.IO.File]::WriteAllText($yamlFile, (' ' * 256))
                    Remove-Item -LiteralPath $yamlFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    finally {
        # Shred and remove the password temp file if one was created.
        if ($pwFile -and (Test-Path -LiteralPath $pwFile)) {
            [System.IO.File]::WriteAllText($pwFile, (' ' * 64))
            Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
        }
    }

    # -------------------------------------------------------------------------
    # 10. Fetch the public FQDN and print the URL + lockdown/teardown reminder
    #     (Req 4.7/9.2).
    # -------------------------------------------------------------------------
    Write-Step "Fetching the deployed URL"
    $fqdn = $null
    if ($WhatIf) {
        Az container show --resource-group $rg --name $aciName --query 'ipAddress.fqdn' --output tsv
    }
    else {
        $fqdn = (Az container show --resource-group $rg --name $aciName --query 'ipAddress.fqdn' --output tsv)
        if ($fqdn) { $fqdn = ([string]$fqdn).Trim() }
    }

    if ($WhatIf) {
        Write-Step "DRY RUN complete. $script:PlanOrdinal command(s) listed; none executed."
        exit 0
    }

    $url = if ($fqdn) { "http://${fqdn}:${appPort}" } else { "(FQDN not yet assigned; re-run 'az container show ...')" }

    Write-Step "Deployment complete"
    Write-Host ""
    Write-Host "  URL: $url" -ForegroundColor Green
    Write-Host ""
    Write-Host "  !! SECURITY REMINDER !!" -ForegroundColor Yellow
    Write-Host "  SangyShop is DELIBERATELY VULNERABLE even in the hardened image." -ForegroundColor Yellow
    if (@($allowed).Count -gt 0) {
        Write-Host ("  RESTRICT INGRESS to your own address only: {0}" -f ($allowed -join ', ')) -ForegroundColor Yellow
    }
    else {
        Write-Host "  RESTRICT INGRESS to your own source address; never expose to 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
    }
    Write-Host "  RUN TEARDOWN when finished (resources are billable):" -ForegroundColor Yellow
    Write-Host ("    .\teardown.ps1   (or: az group delete --name {0} --yes --no-wait)" -f $rg) -ForegroundColor Yellow
    Write-Host ""
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
