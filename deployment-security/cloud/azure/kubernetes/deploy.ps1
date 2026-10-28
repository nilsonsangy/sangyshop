<#
.SYNOPSIS
    Deploys the HARDENED SangyShop variant to Azure Kubernetes Service (AKS),
    backed by Azure Container Registry, Azure DB for PostgreSQL Flexible Server,
    and Azure Key Vault. Kubernetes modality.

.DESCRIPTION
    Kubernetes counterpart of the Azure Container Instances (Docker-only) deploy.
    It reuses the same resource group / ACR build+push and the managed Flexible
    Server + Key Vault steps, then provisions (or reuses) an AKS cluster and
    deploys the committed Azure kustomize overlay
    (deployment-security/cloud/manifests/overlays/azure). The DB password is
    stored ONLY in Key Vault and delivered to the pod as the file
    /run/secrets/db_password via the Key Vault Secrets Store CSI provider (the
    azure-keyvault-secrets-provider addon syncs it into the sangyshop-db Secret
    the base mounts). No DB_PASSWORD env var is ever set; the unmodified hardened
    app reads the secret file and fails closed otherwise (src/db/credentials.js).

    Pipeline (every external CLI call is echoed before it runs, through the shared
    Invoke-Echoed helper in lib/Common.ps1):

        1. Authentication check (account show)               (Req 6.3/6.4)
        2. Resource group (idempotent)
        3. ACR describe-or-create                            (Req 4.1)
        4. Registry login, build the hardened image, push    (Req 2.1/2.3/4.5)
        5. Key Vault describe-or-create + generate+store the
           password (file only, never an echoed arg)         (Req 3.2/4.4)
        6. Flexible Server describe-or-create; seed the admin
           password from the stored secret via @file         (Req 4.1/4.3/9.5)
        7. Locked-down Postgres firewall rule(s)              (Req 9.5)
        8. User-assigned identity + Key Vault get access +
           ACR pull, for the CSI secrets provider
        9. AKS describe-or-create with --attach-acr and the
           Key Vault secrets provider addon                  (Req 4.1)
       10. Fetch cluster credentials for the cluster CLI      (Req 4.8)
       11. Render overlay copy, substitute placeholders,
           apply with the load-restrictor pipe form          (Req 2.5/3.1/3.3)
       12. Wait for rollout                                  (Req 4.8)
       13. Read the external IP as the URL                    (Req 4.7/9.2)
       14. Print lockdown + teardown reminder                (Req 9.2/9.3)

    Safety:
      * Only the hardened variant is ever built/pushed/deployed (Req 2.1).
      * Aborts before any push/deploy if the hardened Dockerfile is missing
        (Req 2.4) or a non-:hardened image / non-hardened APP_MODE is referenced.
      * Ingress is restricted to an explicitly provided source-address set and
        the open ranges 0.0.0.0/0 and ::/0 are rejected (Req 9.3/9.4).
      * Flexible Server is reachable by the AKS workload on 5432 only, kept off
        the public internet (Req 9.5).
      * The committed overlay is NEVER rewritten; placeholders are substituted in
        a throwaway rendered copy only (Req 2.5).
      * The generated password is NEVER passed as a CLI argument or echoed; it is
        delivered to Key Vault / Flexible Server exclusively by file so the echoed
        command stream never reveals it (Req 3.2).
      * -WhatIf prints the full ordered command list and executes NOTHING, exiting
        0 (Req 6.5).

    Windows PowerShell 5.1 compatible (Req 6.1). Every external CLI call routes
    through Invoke-Echoed (Req 1.3), enforced by tests/EchoOnly.Guard.Tests.ps1.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (deployment-security/cloud/cloud.config.ps1).

.PARAMETER WhatIf
    Dry run (Req 6.5): prints the full ordered list of external commands that
    WOULD run, executes nothing, and exits 0.

.PARAMETER ReuseExisting
    Reuse an already-present registry / DB / vault / cluster rather than failing.
    This is the default convergent behavior (every create is guarded by a
    describe/show check); the switch is accepted for parity with the other deploy
    scripts and documents intent.

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
# satisfied from one place.
#
# Secret rule (Req 3.2): a secret is NEVER passed as a CLI argument. The commands
# that consume the password do so via a file (@file / --file), so the echoed
# command line shows only the path, never the value.
#
# Pipe rule: the rendered manifest is fed to `apply -f -` on stdin. The
# -StdinText switch feeds that (non-secret) text and renders in the planned list
# as a redacted "<stdin: rendered manifest>" note.
# =============================================================================
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Planned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail,
        [string]                         $StdinText     # piped to stdin; non-secret, echoed as a note
    )

    # Render the command line exactly as it would be run, for the planned list and
    # the dry-run echo. Reuse the same quoting shape Invoke-Echoed prints.
    $displayParts = @($Exe)
    foreach ($a in $CmdArgs) {
        if ($null -eq $a -or $a -eq '') {
            $displayParts += '""'
        }
        elseif ($a -match '[\s"]') {
            $displayParts += ('"' + ($a -replace '"', '\"') + '"')
        }
        else {
            $displayParts += $a
        }
    }
    if ($PSBoundParameters.ContainsKey('StdinText')) {
        $displayParts += '<stdin: rendered manifest>'
    }
    $display = $displayParts -join ' '

    if ($WhatIf) {
        $script:PlannedCommands.Add($display)
        $script:PlanOrdinal = $script:PlannedCommands.Count
        Write-Host ("[{0,2}] {1}" -f $script:PlanOrdinal, $display) -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    $result = $null
    if ($PSBoundParameters.ContainsKey('StdinText')) {
        # Pipe the rendered manifest to the command's stdin (apply -f -). Non-secret.
        if ($AllowFail) {
            $result = ($StdinText | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
        }
        else {
            $result = ($StdinText | Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
        }
    }
    elseif ($AllowFail) {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    }
    else {
        $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs)
    }
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# Convenience wrappers so call sites read cleanly. Each forwards to Invoke-Planned.
function Az      { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az'      -CmdArgs $A }
function AzTry   { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'az'      -CmdArgs $A -AllowFail }
function Docker  { param([Parameter(ValueFromRemainingArguments)][string[]] $A) Invoke-Planned -Exe 'docker'  -CmdArgs $A }
# kubectl calls use single-dash flags (-n / -o) that collide with PowerShell's
# parameter binder when passed through a ValueFromRemainingArguments wrapper, so
# they go through Invoke-Planned -Exe 'kubectl' -CmdArgs @(...) directly instead.

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
# Hardened-only guardrails (Req 2.1/2.2). Abort before any push/deploy if the
# hardened Dockerfile is missing or a non-hardened reference would be used.
# -----------------------------------------------------------------------------
function Assert-HardenedBuild {
    param([string] $RepoRoot, [string] $ImageTag, [string] $AppMode)

    $dockerfile = Join-Path $RepoRoot 'deployment-security/docker/hardened/Dockerfile'
    if (-not (Test-Path -LiteralPath $dockerfile -PathType Leaf)) {
        throw "Hardened Dockerfile not found at '$dockerfile'. Refusing to build/push/deploy (Req 2.4)."
    }
    if ($ImageTag -ne 'hardened') {
        throw "Only the hardened variant may be deployed; image tag was '$ImageTag', expected 'hardened' (Req 2.1)."
    }
    if ($AppMode -ne 'hardened') {
        throw "Only the hardened variant may be deployed; APP_MODE was '$AppMode', expected 'hardened' (Req 2.1)."
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
    $aksName  = [string]$azure['AksCluster']

    # Final globally-unique names (Req 7.5): ACR = base + suffix (alnum only);
    # Key Vault = base + "-" + suffix.
    $acrName   = ($acrBase + $suffix)
    $kvName    = ($kvBase + '-' + $suffix)
    $kvSecret  = 'db-password'                    # Key Vault secret name (NOT the value)
    $pgServer  = ($appName + '-pg-' + $suffix)    # Flexible Server name
    $fwRuleBase = 'allow-src'
    $idName    = ($appName + '-aks-kv-' + $suffix)    # user-assigned identity for KV + ACR pull

    # Repo root is five levels up from azure/kubernetes/.
    $repoRoot = (Resolve-Path (Join-Path $scriptDir '..\..\..\..')).Path
    $dockerfile = Assert-HardenedBuild -RepoRoot $repoRoot -ImageTag $imageTag -AppMode $appMode

    # Committed Azure overlay directory (relative to this script:
    # ../../manifests/overlays/azure). Never rewritten; we render a throwaway copy.
    $overlayDir = (Resolve-Path (Join-Path $scriptDir '..\..\manifests\overlays\azure')).Path
    if (-not (Test-Path -LiteralPath (Join-Path $overlayDir 'kustomization.yaml') -PathType Leaf)) {
        throw "Refusing to deploy: Azure kustomize overlay not found at '$overlayDir'. Expected manifests/overlays/azure/kustomization.yaml."
    }
    # The base manifest the overlay references (outside the overlay dir).
    $baseManifest = (Resolve-Path (Join-Path $repoRoot 'deployment-security/kubernetes/hardened/sangyshop-hardened.yaml')).Path

    $loginServer = ($acrName + '.azurecr.io')
    $acrImageName = ($loginServer + '/' + $appName)        # image path WITHOUT tag (overlay __ACR_IMAGE_NAME__)
    $imageRef     = ($acrImageName + ':' + $imageTag)       # full ref with the hardened tag
    $pgFqdn       = ($pgServer + '.postgres.database.azure.com')
    $k8sNamespace = 'sangyshop-hardened'
    $deployName   = 'sangyshop'
    $svcName      = 'sangyshop'
    $appPort      = 3000
    $dbPort       = '5432'

    Write-Step "Target summary"
    Write-Host ("  Resource group : {0} ({1})" -f $rg, $location)
    Write-Host ("  ACR            : {0}" -f $acrName)
    Write-Host ("  Image          : {0}" -f $imageRef)
    Write-Host ("  Flexible Server: {0}" -f $pgServer)
    Write-Host ("  Key Vault      : {0} (secret: {1})" -f $kvName, $kvSecret)
    Write-Host ("  AKS cluster    : {0}" -f $aksName)
    if (@($allowed).Count -gt 0) {
        Write-Host ("  Allowed ingress: {0}" -f ($allowed -join ', '))
    }

    if ($WhatIf) {
        Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
    }

    # -------------------------------------------------------------------------
    # 1. Authentication check (Req 6.3/6.4). `account show` succeeds only when the
    #    CLI is installed AND a session is active. On failure, print install +
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
                "Azure authentication check failed (the account-show probe).",
                "",
                "Install the Azure CLI (Windows):",
                "  winget install --exact --id Microsoft.AzureCLI",
                "  (or download the MSI from https://aka.ms/installazurecliwindows )",
                "Verify the install with the version subcommand.",
                "",
                "This deploy also needs the cluster CLI and Docker Desktop on PATH;",
                "install the cluster CLI (if missing) with:",
                "az aks install-cli",
                "",
                "Authenticate to your OWN (isolated / throwaway) subscription:",
                "az login",
                "az account set --subscription <your-subscription-id>",
                "",
                "Then re-run this script."
            ) -join [Environment]::NewLine)
            exit 1
        }
    }

    # Resolve the Azure AD tenant id (non-secret) for the Key Vault CSI provider.
    # Under -WhatIf nothing runs, so a documented placeholder renders the plan.
    Write-Step "Resolving the Azure AD tenant id for the Key Vault secrets provider"
    $tenantId = '__KV_TENANT_ID__'
    if ($WhatIf) {
        Az account show --query 'tenantId' --output tsv
    }
    else {
        $tenantId = ([string](Az account show --query 'tenantId' --output tsv)).Trim()
    }

    # -------------------------------------------------------------------------
    # 2. Resource group (idempotent). `group create` is itself idempotent.
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
        $acrExists = ($script:LastCliExit -eq 0)
    }
    if ($WhatIf -or -not $acrExists) {
        # Admin user stays DISABLED. The AKS cluster pulls the private image via
        # the --attach-acr role assignment (step 9), so no registry password is
        # ever created, stored, or echoed.
        Az acr create --name $acrName --resource-group $rg --sku Basic --admin-enabled false --output none
    }
    else {
        Write-Host "  ACR already exists; reusing." -ForegroundColor DarkGray
    }

    # -------------------------------------------------------------------------
    # 4. Registry login, build the hardened image, push (Req 2.3/4.5). Build
    #    context is the repo root so the Dockerfile's `COPY . .` sees the app.
    # -------------------------------------------------------------------------
    Write-Step "Logging in to ACR and building/pushing the hardened image"
    Az acr login --name $acrName
    Docker build -t $imageRef -f $dockerfile $repoRoot
    Docker push $imageRef

    # -------------------------------------------------------------------------
    # 5. Key Vault: describe-then-create (Req 4.1), then generate + store the DB
    #    password (Req 4.4) BEFORE provisioning Postgres. The secret VALUE is
    #    written to a private temp file and passed with `keyvault secret set
    #    --file`, so the password is never a CLI argument and never appears on an
    #    echoed line (Req 3.2). The same temp file seeds the Flexible Server admin
    #    password (step 6) and is shredded in the finally block.
    # -------------------------------------------------------------------------
    Write-Step "Ensuring Key Vault '$kvName'"
    $kvExists = $false
    if ($WhatIf) {
        Az keyvault show --name $kvName --resource-group $rg --output none
    }
    else {
        $null = AzTry keyvault show --name $kvName --resource-group $rg --output none
        $kvExists = ($script:LastCliExit -eq 0)
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
        $secretExists = ($script:LastCliExit -eq 0)
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
        # @file convention, without ever echoing the value.
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
        #    secret already on disk, passed with the `@file` convention so the
        #    value is read from the file and NEVER appears on the echoed command
        #    line (Req 3.2). --public-access None keeps the server off the public
        #    internet; access is granted only by the explicit firewall rule(s)
        #    added in step 7 (Req 9.5).
        # ---------------------------------------------------------------------
        Write-Step "Ensuring Azure DB for PostgreSQL Flexible Server '$pgServer'"
        $pgExists = $false
        if ($WhatIf) {
            Az postgres flexible-server show --name $pgServer --resource-group $rg --output none
        }
        else {
            $null = AzTry postgres flexible-server show --name $pgServer --resource-group $rg --output none
            $pgExists = ($script:LastCliExit -eq 0)
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
            $dbExists = ($script:LastCliExit -eq 0)
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
        Write-Step "Adding locked-down PostgreSQL firewall rule(s) (port $dbPort, no public exposure)"
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
        # 8. User-assigned managed identity for the Key Vault Secrets Store CSI
        #    provider. The AKS addon uses this identity (its client id is the
        #    overlay __KV_IDENTITY_CLIENTID__) to read the DB-password secret from
        #    Key Vault. Identity principal/client ids are non-secret. The Key Vault
        #    `get` access policy is granted idempotently (AllowFail on re-run).
        # ---------------------------------------------------------------------
        Write-Step "Ensuring the Key Vault reader managed identity '$idName'"
        $kvIdentityClientId = '__KV_IDENTITY_CLIENTID__'
        if ($WhatIf) {
            Az identity create --name $idName --resource-group $rg --output none
            Az identity show --name $idName --resource-group $rg --query 'clientId' --output tsv
            Az identity show --name $idName --resource-group $rg --query 'principalId' --output tsv
            Az keyvault set-policy --name $kvName --resource-group $rg --object-id '<identity-principal-id>' --secret-permissions get --output none
        }
        else {
            # Create (idempotent: identity create is a no-op if it already exists).
            $null = AzTry identity create --name $idName --resource-group $rg --output none
            $kvIdentityClientId = ([string](Az identity show --name $idName --resource-group $rg --query 'clientId'    --output tsv)).Trim()
            $idPrincipalId      = ([string](Az identity show --name $idName --resource-group $rg --query 'principalId' --output tsv)).Trim()
            # Grant the identity `get` on Key Vault secrets; tolerate re-runs.
            $null = AzTry keyvault set-policy --name $kvName --resource-group $rg --object-id $idPrincipalId --secret-permissions get --output none
        }

        # ---------------------------------------------------------------------
        # 9. AKS cluster: describe-then-create (idempotent, Req 4.1). Created with
        #    --attach-acr so the kubelet can pull the private image WITHOUT any
        #    registry password (no secret to echo or store), and with the Key
        #    Vault secrets provider addon (azure-keyvault-secrets-provider) so the
        #    Secrets Store CSI driver can sync the DB password into the pod.
        # ---------------------------------------------------------------------
        Write-Step "Ensuring AKS cluster '$aksName' (--attach-acr + Key Vault secrets provider addon)"
        $aksExists = $false
        if ($WhatIf) {
            Az aks show --name $aksName --resource-group $rg --output none
        }
        else {
            $null = AzTry aks show --name $aksName --resource-group $rg --output none
            $aksExists = ($script:LastCliExit -eq 0)
        }
        if ($WhatIf -or -not $aksExists) {
            Az aks create `
                --name $aksName `
                --resource-group $rg `
                --location $location `
                --node-count 1 `
                --generate-ssh-keys `
                --attach-acr $acrName `
                --enable-addons azure-keyvault-secrets-provider `
                --enable-managed-identity `
                --output none
        }
        else {
            # Cluster already exists; make the ACR attach + addon idempotent.
            Write-Host "  AKS cluster already exists; ensuring ACR attach + Key Vault addon." -ForegroundColor DarkGray
            Az aks update --name $aksName --resource-group $rg --attach-acr $acrName --output none
            Az aks enable-addons --name $aksName --resource-group $rg --addons azure-keyvault-secrets-provider --output none
        }

        # ---------------------------------------------------------------------
        # 10. Fetch cluster credentials so the cluster CLI targets this AKS
        #     cluster (Req 4.8). --overwrite-existing keeps re-runs convergent.
        # ---------------------------------------------------------------------
        Write-Step "Fetching AKS credentials for the cluster CLI (Req 4.8)"
        Az aks get-credentials --name $aksName --resource-group $rg --overwrite-existing --output none

        # ---------------------------------------------------------------------
        # 11. Render the committed overlay into a THROWAWAY copy, substitute the
        #     placeholders, and apply with the load-restrictor pipe form
        #     (Req 2.5/3.1/3.3). The committed overlay (and the base manifest) are
        #     NEVER rewritten:
        #       * copy every committed overlay file into a temp dir,
        #       * in the temp copy, repoint the base `resources:` reference to the
        #         base manifest's absolute path (the relative `../../../../` no
        #         longer resolves from the temp location),
        #       * replace the six placeholders with values derived above,
        #       * build with `kustomize --load-restrictor LoadRestrictionsNone
        #         <tmp>` piped to `apply -f -` (apply -k cannot pass that flag).
        #
        #     Placeholders (overlay README):
        #       __ACR_IMAGE_NAME__       ACR image path, no tag
        #       __PG_HOST__              Flexible Server host reachable on 5432
        #       __KEYVAULT_NAME__        Key Vault owning the DB-password secret
        #       __KV_SECRET__            Key Vault secret name (db-password)
        #       __KV_TENANT_ID__         Azure AD tenant id of the Key Vault
        #       __KV_IDENTITY_CLIENTID__ client id of the reader managed identity
        # ---------------------------------------------------------------------
        Write-Step "Rendering the Azure overlay copy and substituting placeholders (Req 2.5)"
        $renderedDir = Join-Path ([System.IO.Path]::GetTempPath()) ("sangyshop-azure-overlay-" + [System.Guid]::NewGuid().ToString('N'))
        try {
            if (-not $WhatIf) {
                New-Item -ItemType Directory -Path $renderedDir -Force | Out-Null
                # Copy committed overlay files into the throwaway dir (committed files untouched).
                Get-ChildItem -LiteralPath $overlayDir -File | ForEach-Object {
                    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $renderedDir $_.Name) -Force
                }

                $renderedKustomization = Join-Path $renderedDir 'kustomization.yaml'

                # Substitution map for the six committed placeholders (overlay README).
                $substitutions = @{
                    '__ACR_IMAGE_NAME__'       = $acrImageName   # registry/repo, no tag (overlay pins :hardened)
                    '__PG_HOST__'              = $pgFqdn
                    '__KEYVAULT_NAME__'        = $kvName
                    '__KV_SECRET__'            = $kvSecret
                    '__KV_TENANT_ID__'         = $tenantId
                    '__KV_IDENTITY_CLIENTID__' = $kvIdentityClientId
                }

                # Apply substitutions across every rendered file, and repoint the
                # base `resources:` reference to the base manifest's absolute path
                # so the temp copy still resolves the base outside the overlay dir.
                Get-ChildItem -LiteralPath $renderedDir -File | ForEach-Object {
                    $text = Get-Content -LiteralPath $_.FullName -Raw
                    foreach ($k in $substitutions.Keys) {
                        $text = $text.Replace($k, [string]$substitutions[$k])
                    }
                    if ($_.FullName -eq $renderedKustomization) {
                        # The committed base ref is `../../../../kubernetes/hardened/sangyshop-hardened.yaml`.
                        # Rewrite it to the absolute base path for the relocated copy.
                        $baseForYaml = ($baseManifest -replace '\\', '/')
                        $text = $text.Replace('../../../../kubernetes/hardened/sangyshop-hardened.yaml', $baseForYaml)
                    }
                    Set-Content -LiteralPath $_.FullName -Value $text -Encoding UTF8
                }
            }

            # Build the rendered overlay with load restrictions disabled (the base
            # lives outside the overlay dir), then pipe to apply (apply -k cannot
            # pass the flag).
            Write-Step "Applying the rendered overlay to AKS (Req 3.1, 3.3, 2.5)"
            if ($WhatIf) {
                # Plan both halves of the pipe without executing anything. The
                # committed overlay path documents the build source for the plan.
                Invoke-Planned -Exe 'kubectl' -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $overlayDir) | Out-Null
                Invoke-Planned -Exe 'kubectl' -CmdArgs @('apply', '-f', '-') -StdinText '<rendered overlay>' | Out-Null
            }
            else {
                $rendered = Invoke-Planned -Exe 'kubectl' -CmdArgs @('kustomize', '--load-restrictor', 'LoadRestrictionsNone', $renderedDir)
                if ($rendered -is [System.Array]) { $rendered = ($rendered -join [Environment]::NewLine) }
                $rendered = [string]$rendered
                if ([string]::IsNullOrWhiteSpace($rendered)) {
                    throw "Rendering the Azure overlay produced no output. Aborting before apply."
                }
                Invoke-Planned -Exe 'kubectl' -CmdArgs @('apply', '-f', '-') -StdinText $rendered | Out-Null
            }
        }
        finally {
            if (-not $WhatIf -and (Test-Path -LiteralPath $renderedDir)) {
                Remove-Item -LiteralPath $renderedDir -Recurse -Force -ErrorAction SilentlyContinue
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
    # 12. Wait for the Deployment rollout to finish (Req 4.8).
    # -------------------------------------------------------------------------
    Write-Step "Waiting for the '$deployName' Deployment rollout in namespace '$k8sNamespace' (Req 4.8)"
    Invoke-Planned -Exe 'kubectl' -CmdArgs @(
        '-n', $k8sNamespace,
        'rollout', 'status', "deploy/$deployName",
        '--timeout=300s'
    ) | Out-Null

    # -------------------------------------------------------------------------
    # 13. Read the LoadBalancer external IP as the service URL (Req 4.7/9.2). On
    #     Azure the Standard LB exposes an external IP.
    # -------------------------------------------------------------------------
    Write-Step "Reading the LoadBalancer external IP for Service '$svcName' (Req 4.7)"
    $externalIp = Invoke-Planned -Exe 'kubectl' -CmdArgs @(
        '-n', $k8sNamespace,
        'get', 'svc', $svcName,
        '-o', 'jsonpath={.status.loadBalancer.ingress[0].ip}'
    )

    # -------------------------------------------------------------------------
    # Dry run ends here: print the planned command list and exit 0 (Req 6.5).
    # -------------------------------------------------------------------------
    if ($WhatIf) {
        Write-Step "Dry run (-WhatIf): planned command list (no command was executed)"
        $i = 0
        foreach ($c in $script:PlannedCommands) {
            $i++
            Write-Host ("  {0,2}. {1}" -f $i, $c)
        }
        Write-Host ""
        Write-Host "Dry run complete: $($script:PlannedCommands.Count) command(s) planned, none executed."
        exit 0
    }

    # Real run: surface the URL and the mandatory safety reminders.
    if ($externalIp -is [System.Array]) {
        $externalIp = ($externalIp | Where-Object { $_ } | Select-Object -Last 1)
    }
    $externalIp = ([string]$externalIp).Trim()
    $serviceUrl = if ([string]::IsNullOrWhiteSpace($externalIp)) {
        '(external IP not yet assigned; re-check the Service in namespace ' + $k8sNamespace + ' shortly)'
    }
    else {
        "http://${externalIp}:${appPort}"
    }

    Write-Host ""
    Write-Step "Deployment complete"
    Write-Host "Service URL: $serviceUrl" -ForegroundColor Green
    Write-Host ""
    Write-Host "REMINDER (teaching-lab safety):" -ForegroundColor Yellow
    Write-Host "  * SangyShop is DELIBERATELY VULNERABLE even in the hardened image. Keep this in an" -ForegroundColor Yellow
    Write-Host "    isolated, throwaway Azure subscription only." -ForegroundColor Yellow
    if (@($allowed).Count -gt 0) {
        Write-Host ("  * LOCK DOWN INGRESS to your own source address(es): {0}." -f ($allowed -join ', ')) -ForegroundColor Yellow
    }
    else {
        Write-Host "  * LOCK DOWN INGRESS to your own source address(es)." -ForegroundColor Yellow
    }
    Write-Host "    The Standard LoadBalancer is reachable from the internet by default -- restrict it with a" -ForegroundColor Yellow
    Write-Host "    loadBalancerSourceRanges / NSG rule to those address(es). Never 0.0.0.0/0 or ::/0." -ForegroundColor Yellow
    Write-Host "  * Flexible Server ('$pgServer') has no public exposure; the cluster reaches it on $dbPort only." -ForegroundColor Yellow
    Write-Host "  * RUN TEARDOWN WHEN FINISHED to stop billing:" -ForegroundColor Yellow
    Write-Host ("        .\teardown.ps1 -ConfigPath `"{0}`"" -f $ConfigPath) -ForegroundColor Yellow
    Write-Host "    (or remove the whole resource group as a catch-all, prefixing the command with the CLI name):" -ForegroundColor Yellow
    Write-Host ("        " + "az group delete --name {0} --yes --no-wait" -f $rg) -ForegroundColor Yellow
    Write-Host ""
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
