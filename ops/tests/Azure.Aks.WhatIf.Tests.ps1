<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the Azure Kubernetes (AKS)
    scripts (azure/aks/deploy.ps1 and azure/aks/teardown.ps1).

.DESCRIPTION
    Covers task 12.4 of the multi-cloud-deploy plan. Each script is executed with
    -WhatIf in a CHILD PowerShell process whose PATH is both (a) stripped of every
    real cloud CLI directory and (b) seeded with a set of POISONED az/docker/
    kubectl .cmd shims that, if they are ever invoked, print a unique marker and
    exit 1. This gives a doubly-protected "no cloud" sandbox: the real CLIs are
    unreachable, and any accidental external call to a stubbed name surfaces the
    marker in captured output (which we assert is ABSENT). That is a direct proof
    that the dry run "executes NO external command" (Req 6.5). Modeled on
    Azure.Aci.WhatIf.Tests.ps1 (the poisoned-stub PATH sandbox) and
    Gcp.Kubernetes.WhatIf.Tests.ps1 (the $TestDrive config .ps1 + planned-list
    transcript parser).

    Both scripts print their dry-run plan in two forms:
      * each planned external call is echoed live as "[ n] <exe ...>" via
        Invoke-Planned, and
      * deploy.ps1 additionally re-prints the full ordered list after the
        "planned command list" banner as "  n. <command>".
    We parse the "  n. <command>" list for deploy where available and otherwise
    assert on the merged output / the "[ n]" ordinals.

    deploy.ps1 (Req 6.5, 3.1, 3.3):
      * Runs with -WhatIf and exits 0 with NO cloud CLI installed. The azure
        deploy's Assert-AllowedSourceRanges tolerates a missing -AllowedSourceRanges
        under -WhatIf (it prints a NOTE and returns), so `-WhatIf` alone suffices;
        if that ever regresses the Invoke-WhatIfScript helper retries once with a
        safe -AllowedSourceRanges '203.0.113.7/32'.
      * Prints the ordered, numbered command list and executes NOTHING external
        (no poisoned-stub marker appears).
      * Plans the full AKS pipeline in order:
          - az account show                              (auth check)
          - az acr show / az acr create                  (Azure Container Registry)
          - az acr login
          - docker build / docker push                   (hardened image)
          - az keyvault secret set ... --file            (DB password by file only)
          - az postgres flexible-server create ... --public-access None
          - az identity create                           (KV reader managed identity)
          - az aks show / az aks create ... --attach-acr ...
              --enable-addons azure-keyvault-secrets-provider
          - az aks get-credentials
          - kubectl kustomize --load-restrictor LoadRestrictionsNone
          - kubectl apply -f -                           (rendered overlay on stdin)
          - kubectl ... rollout status deploy/sangyshop
          - kubectl ... get svc ... (external IP read)
      * No DB_PASSWORD env token appears anywhere (CASE-SENSITIVE -CNotMatch): the
        lowercase /run/secrets/db_password file path and the lowercase Key Vault
        objectAlias db_password are both correct and allowed; only the uppercase
        env-var form DB_PASSWORD is forbidden (Req 3.1). The password value is
        never on a command line: the dry run renders secret-bearing steps with a
        <generated-password-file> placeholder only.
      * A STATIC read of deploy.ps1 confirms (a) the Key Vault secret is delivered
        by `az keyvault secret set --file` (never on a command line) and (b) the
        committed Azure overlay keeps the /run/secrets/db_password file contract,
        which deploy renders via placeholder substitution. Because the secret file
        path lives in the overlay (not the dry-run command stream), this static
        assertion supplements the output assertions for the YAML-carried contract.

    teardown.ps1 (Req 6.5):
      * Runs with -WhatIf; exits 0.
      * Prints the ordered command list and executes NOTHING external. Plans the
        reverse-order deletes: kubectl overlay delete + namespace delete,
        az aks delete, az postgres flexible-server delete, az keyvault secret /
        vault delete, az identity delete, az acr delete -- with an ordering check
        that the in-cluster workload drains before the cluster and the registry is
        removed last.

    Requires Pester 5.x or 6.x (6.2 is installed here). Windows PowerShell 5.1
    compatible. Everything runs on Windows with NO cloud access. Run with:
        Invoke-Pester -Path ops/tests/Azure.Aks.WhatIf.Tests.ps1
#>

BeforeAll {
    # ---- Locate the two scripts under test (do NOT edit them). --------------
    # tests/ sits directly under ops/; the Azure AKS scripts are two
    # folders deeper under azure/aks/.
    $script:CloudRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:DeployScript  = (Resolve-Path (Join-Path $script:CloudRoot 'azure' 'aks' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $script:CloudRoot 'azure' 'aks' 'teardown.ps1')).Path

    # ---- Author a valid Azure config as a .ps1 returning @{ ... } under TestDrive.
    # No secret fields (Get-CloudConfig rejects them); suffix is 3-24 lower-alnum.
    $script:ConfigPath = Join-Path $TestDrive 'cloud.config.ps1'
    @'
@{
    UniqueSuffix = 'abc12345'
    Common = @{
        AppName  = 'sangyshop'
        DbName   = 'sangyshop'
        DbUser   = 'sangyshop'
        ImageTag = 'hardened'
    }
    Azure = @{
        Location      = 'eastus'
        ResourceGroup = 'sangyshop-lab-rg'
        AcrNameBase   = 'sangyshoplab'
        KeyVaultBase  = 'sangyshop-kv'
        AciName       = 'sangyshop-lab-aci'
        AksCluster    = 'sangyshop-lab-aks'
    }
}
'@ | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8

    # ---- Build an isolated "no cloud CLI" sandbox under TestDrive. ----------
    # Strip the real cloud CLIs from PATH and plant poisoned shims named
    # az/docker/kubectl that, if ever invoked, print a unique marker and exit 1.
    # The dry-run run is doubly protected: the real CLIs are unreachable, and any
    # accidental external call to a stubbed name surfaces the marker in output
    # (which we assert is ABSENT). This verifies "executes NO external command".
    $script:StubDir = Join-Path $TestDrive 'stubbin'
    New-Item -ItemType Directory -Path $script:StubDir -Force | Out-Null
    $script:PoisonMarker = 'EXTERNAL_CLI_WAS_INVOKED_UNEXPECTEDLY'
    foreach ($cli in 'az', 'docker', 'kubectl') {
        # .cmd shim (child process powershell.exe on Windows -> resolves .cmd).
        $cmdPath = Join-Path $script:StubDir ($cli + '.cmd')
        "@echo off`r`necho $script:PoisonMarker $cli %*`r`nexit /b 1" |
            Set-Content -LiteralPath $cmdPath -Encoding ASCII
    }

    # Helper: run a script with -WhatIf in a CHILD powershell process whose PATH
    # contains ONLY the poisoned-stub dir plus the minimum system dirs needed to
    # launch powershell itself (System32). This guarantees no real az/docker/
    # kubectl is reachable. Returns ExitCode, Text (merged stdout+stderr), and
    # Lines (the merged output split into strings).
    #
    # The azure deploy's Assert-AllowedSourceRanges tolerates a missing
    # -AllowedSourceRanges under -WhatIf, so `-WhatIf` alone should exit 0. If a
    # future change makes it error without the parameter, we retry ONCE with a
    # safe non-world-open -AllowedSourceRanges so the dry-run plan is still
    # exercised.
    function Invoke-WhatIfScript {
        param(
            [Parameter(Mandatory)][string] $ScriptPath,
            [string[]] $ExtraArgs = @(),
            [switch]   $RetryWithRanges
        )

        $sysRoot   = $env:SystemRoot
        if ([string]::IsNullOrWhiteSpace($sysRoot)) { $sysRoot = 'C:\Windows' }
        $system32  = Join-Path $sysRoot 'System32'
        $wps       = Join-Path $system32 'WindowsPowerShell\v1.0'
        # PATH = only the poisoned stub dir + what is needed to start powershell.
        $sandboxPath = ($script:StubDir, $system32, $wps) -join ';'

        $psArgs = @(
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-File', $ScriptPath
            '-ConfigPath', $script:ConfigPath
            '-WhatIf'
        ) + $ExtraArgs

        $savedPath = $env:Path
        try {
            $env:Path = $sandboxPath
            # Use Windows PowerShell explicitly so the 5.1-targeted scripts run
            # under their intended host. Capture stdout AND stderr together.
            $raw  = & powershell @psArgs *>&1
            $code = $LASTEXITCODE
        }
        finally {
            $env:Path = $savedPath
        }

        $text  = ($raw | Out-String)
        $lines = @($raw | ForEach-Object { [string]$_ })

        # Fallback: if -WhatIf alone unexpectedly errored, retry once with a safe
        # ingress set. (Not expected for the azure deploy under -WhatIf.)
        if ($code -ne 0 -and $RetryWithRanges -and ($ExtraArgs -notcontains '-AllowedSourceRanges')) {
            return Invoke-WhatIfScript -ScriptPath $ScriptPath -ExtraArgs (@('-AllowedSourceRanges', '203.0.113.7/32') + $ExtraArgs)
        }

        return [pscustomobject]@{
            ExitCode = $code
            Text     = $text
            Lines    = $lines
        }
    }

    # Pull the planned command lines from deploy's dry-run transcript. deploy.ps1
    # re-prints the ordered list as "  <n>. <command>" after the "planned command
    # list" banner. Returns each command text with the numeric prefix stripped.
    function Get-PlannedCommands {
        param([Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]] $Lines)
        $planned = New-Object System.Collections.Generic.List[string]
        $inList  = $false
        foreach ($line in $Lines) {
            if ($line -match 'planned command list') { $inList = $true; continue }
            if (-not $inList) { continue }
            if ($line -match '^\s*\d+\.\s+(.+)$') {
                $planned.Add($Matches[1].Trim())
            }
        }
        return , $planned.ToArray()
    }
}

Describe 'Azure Kubernetes deploy.ps1 -WhatIf dry run (Req 6.5, 3.1, 3.3)' {
    BeforeAll {
        # -WhatIf alone should exit 0 (Assert-AllowedSourceRanges tolerates the
        # missing ingress set in dry-run); retry with a safe CIDR only if needed.
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -RetryWithRanges
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
    }

    Context 'preconditions' {
        It 'the deploy script exists' {
            Test-Path -LiteralPath $script:DeployScript | Should -BeTrue
        }
        It 'the temp Azure config exists under TestDrive' {
            Test-Path -LiteralPath $script:ConfigPath | Should -BeTrue
        }
    }

    It 'exits 0 under -WhatIf with no cloud CLI installed' {
        $script:Deploy.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Deploy.Text)
    }

    It 'executes NO external cloud CLI (no poisoned-stub marker in output)' {
        # If the script had shelled out to az/docker/kubectl, the poisoned stub
        # would have printed the marker. Its absence proves nothing external ran.
        $script:Deploy.Text | Should -Not -Match $script:PoisonMarker
    }

    It 'announces the dry run and reports that nothing executed' {
        $script:Deploy.Text | Should -Match 'DRY RUN'
        $script:Deploy.Text | Should -Match 'none executed'
    }

    It 'prints an ordered, numbered command list (the [ n] live echo)' {
        # Invoke-Planned prefixes each planned command with "[ n]". The full AKS
        # pipeline is long, so many ordinals must be present.
        $ordinals = [regex]::Matches($script:Deploy.Text, '(?m)^\s*\[\s*\d+\]\s')
        $ordinals.Count | Should -BeGreaterThan 5 -Because (
            "the full ordered command list should be printed. Output:`n" + $script:Deploy.Text)
    }

    It 'prints the re-listed ordered plan after the banner' {
        $script:Deploy.Text | Should -Match 'planned command list'
        $script:DeployPlanned.Count | Should -BeGreaterThan 5
    }

    It 'plans the az authentication check' {
        ($script:DeployPlanned -join "`n") | Should -Match 'az account show'
    }

    It 'plans the ACR describe-or-create' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'az acr show'
        $joined | Should -Match 'az acr create'
    }

    It 'plans the ACR login' {
        ($script:DeployPlanned -join "`n") | Should -Match 'az acr login'
    }

    It 'plans the hardened image docker build and push' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'docker build'
        $joined | Should -Match 'docker push'
    }

    It 'plans the Key Vault secret set via --file (value never on the command line)' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'az keyvault secret set'
        # The secret is delivered by file, so a placeholder --file path appears,
        # never the password value.
        $joined | Should -Match 'keyvault secret set .*--file'
    }

    It 'plans the Flexible Server create kept off the public internet' {
        $createLine = $script:DeployPlanned |
            Where-Object { $_ -match 'az postgres flexible-server create' } |
            Select-Object -First 1
        $createLine | Should -Not -BeNullOrEmpty
        # --public-access None keeps the managed Postgres off the public internet.
        $createLine | Should -Match '--public-access None'
    }

    It 'plans the Key Vault reader managed identity create' {
        ($script:DeployPlanned -join "`n") | Should -Match 'az identity create'
    }

    It 'plans the AKS describe-or-create with --attach-acr and the Key Vault secrets provider addon' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'az aks show'
        $createLine = $script:DeployPlanned |
            Where-Object { $_ -match 'az aks create' } |
            Select-Object -First 1
        $createLine | Should -Not -BeNullOrEmpty
        $createLine | Should -Match '--attach-acr'
        $createLine | Should -Match '--enable-addons azure-keyvault-secrets-provider'
    }

    It 'plans fetching the AKS cluster credentials' {
        ($script:DeployPlanned -join "`n") | Should -Match 'az aks get-credentials'
    }

    It 'plans the overlay render with the load-restrictor pipe form and the apply' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'kubectl kustomize --load-restrictor LoadRestrictionsNone'
        $joined | Should -Match 'kubectl apply -f -'
    }

    It 'plans the rollout wait and the external IP read' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'rollout status deploy/sangyshop'
        # The AKS Standard LoadBalancer exposes an external IP, read via jsonpath.
        $joined | Should -Match 'get svc sangyshop'
        $joined | Should -Match 'loadBalancer\.ingress\[0\]\.ip'
    }

    It 'orders the pipeline correctly (auth -> acr -> build -> keyvault -> postgres -> aks create -> get-credentials -> apply)' {
        $authIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'az account show'                      | Select-Object -First 1).LineNumber
        $acrIdx    = ($script:DeployPlanned | Select-String -SimpleMatch 'az acr create'                        | Select-Object -First 1).LineNumber
        $buildIdx  = ($script:DeployPlanned | Select-String -SimpleMatch 'docker build'                         | Select-Object -First 1).LineNumber
        $kvIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'keyvault secret set'                  | Select-Object -First 1).LineNumber
        $pgIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'postgres flexible-server create'      | Select-Object -First 1).LineNumber
        $aksIdx    = ($script:DeployPlanned | Select-String -SimpleMatch 'az aks create'                        | Select-Object -First 1).LineNumber
        $credIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'aks get-credentials'                  | Select-Object -First 1).LineNumber
        $applyIdx  = ($script:DeployPlanned | Select-String -SimpleMatch 'kubectl apply -f -'                   | Select-Object -First 1).LineNumber

        $authIdx  | Should -BeLessThan $acrIdx
        $acrIdx   | Should -BeLessThan $buildIdx
        $buildIdx | Should -BeLessThan $kvIdx
        $kvIdx    | Should -BeLessThan $pgIdx
        $pgIdx    | Should -BeLessThan $aksIdx
        $aksIdx   | Should -BeLessThan $credIdx
        $credIdx  | Should -BeLessThan $applyIdx
    }

    It 'every planned line is an az, docker, or kubectl command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) {
            $cmd | Should -Match '^(az|docker|kubectl)\b'
        }
    }

    It 'sets NO DB_PASSWORD env token anywhere in the planned command set (Req 3.1)' {
        # CASE-SENSITIVE (-CNotMatch) on purpose: the lowercase Key Vault
        # objectAlias (db_password) and the lowercase /run/secrets/db_password
        # file path are both correct and required; only the uppercase env-var form
        # DB_PASSWORD is forbidden (Req 3.1).
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD'
        ($script:DeployPlanned -join "`n") | Should -Not -CMatch 'DB_PASSWORD'
    }

    It 'never reveals a generated password value (uses placeholder file paths only)' {
        # The dry run substitutes a <generated-password-file> placeholder for the
        # real secret file, proving the value is never put on a command line.
        $script:Deploy.Text | Should -Match '<generated-password-file>'
    }
}

Describe 'Azure Kubernetes deploy.ps1 static source assertions (secret delivery + file contract, Req 3.1/3.3)' {
    # The Key Vault secret FILE path (/run/secrets/db_password) is carried by the
    # committed Azure overlay (rendered + applied by deploy), so it cannot appear
    # in the dry-run command stream. We supplement the output assertions above
    # with static reads that document the intent the dry run cannot surface:
    #   (a) deploy delivers the Key Vault secret by `--file` (never on a line),
    #   (b) deploy renders the committed overlay via placeholder substitution, and
    #   (c) that overlay preserves the /run/secrets/db_password file contract.
    BeforeAll {
        $script:DeploySource = Get-Content -LiteralPath $script:DeployScript -Raw
        $script:OverlayDir   = (Resolve-Path (Join-Path $script:CloudRoot 'azure' 'aks' 'overlays')).Path
        $script:SecretProviderSource = Get-Content -LiteralPath (Join-Path $script:OverlayDir 'secret-provider-class.yaml') -Raw
        $script:DeployPatchSource    = Get-Content -LiteralPath (Join-Path $script:OverlayDir 'patch-deployment.yaml') -Raw
    }

    It 'delivers the Key Vault secret via `keyvault secret set --file` (value by file only)' {
        $script:DeploySource | Should -Match 'keyvault secret set[\s\S]*?--file'
    }

    It 'passes the secret file as an argument, never the secret value on the line' {
        # The real branch uses `--file $pwFile`; the dry-run branch uses the
        # <generated-password-file> placeholder. Either way it is a FILE, not the
        # value, on the command line.
        $script:DeploySource | Should -Match '--file\s+\$pwFile'
    }

    It 'renders the committed Azure overlay via placeholder substitution (never rewrites the committed files)' {
        # deploy copies the committed overlay to a throwaway dir and substitutes
        # placeholders there; assert both the substitution map and the Key Vault
        # placeholders exist.
        $script:DeploySource | Should -Match '__KEYVAULT_NAME__'
        $script:DeploySource | Should -Match '__KV_SECRET__'
        $script:DeploySource | Should -Match '\.Replace\('
    }

    It 'the committed overlay keeps the /run/secrets/db_password file contract' {
        # The CSI provider syncs the Key Vault secret into the sangyshop-db Secret
        # under key db_password; the base volume projects it to
        # /run/secrets/db_password, which the hardened app reads unchanged.
        $contract = $script:SecretProviderSource + "`n" + $script:DeployPatchSource
        $contract | Should -Match '/run/secrets/db_password'
        $script:SecretProviderSource | Should -Match 'db_password'
    }

    It 'adds NO DB_PASSWORD env entry in the deployment patch (secret stays a mounted file)' {
        # The patch documents in prose that "No DB_PASSWORD env is added"; the
        # contract we assert is the absence of an actual env list ENTRY named
        # DB_PASSWORD (i.e. a `- name: DB_PASSWORD` item), not the word appearing
        # in an explanatory comment. CASE-SENSITIVE on the uppercase env-var form.
        $script:DeployPatchSource | Should -Not -CMatch '(?m)^\s*-\s*name:\s*"?DB_PASSWORD"?'
    }
}

Describe 'Azure Kubernetes teardown.ps1 -WhatIf dry run (Req 6.5)' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript
    }

    It 'the teardown script exists' {
        Test-Path -LiteralPath $script:TeardownScript | Should -BeTrue
    }

    It 'exits 0 under -WhatIf with no cloud CLI installed' {
        $script:Teardown.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Teardown.Text)
    }

    It 'executes NO external cloud CLI (no poisoned-stub marker in output)' {
        $script:Teardown.Text | Should -Not -Match $script:PoisonMarker
    }

    It 'announces the dry run and reports that nothing executed' {
        $script:Teardown.Text | Should -Match 'DRY RUN'
        $script:Teardown.Text | Should -Match 'none executed'
    }

    It 'prints an ordered, numbered command list' {
        $ordinals = [regex]::Matches($script:Teardown.Text, '(?m)^\s*\[\s*\d+\]\s')
        $ordinals.Count | Should -BeGreaterThan 3 -Because (
            "the full ordered teardown command list should be printed. Output:`n" + $script:Teardown.Text)
    }

    It 'plans the reverse-order deletes (workload -> cluster -> postgres -> keyvault -> identity -> acr)' {
        $t = $script:Teardown.Text
        # In-cluster workload: rendered overlay delete piped on stdin + namespace.
        $t | Should -Match 'kubectl delete -f -'
        $t | Should -Match 'kubectl delete namespace sangyshop-hardened'
        $t | Should -Match 'az aks delete'
        $t | Should -Match 'az postgres flexible-server delete'
        $t | Should -Match 'az keyvault secret delete'
        $t | Should -Match 'az keyvault delete'
        $t | Should -Match 'az identity delete'
        $t | Should -Match 'az acr delete'
    }

    It 'drains the in-cluster workload before the cluster and removes the registry last' {
        $nsIdx       = ($script:Teardown.Lines | Select-String -SimpleMatch 'kubectl delete namespace'       | Select-Object -First 1).LineNumber
        $aksIdx      = ($script:Teardown.Lines | Select-String -SimpleMatch 'az aks delete'                  | Select-Object -First 1).LineNumber
        $pgIdx       = ($script:Teardown.Lines | Select-String -SimpleMatch 'postgres flexible-server delete' | Select-Object -First 1).LineNumber
        $kvIdx       = ($script:Teardown.Lines | Select-String -SimpleMatch 'az keyvault delete'             | Select-Object -First 1).LineNumber
        $idIdx       = ($script:Teardown.Lines | Select-String -SimpleMatch 'az identity delete'             | Select-Object -First 1).LineNumber
        $acrIdx      = ($script:Teardown.Lines | Select-String -SimpleMatch 'az acr delete'                  | Select-Object -First 1).LineNumber

        # The in-cluster workload drains before the control plane it runs on.
        $nsIdx  | Should -BeLessThan $aksIdx
        # Compute then DB then vault then identity.
        $aksIdx | Should -BeLessThan $pgIdx
        $pgIdx  | Should -BeLessThan $kvIdx
        $kvIdx  | Should -BeLessThan $idIdx
        # The native registry is removed LAST (Req 5.3).
        $idIdx  | Should -BeLessThan $acrIdx
    }

    It 'never leaks the DB_PASSWORD env token anywhere in the dry-run output' {
        # Case-sensitive: teardown does not touch the secret file, but keep the
        # guard that the uppercase env-var form never appears.
        $script:Teardown.Text | Should -Not -CMatch 'DB_PASSWORD'
    }
}
