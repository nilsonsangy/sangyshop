<#
.SYNOPSIS
    -WhatIf (dry-run) assertions for the Azure Docker-only (ACI) scripts
    azure/aci/deploy.ps1 and azure/aci/teardown.ps1.

.DESCRIPTION
    Exercises each script with -WhatIf and asserts the dry-run contract
 WITHOUT touching any cloud:

      * Running each script with -WhatIf prints the full ordered command list
        and executes NO external command. We run in a child powershell process
        whose PATH is stripped of every real cloud CLI directory AND is given a
        set of poisoned az/docker/kubectl shims that fail loudly if invoked, so
        if the script ever shelled out to a cloud CLI the run would error / the
        poisoned marker would appear. Under -WhatIf the script instead exits 0
        and prints its planned `az ...` / `docker ...` command lines, which we
        assert appear in captured stdout.

      * No DB_PASSWORD env appears anywhere in the planned command set. The
        azure deploy delivers the secret via an ACI YAML built ONLY in the
        non-WhatIf branch and handed to `az container create --file <...>`, so
        under -WhatIf we assert (a) the planned `az container create --file`
        step IS present and (b) the token "DB_PASSWORD" never appears anywhere
        in the dry-run output.

      * The secret volume targets /run/secrets/db_password. Because the ACI
        secret YAML (which maps the secret key `db_password` at mountPath
        `/run/secrets`) is only built in the real branch, it cannot appear in
        the dry-run output. We therefore assert the deploy script's INTENT two
        ways: (a) the dry-run plan contains the `az container create --file`
        step that would carry that YAML, and (b) a STATIC read of deploy.ps1
        confirms the secret volume maps key `db_password` at mountPath
        `/run/secrets` (yielding /run/secrets/db_password). We prefer asserting
        on the dry-run OUTPUT where possible and supplement with this static
        source assertion for the YAML-built secret mount.

    Requires Pester 5.x or 6.x (6.2 is installed). Run:
        Invoke-Pester -Path ops/tests/Azure.Aci.WhatIf.Tests.ps1

    Everything here runs on Windows with NO cloud access.
#>

BeforeAll {
    # ---- Locate the scripts under test (tests/ sits under ops/). ----
    $script:CloudRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:DeployPath  = Join-Path $script:CloudRoot 'azure\aci\deploy.ps1'
    $script:TeardownPath = Join-Path $script:CloudRoot 'azure\aci\teardown.ps1'

    # ---- Author a valid Azure config as a .ps1 returning @{ ... } under TestDrive. ----
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

    # ---- Build an isolated "no cloud CLI" sandbox under TestDrive. ----
    # We strip the real cloud CLIs from PATH and plant poisoned shims named
    # az/docker/kubectl that, if ever invoked, print a unique marker and exit 1.
    # So the dry-run run is doubly protected: the real CLIs are unreachable, and
    # any accidental external call to a stubbed name would surface the marker in
    # output (which we assert is ABSENT). This directly verifies "executes NO
    # external command".
    $script:StubDir = Join-Path $TestDrive 'stubbin'
    New-Item -ItemType Directory -Path $script:StubDir -Force | Out-Null
    $script:PoisonMarker = 'EXTERNAL_CLI_WAS_INVOKED_UNEXPECTEDLY'
    foreach ($cli in 'az', 'docker', 'kubectl') {
        # .cmd shim (child process is powershell.exe on Windows -> resolves .cmd).
        $cmdPath = Join-Path $script:StubDir ($cli + '.cmd')
        "@echo off`r`necho $script:PoisonMarker $cli %*`r`nexit /b 1" |
            Set-Content -LiteralPath $cmdPath -Encoding ASCII
    }

    # Helper: run a script with -WhatIf in a CHILD powershell process whose PATH
    # contains ONLY the poisoned-stub dir plus the minimum system dirs needed to
    # launch powershell itself (System32). This guarantees no real az/docker is
    # reachable. Returns a hashtable with ExitCode and Output (stdout+stderr).
    function Invoke-WhatIfScript {
        param(
            [Parameter(Mandatory)][string] $ScriptPath,
            [string[]] $ExtraArgs = @()
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

        # Run with the stripped PATH in effect only for this child invocation.
        $savedPath = $env:Path
        try {
            $env:Path = $sandboxPath
            # Capture stdout AND stderr together (*>&1). Use the Windows PowerShell
            # host explicitly so the 5.1-targeted scripts run under their intended host.
            $raw = & powershell @psArgs *>&1
            $code = $LASTEXITCODE
        }
        finally {
            $env:Path = $savedPath
        }

        $text = ($raw | Out-String)
        return @{ ExitCode = $code; Output = $text }
    }
}

Describe 'Azure Docker-only -WhatIf dry run' {

    Context 'preconditions' {
        It 'the deploy script exists' {
            Test-Path -LiteralPath $script:DeployPath | Should -BeTrue
        }
        It 'the teardown script exists' {
            Test-Path -LiteralPath $script:TeardownPath | Should -BeTrue
        }
        It 'the temp Azure config exists under TestDrive' {
            Test-Path -LiteralPath $script:ConfigPath | Should -BeTrue
        }
    }

    Context 'deploy.ps1 -WhatIf' {
        BeforeAll {
            $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployPath
        }

        It 'exits 0 under -WhatIf even with no cloud CLI installed' {
            $script:Deploy.ExitCode | Should -Be 0 -Because (
                "the dry run must not execute anything and must succeed. Output:`n" + $script:Deploy.Output)
        }

        It 'executes NO external cloud CLI (no poisoned-stub marker in output)' {
            # If the script had actually shelled out to az/docker/kubectl, the
            # poisoned stub would have printed the marker. Its absence proves the
            # dry run executed nothing external.
            $script:Deploy.Output | Should -Not -Match $script:PoisonMarker
        }

        It 'announces the dry run and does not execute the commands' {
            $script:Deploy.Output | Should -Match 'DRY RUN'
            $script:Deploy.Output | Should -Match 'none executed'
        }

        It 'prints an ordered, numbered command list' {
            # Invoke-Planned prefixes each planned command with "[ n]". At least a
            # handful of ordinals must be present for the full ACI deploy flow.
            $ordinals = [regex]::Matches($script:Deploy.Output, '(?m)^\s*\[\s*\d+\]\s')
            $ordinals.Count | Should -BeGreaterThan 5 -Because (
                "the full ordered command list should be printed. Output:`n" + $script:Deploy.Output)
        }

        It 'plans the az authentication check' {
            $script:Deploy.Output | Should -Match 'az account show'
        }

        It 'plans the hardened image build and push via docker' {
            $script:Deploy.Output | Should -Match 'docker build'
            $script:Deploy.Output | Should -Match 'docker push'
        }

        It 'plans the ACR create/login steps' {
            $script:Deploy.Output | Should -Match 'az acr'
        }

        It 'plans the Key Vault secret set via --file (value never on the line)' {
            $script:Deploy.Output | Should -Match 'az keyvault secret set'
            # The secret is delivered by file, so a <...-file> placeholder appears,
            # never the password value.
            $script:Deploy.Output | Should -Match 'keyvault secret set .*--file'
        }

        It 'plans the Flexible Server (managed Postgres) create' {
            $script:Deploy.Output | Should -Match 'az postgres flexible-server create'
        }

        It 'plans the ACI container create using the YAML --file step' {
            # The secret-bearing ACI YAML is built only in the real branch; under
            # -WhatIf the planned step is `az container create ... --file <...>`.
            $script:Deploy.Output | Should -Match 'az container create'
            $script:Deploy.Output | Should -Match 'container create .*--file'
        }

        It 'never leaks the DB_PASSWORD env token anywhere in the dry-run output' {
            # No DB_PASSWORD env is set, and the secret YAML (the only place a
            # password value would live) is NOT built under -WhatIf. So the
            # uppercase env-var token must not appear anywhere in the planned
            # command set / output.
            #
            # IMPORTANT: this is a CASE-SENSITIVE check (-CNotMatch). The secret is
            # delivered as the FILE /run/secrets/db_password (lowercase key/path),
            # which is exactly the intended delivery and legitimately
            # appears in a step banner. A case-insensitive match would wrongly
            # flag that lowercase file path. The forbidden thing is the uppercase
            # env-var form `DB_PASSWORD` (an environmentVariables entry), which
            # must never be present.
            $script:Deploy.Output | Should -Not -CMatch 'DB_PASSWORD'
        }

        It 'contains the intended lowercase /run/secrets/db_password file reference, not an env var' {
            # Positive sanity check distinguishing the file path (wanted)
            # from the env var (forbidden): the lowercase db_password file
            # reference is present while the uppercase env token is not.
            $script:Deploy.Output | Should -CMatch '/run/secrets/db_password'
        }

        It 'does not reveal any generated password value (uses placeholder paths only)' {
            # The dry-run substitutes placeholder file paths for the real secret
            # files, proving the value is never put on a command line.
            $script:Deploy.Output | Should -Match '<generated-password-file>'
        }
    }

    Context 'teardown.ps1 -WhatIf' {
        BeforeAll {
            $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownPath
        }

        It 'exits 0 under -WhatIf even with no cloud CLI installed' {
            $script:Teardown.ExitCode | Should -Be 0 -Because (
                "the dry run must not execute anything and must succeed. Output:`n" + $script:Teardown.Output)
        }

        It 'executes NO external cloud CLI (no poisoned-stub marker in output)' {
            $script:Teardown.Output | Should -Not -Match $script:PoisonMarker
        }

        It 'announces the dry run and does not execute the commands' {
            $script:Teardown.Output | Should -Match 'DRY RUN'
            $script:Teardown.Output | Should -Match 'none executed'
        }

        It 'prints an ordered, numbered command list' {
            $ordinals = [regex]::Matches($script:Teardown.Output, '(?m)^\s*\[\s*\d+\]\s')
            $ordinals.Count | Should -BeGreaterThan 3 -Because (
                "the full ordered teardown command list should be printed. Output:`n" + $script:Teardown.Output)
        }

        It 'plans the reverse-order deletes (container, postgres, keyvault, acr)' {
            $script:Teardown.Output | Should -Match 'az container delete'
            $script:Teardown.Output | Should -Match 'az postgres flexible-server delete'
            $script:Teardown.Output | Should -Match 'az keyvault'
            $script:Teardown.Output | Should -Match 'az acr delete'
        }

        It 'never leaks the DB_PASSWORD env token anywhere in the dry-run output' {
            # Case-sensitive: the uppercase env-var form must not appear. (Teardown
            # does not reference the secret file at all, but we keep the guard.)
            $script:Teardown.Output | Should -Not -CMatch 'DB_PASSWORD'
        }
    }

    Context 'static source assertion: ACI secret volume maps /run/secrets/db_password' {
        # The ACI secret YAML is built ONLY in the real (non-WhatIf) branch, so it
        # cannot appear in the dry-run OUTPUT. We supplement the output assertions
        # above with a static read of deploy.ps1 to confirm the secret volume maps
        # key `db_password` at mountPath `/run/secrets`, which ACI renders as the
        # file /run/secrets/db_password. This documents intent that the
        # dry run cannot surface.
        BeforeAll {
            $script:DeploySource = Get-Content -LiteralPath $script:DeployPath -Raw
        }

        It 'declares a secretVolume entry keyed db_password' {
            # In the YAML here-string: `secret:` block with a `db_password:` key.
            $script:DeploySource | Should -Match 'secret:\s*[\r\n]+\s*db_password:'
        }

        It 'mounts that secret volume at /run/secrets' {
            $script:DeploySource | Should -Match 'mountPath:\s*/run/secrets'
        }

        It 'states the resulting secret file path is /run/secrets/db_password' {
            # The script documents the resulting file explicitly; assert the intent
            # the dry run cannot show (key db_password at /run/secrets -> the file).
            $script:DeploySource | Should -Match '/run/secrets/db_password'
        }

        It 'delivers the secret via az container create --file (YAML built only in the real branch)' {
            $script:DeploySource | Should -Match 'container.*create.*--file'
        }
    }
}
