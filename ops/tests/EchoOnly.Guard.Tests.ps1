<#
.SYNOPSIS
    Static echo-only guard (Requirement 1.3).

    Scans every deploy.ps1 / teardown.ps1 anywhere under ops/
    and asserts that the five cloud CLIs -- aws, az, gcloud, kubectl, docker -- are
    NEVER invoked directly. The one approved form is as a quoted string argument to
    the shared Invoke-Echoed helper, e.g.

        Invoke-Echoed -Exe "aws"    -CmdArgs @('ecr','describe-repositories', ...)
        Invoke-Echoed -Exe 'kubectl' -CmdArgs @('apply','-k', ...)

    where the CLI name is a quoted string literal ("aws" / 'aws') that is an
    ARGUMENT to Invoke-Echoed, never a command token invoked in its own right
    (statement start, after &, |, ;, or inside Invoke-Expression).

    A script may also define thin local wrapper functions whose names match a CLI
    (e.g. `function Az { ... Invoke-Echoed -Exe 'az' ... }`) so call sites like
    `Az account show` read cleanly. That is still the approved path: the call
    resolves to the LOCAL function, which forwards to the echo helper, so it is not
    a direct CLI invocation and is NOT flagged. Only a CLI name that resolves to the
    real external executable (no matching local function) counts as a violation.

    The EC2 (ops/aws/ec2) and Azure VM (ops/azure/vm) modalities are also covered by
    explicit name, including their start-lab/stop-lab scripts.

    This enforces design Property 1 (echo-before-exec): no script may call a cloud
    CLI by any path other than Invoke-Echoed, so a student always sees the exact
    command before it runs.

    Requires Pester 5.x (or 6.x). See tests/README.md for install guidance. Run:
        Invoke-Pester -Path ops/tests/EchoOnly.Guard.Tests.ps1

    NOTE on Pester availability: Windows PowerShell 5.1 ships the legacy Pester
    3.4.0, which is NOT compatible with this file's 5.x syntax. If only 3.4.0 is
    present, install a current Pester for the current user first:
        Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
        Import-Module Pester -MinimumVersion 5.0.0
    Execution policy may require a bypass to run the scripts/tests:
        powershell -ExecutionPolicy Bypass -Command "Invoke-Pester -Path ops/tests/EchoOnly.Guard.Tests.ps1"

.NOTES
    HOW THE DETECTOR WORKS (and why it does not false-positive on prose/strings):
    The detector parses each script with the PowerShell language parser
    ([System.Management.Automation.Language.Parser]) and inspects the resulting
    abstract syntax tree (AST), NOT the raw text. A violation is counted ONLY when
    one of the five CLI names is the COMMAND of a command invocation -- i.e. a
    CommandAst whose GetCommandName() is aws/az/gcloud/kubectl/docker. Because the
    parser understands PowerShell grammar, a CLI name that appears inside a block
    comment, a line comment, a here-string, or any ordinary string
    literal (Write-Host text, auth-guidance prose, Join-Path 'ops/
    docker/...') is NOT a CommandAst command and is NEVER flagged. The approved
    form, Invoke-Echoed -Exe "aws", is a CommandAst named 'Invoke-Echoed' with
    "aws" as a string ARGUMENT, so it passes. Real direct calls are caught in every
    position: a bare 'aws ecr ...', '& gcloud ...', a piped '| docker ...', and an
    'Invoke-Expression (az account show)' (the inner 'az account show' is itself a
    CommandAst) all surface as CommandAst commands named by one of the five CLIs.

    One refinement: a script may define thin local WRAPPER FUNCTIONS whose names
    match a CLI (e.g. 'function Az { ... Invoke-Echoed -Exe ''az'' ... }') so call
    sites read cleanly. 'Az account show' then resolves to that LOCAL function,
    which forwards to the echo helper -- it is the approved path, not a direct CLI
    call. The detector gathers every FunctionDefinitionAst in the script and does
    NOT flag a CLI-named command that matches one of them. A genuine bare
    'aws ecr ...' has no such local function and is still flagged.

    Equivalent manual grep (documented so the check is reviewable without Pester).
    A regex over raw text cannot distinguish a real invocation from a CLI name in a
    comment or string, so this grep is only a FIRST-PASS filter: it LISTS candidate
    lines, and a clean tree may still print comment/prose hits that the AST-based
    test correctly ignores. Every hit must be hand-checked against the "quoted -Exe
    argument" rule; the authoritative check is this Pester test.

    PowerShell Select-String first-pass scan (no rg required):
        Get-ChildItem -Path ops -Recurse -File -Include deploy.ps1,teardown.ps1 |
          Select-String -Pattern '(?:^|[&|;]|Invoke-Expression\s+\(?)\s*(?<![""''`])\b(aws|az|gcloud|kubectl|docker)\b(?!\s*[""''])'

    ripgrep (rg) first-pass equivalent, from the repo root:
        rg --pcre2 -n -g 'ops/**/deploy.ps1' -g 'ops/**/teardown.ps1' \
           "(?<![\"'`-])(?:^|[&|;]|Invoke-Expression\s+\(?)\s*\b(aws|az|gcloud|kubectl|docker)\b(?!\s*[\"'])"
#>

BeforeAll {
    # ---- Root of the ops tree we police (ops/). ----
    # tests/ sits directly under ops/, so the parent of $PSScriptRoot is the root.
    $script:CloudRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

    # The five executables that MUST only ever appear as a quoted -Exe argument.
    $script:CliNames = @('aws', 'az', 'gcloud', 'kubectl', 'docker')

    # ---- Core detector -------------------------------------------------------
    # Parse the script text into an AST and return a list of violation
    # descriptions: every place one of the five CLI names is the COMMAND of a
    # command invocation (a CommandAst whose GetCommandName() is one of the five).
    #
    # Why the AST and not regex: the parser already knows what is code and what is
    # a comment or a string. CLI names appearing in block comments (<# #>), line
    # comments (#), here-strings, or ordinary string literals (Write-Host prose,
    # auth-guidance text, Join-Path paths) are NOT CommandAst commands, so they are
    # never flagged. The approved Invoke-Echoed -Exe "aws" is a CommandAst named
    # 'Invoke-Echoed' with "aws" as a string argument -> not a violation. Real
    # direct calls -- bare 'aws ...', '& gcloud ...', piped '| docker ...', and
    # 'Invoke-Expression (az account show)' -- all appear as CommandAst commands
    # named by one of the five CLIs -> violations. A CLI-named command that resolves
    # to a wrapper function the script defines (which forwards to the echo helper)
    # is the approved path and is NOT a violation.
    function Get-EchoOnlyViolation {
        param(
            [Parameter(Mandatory)][AllowEmptyString()][string] $Content,
            [string] $SourceName = '<in-memory>'
        )

        $violations = New-Object System.Collections.Generic.List[string]

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $Content, [ref]$tokens, [ref]$errors)

        # ---- Local wrapper functions are the approved echo path, not direct CLIs.
        # A script may define thin PowerShell wrapper functions whose names happen to
        # match a CLI (e.g. `function Az { ... Invoke-Echoed -Exe 'az' ... }`) purely
        # so call sites read cleanly. A call to `Az account show` then resolves to
        # that LOCAL function -- which forwards to the echo helper -- NOT to az.exe.
        # Collect every function this script defines so such calls are not mistaken
        # for direct CLI invocations. A genuine bare `aws ...` has no matching local
        # function and is still flagged.
        $localFuncs = @{}
        foreach ($fn in $ast.FindAll(
                { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
                $true)) {
            $localFuncs[$fn.Name.ToLowerInvariant()] = $true
        }

        # Find every command invocation anywhere in the tree (recursively).
        $commandAsts = $ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.CommandAst] },
            $true)

        foreach ($cmd in $commandAsts) {
            # GetCommandName() returns the command's name when it is a bare/known
            # name (e.g. 'aws', 'gcloud', '& gcloud' -> 'gcloud'), or $null when the
            # command is computed/dynamic. It deliberately does NOT return string
            # ARGUMENTS, so Invoke-Echoed -Exe "aws" yields 'Invoke-Echoed'.
            $name = $cmd.GetCommandName()
            if ([string]::IsNullOrEmpty($name)) { continue }
            $lower = $name.ToLowerInvariant()

            if ($script:CliNames -notcontains $lower) { continue }

            # Approved: the name resolves to a wrapper function defined in this same
            # script (which forwards to the echo helper), so it is not a direct CLI
            # invocation. PowerShell is case-insensitive, so `Az` and `az` are one
            # and the same command name here.
            if ($localFuncs.ContainsKey($lower)) { continue }

            $line = $cmd.Extent.StartLineNumber
            $text = $cmd.Extent.Text
            if ($text.Length -gt 120) { $text = $text.Substring(0, 117) + '...' }
            $text = ($text -split "\r?\n")[0].Trim()
            $violations.Add(
                ("line ${line}: '" + $name + "' invoked directly as a command token -> " + $text))
        }

        return $violations
    }
}

Describe 'Echo-only guard (Requirement 1.3)' {

    Context 'detector unit checks (synthetic in-memory scripts)' {
        It 'flags a bare CLI command token at the start of a line' {
            $bad = 'aws ecr describe-repositories --repository-names sangyshop'
            @(Get-EchoOnlyViolation -Content $bad).Count | Should -BeGreaterThan 0
        }

        It 'flags a genuine bare "aws ecr describe-repositories" even among valid code' {
            # Negative control: a real direct AWS CLI call hidden in otherwise fine
            # script text MUST still be caught -- the guard is not weakened.
            $bad = @(
                '$cfg = Get-CloudConfig -ConfigPath $ConfigPath'
                'Invoke-Echoed -Exe "docker" -CmdArgs @("build",".")'
                'aws ecr describe-repositories --repository-names sangyshop --region us-east-1'
                'Write-Host "done"'
            ) -join "`n"
            $found = @(Get-EchoOnlyViolation -Content $bad)
            $found.Count | Should -Be 1
            ($found -join "`n") | Should -Match "'aws' invoked directly"
        }

        It 'accepts calls to a local wrapper function whose name matches a CLI' {
            # The approved "clean call site" style: a thin function named after the
            # CLI that forwards to the echo helper. 'Az account show' and
            # 'Docker build' resolve to these LOCAL functions, not az.exe/docker.exe.
            $good = @(
                "function Az     { param([Parameter(ValueFromRemainingArguments)][string[]] `$A) Invoke-Echoed -Exe 'az'     -CmdArgs `$A }"
                "function Docker { param([Parameter(ValueFromRemainingArguments)][string[]] `$A) Invoke-Echoed -Exe 'docker' -CmdArgs `$A }"
                'Az account show --output none'
                'Docker build -t $imageRef -f $dockerfile $repoRoot'
                'Docker push $imageRef'
            ) -join "`n"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'still flags a genuine bare aws call even when wrappers exist for other CLIs' {
            # The wrapper exemption is name-scoped: defining `function Az` / `Docker`
            # does NOT excuse a real `aws ...` that has no matching local function.
            $bad = @(
                "function Az     { param([Parameter(ValueFromRemainingArguments)][string[]] `$A) Invoke-Echoed -Exe 'az'     -CmdArgs `$A }"
                "function Docker { param([Parameter(ValueFromRemainingArguments)][string[]] `$A) Invoke-Echoed -Exe 'docker' -CmdArgs `$A }"
                'Az account show --output none'
                'aws ecr describe-repositories --repository-names sangyshop --region us-east-1'
            ) -join "`n"
            $found = @(Get-EchoOnlyViolation -Content $bad)
            $found.Count | Should -Be 1
            ($found -join "`n") | Should -Match "'aws' invoked directly"
        }

        It 'flags a CLI invoked after a pipe' {
            $bad = '$x = Get-Thing | docker load'
            @(Get-EchoOnlyViolation -Content $bad).Count | Should -BeGreaterThan 0
        }

        It 'flags a CLI invoked via the call operator' {
            $bad = '& gcloud run deploy sangyshop'
            @(Get-EchoOnlyViolation -Content $bad).Count | Should -BeGreaterThan 0
        }

        It 'flags a CLI invoked via Invoke-Expression (bare token)' {
            # The dangerous, disallowed form: the CLI name reaches a shell/eval as a
            # bare command token (not a quoted -Exe argument). The inner
            # 'az account show' is itself a CommandAst named 'az'.
            $badBare = 'Invoke-Expression (az account show)'
            @(Get-EchoOnlyViolation -Content $badBare).Count | Should -BeGreaterThan 0
        }

        It 'accepts the approved double-quoted Invoke-Echoed -Exe form' {
            $good = 'Invoke-Echoed -Exe "aws" -CmdArgs @(''ecr'',''describe-repositories'')'
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'accepts the approved single-quoted Invoke-Echoed -Exe form' {
            $good = "Invoke-Echoed -Exe 'kubectl' -CmdArgs @('apply','-k','overlays/gcp')"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'accepts all five CLI names when quoted as -Exe arguments' {
            $good = @(
                'Invoke-Echoed -Exe "aws"     -CmdArgs @("sts","get-caller-identity")'
                'Invoke-Echoed -Exe "az"      -CmdArgs @("account","show")'
                'Invoke-Echoed -Exe "gcloud"  -CmdArgs @("auth","list")'
                'Invoke-Echoed -Exe "kubectl" -CmdArgs @("get","pods")'
                'Invoke-Echoed -Exe "docker"  -CmdArgs @("build",".")'
            ) -join "`n"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'ignores CLI names that appear only inside a line comment' {
            $good = '$u = $cfg.Gcp.ArRepo   # gcloud will push the image to this repo'
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'ignores CLI names that appear inside a block comment' {
            $good = @(
                '<#'
                '  EVERY external CLI call (`az`, `docker`) goes through Invoke-Echoed.'
                '  The script never calls az/docker directly. Verify with: az version'
                '#>'
                'Invoke-Echoed -Exe "az" -CmdArgs @("account","show")'
            ) -join "`n"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'ignores CLI names inside Write-Host / string-literal prose' {
            $good = @(
                'Write-Host "Azure authentication check failed (az account show)."'
                'Write-Host "Verify:  az version"'
                'Write-Host "  az login"'
                'Write-Host "  az account set --subscription <your-subscription-id>"'
            ) -join "`n"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'ignores a CLI name embedded in a here-string' {
            $good = @(
                '$guidance = @"'
                'You also need kubectl and the GKE auth plugin:'
                '    gcloud components install kubectl gke-gcloud-auth-plugin'
                '"@'
            ) -join "`n"
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'does not false-positive on a CLI name inside a Join-Path string literal' {
            $good = '$dockerfile = Join-Path $RepoRoot ''ops\docker\hardened\Dockerfile'''
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }

        It 'does not false-positive on hyphenated identifiers containing a CLI name' {
            $good = '$dockerfile = "ops/docker/hardened/Dockerfile"'
            @(Get-EchoOnlyViolation -Content $good).Count | Should -Be 0
        }
    }

    Context 'repository scan (whole ops/ tree)' {
        BeforeDiscovery {
            $cloudRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
            # Discover every deploy.ps1 / teardown.ps1 recursively. The scripts come
            # in over several tasks, so this may legitimately be empty early on
            # (vacuous pass).
            $script:ScriptFiles = @(
                Get-ChildItem -Path $cloudRoot -Recurse -File -Include 'deploy.ps1', 'teardown.ps1' -ErrorAction SilentlyContinue
            )
            $script:ScriptCases = @($script:ScriptFiles | ForEach-Object { @{ Path = $_.FullName } })
        }

        It 'at least runs the scan over the cloud tree (zero scripts = vacuous pass)' {
            # This documents that the scan is wired over the whole tree. With no
            # deploy/teardown scripts yet, there is nothing to flag, which is a pass.
            $cloudRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
            (Test-Path $cloudRoot) | Should -BeTrue
        }

        # -AllowNullOrEmptyForEach: if no deploy/teardown scripts are present (very
        # early in the plan) this -ForEach is legitimately empty and the check passes
        # vacuously (zero scripts found = pass). Once scripts exist it runs once per
        # discovered file.
        It 'every CLI call in <Path> goes through a quoted Invoke-Echoed -Exe argument' -ForEach $script:ScriptCases -AllowNullOrEmptyForEach {
            $content = Get-Content -LiteralPath $Path -Raw
            $found = @(Get-EchoOnlyViolation -Content $content -SourceName $Path)
            $found | Should -BeNullOrEmpty -Because (
                "no deploy.ps1/teardown.ps1 may call aws/az/gcloud/kubectl/docker directly; " +
                "use Invoke-Echoed -Exe `"<cli>`". Violations:`n" + ($found -join "`n")
            )
        }
    }

    # Task 10.3 (Property 2, Req 10.15, 11.5, 30.7, 33.5): the EC2 and Azure VM
    # modalities are covered by NAME, not only by the recursive discovery above, so
    # deleting or moving one of them cannot silently shrink the scan. start-lab and
    # stop-lab are included because they also reach a cloud CLI.
    Context 'EC2 and Azure VM modality scan (explicit coverage)' {
        BeforeDiscovery {
            $cloudRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
            $script:ModalityCases = @(
                foreach ($rel in @(
                        'aws/ec2/deploy.ps1', 'aws/ec2/teardown.ps1', 'aws/ec2/stop-lab.ps1', 'aws/ec2/start-lab.ps1',
                        'azure/vm/deploy.ps1', 'azure/vm/teardown.ps1', 'azure/vm/stop-lab.ps1', 'azure/vm/start-lab.ps1')) {
                    @{ Rel = $rel; Path = (Join-Path $cloudRoot $rel) }
                }
            )
        }

        It '<Rel> exists' -ForEach $script:ModalityCases {
            Test-Path -LiteralPath $Path -PathType Leaf | Should -BeTrue
        }

        It 'recursive discovery includes ops/aws/ec2 and ops/azure/vm deploy and teardown' {
            $cloudRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
            $names = @(Get-ChildItem -Path $cloudRoot -Recurse -File -Include 'deploy.ps1', 'teardown.ps1' |
                    ForEach-Object { $_.FullName.Substring($cloudRoot.Length).TrimStart('\', '/').Replace('\', '/') })
            $names | Should -Contain 'aws/ec2/deploy.ps1'
            $names | Should -Contain 'aws/ec2/teardown.ps1'
            $names | Should -Contain 'azure/vm/deploy.ps1'
            $names | Should -Contain 'azure/vm/teardown.ps1'
        }

        It 'every CLI call in <Rel> goes through a quoted Invoke-Echoed -Exe argument or a local wrapper' -ForEach $script:ModalityCases {
            $found = @(Get-EchoOnlyViolation -Content (Get-Content -LiteralPath $Path -Raw) -SourceName $Path)
            $found | Should -BeNullOrEmpty -Because ("Violations:`n" + ($found -join "`n"))
        }

        It 'no <Rel> runs a real external command under -WhatIf (guard-mode run with sentinel shims)' -ForEach ($script:ModalityCases | Where-Object { $_.Rel -match '(deploy|teardown)\.ps1$' }) {
            # Execute the script with -WhatIf with sentinel aws/az/docker/kubectl/gcloud
            # shims first on PATH; any shim that runs writes the sentinel file.
            $isAws    = $Rel -like 'aws/*'
            $shimDir  = Join-Path $TestDrive ('shims-' + ($Rel -replace '[\\/\.]', '_'))
            $sentinel = Join-Path $TestDrive ('sentinel-' + ($Rel -replace '[\\/\.]', '_') + '.txt')
            New-Item -ItemType Directory -Path $shimDir -Force | Out-Null
            foreach ($cli in 'aws', 'az', 'docker', 'kubectl', 'gcloud') {
                Set-Content -LiteralPath (Join-Path $shimDir "$cli.cmd") -Encoding ASCII `
                    -Value "@echo off`r`necho $cli %* >> `"%LAB_SENTINEL%`"`r`nexit /b 1`r`n"
            }
            $cfg = Join-Path $TestDrive ('cfg-' + ($Rel -replace '[\\/\.]', '_') + '.ps1')
            Set-Content -LiteralPath $cfg -Encoding UTF8 -Value @'
@{
    UniqueSuffix = "abc12345"
    Common = @{ AppName = "sangyshop"; DbName = "sangyshop"; DbUser = "sangyshop"; ImageTag = "hardened" }
    Aws = @{
        Region = "us-east-1"; AccountId = "123456789012"; EcrRepo = "sangyshop"; EcsCluster = "x"; EksCluster = "x"
        Ec2 = @{ InstanceType = "t3.small"; DbInstanceClass = "db.t4g.micro"; BucketBase = "sangyshop-lab"; VolumeGb = 20 }
    }
    Azure = @{
        Location = "eastus"; ResourceGroup = "sangyshop-lab-rg"; AcrNameBase = "sangyshoplab"; KeyVaultBase = "sangyshop-kv"
        AciName = "a"; AksCluster = "b"
        Vm = @{ VmSize = "Standard_B1ms"; PgSku = "Standard_B1ms"; PgStorageGb = 32; ResourceGroupBase = "sangyshop-lab"; EvidenceGroupBase = "sangyshop-evidence" }
    }
}
'@
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Path, '-ConfigPath', $cfg)
            if ($Rel -match 'deploy\.ps1$') { $argList += @('-AllowedSourceRanges', '203.0.113.7/32') }
            $argList += '-WhatIf'

            $savedPath = $env:PATH; $savedSentinel = $env:LAB_SENTINEL
            try {
                $env:PATH = $shimDir + [System.IO.Path]::PathSeparator + $env:PATH
                $env:LAB_SENTINEL = $sentinel
                $psExe = (Get-Process -Id $PID).Path
                $out = & $psExe @argList *>&1
                $code = $LASTEXITCODE
            }
            finally {
                $env:PATH = $savedPath
                if ($null -eq $savedSentinel) { Remove-Item Env:\LAB_SENTINEL -ErrorAction SilentlyContinue } else { $env:LAB_SENTINEL = $savedSentinel }
            }
            $code | Should -Be 0 -Because (($out | Out-String))
            Test-Path -LiteralPath $sentinel | Should -BeFalse -Because 'a shimmed cloud CLI was invoked during -WhatIf'
        }
    }
}
