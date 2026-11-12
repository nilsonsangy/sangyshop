<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the GCP Docker-only scripts
    (gcp/docker/deploy.ps1 and gcp/docker/teardown.ps1).

.DESCRIPTION
    Covers task 6.3 of the multi-cloud-deploy plan. Each script is executed in a
    fresh child PowerShell with -WhatIf against a well-formed temporary GCP config
    written under $TestDrive. Nothing here touches a real cloud: the scripts need
    no cloud CLI installed to run their dry run, so these assertions hold on
    Windows with no account and no gcloud/docker on PATH.

    deploy.ps1 (Req 6.5, 3.1, 3.3):
      * Runs with -WhatIf and a safe -AllowedSourceRanges value; exits 0.
      * Prints the full ordered planned command list and executes NO external
        command (the dry-run footer reports "none executed").
      * Every planned line is a `gcloud ...` or `docker ...` command; the expected
        gcloud/docker steps all appear.
      * The planned env set carries NO DB_PASSWORD (Req 3.1): the deploy sets env
        via --set-env-vars=APP_MODE=hardened,DB_BACKEND=pg,... and that string must
        not contain DB_PASSWORD anywhere in the captured dry-run output.
      * The native secret file mount --set-secrets=/run/secrets/db_password=...
        appears in the planned command set (Req 3.3).

    teardown.ps1 (Req 6.5):
      * Runs with -WhatIf; exits 0.
      * Prints the full ordered planned command list (reverse-order deletes) and
        executes NO external command.

    The password is never exposed: deploy's dry run renders secret-stdin commands
    with a redacted "<stdin: db password (redacted)>" marker, so no generated value
    can leak into the captured output.

    Requires Pester 5.x or 6.x (6.2 is installed here). Windows PowerShell 5.1
    compatible. Run with:
        Invoke-Pester -Path ops/tests/Gcp.Docker.WhatIf.Tests.ps1
#>

BeforeAll {
    # ---- Locate the two scripts under test (do NOT edit them). --------------
    # tests/ sits directly under ops/; the GCP docker scripts are two folders
    # deeper under gcp/docker/.
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'gcp' 'docker' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'gcp' 'docker' 'teardown.ps1')).Path

    # ---- Write a valid temporary GCP config under $TestDrive. ---------------
    # A real .ps1 that returns an @{ ... } hashtable, the exact shape
    # Get-CloudConfig evaluates: a legal 8-char lowercase-alnum UniqueSuffix, the
    # Common block (AppName/DbName/DbUser/ImageTag) and the Gcp block
    # (ProjectId/Region/ArRepo/CloudRunName/GkeCluster). No secret fields.
    $script:ConfigPath = Join-Path $TestDrive 'cloud.config.ps1'
    $configBody = @'
@{
    UniqueSuffix = "abc12345"
    Common = @{
        AppName  = "sangyshop"
        DbName   = "sangyshop"
        DbUser   = "sangyshop"
        ImageTag = "hardened"
    }
    Gcp = @{
        ProjectId    = "my-project-123"
        Region       = "us-central1"
        ArRepo       = "sangyshop"
        CloudRunName = "sangyshop-lab"
        GkeCluster   = "sangyshop-lab"
    }
}
'@
    Set-Content -LiteralPath $script:ConfigPath -Value $configBody -Encoding UTF8

    # ---- Resolve the PowerShell host to launch the scripts with. ------------
    # Prefer the current host (pwsh on PS 7, powershell.exe on 5.1); fall back to
    # Windows PowerShell. Each script runs in a FRESH process so its exit code and
    # full stdout+stderr are captured cleanly without polluting the test session.
    $script:PsExe = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($script:PsExe)) { $script:PsExe = 'powershell' }

    # Invoke one script with -WhatIf in a child host and capture merged output
    # (stdout + stderr via *>&1) plus the child's exit code.
    function Invoke-WhatIfScript {
        param(
            [Parameter(Mandatory)][string]   $ScriptPath,
            [Parameter(Mandatory)][string[]] $ExtraArgs
        )
        $argList = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $ScriptPath,
            '-ConfigPath', $script:ConfigPath
        ) + $ExtraArgs

        $out  = & $script:PsExe @argList *>&1
        $code = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $code
            Text     = ($out | Out-String)
            Lines    = @($out | ForEach-Object { [string]$_ })
        }
    }

    # Pull the planned command lines out of a captured dry-run transcript. Both
    # scripts print the ordered list as "  <n>. <command>" after the
    # "planned command list" banner. Returns the command text with the numeric
    # prefix stripped.
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

Describe 'GCP Docker-only deploy.ps1 -WhatIf dry run (Req 6.5, 3.1, 3.3)' {
    BeforeAll {
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', '203.0.113.7/32', '-WhatIf'
        )
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Deploy.ExitCode | Should -Be 0
    }

    It 'prints the ordered planned command list and executes nothing' {
        $script:Deploy.Text | Should -Match 'planned command list'
        # The dry-run footer proves no external command ran.
        $script:Deploy.Text | Should -Match 'none executed'
        $script:DeployPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the expected gcloud ... steps' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud auth list'
        $joined | Should -Match 'gcloud config set project my-project-123'
        $joined | Should -Match 'gcloud artifacts repositories (describe|create) sangyshop'
        $joined | Should -Match 'gcloud sql instances (describe|create) sangyshop-pg'
        $joined | Should -Match 'gcloud run deploy sangyshop-lab'
        $joined | Should -Match 'gcloud run services describe sangyshop-lab'
    }

    It 'plans the hardened image docker build and push' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'docker build .+:hardened'
        $joined | Should -Match 'docker push .+:hardened'
    }

    It 'every planned line is a gcloud or docker command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) {
            $cmd | Should -Match '^(gcloud|docker)\b'
        }
    }

    It 'sets NO DB_PASSWORD env anywhere in the planned command set (Req 3.1)' {
        # The deploy wires env via --set-env-vars=APP_MODE=hardened,DB_BACKEND=pg,...
        # which must NOT contain a DB_PASSWORD entry. Grep the whole captured
        # dry-run output to be safe. Match is CASE-SENSITIVE (-CMatch) on purpose:
        # the lowercase 'db_password' is the Secret Manager id and the
        # /run/secrets/db_password FILE mount (both correct and required); only the
        # uppercase env-var form DB_PASSWORD is forbidden (Req 3.1).
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD'
        ($script:DeployPlanned -join "`n") | Should -Not -CMatch 'DB_PASSWORD'
    }

    It 'carries the expected env vars on the Cloud Run deploy (and still no DB_PASSWORD)' {
        $runLine = $script:DeployPlanned | Where-Object { $_ -match 'gcloud run deploy ' } | Select-Object -First 1
        $runLine | Should -Not -BeNullOrEmpty
        $runLine | Should -Match '--set-env-vars=APP_MODE=hardened,DB_BACKEND=pg,'
        $runLine | Should -Match 'DB_NAME=sangyshop'
        $runLine | Should -Match 'DB_USER=sangyshop'
        # Case-sensitive: the uppercase env-var DB_PASSWORD must never be set,
        # even though the lowercase secret id/mount legitimately appears.
        $runLine | Should -Not -CMatch 'DB_PASSWORD'
    }

    It 'mounts the secret as the file /run/secrets/db_password (Req 3.3)' {
        ($script:DeployPlanned -join "`n") |
            Should -Match '--set-secrets=/run/secrets/db_password=db_password:latest'
    }

    It 'never leaks a secret value (secret-stdin commands are redacted)' {
        # Secret-bearing commands render with a redacted stdin marker; the dry run
        # never generates or prints a real password.
        $script:Deploy.Text | Should -Match 'stdin: db password \(redacted\)'
    }
}

Describe 'GCP Docker-only teardown.ps1 -WhatIf dry run (Req 6.5)' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript -ExtraArgs @('-WhatIf')
        $script:TeardownPlanned = Get-PlannedCommands -Lines $script:Teardown.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Teardown.ExitCode | Should -Be 0
    }

    It 'prints the ordered planned command list and executes nothing' {
        $script:Teardown.Text | Should -Match 'planned command list'
        $script:Teardown.Text | Should -Match 'none executed'
        $script:TeardownPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the reverse-order deletes (run -> sql -> secret -> registry)' {
        $joined = ($script:TeardownPlanned -join "`n")
        $joined | Should -Match 'gcloud run services delete sangyshop-lab'
        $joined | Should -Match 'gcloud sql instances delete sangyshop-pg'
        $joined | Should -Match 'gcloud secrets delete db_password'
        $joined | Should -Match 'gcloud artifacts repositories delete sangyshop'
    }

    It 'every planned line is a gcloud command (no bare external calls)' {
        foreach ($cmd in $script:TeardownPlanned) {
            $cmd | Should -Match '^gcloud\b'
        }
    }
}
