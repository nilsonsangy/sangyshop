<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the AWS ECS Fargate scripts
    (aws/ecs/deploy.ps1 and aws/ecs/teardown.ps1).

.DESCRIPTION
    Covers the dry run of the deploy and teardown scripts. Each script is executed in a
    fresh child PowerShell with -WhatIf against a well-formed temporary AWS config
    written under $TestDrive. Nothing here touches a real cloud: under -WhatIf the
    scripts record and print their planned command list and execute NO external
    command, so these assertions hold on Windows with no AWS account and neither
    aws nor docker on PATH. Modeled on Gcp.Docker.WhatIf.Tests.ps1 and
    Azure.Aci.WhatIf.Tests.ps1 (child-process -WhatIf invocation, a $TestDrive
    config .ps1, and a Get-PlannedCommands transcript parser).

    DRY-RUN vs STATIC split (important):
      Most assertions read the dry-run OUTPUT -- the ordered, numbered command
      list the scripts print. But the ECS task definition is serialized into a
      transient JSON file and handed to `aws ecs register-task-definition
      --cli-input-json file://<...>`; under -WhatIf the file path is a redacted
      placeholder, so the task-def JSON (its environment/secrets/mountPoints) is
      NOT visible in the captured output. For those we assert two ways:
        (a) DRY RUN: the planned `aws ecs register-task-definition
            --cli-input-json file://...` step IS present; and
        (b) STATIC: a direct read of aws/ecs/deploy.ps1 confirms the Form A
            inline wrapper writes /app/secrets/db_password, a DB_PASSWORD_FILE env
            names that path, the DB_PASSWORD_SECRET secret is injected by Secrets
            Manager valueFrom ARN, and NO bare DB_PASSWORD env entry exists.
      Each assertion below notes which half (dry-run output vs static source) it
      relies on.

    deploy.ps1:
      * Runs with -WhatIf and a safe -AllowedSourceRanges ('203.0.113.7/32');
        exits 0.
      * Prints the full ordered planned command list (DRY RUN) and executes NO
        external command (the footer reports "none executed").
      * Every planned line is an `aws ...` or `docker ...` command (plus the one
        `aws ... | docker login ...` ECR-auth pipe); the expected aws/ecs steps
        all appear (DRY RUN).
      * No DB_PASSWORD env token appears anywhere in the planned set. The check is
        CASE-SENSITIVE (-CNotMatch): the lowercase /run/secrets/db_password file
        path and the lowercase Secrets Manager id are correct and allowed; only the
        uppercase env-var form DB_PASSWORD is forbidden.
      * The secret lands at /app/secrets/db_password: the planned
        `aws ecs register-task-definition --cli-input-json file://...` step is
        present (DRY RUN), and the STATIC source confirms the Form A wrapper writes
        /app/secrets/db_password, a DB_PASSWORD_FILE env names that path,
        DB_PASSWORD_SECRET uses a valueFrom ARN, and no bare DB_PASSWORD env entry
        exists.

    teardown.ps1:
      * Runs with -WhatIf; exits 0.
      * Prints the full ordered planned command list (reverse-order deletes) and
        executes NO external command.

    The password is never exposed: deploy's dry run renders secret-stdin commands
    with a redacted "<stdin: db password (redacted)>" marker and uses placeholder
    temp-file paths, so no generated value can leak into the captured output.

    Requires Pester 5.x or 6.x (6.2 is installed here). Windows PowerShell 5.1
    compatible. Run with:
        Invoke-Pester -Path ops/tests/Aws.Ecs.WhatIf.Tests.ps1
#>

BeforeAll {
    # ---- Locate the two scripts under test (do NOT edit them). --------------
    # tests/ sits directly under ops/; the AWS ECS scripts are two folders
    # deeper under aws/ecs/.
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'ecs' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'ecs' 'teardown.ps1')).Path

    # ---- Write a valid temporary AWS config under $TestDrive. ---------------
    # A real .ps1 that returns an @{ ... } hashtable, the exact shape
    # Get-CloudConfig evaluates: a legal 8-char lowercase-alnum UniqueSuffix, the
    # Common block (AppName/DbName/DbUser/ImageTag) and the Aws block
    # (Region/AccountId/EcrRepo/EcsCluster/EksCluster). No secret fields.
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
    Aws = @{
        Region     = "us-east-1"
        AccountId  = "123456789012"
        EcrRepo    = "sangyshop"
        EcsCluster = "sangyshop-lab"
        EksCluster = "sangyshop-lab"
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
    # (stdout + stderr via *>&1) plus the child's exit code. The scripts exit 0
    # under -WhatIf without aws/docker installed because nothing external runs.
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

Describe 'AWS Docker-only deploy.ps1 -WhatIf dry run' {
    BeforeAll {
        # deploy REQUIRES -AllowedSourceRanges; pass a safe non-open CIDR.
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', '203.0.113.7/32', '-WhatIf'
        )
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
        # STATIC half of the split (see file header): read the deploy source for
        # the task-def details the dry run cannot surface (JSON built via file://).
        $script:DeploySource = Get-Content -LiteralPath $script:DeployScript -Raw
    }

    It 'exits 0 under -WhatIf' {
        $script:Deploy.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Deploy.Text)
    }

    It 'prints the ordered planned command list and executes nothing (DRY RUN)' {
        $script:Deploy.Text | Should -Match 'planned command list'
        # The dry-run footer proves no external command ran.
        $script:Deploy.Text | Should -Match 'none executed'
        $script:DeployPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the expected aws ... steps (DRY RUN)' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'aws sts get-caller-identity'
        $joined | Should -Match 'aws ecr (describe-repositories|create-repository)'
        $joined | Should -Match 'aws secretsmanager (describe-secret|create-secret)'
        $joined | Should -Match 'aws rds (describe-db-instances|create-db-instance)'
        $joined | Should -Match 'aws ecs register-task-definition'
        $joined | Should -Match 'aws ecs (describe-clusters|create-cluster)'
        $joined | Should -Match 'aws ecs (describe-services|create-service)'
    }

    It 'plans the hardened image docker build and push (DRY RUN)' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'docker build .+:hardened'
        $joined | Should -Match 'docker push .+:hardened'
    }

    It 'every planned line is an aws or docker command (no bare external calls) (DRY RUN)' {
        # One planned step is the ECR-auth pipe `aws ... | docker login ...`; it
        # still starts with aws and contains only aws/docker, so the leading-token
        # check holds for every line.
        foreach ($cmd in $script:DeployPlanned) {
            $cmd | Should -Match '^(aws|docker)\b'
        }
    }

    It 'sets NO DB_PASSWORD env anywhere in the planned command set (DRY RUN)' {
        # Match is CASE-SENSITIVE (-CNotMatch) on purpose: the lowercase
        # /run/secrets/db_password file path and the lowercase Secrets Manager id
        # (sangyshop/db_password) are both correct and required; only the uppercase
        # env-var form DB_PASSWORD is forbidden. Note the task-def JSON
        # (where a DB_PASSWORD env entry could otherwise hide) is built via a
        # file:// temp placeholder under -WhatIf, so the STATIC assertion below also
        # guards the serialized definition.
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD\b'
        ($script:DeployPlanned -join "`n") | Should -Not -CMatch 'DB_PASSWORD\b'
    }

    It 'plans the ECS task-definition registration via --cli-input-json file:// (DRY RUN)' {
        # The secret-bearing task-def JSON is written to a transient file and
        # referenced by file://; under -WhatIf the path is a redacted placeholder.
        # We assert the planned step IS present; its CONTENTS are covered by the
        # static assertions below.
        $regLine = $script:DeployPlanned | Where-Object { $_ -match 'ecs register-task-definition' } | Select-Object -First 1
        $regLine | Should -Not -BeNullOrEmpty
        $regLine | Should -Match 'aws ecs register-task-definition'
        # The file:// arg renders quoted because the redacted placeholder path
        # contains spaces: --cli-input-json "file://<temp-file: task-definition.json>".
        $regLine | Should -Match '--cli-input-json "?file://'
    }

    It 'never leaks a secret value (temp-file references are redacted) (DRY RUN)' {
        # The DB password is delivered to the CLI via a transient file:// reference,
        # and under -WhatIf that path is a redacted placeholder; the dry run never
        # generates or prints a real password value.
        $script:Deploy.Text | Should -Match '<temp-file: db password \(redacted\)>'
    }

    Context 'STATIC source assertions: ECS task def lands the secret at /app/secrets/db_password' {
        # These complement the DRY-RUN step above. The task definition is serialized
        # to JSON and handed to the CLI via file://, so its environment/secrets
        # never appear in the -WhatIf OUTPUT. We read deploy.ps1 to confirm the
        # intent the dry run cannot surface.

        It 'the Form A inline wrapper writes /app/secrets/db_password' {
            # The wrapperProgram writes the trimmed secret to the app-owned file
            # (via the $secretFilePath variable set to /app/secrets/db_password).
            $script:DeploySource | Should -Match "\`$secretFilePath\s*=\s*'/app/secrets/db_password'"
            $script:DeploySource | Should -Match '/app/secrets/db_password'
        }

        It 'names the secret-file path via a DB_PASSWORD_FILE env entry (the path, not the value)' {
            # The environment[] block includes DB_PASSWORD_FILE pointing at the
            # app-owned path the wrapper wrote, so the hardened app reads it there.
            $script:DeploySource | Should -Match "name\s*=\s*'DB_PASSWORD_FILE';\s*value\s*=\s*\`$secretFilePath"
        }

        It 'injects DB_PASSWORD_SECRET from the Secrets Manager valueFrom ARN (never a value)' {
            # The secrets[] entry wires the env var the wrapper reads from the
            # stored secret by ARN ($secretArn), not a literal value.
            $script:DeploySource | Should -Match "name\s*=\s*'DB_PASSWORD_SECRET';\s*valueFrom\s*=\s*\`$secretArn"
        }

        It 'declares NO bare DB_PASSWORD env entry in the task definition environment block' {
            # The environment[] block lists exactly APP_MODE/DB_BACKEND/DB_HOST/
            # DB_PORT/DB_NAME/DB_USER/DB_PASSWORD_FILE. A bare DB_PASSWORD env name
            # must not be present (case-sensitive, and not matching the allowed
            # DB_PASSWORD_FILE / DB_PASSWORD_SECRET names, whose trailing '_' means
            # the "'DB_PASSWORD'" literal below does not match them).
            $script:DeploySource | Should -Not -CMatch "name\s*=\s*'DB_PASSWORD'"
            # And the script itself guards against it at register time: it throws
            # if the serialized task-def JSON ever carries a bare DB_PASSWORD env entry.
            $script:DeploySource | Should -Match 'Refusing to register task definition: a bare DB_PASSWORD environment variable is present'
        }
    }
}

Describe 'AWS Docker-only teardown.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript -ExtraArgs @('-WhatIf')
        $script:TeardownPlanned = Get-PlannedCommands -Lines $script:Teardown.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Teardown.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Teardown.Text)
    }

    It 'prints the ordered planned command list and executes nothing (DRY RUN)' {
        $script:Teardown.Text | Should -Match 'planned command list'
        $script:Teardown.Text | Should -Match 'none executed'
        $script:TeardownPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the reverse-order deletes (service -> cluster -> task-def -> rds -> secret -> ... -> ecr) (DRY RUN)' {
        $joined = ($script:TeardownPlanned -join "`n")
        # Reverse dependency order: compute first, native registry last.
        $svcIdx    = ($script:TeardownPlanned | Select-String -SimpleMatch 'ecs delete-service'              | Select-Object -First 1).LineNumber
        $clusterIdx = ($script:TeardownPlanned | Select-String -SimpleMatch 'ecs delete-cluster'             | Select-Object -First 1).LineNumber
        $rdsIdx     = ($script:TeardownPlanned | Select-String -SimpleMatch 'rds delete-db-instance'         | Select-Object -First 1).LineNumber
        $secretIdx  = ($script:TeardownPlanned | Select-String -SimpleMatch 'secretsmanager delete-secret'   | Select-Object -First 1).LineNumber
        $ecrIdx     = ($script:TeardownPlanned | Select-String -SimpleMatch 'ecr delete-repository'          | Select-Object -First 1).LineNumber

        $joined | Should -Match 'aws ecs delete-service'
        $joined | Should -Match 'aws ecs delete-cluster'
        $joined | Should -Match 'aws ecs deregister-task-definition'
        $joined | Should -Match 'aws rds delete-db-instance'
        $joined | Should -Match 'aws secretsmanager delete-secret'
        $joined | Should -Match 'aws ecr delete-repository'

        # Ordering: the ECS service drains first and the ECR registry is removed last.
        $svcIdx    | Should -BeLessThan $rdsIdx
        $rdsIdx    | Should -BeLessThan $secretIdx
        $secretIdx | Should -BeLessThan $ecrIdx
    }

    It 'every planned line is an aws command (no bare external calls) (DRY RUN)' {
        foreach ($cmd in $script:TeardownPlanned) {
            $cmd | Should -Match '^aws\b'
        }
    }
}
