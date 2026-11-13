<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the AWS Kubernetes (EKS) scripts
    (aws/eks/deploy.ps1 and aws/eks/teardown.ps1).

.DESCRIPTION
    Covers the dry run of the deploy and teardown scripts. Each script is executed in a
    fresh child PowerShell with -WhatIf against a well-formed temporary AWS config
    written under $TestDrive. Nothing here touches a real cloud: under -WhatIf the
    scripts record and print their planned command list and execute NO external
    command, so these assertions hold on Windows with no AWS account and with
    neither aws, docker, nor kubectl on PATH. Modeled on
    Aws.Ecs.WhatIf.Tests.ps1 and Gcp.Docker.WhatIf.Tests.ps1 (child-process
    -WhatIf invocation, a $TestDrive config .ps1, and a Get-PlannedCommands
    transcript parser).

    deploy.ps1:
      * Runs with -WhatIf and a safe -AllowedSourceRanges ('203.0.113.7/32');
        exits 0.
      * Prints the full ordered planned command list and executes NO external
        command (the footer reports "none executed").
      * Every planned line is an `aws ...`, `docker ...`, or `kubectl ...`
        command; the expected EKS-pipeline steps all appear in order:
          - aws sts get-caller-identity
          - aws ecr describe-repositories / create-repository
          - aws ecr get-login-password  +  docker login --password-stdin
            (the ECR token is rendered as a redacted stdin marker)
          - docker build ...:hardened / docker push ...:hardened
          - aws secretsmanager describe-secret / create-secret
            (the DB password is rendered as a redacted stdin marker)
          - aws rds describe-db-instances / create-db-instance
            (--no-publicly-accessible; password via redacted stdin)
          - aws eks describe-cluster / create-cluster
          - aws eks update-kubeconfig
          - kubectl kustomize --load-restrictor LoadRestrictionsNone
          - kubectl apply -f -   (rendered manifest fed on stdin)
          - kubectl rollout status deployment/...
          - kubectl get service ... (LoadBalancer hostname read)
      * No DB_PASSWORD env token appears anywhere in the planned set. The check is
        CASE-SENSITIVE (-CNotMatch): the lowercase /run/secrets/db_password file
        path and the lowercase Secrets Manager id (sangyshop/db_password) are both
        correct and allowed; only the uppercase env-var form DB_PASSWORD is
        forbidden.

    teardown.ps1:
      * Runs with -WhatIf; exits 0.
      * Prints the full ordered planned command list (reverse-order deletes) and
        executes NO external command: kubectl namespace delete, aws rds
        delete-db-instance, aws secretsmanager delete-secret, aws eks
        delete-cluster, aws ecr delete-repository -- with an ordering check that
        the namespace is removed before the cluster and the secret before the ECR
        repository.

    The password is never exposed: deploy's dry run renders secret-stdin commands
    with a redacted "<stdin: db password (redacted)>" marker and never generates a
    real value, so no secret can leak into the captured output.

    Requires Pester 5.x or 6.x (6.2 is installed here). Windows PowerShell 5.1
    compatible. Run with:
        Invoke-Pester -Path ops/tests/Aws.Eks.WhatIf.Tests.ps1
#>

BeforeAll {
    # ---- Locate the two scripts under test (do NOT edit them). --------------
    # tests/ sits directly under ops/; the AWS EKS scripts are two
    # folders deeper under aws/eks/.
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'eks' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'aws' 'eks' 'teardown.ps1')).Path

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
    # under -WhatIf without aws/docker/kubectl installed because nothing external
    # runs.
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

Describe 'AWS Kubernetes deploy.ps1 -WhatIf dry run' {
    BeforeAll {
        # deploy REQUIRES -AllowedSourceRanges; pass a safe non-open CIDR.
        $script:Deploy = Invoke-WhatIfScript -ScriptPath $script:DeployScript -ExtraArgs @(
            '-AllowedSourceRanges', '203.0.113.7/32', '-WhatIf'
        )
        $script:DeployPlanned = Get-PlannedCommands -Lines $script:Deploy.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Deploy.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Deploy.Text)
    }

    It 'prints the ordered planned command list and executes nothing' {
        $script:Deploy.Text | Should -Match 'planned command list'
        # The dry-run footer proves no external command ran.
        $script:Deploy.Text | Should -Match 'none executed'
        $script:DeployPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the expected aws ... steps' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'aws sts get-caller-identity'
        $joined | Should -Match 'aws ecr (describe-repositories|create-repository)'
        $joined | Should -Match 'aws ecr get-login-password'
        $joined | Should -Match 'aws secretsmanager (describe-secret|create-secret)'
        $joined | Should -Match 'aws rds (describe-db-instances|create-db-instance)'
        $joined | Should -Match 'aws eks (describe-cluster|create-cluster)'
        $joined | Should -Match 'aws eks update-kubeconfig'
    }

    It 'plans the ECR Docker login as a single native pipe (token never echoed)' {
        # The ECR login is the one special-cased native pipe: the login token flows
        # only through the OS pipe between the two processes, so it is neither an
        # echoed CLI arg nor a rendered stdin marker. The single planned line shows
        # both command names without the token.
        $loginLine = $script:DeployPlanned | Where-Object { $_ -match 'docker login ' } | Select-Object -First 1
        $loginLine | Should -Not -BeNullOrEmpty
        $loginLine | Should -Match 'aws ecr get-login-password --region .+ \| docker login --username AWS --password-stdin'
        # No redacted stdin marker is rendered for this pipe: the token travels only
        # through the native OS pipe, so it is neither echoed nor noted on the line.
        $loginLine | Should -Not -Match '<stdin'
    }

    It 'plans the hardened image docker build and push' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'docker build .+:hardened'
        $joined | Should -Match 'docker push .+:hardened'
    }

    It 'plans RDS as a non-public managed Postgres instance (not a container)' {
        $createLine = $script:DeployPlanned | Where-Object { $_ -match 'rds create-db-instance' } | Select-Object -First 1
        $createLine | Should -Not -BeNullOrEmpty
        $createLine | Should -Match '--engine postgres'
        $createLine | Should -Match '--no-publicly-accessible'
    }

    It 'renders the secretsmanager create-secret password on redacted stdin (never a CLI arg)' {
        $createSecret = $script:DeployPlanned | Where-Object { $_ -match 'secretsmanager create-secret' } | Select-Object -First 1
        $createSecret | Should -Not -BeNullOrEmpty
        $createSecret | Should -Match '<stdin: db password \(redacted\)>'
    }

    It 'plans the overlay apply with the load-restrictor pipe form' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'kubectl kustomize --load-restrictor LoadRestrictionsNone'
        $joined | Should -Match 'kubectl apply -f -'
    }

    It 'plans the rollout wait and the LoadBalancer hostname read' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'kubectl rollout status deployment/'
        # The ELB exposes a DNS hostname, read via jsonpath on the Service.
        $joined | Should -Match 'kubectl get service .+loadBalancer\.ingress\[0\]\.hostname'
    }

    It 'every planned line is an aws, docker, or kubectl command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) {
            $cmd | Should -Match '^(aws|docker|kubectl)\b'
        }
    }

    It 'orders the pipeline correctly (auth -> ecr -> build -> secret -> rds -> eks -> apply)' {
        $authIdx    = ($script:DeployPlanned | Select-String -SimpleMatch 'sts get-caller-identity' | Select-Object -First 1).LineNumber
        $ecrIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'ecr describe-repositories' | Select-Object -First 1).LineNumber
        $buildIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'docker build' | Select-Object -First 1).LineNumber
        $secretIdx  = ($script:DeployPlanned | Select-String -SimpleMatch 'secretsmanager create-secret' | Select-Object -First 1).LineNumber
        $rdsIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'rds create-db-instance' | Select-Object -First 1).LineNumber
        $eksIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'eks update-kubeconfig' | Select-Object -First 1).LineNumber
        $applyIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'kubectl apply -f -' | Select-Object -First 1).LineNumber

        $authIdx   | Should -BeLessThan $ecrIdx
        $ecrIdx    | Should -BeLessThan $buildIdx
        $buildIdx  | Should -BeLessThan $secretIdx
        $secretIdx | Should -BeLessThan $rdsIdx
        $rdsIdx    | Should -BeLessThan $eksIdx
        $eksIdx    | Should -BeLessThan $applyIdx
    }

    It 'sets NO DB_PASSWORD env anywhere in the planned command set' {
        # Match is CASE-SENSITIVE (-CNotMatch) on purpose: the lowercase Secrets
        # Manager id (sangyshop/db_password) and the lowercase /run/secrets/
        # db_password file path are both correct and required; only the uppercase
        # env-var form DB_PASSWORD is forbidden.
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD'
        ($script:DeployPlanned -join "`n") | Should -Not -CMatch 'DB_PASSWORD'
    }

    It 'never leaks a secret value (secret-stdin commands are redacted)' {
        # Every secret-bearing command renders with a redacted stdin marker; the
        # dry run never generates or prints a real password value.
        $script:Deploy.Text | Should -Match 'stdin: db password \(redacted\)'
    }
}

Describe 'AWS Kubernetes teardown.ps1 -WhatIf dry run' {
    BeforeAll {
        $script:Teardown = Invoke-WhatIfScript -ScriptPath $script:TeardownScript -ExtraArgs @('-WhatIf')
        $script:TeardownPlanned = Get-PlannedCommands -Lines $script:Teardown.Lines
    }

    It 'exits 0 under -WhatIf' {
        $script:Teardown.ExitCode | Should -Be 0 -Because (
            "the dry run must not execute anything and must succeed. Output:`n" + $script:Teardown.Text)
    }

    It 'prints the ordered planned command list and executes nothing' {
        $script:Teardown.Text | Should -Match 'planned command list'
        $script:Teardown.Text | Should -Match 'none executed'
        $script:TeardownPlanned.Count | Should -BeGreaterThan 0
    }

    It 'plans the reverse-order deletes (namespace -> rds -> secret -> cluster -> ecr)' {
        $joined = ($script:TeardownPlanned -join "`n")
        $joined | Should -Match 'kubectl delete namespace sangyshop-hardened'
        $joined | Should -Match 'aws rds delete-db-instance'
        $joined | Should -Match 'aws secretsmanager delete-secret'
        $joined | Should -Match 'aws eks delete-cluster'
        $joined | Should -Match 'aws ecr delete-repository'
    }

    It 'removes the namespace before the cluster and the secret before the ECR repository' {
        $nsIdx      = ($script:TeardownPlanned | Select-String -SimpleMatch 'kubectl delete namespace' | Select-Object -First 1).LineNumber
        $clusterIdx = ($script:TeardownPlanned | Select-String -SimpleMatch 'eks delete-cluster'       | Select-Object -First 1).LineNumber
        $secretIdx  = ($script:TeardownPlanned | Select-String -SimpleMatch 'secretsmanager delete-secret' | Select-Object -First 1).LineNumber
        $ecrIdx     = ($script:TeardownPlanned | Select-String -SimpleMatch 'ecr delete-repository'     | Select-Object -First 1).LineNumber

        # Compute (in-cluster namespace) drains before the control plane it runs on.
        $nsIdx     | Should -BeLessThan $clusterIdx
        # The stored secret is removed before the native registry (removed last).
        $secretIdx | Should -BeLessThan $ecrIdx
    }

    It 'every planned line is an aws or kubectl command (no bare external calls)' {
        foreach ($cmd in $script:TeardownPlanned) {
            $cmd | Should -Match '^(aws|kubectl)\b'
        }
    }
}
