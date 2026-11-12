<#
.SYNOPSIS
    Pester 5.x/6.x -WhatIf dry-run assertions for the GCP Kubernetes (GKE) scripts
    (gcp/kubernetes/deploy.ps1 and gcp/kubernetes/teardown.ps1).

.DESCRIPTION
    Covers task 7.4 of the multi-cloud-deploy plan. Each script is executed in a
    fresh child PowerShell with -WhatIf against a well-formed temporary GCP config
    written under $TestDrive. Nothing here touches a real cloud: under -WhatIf the
    scripts record and print their planned command list and execute NO external
    command, so these assertions hold on Windows with no GCP account and with
    none of gcloud, docker, or kubectl on PATH. Modeled on
    Gcp.Docker.WhatIf.Tests.ps1 and Aws.Kubernetes.WhatIf.Tests.ps1 (child-process
    -WhatIf invocation, a $TestDrive config .ps1, and a Get-PlannedCommands
    transcript parser).

    deploy.ps1 (Req 6.5, 3.1, 3.3):
      * Runs with -WhatIf and a safe -AllowedSourceRanges ('203.0.113.7/32');
        exits 0.
      * Prints the full ordered planned command list and executes NO external
        command (the dry-run footer reports "none executed").
      * Every planned line is a `gcloud ...`, `docker ...`, or `kubectl ...`
        command; the expected GKE-pipeline steps all appear in order:
          - gcloud auth list
          - gcloud config set project
          - gcloud artifacts repositories describe / create  (Artifact Registry)
          - gcloud auth configure-docker
          - docker build ...:hardened / docker push ...:hardened
          - gcloud secrets create / versions add  (DB password on redacted stdin)
          - gcloud sql instances create (--no-assign-ip) + db + user
          - gcloud container clusters describe / create
          - gcloud container clusters get-credentials
          - kubectl kustomize --load-restrictor LoadRestrictionsNone
          - kubectl apply -f -   (rendered manifest fed on stdin)
          - kubectl -n sangyshop-hardened rollout status deploy/sangyshop
          - kubectl get svc ... (external IP read)
      * No DB_PASSWORD env token appears anywhere in the planned set. The check is
        CASE-SENSITIVE (-CNotMatch): the lowercase /run/secrets/db_password file
        path and the lowercase Secret Manager id (db_password) are both correct
        and allowed; only the uppercase env-var form DB_PASSWORD is forbidden
        (Req 3.1). The GKE overlay carries the secret-file contract (the app reads
        /run/secrets/db_password via the CSI driver), so the only secret-related
        assertion needed here is "no DB_PASSWORD" plus "kubectl apply is planned".

    teardown.ps1 (Req 6.5):
      * Runs with -WhatIf; exits 0.
      * Prints the full ordered planned command list (reverse-order deletes) and
        executes NO external command: kubectl delete (overlay + namespace),
        gcloud container clusters delete, gcloud sql instances delete, gcloud
        secrets delete, gcloud artifacts repositories delete -- with an ordering
        check that the namespace/workload drains before the cluster, and the
        registry is removed last.

    The password is never exposed: deploy's dry run renders secret-stdin commands
    with a redacted "<stdin: db password (redacted)>" marker and never generates a
    real value, so no secret can leak into the captured output.

    Requires Pester 5.x or 6.x (6.2 is installed here). Windows PowerShell 5.1
    compatible. Run with:
        Invoke-Pester -Path ops/tests/Gcp.Kubernetes.WhatIf.Tests.ps1
#>

BeforeAll {
    # ---- Locate the two scripts under test (do NOT edit them). --------------
    # tests/ sits directly under ops/; the GCP kubernetes scripts are two
    # folders deeper under gcp/kubernetes/.
    $script:DeployScript   = (Resolve-Path (Join-Path $PSScriptRoot '..' 'gcp' 'kubernetes' 'deploy.ps1')).Path
    $script:TeardownScript = (Resolve-Path (Join-Path $PSScriptRoot '..' 'gcp' 'kubernetes' 'teardown.ps1')).Path

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
    # (stdout + stderr via *>&1) plus the child's exit code. The scripts exit 0
    # under -WhatIf without gcloud/docker/kubectl installed because nothing
    # external runs.
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

Describe 'GCP Kubernetes deploy.ps1 -WhatIf dry run (Req 6.5, 3.1, 3.3)' {
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

    It 'plans the auth check and active-project bind' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud auth list'
        $joined | Should -Match 'gcloud config set project my-project-123'
    }

    It 'plans the Artifact Registry describe-or-create and the docker auth config' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud artifacts repositories (describe|create) sangyshop'
        $joined | Should -Match 'gcloud auth configure-docker us-central1-docker\.pkg\.dev'
    }

    It 'plans the hardened image docker build and push' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'docker build .+:hardened'
        $joined | Should -Match 'docker push .+:hardened'
    }

    It 'plans the Secret Manager create/add with the password on redacted stdin' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud secrets (create|versions add) db_password'
        # The DB password is piped via --data-file=- and rendered redacted.
        $secretLine = $script:DeployPlanned |
            Where-Object { $_ -match 'gcloud secrets (create|versions add) db_password' } |
            Select-Object -First 1
        $secretLine | Should -Not -BeNullOrEmpty
        $secretLine | Should -Match '--data-file=-'
        $secretLine | Should -Match '<stdin: db password \(redacted\)>'
    }

    It 'plans Cloud SQL as a non-public managed Postgres instance (not a container)' {
        $createLine = $script:DeployPlanned |
            Where-Object { $_ -match 'sql instances create sangyshop-pg' } |
            Select-Object -First 1
        $createLine | Should -Not -BeNullOrEmpty
        $createLine | Should -Match '--database-version=POSTGRES'
        # --no-assign-ip => no public IPv4 => not publicly reachable (Req 9.5).
        $createLine | Should -Match '--no-assign-ip'
    }

    It 'plans the database and db user on the Cloud SQL instance' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud sql databases (describe|create) sangyshop'
        $joined | Should -Match 'gcloud sql users (list|create|set-password) sangyshop'
    }

    It 'plans the GKE cluster describe-or-create and get-credentials' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'gcloud container clusters (describe|create) sangyshop-lab'
        $joined | Should -Match 'gcloud container clusters get-credentials sangyshop-lab'
    }

    It 'plans the overlay render with the load-restrictor pipe form and the apply' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'kubectl kustomize --load-restrictor LoadRestrictionsNone'
        $joined | Should -Match 'kubectl apply -f -'
    }

    It 'plans the rollout wait and the external IP read' {
        $joined = ($script:DeployPlanned -join "`n")
        $joined | Should -Match 'kubectl -n sangyshop-hardened rollout status deploy/sangyshop'
        # The GKE LoadBalancer exposes an external IP, read via jsonpath on the svc.
        $joined | Should -Match 'kubectl -n sangyshop-hardened get svc sangyshop'
        $joined | Should -Match 'loadBalancer\.ingress\[0\]\.ip'
    }

    It 'every planned line is a gcloud, docker, or kubectl command (no bare external calls)' {
        foreach ($cmd in $script:DeployPlanned) {
            $cmd | Should -Match '^(gcloud|docker|kubectl)\b'
        }
    }

    It 'orders the pipeline correctly (auth -> AR -> build -> secret -> sql -> cluster -> get-credentials -> apply)' {
        $authIdx    = ($script:DeployPlanned | Select-String -SimpleMatch 'auth list'                       | Select-Object -First 1).LineNumber
        $arIdx      = ($script:DeployPlanned | Select-String -SimpleMatch 'artifacts repositories'          | Select-Object -First 1).LineNumber
        $buildIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'docker build'                    | Select-Object -First 1).LineNumber
        $secretIdx  = ($script:DeployPlanned | Select-String -SimpleMatch 'secrets create db_password'      | Select-Object -First 1).LineNumber
        $sqlIdx     = ($script:DeployPlanned | Select-String -SimpleMatch 'sql instances create sangyshop-pg' | Select-Object -First 1).LineNumber
        $clusterIdx = ($script:DeployPlanned | Select-String -SimpleMatch 'container clusters create sangyshop-lab' | Select-Object -First 1).LineNumber
        $credIdx    = ($script:DeployPlanned | Select-String -SimpleMatch 'container clusters get-credentials' | Select-Object -First 1).LineNumber
        $applyIdx   = ($script:DeployPlanned | Select-String -SimpleMatch 'kubectl apply -f -'              | Select-Object -First 1).LineNumber

        $authIdx    | Should -BeLessThan $arIdx
        $arIdx      | Should -BeLessThan $buildIdx
        $buildIdx   | Should -BeLessThan $secretIdx
        $secretIdx  | Should -BeLessThan $sqlIdx
        $sqlIdx     | Should -BeLessThan $clusterIdx
        $clusterIdx | Should -BeLessThan $credIdx
        $credIdx    | Should -BeLessThan $applyIdx
    }

    It 'sets NO DB_PASSWORD env anywhere in the planned command set (Req 3.1)' {
        # Match is CASE-SENSITIVE (-CNotMatch) on purpose: the lowercase Secret
        # Manager id (db_password) and the lowercase /run/secrets/db_password file
        # path are both correct and required; only the uppercase env-var form
        # DB_PASSWORD is forbidden (Req 3.1).
        $script:Deploy.Text | Should -Not -CMatch 'DB_PASSWORD'
        ($script:DeployPlanned -join "`n") | Should -Not -CMatch 'DB_PASSWORD'
    }

    It 'applies the overlay via kubectl (secret-file contract carried by the overlay, Req 3.3)' {
        # The GKE overlay delivers the secret as the file /run/secrets/db_password
        # (CSI driver); here we only need to confirm the overlay apply is planned.
        ($script:DeployPlanned -join "`n") | Should -Match 'kubectl apply -f -'
    }

    It 'never leaks a secret value (secret-stdin commands are redacted)' {
        # Every secret-bearing command renders with a redacted stdin marker; the
        # dry run never generates or prints a real password value.
        $script:Deploy.Text | Should -Match 'stdin: db password \(redacted\)'
    }
}

Describe 'GCP Kubernetes teardown.ps1 -WhatIf dry run (Req 6.5)' {
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

    It 'plans the reverse-order deletes (workload/namespace -> cluster -> sql -> secret -> registry)' {
        $joined = ($script:TeardownPlanned -join "`n")
        # In-cluster workload: overlay delete piped on stdin + namespace catch-all.
        $joined | Should -Match 'kubectl delete -f -'
        $joined | Should -Match 'kubectl delete namespace sangyshop-hardened'
        $joined | Should -Match 'gcloud container clusters delete sangyshop-lab'
        $joined | Should -Match 'gcloud sql instances delete sangyshop-pg'
        $joined | Should -Match 'gcloud secrets delete db_password'
        $joined | Should -Match 'gcloud artifacts repositories delete sangyshop'
    }

    It 'drains the namespace/workload before the cluster and removes the registry last' {
        $nsIdx       = ($script:TeardownPlanned | Select-String -SimpleMatch 'kubectl delete namespace'          | Select-Object -First 1).LineNumber
        $clusterIdx  = ($script:TeardownPlanned | Select-String -SimpleMatch 'container clusters delete'         | Select-Object -First 1).LineNumber
        $sqlIdx      = ($script:TeardownPlanned | Select-String -SimpleMatch 'sql instances delete'              | Select-Object -First 1).LineNumber
        $secretIdx   = ($script:TeardownPlanned | Select-String -SimpleMatch 'secrets delete db_password'        | Select-Object -First 1).LineNumber
        $registryIdx = ($script:TeardownPlanned | Select-String -SimpleMatch 'artifacts repositories delete'     | Select-Object -First 1).LineNumber

        # The in-cluster workload drains before the control plane it runs on, and
        # the cluster delete precedes the sql/secret removals (acceptable order).
        $nsIdx      | Should -BeLessThan $clusterIdx
        $clusterIdx | Should -BeLessThan $sqlIdx
        $clusterIdx | Should -BeLessThan $secretIdx
        # The native registry is removed LAST (Req 5.3).
        $sqlIdx     | Should -BeLessThan $registryIdx
        $secretIdx  | Should -BeLessThan $registryIdx
    }

    It 'every planned line is a gcloud or kubectl command (no bare external calls)' {
        foreach ($cmd in $script:TeardownPlanned) {
            $cmd | Should -Match '^(gcloud|kubectl)\b'
        }
    }
}
