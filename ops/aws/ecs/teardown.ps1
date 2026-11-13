<#
.SYNOPSIS
    Tear down the HARDENED SangyShop AWS ECS Fargate deployment (Docker-only modality).

.DESCRIPTION
    Matching teardown for aws/docker/deploy.ps1. Removes every resource that
    deploy.ps1 created, in REVERSE dependency order so a dependent resource is
    gone before the thing it depends on:

        1. ECS service              scaled to 0, then deleted      (compute)
        2. ECS cluster              deleted after the service
        3. ECS task definition      every revision deregistered
        4. RDS for PostgreSQL       deleted --skip-final-snapshot  (DB)
        5. Secrets Manager secret   deleted --force-delete-without-recovery
                                    (stored DB password)
        6. Security groups          the task SG and the RDS SG
        7. CloudWatch Logs group    /ecs/<app>-hardened
        8. ECR repository           native registry -- LAST, and only
                                    unless -KeepRegistry

    Every external CLI call routes through the shared Invoke-Echoed helper in
    lib/Common.ps1, so each command is echoed before it runs. The
    executable name ('aws') is only ever passed as the -Exe argument, never a
    bare token; this script never invokes `aws` directly, and no other CLI is
    used.

    Convergent / idempotent: every deletion uses -AllowFail, so a
    resource that is already gone is treated as successfully removed and skipped,
    and a second run of this script converges to zero remaining resources and
    exits success. Each resource whose deletion command ran without a real error
    has its identifier printed.

    Fail-but-continue: a real removal failure (a non-zero exit that is
    NOT the "already deleted / not found" case) does NOT stop teardown. The script
    records the failure, reports it to stderr naming the resource, keeps removing
    the remaining resources, and finally exits with a NON-success status. Only an
    already-deleted resource is tolerated silently.

    DEPENDENCY NOTE: an AWS security group cannot be deleted while a network
    interface (the running Fargate task's ENI) or another resource still
    references it. Such a delete legitimately fails with a DependencyViolation
    until the referencing resource drains. That is treated as a REAL failure
    (reported, non-success exit) rather than "already gone", because the resource
    still exists -- a re-run once the task/RDS has fully drained converges and
    succeeds. The compute+RDS deletes are issued first (reverse
    order) precisely so the groups can be freed.

    -WhatIf: print the full ordered command list that WOULD run, execute
    no external command, and exit 0.

    Windows PowerShell 5.1 compatible.

.PARAMETER ConfigPath
    Path to cloud.config.ps1. Defaults to the git-ignored config two folders up
    (ops/cloud.config.ps1).

.PARAMETER Force
    Skip the interactive confirmation prompt and proceed with the (destructive)
    teardown. Without it, an interactive host is asked to confirm before anything
    is deleted; under -WhatIf no confirmation is needed (nothing is deleted).

.PARAMETER KeepRegistry
    Preserve the ECR repository (and the pushed hardened image). When set, the
    final step is skipped so the registry survives teardown.

.PARAMETER WhatIf
    Dry run: print the full ordered command list without executing any external
    command, then exit 0.

.EXAMPLE
    .\teardown.ps1

.EXAMPLE
    .\teardown.ps1 -KeepRegistry

.EXAMPLE
    .\teardown.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot '..\..\cloud.config.ps1'),
    [switch] $Force,
    [switch] $KeepRegistry,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Dot-source the shared library (Invoke-Echoed, Write-Step, Get-CloudConfig).
# Relative to this script: ../../lib/Common.ps1.
. (Join-Path $PSScriptRoot '..\..\lib\Common.ps1')

# ---------------------------------------------------------------------------
# WhatIf-aware command runner (mirrors deploy.ps1 / gcp teardown Invoke-Cli).
#
# Every external CLI call goes through Invoke-Cli, never a bare CLI token
#. Under -WhatIf it records and prints the planned command line and
# executes NOTHING; otherwise it delegates to the shared Invoke-Echoed
# helper, which echoes the exact command and then runs it.
#
# Teardown always passes -AllowFail: a non-zero exit must not throw,
# so the caller can inspect $script:LastCliExit, decide whether it was an
# "already deleted" case, and keep going regardless.
# ---------------------------------------------------------------------------
$script:PlannedCommands = New-Object System.Collections.Generic.List[string]
$script:LastCliExit     = 0

function Invoke-Cli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs
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
    $display = $displayParts -join ' '

    if ($WhatIf) {
        # record + print the planned command; execute NOTHING. Model a
        # "would succeed" exit so read-then-act lookups pick a deterministic
        # branch for the planned list.
        $script:PlannedCommands.Add($display)
        Write-Host "> $display" -ForegroundColor DarkCyan
        $script:LastCliExit = 0
        return $null
    }

    # Real execution path: route through the shared, echoing helper.
    # -AllowFail so an already-deleted resource's non-zero exit returns control
    # here instead of throwing.
    $result = (Invoke-Echoed -Exe $Exe -CmdArgs $CmdArgs -AllowFail)
    $script:LastCliExit = $LASTEXITCODE
    return $result
}

# Collapse a (possibly multi-line / array) CLI stdout into a single trimmed value.
function Get-CliScalar {
    param($Value)
    if ($Value -is [System.Array]) {
        $Value = ($Value | Where-Object { $_ } | Select-Object -Last 1)
    }
    return ([string]$Value).Trim()
}

# ---------------------------------------------------------------------------
# Removal bookkeeping.
#
# $removed       : identifiers whose deletion command ran without a real error
#                  (deleted now OR already gone). Printed on success.
# $failures      : identifiers that hit a real (non-"already deleted") failure.
# $realFailure   : the flag that drives the final non-success exit code.
# ---------------------------------------------------------------------------
$script:removed     = New-Object System.Collections.Generic.List[string]
$script:failures    = New-Object System.Collections.Generic.List[string]
$script:realFailure = $false

# Run one deletion and classify its outcome. A non-zero exit whose output looks
# like a "not found / already deleted" case is tolerated as success;
# any other non-zero exit is a real failure that is reported to stderr and flips
# the exit code, but DOES NOT stop the remaining deletions.
#
# AWS "already gone" signals vary by service: RDS DBInstanceNotFound, ECS
# ClusterNotFound/ServiceNotFound/ClientException "does not exist", Secrets
# Manager ResourceNotFoundException, EC2 InvalidGroup.NotFound, CloudWatch Logs
# ResourceNotFoundException, ECR RepositoryNotFoundException -- all of which
# contain a "not found / does not exist / no such" phrase we match generically.
function Remove-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Identifier,  # human-readable id for reporting
        [Parameter(Mandatory)][string[]] $CmdArgs       # aws CLI args (without the exe)
    )

    $output = Invoke-Cli -Exe 'aws' -CmdArgs $CmdArgs

    if ($WhatIf) {
        # Nothing executed; planning only. Do not record removal under a dry run.
        return
    }

    if ($script:LastCliExit -eq 0) {
        $script:removed.Add($Identifier)
        Write-Host "    removed: $Identifier" -ForegroundColor Green
        return
    }

    # Non-zero exit. Distinguish "already deleted / not found" (tolerated)
    # from a real failure (reported + non-success).
    $text = ''
    if ($null -ne $output) { $text = ($output | Out-String) }
    $alreadyGone = $text -match '(?i)(not\s*found|notfound|does\s*not\s*exist|was\s*not\s*found|no\s*such|InvalidGroup\.NotFound|DBInstanceNotFound|ResourceNotFoundException|RepositoryNotFoundException|ClusterNotFoundException|ServiceNotFoundException)'

    if ($alreadyGone) {
        # Converge: treat an already-absent resource as removed.
        $script:removed.Add("$Identifier (already absent)")
        Write-Host "    already absent (skipped): $Identifier" -ForegroundColor DarkGray
    }
    else {
        # Real failure (includes DependencyViolation while an ENI still references
        # a security group): record, report to stderr, continue. A re-run
        # once the referencing resource has drained converges and succeeds.
        $script:realFailure = $true
        $script:failures.Add($Identifier)
        Write-Error "Failed to remove: $Identifier (CLI exit $($script:LastCliExit)). Continuing with remaining resources."
    }
}

# ---------------------------------------------------------------------------
# 0. Load + validate config (fail-closed BEFORE any external command).
#    Config-derived names mirror deploy.ps1 exactly so the SAME resources are
#    targeted.
# ---------------------------------------------------------------------------
Write-Step "Loading configuration (cloud: Aws)"
$cfg = Get-CloudConfig -ConfigPath $ConfigPath -Cloud 'Aws'

$region      = [string]$cfg.Aws.Region
$ecrRepo     = [string]$cfg.Aws.EcrRepo
$ecsCluster  = [string]$cfg.Aws.EcsCluster
$appName     = [string]$cfg.Common.AppName

# Derived names / identifiers (identical to deploy.ps1).
$secretName  = "$appName/db_password"      # Secrets Manager secret id
$rdsId       = "$appName-pg"               # RDS db instance identifier
$taskFamily  = "$appName-hardened"         # ECS task definition family
$serviceName = "$appName-svc"              # ECS service name
$sgName      = "$appName-task-sg"          # task security group name
$rdsSgName   = "$appName-rds-sg"           # RDS security group name
$logGroup    = "/ecs/$appName-hardened"    # CloudWatch Logs group for the task

# ---------------------------------------------------------------------------
# Confirmation (destructive). Skipped under -WhatIf (nothing is deleted) and when
# -Force is passed. The delete commands themselves never prompt (AWS deletes are
# non-interactive), so -Force only governs this gate.
# ---------------------------------------------------------------------------
if (-not $WhatIf -and -not $Force) {
    Write-Host ""
    Write-Host "This will PERMANENTLY DELETE the following AWS resources (region '$region'):" -ForegroundColor Yellow
    Write-Host "  * ECS service              : $serviceName (cluster $ecsCluster)" -ForegroundColor Yellow
    Write-Host "  * ECS cluster              : $ecsCluster" -ForegroundColor Yellow
    Write-Host "  * ECS task definition      : $taskFamily (all revisions)" -ForegroundColor Yellow
    Write-Host "  * RDS instance             : $rdsId  (--skip-final-snapshot)" -ForegroundColor Yellow
    Write-Host "  * Secrets Manager secret   : $secretName  (--force-delete-without-recovery)" -ForegroundColor Yellow
    Write-Host "  * Security groups          : $sgName, $rdsSgName" -ForegroundColor Yellow
    Write-Host "  * CloudWatch Logs group    : $logGroup" -ForegroundColor Yellow
    if ($KeepRegistry) {
        Write-Host "  * ECR repository           : $ecrRepo  (KEPT: -KeepRegistry)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  * ECR repository           : $ecrRepo" -ForegroundColor Yellow
    }
    Write-Host ""
    $answer = Read-Host "Type 'yes' to proceed (or re-run with -Force to skip this prompt)"
    if ($answer -ne 'yes') {
        Write-Host "Teardown aborted; nothing was deleted." -ForegroundColor Cyan
        exit 0
    }
}

if ($WhatIf) {
    Write-Step "DRY RUN (-WhatIf): the ordered command list below WOULD run; nothing is executed."
}

# ---------------------------------------------------------------------------
# Authentication check (fail-closed). `aws sts get-caller-identity` succeeds only
# when the CLI is installed AND a session is active. On failure, print install +
# auth guidance and exit non-zero so we never report a false "nothing left".
# ---------------------------------------------------------------------------
Write-Step "Checking AWS authentication via sts get-caller-identity"
if ($WhatIf) {
    Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
}
else {
    Invoke-Cli -Exe 'aws' -CmdArgs @('sts', 'get-caller-identity', '--output', 'text', '--query', 'Account') | Out-Null
    if ($script:LastCliExit -ne 0) {
        Write-Error (@(
            "AWS authentication/CLI check failed (aws sts get-caller-identity).",
            "",
            "Install the AWS CLI v2 for Windows:",
            "    https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
            "    (verify with: aws --version)",
            "Authenticate to the SAME (isolated / throwaway) account you deployed to:",
            "    aws configure                 # static access keys, or",
            "    aws sso login                 # IAM Identity Center / SSO",
            "Confirm the active identity with:",
            "    aws sts get-caller-identity",
            "",
            "Then re-run this script."
        ) -join [Environment]::NewLine)
        exit 1
    }
}

# ===========================================================================
# 1. Compute first: scale the ECS service to 0, then delete it. The
#    service must be drained to 0 desired tasks before --force deletion so the
#    task ENI is released and the task security group can later be freed.
# ===========================================================================
Write-Step "Scaling the ECS service '$serviceName' to 0 and deleting it"

# Scale to 0 first. This is tolerant (-AllowFail via Invoke-Cli): if the service
# or cluster is already gone the update no-ops and the subsequent delete converges.
Invoke-Cli -Exe 'aws' -CmdArgs @(
    'ecs', 'update-service',
    '--region', $region,
    '--cluster', $ecsCluster,
    '--service', $serviceName,
    '--desired-count', '0'
) | Out-Null

Remove-Resource -Identifier "ecs-service/$serviceName" -CmdArgs @(
    'ecs', 'delete-service',
    '--region', $region,
    '--cluster', $ecsCluster,
    '--service', $serviceName,
    '--force'
)

# ---------------------------------------------------------------------------
# 2. ECS cluster: deleted after its service.
# ---------------------------------------------------------------------------
Write-Step "Deleting the ECS cluster '$ecsCluster'"
Remove-Resource -Identifier "ecs-cluster/$ecsCluster" -CmdArgs @(
    'ecs', 'delete-cluster',
    '--region', $region,
    '--cluster', $ecsCluster
)

# ---------------------------------------------------------------------------
# 3. ECS task definition: deregister every ACTIVE revision of the family so no
#    orphaned task definition lingers. deregister-task-definition takes
#    a single family:revision, so list the active revisions and deregister each.
# ---------------------------------------------------------------------------
Write-Step "Deregistering every revision of the ECS task definition '$taskFamily'"
if ($WhatIf) {
    # Plan the shape: list then a representative deregister.
    Invoke-Cli -Exe 'aws' -CmdArgs @(
        'ecs', 'list-task-definitions',
        '--region', $region,
        '--family-prefix', $taskFamily,
        '--status', 'ACTIVE',
        '--output', 'text', '--query', 'taskDefinitionArns'
    ) | Out-Null
    Remove-Resource -Identifier "ecs-task-definition/${taskFamily}:<revision>" -CmdArgs @(
        'ecs', 'deregister-task-definition',
        '--region', $region,
        '--task-definition', "${taskFamily}:<revision>"
    )
}
else {
    $tdOut = Invoke-Cli -Exe 'aws' -CmdArgs @(
        'ecs', 'list-task-definitions',
        '--region', $region,
        '--family-prefix', $taskFamily,
        '--status', 'ACTIVE',
        '--output', 'text', '--query', 'taskDefinitionArns'
    )
    if ($script:LastCliExit -ne 0) {
        # The listing itself failed for a non-"not found" reason; record it so the
        # task definitions are not silently skipped. A "not found" style
        # listing simply yields no ARNs and is treated as nothing to do.
        $listText = ''
        if ($null -ne $tdOut) { $listText = ($tdOut | Out-String) }
        if ($listText -notmatch '(?i)(not\s*found|notfound|does\s*not\s*exist|no\s*such)') {
            $script:realFailure = $true
            $script:failures.Add("ecs-task-definition/$taskFamily (list failed)")
            Write-Error "Failed to list task definitions for family '$taskFamily' (CLI exit $($script:LastCliExit)). Continuing with remaining resources."
        }
    }

    $tdArns = @()
    if ($null -ne $tdOut) {
        $tdArns = @(($tdOut | Out-String) -split '\s+' | Where-Object { $_ -and $_ -ne 'None' })
    }
    if ($tdArns.Count -eq 0) {
        $script:removed.Add("ecs-task-definition/$taskFamily (already absent)")
        Write-Host "    already absent (skipped): ecs-task-definition/$taskFamily" -ForegroundColor DarkGray
    }
    else {
        foreach ($arn in $tdArns) {
            Remove-Resource -Identifier "ecs-task-definition/$arn" -CmdArgs @(
                'ecs', 'deregister-task-definition',
                '--region', $region,
                '--task-definition', $arn
            )
        }
    }
}

# ---------------------------------------------------------------------------
# 4. RDS for PostgreSQL: delete the managed instance. --skip-final-
#    snapshot and --delete-automated-backups avoid leaving a billable snapshot or
#    backups behind in a teaching lab.
# ---------------------------------------------------------------------------
Write-Step "Deleting the RDS instance '$rdsId' (--skip-final-snapshot)"
Remove-Resource -Identifier "rds/$rdsId" -CmdArgs @(
    'rds', 'delete-db-instance',
    '--region', $region,
    '--db-instance-identifier', $rdsId,
    '--skip-final-snapshot',
    '--delete-automated-backups'
)

# ---------------------------------------------------------------------------
# 5. Secrets Manager secret: delete the stored DB password AFTER compute + DB
#. --force-delete-without-recovery removes it immediately with no
#    recovery window, so no lingering (billable-eligible) secret remains.
# ---------------------------------------------------------------------------
Write-Step "Deleting the Secrets Manager secret '$secretName' (--force-delete-without-recovery)"
Remove-Resource -Identifier "secrets-manager/$secretName" -CmdArgs @(
    'secretsmanager', 'delete-secret',
    '--region', $region,
    '--secret-id', $secretName,
    '--force-delete-without-recovery'
)

# ---------------------------------------------------------------------------
# 6. Security groups: the task SG and the RDS SG. AWS deletes a security
#    group by id, so resolve each name -> id first (describe is tolerant). A group
#    still referenced by the draining task ENI fails with DependencyViolation,
#    which Remove-Resource classifies as a real failure; a re-run after the ENI is
#    released converges. Delete the task SG before the RDS SG since
#    the RDS SG's ingress references the task SG.
# ---------------------------------------------------------------------------
Write-Step "Deleting the task and RDS security groups ('$sgName', '$rdsSgName')"
foreach ($sg in @(
        @{ Name = $sgName;    Id = "sg/$sgName" },
        @{ Name = $rdsSgName; Id = "sg/$rdsSgName" }
    )) {
    if ($WhatIf) {
        Invoke-Cli -Exe 'aws' -CmdArgs @(
            'ec2', 'describe-security-groups',
            '--region', $region,
            '--filters', "Name=group-name,Values=$($sg.Name)",
            '--output', 'text', '--query', 'SecurityGroups[0].GroupId'
        ) | Out-Null
        Remove-Resource -Identifier $sg.Id -CmdArgs @(
            'ec2', 'delete-security-group',
            '--region', $region,
            '--group-id', '<sg-id>'
        )
        continue
    }

    $sgIdOut = Invoke-Cli -Exe 'aws' -CmdArgs @(
        'ec2', 'describe-security-groups',
        '--region', $region,
        '--filters', "Name=group-name,Values=$($sg.Name)",
        '--output', 'text', '--query', 'SecurityGroups[0].GroupId'
    )
    $sgId = Get-CliScalar $sgIdOut

    if ([string]::IsNullOrWhiteSpace($sgId) -or $sgId -eq 'None') {
        # The describe succeeded but matched nothing (or the group is gone):
        # already absent, converge.
        $script:removed.Add($sg.Id + ' (already absent)')
        Write-Host "    already absent (skipped): $($sg.Id)" -ForegroundColor DarkGray
        continue
    }

    Remove-Resource -Identifier ($sg.Id + " ($sgId)") -CmdArgs @(
        'ec2', 'delete-security-group',
        '--region', $region,
        '--group-id', $sgId
    )
}

# ---------------------------------------------------------------------------
# 7. CloudWatch Logs group: the task's log group.
# ---------------------------------------------------------------------------
Write-Step "Deleting the CloudWatch Logs group '$logGroup'"
Remove-Resource -Identifier "logs/$logGroup" -CmdArgs @(
    'logs', 'delete-log-group',
    '--region', $region,
    '--log-group-name', $logGroup
)

# ---------------------------------------------------------------------------
# 8. ECR repository (native registry, removed LAST). Skipped entirely
#    when -KeepRegistry preserves the registry + image. --force deletes the repo
#    even when it still contains the pushed hardened image.
# ---------------------------------------------------------------------------
if ($KeepRegistry) {
    Write-Step "Keeping the ECR repository '$ecrRepo' (-KeepRegistry)"
}
else {
    Write-Step "Deleting the ECR repository '$ecrRepo' (last)"
    Remove-Resource -Identifier "ecr/$ecrRepo" -CmdArgs @(
        'ecr', 'delete-repository',
        '--region', $region,
        '--repository-name', $ecrRepo,
        '--force'
    )
}

# ---------------------------------------------------------------------------
# Dry run ends here: print the planned command list and exit 0.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Final report.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Step "Teardown summary"
if ($script:removed.Count -gt 0) {
    Write-Host "Removed resource(s):"
    foreach ($id in $script:removed) {
        Write-Host "  - $id"
    }
}
else {
    Write-Host "No resources were removed (nothing to remove, or all were already absent)."
}

if ($script:realFailure) {
    Write-Host ""
    Write-Error (@(
        "Teardown finished with failures. The following resource(s) could NOT be removed:",
        ($script:failures | ForEach-Object { "  - $_" }),
        "",
        "Some AWS deletes (security groups) legitimately fail while a draining task ENI or",
        "the RDS instance still references them. Re-run this script once those have fully",
        "drained; already-deleted resources are skipped and the re-run converges."
    ) -join [Environment]::NewLine)
    # a real removal failure means a NON-success exit status.
    exit 1
}

# every resource was removed (or already absent); exit success.
Write-Host ""
Write-Host "Teardown complete: zero billable resources remain for this target." -ForegroundColor Green
if ($KeepRegistry) {
    Write-Host "(ECR repository '$ecrRepo' was kept at your request.)" -ForegroundColor Cyan
}
exit 0
