<#
.SYNOPSIS
    Pester 5.x property tests for the permission-error handling (lib/LabPermissions.ps1).

.DESCRIPTION
    Property: for any service, any action and any recognized error format, on AWS
    and on Azure, a permission failure handled by Stop-LabForPermission

      * ends the process with exit code 3 (each case runs in a child pwsh, because
        the function calls exit),
      * prints a complete message: the BLOCKED marker, the step, the denied service
        and action, the exact managed policy or built-in role (or the scoped policy
        file), and the instruction to run the same script again,
      * makes no grant call: stand-in aws and az functions in the child record every
        call, and the recording must stay empty.

    Inputs are generated from a fixed seed so a failure is reproducible. The
    services come from the hint tables themselves, plus one service that is not in
    the table, so the fallback message is covered too. No cloud CLI is ever invoked.

    Run with:
        Invoke-Pester -Path ops/tests/LabPermissions.Tests.ps1
#>

BeforeDiscovery {
    . (Join-Path $PSScriptRoot '..' 'lib' 'LabPermissions.ps1')

    $rng = [System.Random]::new(27)

    $awsActions = @('create-topic', 'CreateTrail', 'put-metric-filter', 'create-detector',
        'describe-instances', 'sns:Subscribe', 'run-instances', 'GetSecretValue')
    $azureActions = @('create', 'show', 'list', 'role assignment create', 'update',
        'Microsoft.Network/virtualNetworks/write', 'delete')

    # One error text builder per recognized format. Each embeds the service and action.
    $awsFormats = @(
        { param($s, $a) "An error occurred (AccessDenied) when calling the $a operation: Access Denied" },
        { param($s, $a) "An error occurred (AccessDeniedException) when calling the $a operation: User is not allowed" },
        { param($s, $a) "An error occurred (UnauthorizedOperation) when calling the $a operation: You are not allowed" },
        { param($s, $a) "An error occurred (AuthorizationError) when calling the $a operation: denied for $s" },
        { param($s, $a) "An error occurred when calling $a : User: arn:aws:iam::123456789012:user/lab is not authorized to perform: ${s}:$a on resource: *" },
        { param($s, $a) "An error occurred (403) when calling the $a operation: Forbidden. HTTP 403 for $s" }
    )
    $azureFormats = @(
        { param($s, $a) "ERROR: (AuthorizationFailed) The client does not have authorization to perform action for $s $a" },
        { param($s, $a) "ERROR: The client is not authorized to perform action $a over scope for $s" },
        { param($s, $a) "ERROR: AuthorizationFailed while running az $s $a" },
        { param($s, $a) "ERROR: Operation returned HTTP 403 Forbidden for az $s $a" },
        { param($s, $a) "ERROR: (AuthorizationError) caller cannot run $a on $s" },
        { param($s, $a) "ERROR: (AccessDenied) $s $a was refused" }
    )

    $cases = New-Object System.Collections.Generic.List[object]

    $awsServices = @($script:LabAwsPermissionTable.Keys) + @('someunknownservice')
    $i = 0
    foreach ($svc in $awsServices) {
        $act = $awsActions[$rng.Next($awsActions.Count)]
        $fmtIndex = $i % $awsFormats.Count
        $text = & $awsFormats[$fmtIndex] $svc $act
        $cases.Add(@{ Cloud = 'Aws'; Service = $svc; Action = $act; ErrorText = $text; Label = "aws $svc $act (format $fmtIndex)" })
        $i++
    }

    $azureServices = @($script:LabAzurePermissionTable.Keys) + @('Microsoft.Network', 'someunknownprovider')
    $i = 0
    foreach ($svc in $azureServices) {
        $act = $azureActions[$rng.Next($azureActions.Count)]
        $fmtIndex = $i % $azureFormats.Count
        $text = & $azureFormats[$fmtIndex] $svc $act
        $cases.Add(@{ Cloud = 'Azure'; Service = $svc; Action = $act; ErrorText = $text; Label = "azure $svc $act (format $fmtIndex)" })
        $i++
    }

    $script:PermissionCases = $cases.ToArray()
}

BeforeAll {
    $script:LibPath = (Resolve-Path (Join-Path $PSScriptRoot '..' 'lib' 'LabPermissions.ps1')).Path
    . $script:LibPath

    $script:PwshExe = (Get-Process -Id $PID).Path

    # Child script: dot-sources the library, installs recording stand-ins for aws and
    # az, runs the detection and Stop-LabForPermission. Any call to a stand-in is
    # appended to the log file, so an empty log means no cloud call of any kind.
    $script:ChildScript = Join-Path $TestDrive 'child-permission.ps1'
    $childBody = @'
param(
    [string] $Lib,
    [string] $Cloud,
    [string] $Service,
    [string] $Action,
    [string] $ErrorText,
    [string] $CallLog
)
function aws { Add-Content -LiteralPath $CallLog -Value ('aws ' + ($args -join ' ')) }
function az  { Add-Content -LiteralPath $CallLog -Value ('az '  + ($args -join ' ')) }
. $Lib
if (-not (Test-LabAccessDenied -Text $ErrorText)) {
    Write-Output 'NOT-RECOGNIZED'
    exit 9
}
$hint = Get-LabPermissionHint -Cloud $Cloud -Service $Service -Action $Action
Stop-LabForPermission -Hint $hint -Step 'case-step'
Write-Output 'NOT-STOPPED'
exit 0
'@
    Set-Content -LiteralPath $script:ChildScript -Value $childBody -Encoding UTF8

    function Invoke-PermissionChild {
        param([string] $Cloud, [string] $Service, [string] $Action, [string] $ErrorText)
        $log = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.log')
        $out = & $script:PwshExe -NoProfile -NonInteractive -File $script:ChildScript `
            -Lib $script:LibPath -Cloud $Cloud -Service $Service -Action $Action `
            -ErrorText $ErrorText -CallLog $log 2>&1
        $code = $LASTEXITCODE
        $calls = @()
        if (Test-Path -LiteralPath $log) { $calls = @(Get-Content -LiteralPath $log) }
        return [pscustomobject]@{
            ExitCode = $code
            Output   = (($out | ForEach-Object { "$_" }) -join "`n")
            Calls    = $calls
        }
    }
}

Describe 'Permission error handling' {

    Context 'Any service, action and recognized error format' {

        It 'stops with exit code 3, a complete message and no grant call: <Label>' -ForEach $script:PermissionCases {
            $r = Invoke-PermissionChild -Cloud $Cloud -Service $Service -Action $Action -ErrorText $ErrorText

            # Exit code 3 and the process really stopped.
            $r.ExitCode | Should -Be 3
            $r.Output | Should -Not -Match 'NOT-STOPPED'
            $r.Output | Should -Not -Match 'NOT-RECOGNIZED'

            # Complete message: marker, step, denied service and action, rerun instruction.
            $r.Output | Should -Match 'BLOCKED: permission missing in step .case-step.'
            $r.Output | Should -Match ([regex]::Escape($Service))
            $r.Output | Should -Match ([regex]::Escape($Action))
            $r.Output | Should -Match 'run this same script again'

            # The exact fix named for the cloud, taken from the hint tables.
            $hint = Get-LabPermissionHint -Cloud $Cloud -Service $Service -Action $Action
            if ($Cloud -eq 'Aws') {
                foreach ($p in $hint.ManagedPolicies) { $r.Output | Should -Match ([regex]::Escape($p)) }
                if ($hint.ScopedTemplate) { $r.Output | Should -Match ([regex]::Escape($hint.ScopedTemplate)) }
                $r.Output | Should -Match ([regex]::Escape($hint.IamAction))
            }
            else {
                foreach ($role in $hint.BuiltInRoles) { $r.Output | Should -Match ([regex]::Escape($role)) }
                $r.Output | Should -Match 'az '
            }
            if (-not $hint.Known) { $r.Output | Should -Match 'not in the lab permission table' }

            # No grant call of any kind reached the cloud CLIs.
            $r.Calls.Count | Should -Be 0
        }
    }

    Context 'Detection of the recognized formats' {

        It 'recognizes every error format and ignores unrelated text' {
            $recognized = @(
                'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                'AuthorizationError', 'AuthorizationFailed',
                'User is not authorized to perform: sns:CreateTopic', 'HTTP 403'
            )
            foreach ($t in $recognized) { Test-LabAccessDenied -Text $t | Should -BeTrue }
            foreach ($t in @('', '   ', 'ResourceNotFoundException: topic missing', 'Throttling: slow down')) {
                Test-LabAccessDenied -Text $t | Should -BeFalse
            }
        }
    }

    Context 'Hints follow the read or write nature of the action' {

        It 'points ssm read actions to AmazonSSMReadOnlyAccess only' -ForEach @(
            @{ Action = 'ssm:GetCommandInvocation' }, @{ Action = 'get-parameter' },
            @{ Action = 'describe-instance-information' }, @{ Action = 'ssm:ListCommands' }
        ) {
            $h = Get-LabPermissionHint -Cloud Aws -Service 'ssm' -Action $Action
            @($h.ManagedPolicies) | Should -Be @('AmazonSSMReadOnlyAccess')
            $h.ScopedTemplate | Should -BeNullOrEmpty
        }

        It 'points ssm SendCommand to lab-core.json first and AmazonSSMFullAccess as the alternative' -ForEach @(
            @{ Action = 'ssm:SendCommand' }, @{ Action = 'send-command' }
        ) {
            $h = Get-LabPermissionHint -Cloud Aws -Service 'ssm' -Action $Action
            $h.IamAction | Should -Be 'ssm:SendCommand'
            @($h.ManagedPolicies) | Should -Be @('AmazonSSMFullAccess')
            $h.ScopedTemplate | Should -Be 'lab-core.json'
            $text = (Format-LabPermissionMessage -Hint $h -Step 's') -join "`n"
            $text | Should -Match 'lab-core\.json'
            $text | Should -Match 'ensure-lab-group\.ps1'
            $text | Should -Match 'AmazonSSMFullAccess'
            $text | Should -Match 'preferred'
            # The note may say the read only policy is not enough, but it is never the policy to attach.
            $text | Should -Not -Match 'attach the AWS managed policy AmazonSSMReadOnlyAccess'
            $text | Should -Match 'not in AmazonSSMReadOnlyAccess'
        }

        It 'keeps full-access services on their managed policy for read and write actions' -ForEach @(
            @{ Svc = 'lambda'; Pol = 'AWSLambda_FullAccess'; Act = 'lambda:GetFunction' },
            @{ Svc = 'lambda'; Pol = 'AWSLambda_FullAccess'; Act = 'lambda:CreateFunction' },
            @{ Svc = 'events'; Pol = 'AmazonEventBridgeFullAccess'; Act = 'events:DescribeRule' },
            @{ Svc = 'events'; Pol = 'AmazonEventBridgeFullAccess'; Act = 'events:PutRule' }
        ) {
            $h = Get-LabPermissionHint -Cloud Aws -Service $Svc -Action $Act
            @($h.ManagedPolicies) | Should -Be @($Pol)
        }

        It 'points iam read and write actions to the scoped template' -ForEach @(
            @{ Act = 'iam:GetRole' }, @{ Act = 'iam:CreateRole' }
        ) {
            $h = Get-LabPermissionHint -Cloud Aws -Service 'iam' -Action $Act
            $h.ScopedTemplate | Should -Be 'lab-iam-scoped.json'
        }
    }

    Context 'Library never grants anything' {

        It 'contains no IAM grant verb or cloud CLI call in its source' {
            # Drop block comments (the header explains the rule in prose), line comments
            # and the message strings, so only executable code is scanned.
            $raw = Get-Content -LiteralPath $script:LibPath -Raw
            $raw = [regex]::Replace($raw, '(?s)<#.*?#>', '')
            $code = $raw -split "`n" |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch "^\s*'" -and $_ -notmatch '^\s*\$lines\.Add' }
            $joined = $code -join "`n"
            $joined | Should -Not -Match '(?m)^\s*(&\s*)?(aws|az)\s+\w'
            $joined | Should -Not -Match '(?i)\b(attach-(user|group|role)-policy|put-(user|group|role)-policy|add-user-to-group|create-(policy|group|role)|role assignment create)\b'
        }
    }
}
