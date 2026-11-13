<#
.SYNOPSIS
    Step 6 of the simulated attack: uses the leaked service principal against Azure (max 10 API calls).

.DESCRIPTION
    Azure counterpart of ops/aws/ir-lab/use-leaked-credential.ps1. Reads the credential file that the
    attack script saved in step 5 (out/exposed-credential.json, from GET /debug/config) and calls
    Azure with it, so the Activity Log and Microsoft Entra ID sign-in logs record the identity and
    the source IP. Calls (8 at most, hard cap 10):
      1 az login --service-principal      (sign-in event in Entra ID)
      2 az account show
      3 az resource list                  (Reader on the lab resource group)
      4 az storage account list
      5 az vm list
      6 az storage blob list              (Storage Blob Data Reader; only when account and container are known)
      7 az storage account keys list      (expected DENIED: Reader cannot list keys)
      8 az logout
    The output shows ONLY the operation name and its status (OK, DENIED or ERROR). It never shows
    response data, the secret, the tenant id or the file content. The sign-in runs in a throwaway
    Azure CLI profile, so your own 'az login' session is not touched.
    Use it only against the isolated user subscription. Supports -WhatIf (prints the plan, no call).

.PARAMETER LeakedCredentialPath
    JSON file saved by the attack script (keys: tenantId, clientId, clientSecret; optional
    storageAccount, container, subscriptionId).
.PARAMETER Subscription
    Subscription id or name used for the calls (optional if the file has subscriptionId).
.PARAMETER ResourceGroup
    Lab resource group for the resource and VM listing (optional).

.EXAMPLE
    .\use-leaked-credential.ps1 -LeakedCredentialPath ..\..\..\attack-simulation\out\exposed-credential.json `
        -Subscription 00000000-0000-0000-0000-000000000000 -ResourceGroup rg-sangyshop-lab
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LeakedCredentialPath,
    [string]$Subscription,
    [string]$ResourceGroup
)
. "$PSScriptRoot\detection\Detection-Common.ps1"

$MaxCalls = 10
if ([string]::IsNullOrWhiteSpace($LeakedCredentialPath)) { Stop-Lab -Code 2 -Message 'Missing required parameter: -LeakedCredentialPath' }
if (-not (Test-Path -LiteralPath $LeakedCredentialPath)) { Stop-Lab -Code 1 -Message "Credential file not found: $LeakedCredentialPath" }

$cred = ConvertFrom-LabJson -Text (Get-Content -LiteralPath $LeakedCredentialPath -Raw)
if (-not $cred) { Stop-Lab -Code 1 -Message 'The credential file is not valid JSON.' }
foreach ($k in 'tenantId', 'clientId', 'clientSecret') {
    if (-not $cred.PSObject.Properties[$k] -or [string]::IsNullOrWhiteSpace("$($cred.$k)")) {
        Stop-Lab -Code 1 -Message "The credential file has no '$k' value."
    }
}
if (-not $Subscription -and $cred.PSObject.Properties['subscriptionId']) { $Subscription = "$($cred.subscriptionId)" }
if ([string]::IsNullOrWhiteSpace($Subscription)) { Stop-Lab -Code 2 -Message 'Missing required parameter: -Subscription (not found in the credential file either)' }
if (-not $global:LabAzHandler -and -not $WhatIfPreference) {
    if (-not (Get-Command az -CommandType Application -ErrorAction SilentlyContinue)) { Stop-Lab -Code 1 -Message 'Azure CLI (az) is not installed or not in PATH' }
}
$account = if ($cred.PSObject.Properties['storageAccount']) { "$($cred.storageAccount)" } else { '' }
$container = if ($cred.PSObject.Properties['container']) { "$($cred.container)" } else { '' }

$script:CallCount = 0
$script:Results = New-Object System.Collections.ArrayList

function Invoke-LeakedCall {
    # One counted call. Prints the operation name and the status only; never the arguments or the output.
    param([string]$Operation, [string[]]$CliArgs)
    if ($script:CallCount -ge $MaxCalls) { Stop-Lab -Code 1 -Message "Call limit reached ($MaxCalls). No further call was made." }
    $script:CallCount++
    if ($WhatIfPreference) {
        Write-Host ("What if: {0}" -f $Operation)
        return
    }
    if ($global:LabAzHandler) {
        $r = & $global:LabAzHandler $CliArgs
        if ($null -eq $r) { $r = [pscustomobject]@{ ExitCode = 0; Output = '' } }
        $code = $r.ExitCode; $text = "$($r.Output)"
    } else {
        $text = (& az @CliArgs 2>&1 | Out-String)
        $code = $LASTEXITCODE
    }
    $status = 'OK'
    if ($code -ne 0) {
        $status = if ($text -match 'AuthorizationFailed|AuthorizationPermissionMismatch|Forbidden|does not have authorization|\(403\)|AuthorizationFailure') { 'DENIED' } else { 'ERROR' }
    }
    [void]$script:Results.Add([pscustomobject]@{ Operation = $Operation; Status = $status })
    Write-Host ("{0,2}. {1,-34} {2}" -f $script:CallCount, $Operation, $status)
    return $status
}

$sub = $Subscription.Trim()
$rgArgs = @(); if ($ResourceGroup) { $rgArgs = @('--resource-group', $ResourceGroup) }

# Throwaway CLI profile so the operator session is untouched.
$oldConfig = $env:AZURE_CONFIG_DIR
$tmpConfig = Join-Path ([System.IO.Path]::GetTempPath()) ("lab-leaked-{0}" -f [guid]::NewGuid().ToString('N'))
if (-not $WhatIfPreference) {
    New-Item -ItemType Directory -Path $tmpConfig -Force | Out-Null
    $env:AZURE_CONFIG_DIR = $tmpConfig
}
Write-LabInfo "Using the leaked service principal against subscription '$sub' (max $MaxCalls calls, names and status only)."
try {
    $login = Invoke-LeakedCall -Operation 'az login --service-principal' -CliArgs @('login', '--service-principal', '--username', "$($cred.clientId)", '--password', "$($cred.clientSecret)", '--tenant', "$($cred.tenantId)", '--only-show-errors', '--output', 'none')
    if (-not $WhatIfPreference -and $login -ne 'OK') {
        Stop-Lab -Code 1 -Message 'Sign-in with the leaked credential failed (secret expired, rotated or the principal is disabled). Nothing else was called.'
    }
    $base = @('--subscription', $sub, '--only-show-errors', '--output', 'none')
    [void](Invoke-LeakedCall -Operation 'az account show' -CliArgs (@('account', 'show') + $base))
    [void](Invoke-LeakedCall -Operation 'az resource list' -CliArgs (@('resource', 'list') + $rgArgs + $base))
    [void](Invoke-LeakedCall -Operation 'az storage account list' -CliArgs (@('storage', 'account', 'list') + $base))
    [void](Invoke-LeakedCall -Operation 'az vm list' -CliArgs (@('vm', 'list') + $rgArgs + $base))
    if ($account -and $container) {
        [void](Invoke-LeakedCall -Operation 'az storage blob list' -CliArgs (@('storage', 'blob', 'list', '--account-name', $account, '--container-name', $container, '--auth-mode', 'login', '--num-results', '5') + $base))
    }
    if ($account -and $ResourceGroup) {
        [void](Invoke-LeakedCall -Operation 'az storage account keys list' -CliArgs (@('storage', 'account', 'keys', 'list', '--account-name', $account, '--resource-group', $ResourceGroup) + $base))
    }
    [void](Invoke-LeakedCall -Operation 'az logout' -CliArgs @('logout', '--only-show-errors'))
} finally {
    $env:AZURE_CONFIG_DIR = $oldConfig
    if (-not $oldConfig) { Remove-Item Env:\AZURE_CONFIG_DIR -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $tmpConfig) { Remove-Item -LiteralPath $tmpConfig -Recurse -Force -WhatIf:$false -ErrorAction SilentlyContinue }
    $cred = $null
}
$verb = if ($WhatIfPreference) { 'planned (dry-run, none made)' } else { 'made' }
Write-LabInfo "$($script:CallCount) call(s) $verb (limit $MaxCalls). Check the Activity Log and the Entra ID sign-in logs for sp-lab-leaked."
exit 0
