<#
.SYNOPSIS
    Plants the lab "leaked" credential: service principal sp-lab-leaked + /lab/leaked.json on the lab VM.

.DESCRIPTION
    Azure counterpart of ops/aws/ir-lab/plant-leaked-credential.ps1 (IAM user sangyshop-lab-leaked).
    Creates (idempotent, safe to re-run):
      1. App registration + service principal 'sp-lab-leaked' (app registration tagged lab=sangyshop-lab-azure)
      2. Role 'Reader' on the lab resource group
      3. Role 'Storage Blob Data Reader' on the application blob container ONLY
      4. A short-lived client secret (default 7 days). Re-running rotates it (older secrets are replaced).
      5. The file LeakedPath (default /lab/leaked.json) on the lab VM, through
         'az vm run-command invoke'. SangyShop (LAB_MODE=1) serves that file at /debug/config,
         without restarting the container (/lab is a volume created empty by the VM deploy).
    Every created item is recorded in the lab manifest (type app-registration, role-assignment,
    app-secret, vm-file) so full-teardown.ps1 can remove it. The secret is never printed,
    never written to the repository and never put on a visible command line: the script sent
    to the VM travels in a temporary file that is deleted at the end.

    The service principal has least privilege on purpose (read-only). It is a LAB credential:
    use it only in the isolated user subscription.
    Supports -WhatIf (no change, no secret is created).

.PARAMETER Subscription
    Azure subscription id or name (required, no default).
.PARAMETER ResourceGroup
    Lab resource group (Lab resource group) that holds the VM and the app storage account.
.PARAMETER Region
    Azure region of the lab (required, no default).
.PARAMETER VmName
    Name of the lab VM that receives the file.
.PARAMETER StorageAccount
    App storage account name (same resource group unless -StorageResourceGroup is given).
.PARAMETER Container
    App blob container (scope of Storage Blob Data Reader).
.PARAMETER LeakedPath
    File path on the VM, default /lab/leaked.json (the LAB_LEAKED_FILE default of SangyShop).
.PARAMETER SecretDays
    Secret lifetime in days, 1 to 30 (default 7).

.EXAMPLE
    .\plant-leaked-credential.ps1 -Subscription 00000000-0000-0000-0000-000000000000 `
        -ResourceGroup rg-sangyshop-lab -Region eastus -VmName vm-sangyshop-lab `
        -StorageAccount stsangyshoplab0000 -Container sangyshop -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$ResourceGroup,
    [string]$Region,
    [string]$VmName,
    [string]$StorageAccount,
    [string]$Container,
    [string]$StorageResourceGroup,
    [string]$VmResourceGroup,
    [string]$LeakedPath = '/lab/leaked.json',
    [int]$SecretDays = 7,
    [string]$RunId
)
. "$PSScriptRoot\detection\Detection-Common.ps1"

$SpName = 'sp-lab-leaked'
$ZeroGuid = '00000000-0000-0000-0000-000000000000'

Initialize-Lab -Subscription $Subscription -Region $Region
foreach ($p in 'ResourceGroup', 'VmName', 'StorageAccount', 'Container') {
    if ([string]::IsNullOrWhiteSpace((Get-Variable $p).Value)) { Stop-Lab -Code 2 -Message "Missing required parameter: -$p" }
}
if ($LeakedPath -notmatch '^/[A-Za-z0-9._/-]+$' -or $LeakedPath -match '\.\.') {
    Stop-Lab -Code 2 -Message "Invalid -LeakedPath '$LeakedPath' (use an absolute Linux path such as /lab/leaked.json)"
}
if ($SecretDays -lt 1 -or $SecretDays -gt 30) { Stop-Lab -Code 2 -Message 'Invalid -SecretDays: use a value from 1 to 30' }
if (-not $StorageResourceGroup) { $StorageResourceGroup = $ResourceGroup }
if (-not $VmResourceGroup) { $VmResourceGroup = $ResourceGroup }
$RunId = Get-LabRunId -RunId $RunId
$subId = Get-LabSubscriptionId

# Error text may carry resource names but never the secret (the secret is only read from stdout of 'credential reset').
$secret = $null
try {
    # --- Scopes -------------------------------------------------------------------------------
    $rg = Invoke-LabAz -CliArgs @('group', 'show', '--name', $ResourceGroup, '--query', 'id', '--output', 'tsv')
    if ($rg.ExitCode -ne 0) {
        if (Test-LabNotFound -Text $rg.Output) { Stop-Lab -Code 1 -Message "Resource group '$ResourceGroup' not found. Nothing was changed." }
        Stop-Lab -Code 1 -Message "Could not read resource group '$ResourceGroup'. $(Hide-LabSecrets -Text "$($rg.Output)")"
    }
    $rgScope = "$($rg.Output)".Trim()
    if (-not $rgScope) { $rgScope = "/subscriptions/$subId/resourceGroups/$ResourceGroup" }

    $sa = Invoke-LabAz -CliArgs @('storage', 'account', 'show', '--name', $StorageAccount, '--resource-group', $StorageResourceGroup, '--query', 'id', '--output', 'tsv')
    if ($sa.ExitCode -ne 0) {
        Stop-Lab -Code 1 -Message "Storage account '$StorageAccount' not found or not readable in '$StorageResourceGroup'. Nothing was changed."
    }
    $saId = "$($sa.Output)".Trim()
    if (-not $saId) { $saId = "/subscriptions/$subId/resourceGroups/$StorageResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccount" }
    $containerScope = "$saId/blobServices/default/containers/$Container"

    # --- 1. App registration + service principal ---------------------------------------------
    $q = Invoke-LabAz -CliArgs @('ad', 'app', 'list', '--display-name', $SpName, '--query', '[].{appId:appId,tags:tags}', '--output', 'json')
    if ($q.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not query app registrations. $(Hide-LabSecrets -Text "$($q.Output)")" }
    $apps = @(ConvertFrom-LabJson -Text $q.Output | Where-Object { $_ })
    $tagValue = "$($script:LabTagKey)=$($script:LabTagValue)"
    $appId = $null
    if ($apps.Count -gt 1) {
        Stop-Lab -Code 1 -Message "More than one app registration is named '$SpName'. Remove the extra ones and re-run. Nothing was changed."
    } elseif ($apps.Count -eq 1) {
        if (@($apps[0].tags) -notcontains $tagValue) { Confirm-LabUntaggedRefusal -Kind 'App registration' -Name $SpName }
        $appId = "$($apps[0].appId)"
        Write-LabInfo "App registration '$SpName' already exists and is tagged. Reusing it."
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs @('ad', 'app', 'create', '--display-name', $SpName, '--query', 'appId', '--output', 'tsv')
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create app registration '$SpName'. $(Hide-LabSecrets -Text "$($c.Output)")" }
        $appId = "$($c.Output)".Trim()
        if (-not $appId) { $appId = $ZeroGuid }   # dry-run placeholder
        $body = (@{ tags = @($tagValue, "run-id=$RunId", 'component=leaked-credential') } | ConvertTo-Json -Compress)
        $t = Invoke-LabAz -Mutating -NoSubscription -CliArgs @('rest', '--method', 'PATCH', '--url', "https://graph.microsoft.com/v1.0/applications(appId='$appId')", '--headers', 'Content-Type=application/json', '--body', (New-LabTempFile -Text $body))
        if ($t.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not tag app registration '$SpName'. It was created; run full-teardown.ps1 or delete it. $(Hide-LabSecrets -Text "$($t.Output)")" }
    }
    Add-LabManifestEntry -Type 'app-registration' -Id $appId -RunId $RunId

    $sp = Invoke-LabAz -CliArgs @('ad', 'sp', 'show', '--id', $appId, '--query', 'id', '--output', 'tsv')
    $spObjectId = "$($sp.Output)".Trim()
    if ($sp.ExitCode -ne 0 -or -not $spObjectId) {
        $c = Invoke-LabAz -Mutating -CliArgs @('ad', 'sp', 'create', '--id', $appId, '--query', 'id', '--output', 'tsv')
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the service principal for '$SpName'. $(Hide-LabSecrets -Text "$($c.Output)")" }
        $spObjectId = "$($c.Output)".Trim()
        if (-not $spObjectId) { $spObjectId = $ZeroGuid }
    }

    # --- 2 and 3. Least-privilege role assignments ---------------------------------------------
    foreach ($ra in @(@{ Role = 'Reader'; Scope = $rgScope }, @{ Role = 'Storage Blob Data Reader'; Scope = $containerScope })) {
        $l = Invoke-LabAz -CliArgs @('role', 'assignment', 'list', '--assignee', $spObjectId, '--role', $ra.Role, '--scope', $ra.Scope, '--query', 'length(@)', '--output', 'tsv')
        if ($l.ExitCode -eq 0 -and "$($l.Output)".Trim() -match '^[1-9]') {
            Write-LabInfo "Role '$($ra.Role)' is already assigned. Nothing to create."
        } else {
            $c = Invoke-LabAz -Mutating -CliArgs @('role', 'assignment', 'create', '--assignee-object-id', $spObjectId, '--assignee-principal-type', 'ServicePrincipal', '--role', $ra.Role, '--scope', $ra.Scope)
            if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not assign role '$($ra.Role)'. A new service principal can take a minute to replicate: wait and re-run. $(Hide-LabSecrets -Text "$($c.Output)")" }
        }
        Add-LabManifestEntry -Type 'role-assignment' -Id ("{0}#{1}#{2}" -f $ra.Scope, $ra.Role, $spObjectId) -RunId $RunId
    }

    # --- 4. Short-lived client secret (never printed) -------------------------------------------
    $end = [datetime]::UtcNow.AddDays($SecretDays).ToString('yyyy-MM-dd')
    $c = Invoke-LabAz -Mutating -CliArgs @('ad', 'app', 'credential', 'reset', '--id', $appId, '--display-name', 'lab-leaked-secret', '--end-date', $end, '--query', 'password', '--output', 'tsv')
    if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not create the client secret for '$SpName'." }
    $secret = "$($c.Output)".Trim()
    Add-LabManifestEntry -Type 'app-secret' -Id "$appId/lab-leaked-secret" -RunId $RunId

    $tenant = Invoke-LabAz -CliArgs @('account', 'show', '--query', 'tenantId', '--output', 'tsv')
    $tenantId = "$($tenant.Output)".Trim()
    if (-not $tenantId) { $tenantId = $ZeroGuid }

    # --- 5. Write the file on the VM (script travels in a temp file, not on the command line) ---
    if ($WhatIfPreference) {
        Write-Host "What if: write $LeakedPath on VM '$VmName' (az vm run-command invoke, content not shown)"
    } else {
        if ([string]::IsNullOrEmpty($secret)) { Stop-Lab -Code 1 -Message 'The client secret came back empty. The file was not written.' }
        $doc = [ordered]@{
            note = 'LAB ONLY credential planted by plant-leaked-credential.ps1. Read-only. Isolated user subscription.'
            cloud = 'azure'; tenantId = $tenantId; subscriptionId = $subId
            clientId = $appId; clientSecret = $secret
            storageAccount = $StorageAccount; container = $Container
        }
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($doc | ConvertTo-Json -Compress)))
        $dir = $LeakedPath.Substring(0, $LeakedPath.LastIndexOf('/'))
        if (-not $dir) { $dir = '/' }
        $sh = "set -e`nmkdir -p '$dir'`nprintf '%s' '$b64' | base64 -d > '$LeakedPath'`nchmod 0644 '$LeakedPath'`necho leaked-file-written"
        $r = Invoke-LabAz -Mutating -CliArgs @('vm', 'run-command', 'invoke', '--resource-group', $VmResourceGroup, '--name', $VmName, '--command-id', 'RunShellScript', '--scripts', (New-LabTempFile -Text $sh))
        if ($r.ExitCode -ne 0 -or "$($r.Output)" -notmatch 'leaked-file-written') {
            Stop-Lab -Code 1 -Message "Could not write $LeakedPath on VM '$VmName'. Check that the VM is running and has the VM agent ready. The service principal exists; re-run to retry."
        }
        Write-LabInfo "Wrote $LeakedPath on VM '$VmName' (content not shown)."
    }
    Add-LabManifestEntry -Type 'vm-file' -Id "${VmName}:$LeakedPath" -RunId $RunId

    if ($WhatIfPreference) {
        Write-LabInfo 'Dry-run finished. Nothing was changed and no secret was created.'
    } else {
        Write-LabInfo "Done. Service principal '$SpName' (appId $appId) is planted. Secret expires $end. Nothing sensitive was printed."
    }
} finally {
    $secret = $null
    Clear-LabTempFiles
}
exit 0
