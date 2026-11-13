<#
.SYNOPSIS
    Zero-cost check (Azure): lists what the Azure incident response lab still leaves in a subscription.

.DESCRIPTION
    Read-only: it never changes or deletes anything (no mutating call exists in this script).
    It scans, by lab tag and by the billable risk classes listed below, in the lab region
    and at subscription scope:
      resource groups, VMs, managed disks, snapshots, public IPs, NAT Gateways, load
      balancers and Application Gateways, Azure Bastion, Azure Firewall, PostgreSQL
      Flexible Servers, Storage Accounts, Key Vaults (including soft-deleted), Log
      Analytics workspaces (including soft-deleted), Microsoft Sentinel, Defender for
      Cloud plans above Free, Action Groups, alert rules, Logic Apps and Functions,
      VNet flow logs, and service principals (with their secrets and role assignments),
      plus custom roles and role assignments of the lab.
    A billable-class resource with no lab tag that is not in the manifest is reported
    as 'unmarked' for a manual decision. It is NEVER removed.

    Prints "nothing billable remaining" and exits 0, or the pending list (type, id,
    region, reason, tagged|unmarked) and exits 1. If something could not be read, the
    result is 'unverified' and the exit code is 1 (a clean result is never assumed).
    Exit codes: 0 clean; 1 pending or unverified; 2 invalid parameter; 3 credentials.

.PARAMETER Json
    Print a single JSON document on stdout (commands are echoed on stderr).
.PARAMETER ManifestPath
    lab manifest path (default: $HOME/.sangyshop-lab/manifest-sangyshop-lab-azure.json).

.EXAMPLE
    .\verify-zero-cost.ps1 -Subscription 00000000-0000-0000-0000-000000000000 -Region eastus

.EXAMPLE
    .\verify-zero-cost.ps1 -Subscription 00000000-0000-0000-0000-000000000000 -Region eastus -Json
#>
[CmdletBinding()]
param(
    [string]$Subscription,
    [string]$Region,
    [switch]$Json,
    [string]$ManifestPath
)
. "$PSScriptRoot\Teardown-Common.ps1"

$prevManifestEnv = $env:LAB_MANIFEST_PATH
try {
    Initialize-Lab -Subscription $Subscription -Region $Region
    if ($ManifestPath) { $env:LAB_MANIFEST_PATH = $ManifestPath }
    $subId = Get-LabSubscriptionId   # exit 3 when the login is missing or expired

    if ($Json) {
        # Keep stdout pure JSON: command echoes (information stream) are moved to stderr.
        $inventory = @(Get-LabInventory -Region $script:LabRegion -IncludeUnmarked 6>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.InformationRecord]) { [Console]::Error.WriteLine("$($_.MessageData)") } else { $_ }
            })
    } else {
        Write-LabInfo "Verifying zero cost for tag $($script:LabTagKey)=$($script:LabTagValue) in $($script:LabRegion) (read-only)."
        $inventory = @(Get-LabInventory -Region $script:LabRegion -IncludeUnmarked)
    }

    $pending = @()
    foreach ($e in $inventory) {
        if (-not $e.Class) { continue }
        $scope = if ($e.Source -eq 'unmarked') { 'unmarked' } else { 'tagged' }
        $reason = ''
        switch ($e.Kind) {
            'deleted-vault' {
                if ($e.Extra.PurgeProtected) { $reason = "soft-deleted Key Vault with purge protection; Azure removes it at $($e.Extra.PurgeDate)" }
                else { $reason = 'soft-deleted Key Vault; run full-teardown.ps1 or az keyvault purge' }
            }
            'deleted-workspace' { $reason = 'soft-deleted Log Analytics workspace (still reserved for the retention period)' }
            'sentinel-onboarding' { $reason = 'Microsoft Sentinel is still enabled on the workspace' }
            'defender-plan' { $reason = "Defender for Cloud plan above Free (tier $($e.Extra.Tier))" }
            'sp' { $reason = 'service principal still exists' }
            'sp-secret' { $reason = 'service principal secret still exists' }
            'sp-role-assignment' { $reason = 'role assignment of a lab service principal still exists' }
            'role-assignment' { $reason = 'lab role assignment still exists' }
            'role-definition' { $reason = 'lab custom role definition still exists' }
            default { $reason = 'resource still exists' }
        }
        if ($scope -eq 'unmarked') { $reason = "no lab tag and not in the manifest: decide manually, left unchanged ($reason)" }
        $tagVal = $null
        if ($e.Extra -and $e.Extra.ContainsKey('Tags')) { $tagVal = Get-LabTagValue -Tags $e.Extra.Tags -Key 'evidence' }
        if ($tagVal -eq 'preserved') { $reason = "preserved evidence (evidence=preserved) keeps costing every month; $reason" }
        $loc = if ($e.Location) { $e.Location } else { 'global' }
        $pending += [pscustomobject][ordered]@{ type = $e.Type; id = $e.Id; region = $loc; class = $e.Class; reason = $reason; scope = $scope }
    }
    $unverified = @($script:LabInventoryErrors | ForEach-Object { "$_" })

    $status = 'clean'
    if ($pending.Count -gt 0) { $status = 'pending' }
    if ($unverified.Count -gt 0 -and $pending.Count -eq 0) { $status = 'unverified' }

    if ($Json) {
        $doc = [ordered]@{
            status = $status
            lab = $script:LabTagValue
            subscription = $subId
            region = $script:LabRegion
            checked_utc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            pending = @($pending)
            unverified = @($unverified)
        }
        ConvertTo-Json -InputObject $doc -Depth 6
    } else {
        Write-Host ''
        if ($status -eq 'clean') {
            Write-Host 'nothing billable remaining'
        } else {
            if ($pending.Count -gt 0) {
                Write-Host "Pending items ($($pending.Count)):"
                foreach ($p in $pending) { Write-Host ("  - {0}  {1}  region={2}  [{3}]  {4}" -f $p.type, $p.id, $p.region, $p.scope, $p.reason) }
            }
            if ($unverified.Count -gt 0) {
                Write-Host 'Could not verify (fix the error and run again):'
                foreach ($u in $unverified) { Write-Host "  - $u" }
            }
            [Console]::Error.WriteLine('Not clean: pending items or unverified checks remain. Run full-teardown.ps1 or decide the unmarked items manually.')
        }
    }
    if ($status -eq 'clean') { exit 0 }
    exit 1
} finally {
    $env:LAB_MANIFEST_PATH = $prevManifestEnv
    Clear-LabTempFiles
}
