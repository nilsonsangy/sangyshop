<#
.SYNOPSIS
    Enables Microsoft Defender for Servers Plan 2 (30-day free trial) on the subscription (idempotent).

.DESCRIPTION
    Sets the Defender for Cloud pricing plan 'VirtualMachines' to tier Standard, sub-plan P2.
    Foundational CSPM stays free. The 30-day trial applies per plan, cannot be paused or
    extended, and bills after it ends (about US$ 0.49 per 24 h in the lab estimate); run
    disable-defender.ps1 or full-teardown.ps1 when done.
    The plan is a SUBSCRIPTION-level setting without tags. When this script changes it, it is
    recorded in the lab manifest, and disable-defender.ps1 reverts it only for recorded changes.
    A plan that is already Standard/P2 is not touched and not recorded (it was not enabled by
    the lab). Re-running creates nothing new. Supports -WhatIf.

.EXAMPLE
    .\enable-defender.ps1 -Subscription <id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [string]$RunId
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
$RunId = Get-LabRunId -RunId $RunId
$null = Get-LabSubscriptionId

try {
    $plan = $script:LabDefenderPlan
    $r = Invoke-LabAz -CliArgs @('security', 'pricing', 'show', '--name', $plan, '--query', '{tier:pricingTier,sub:subPlan}', '--output', 'json')
    $cur = $null
    if ($r.ExitCode -eq 0) { $cur = ConvertFrom-LabJson -Text $r.Output }
    Stop-LabIfDenied -Result $r -Service 'security' -Action 'pricing show' -Step 'defender plan read'
    if ($cur -and "$($cur.tier)" -eq 'Standard' -and "$($cur.sub)" -eq $script:LabDefenderSubPlan) {
        $own = Get-LabExistingOwnership -Type 'defender-plan' -Id $plan
        if ($own -eq 'reused') { Write-LabInfo "Defender plan '$plan' is already Standard/$($script:LabDefenderSubPlan) and was not enabled by the lab. Reusing it as is; it is never switched to Free." }
        else { Write-LabInfo "Defender plan '$plan' is already Standard/$($script:LabDefenderSubPlan). Nothing to change." }
        Add-LabManifestEntry -Type 'defender-plan' -Id $plan -RunId $RunId -Ownership $own
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs @('security', 'pricing', 'create', '--name', $plan, '--tier', 'standard', '--subplan', $script:LabDefenderSubPlan)
        Assert-LabAzOk -Result $c -Service 'security' -Action 'pricing create' -Failure "Could not enable Defender plan '$plan'."
        Write-LabInfo "Defender for Servers $($script:LabDefenderSubPlan) enabled (30-day free trial, then billable)."
        Add-LabManifestEntry -Type 'defender-plan' -Id $plan -RunId $RunId -Ownership 'created'
    }
} finally {
    Clear-LabTempFiles
}
exit 0
