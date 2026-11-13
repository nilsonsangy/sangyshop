<#
.SYNOPSIS
    Returns the Defender for Servers plan to the Free tier (idempotent; only for changes made by the lab).

.DESCRIPTION
    Reverts the 'VirtualMachines' plan to tier Free when the lab manifest records that
    enable-defender.ps1 turned it on. A plan that the lab did not enable is left unchanged
    (untagged resource) unless -Force is given. An already Free plan exits 0. Supports -WhatIf.

.EXAMPLE
    .\disable-defender.ps1 -Subscription <id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Subscription,
    [switch]$Force
)
. "$PSScriptRoot\Detection-Common.ps1"
Initialize-Lab -Subscription $Subscription -RegionOptional
$null = Get-LabSubscriptionId

try {
    $plan = $script:LabDefenderPlan
    $r = Invoke-LabAz -CliArgs @('security', 'pricing', 'show', '--name', $plan, '--query', '{tier:pricingTier,sub:subPlan}', '--output', 'json')
    $cur = $null
    if ($r.ExitCode -eq 0) { $cur = ConvertFrom-LabJson -Text $r.Output }
    if (-not $cur -or "$($cur.tier)" -ne 'Standard') {
        Write-LabInfo "Defender plan '$plan' is already Free (or not readable). Nothing to change."
        Remove-LabManifestEntry -Type 'defender-plan' -Id $plan
    } elseif (-not (Test-LabManifestEntry -Type 'defender-plan' -Id $plan) -and -not $Force) {
        Write-LabWarn "Defender plan '$plan' is Standard but was not enabled by this lab (no manifest entry). Left unchanged. Use -Force to switch it to Free."
    } else {
        $c = Invoke-LabAz -Mutating -CliArgs @('security', 'pricing', 'create', '--name', $plan, '--tier', 'free')
        if ($c.ExitCode -ne 0) { Stop-Lab -Code 1 -Message "Could not disable Defender plan '$plan'. $($c.Output)" }
        Write-LabInfo "Defender plan '$plan' set to Free."
        Remove-LabManifestEntry -Type 'defender-plan' -Id $plan
    }
} finally {
    Clear-LabTempFiles
}
exit 0
