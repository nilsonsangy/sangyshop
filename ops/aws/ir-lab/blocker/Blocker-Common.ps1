<#
.SYNOPSIS
    Shared helpers for the auto-block scripts (ops/aws/ir-lab/blocker).

.DESCRIPTION
    Dot-source it from each script:
        . "$PSScriptRoot\Blocker-Common.ps1"

    It reuses the detection helpers (Invoke-LabCli seam, lab tags, temp files,
    $global:LabCliHandler for tests) instead of duplicating them, and adds the
    resource names (from Get-AwsLabNames) and the policy template renderer for the blocker.
#>

. "$PSScriptRoot\..\detection\Detection-Common.ps1"

$script:LabComponent = 'blocker'
$script:BlockerFunctionName = [string]$script:LabNames['BlockerFunction']
$script:BlockerRoleName = [string]$script:LabNames['BlockerRole']
$script:BlockerRolePolicyName = [string]$script:LabNames['BlockerPolicy']
$script:BlockerRuleName = [string]$script:LabNames['BlockerRule']
$script:BlockerStatementId = [string]$script:LabNames['BlockerStatement']
$script:BlockerPoliciesDir = Join-Path $PSScriptRoot 'policies'
$script:BlockerRuleMin = 100
$script:BlockerRuleMax = 199

function Test-BlockerNaclId {
    param([string]$Id)
    return ($Id -match '^acl-[0-9a-f]{8,17}$')
}

function Get-BlockerPolicyText {
    <# Reads a policies/*.json template and replaces ${NAME} placeholders from a hashtable. #>
    param([string]$File, [hashtable]$Values)
    $path = Join-Path $script:BlockerPoliciesDir $File
    if (-not (Test-Path -LiteralPath $path)) { Stop-Lab -Code 1 -Message "Policy template not found: $path" }
    $text = [System.IO.File]::ReadAllText($path)
    foreach ($k in $Values.Keys) { $text = $text.Replace('${' + $k + '}', [string]$Values[$k]) }
    if ($text -match '\$\{[A-Z_]+\}') { Stop-Lab -Code 1 -Message "Unresolved placeholder in $File ($($Matches[0]))" }
    return $text
}

function Test-BlockerAwsNotFound {
    <# True when CLI output says the resource does not exist. #>
    param($Result)
    return ($Result.ExitCode -ne 0 -and "$($Result.Output)" -match 'NoSuchEntity|ResourceNotFoundException|NotFound|does not exist')
}
