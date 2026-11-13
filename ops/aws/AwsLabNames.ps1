# =============================================================================
# AwsLabNames.ps1 -- shared, side-effect-free naming for the AWS lab
# =============================================================================
# Dot-sourced by ops/aws/ec2/deploy.ps1 and by the scripts under ops/aws/ir-lab/
# so all of them derive IDENTICAL resource names from the same config. No aws
# call, no file write, no secret. Windows PowerShell 5.1 compatible.
#
# Names that already exist in the running lab are FROZEN: for AppName 'sangyshop'
# every derived value below must stay byte for byte the same.

Set-StrictMode -Version Latest

# Frozen constants. They are not derivable from AppName (the casing of the metric
# namespace differs) and they must match the log schema written by accesslog.js.
$script:AwsLabMetricNamespace = 'SangyShopLab'
$script:AwsLabMetricName      = 'LoginFailure'
$script:AwsLabFilterPattern   = '{ $.event = "auth_login" && $.result = "failure" }'

function Get-AwsLabNames {
    <#
    .SYNOPSIS
        Returns the ordered hashtable of every resource name used by the AWS lab.
    .PARAMETER Config
        Hashtable returned by Get-CloudConfig -Cloud Aws -Modality ec2.
    #>
    param([Parameter(Mandatory)][hashtable] $Config)

    $app     = ([string]$Config['Common']['AppName']).ToLowerInvariant()
    $region  = [string]$Config['Aws']['Region']
    $account = [string]$Config['Aws']['AccountId']

    $n = [ordered]@{}
    $n['Region']          = $region
    $n['AccountId']       = $account
    $n['LabTag']          = "$app-lab-aws"
    $n['TrailName']       = "$app-lab-trail"
    $n['TrailBucket']     = "$app-lab-trail-$account-$region"
    $n['AppLogGroup']     = "/$app/app"
    $n['FlowLogGroup']    = "/$app/vpcflow"
    $n['FlowRoleName']    = "$app-lab-flowlogs-role"
    $n['TopicName']       = "$app-lab-alerts"
    $n['FilterName']      = "$app-auth-login-failure"
    $n['AlarmName']       = "$app-lab-bruteforce"
    $n['BlockerFunction'] = "$app-lab-blocker"
    $n['BlockerRole']     = "$app-lab-blocker-role"
    $n['BlockerPolicy']   = "$app-lab-blocker-policy"
    $n['BlockerRule']     = "$app-lab-blocker-trigger"
    $n['BlockerStatement'] = "$app-lab-blocker-eventbridge"
    $n['LeakedUser']      = "$app-lab-leaked"
    $n['LeakedPolicy']    = "$app-lab-leaked-readonly"
    $n['LabGroup']        = "$app-lab-group"
    $n['Ec2Name']         = "$app-lab-ec2"
    # Application bucket: the same derivation as ops/aws/ec2/deploy.ps1 (BucketBase + '-' + UniqueSuffix).
    # Empty when the config has no Aws.Ec2.BucketBase or no UniqueSuffix, so callers can fall back.
    $bucketBase = ''
    if ($Config.Contains('Aws') -and $Config['Aws'].Contains('Ec2') -and $Config['Aws']['Ec2'].Contains('BucketBase')) {
        $bucketBase = [string]$Config['Aws']['Ec2']['BucketBase']
    }
    $suffix = if ($Config.Contains('UniqueSuffix')) { [string]$Config['UniqueSuffix'] } else { '' }
    $n['AppBucket']       = if ($bucketBase -and $suffix) { "$bucketBase-$suffix" } else { '' }
    $n['MetricNamespace'] = $script:AwsLabMetricNamespace
    $n['MetricName']      = $script:AwsLabMetricName
    $n['FilterPattern']   = $script:AwsLabFilterPattern
    return $n
}
