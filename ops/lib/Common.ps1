<#
.SYNOPSIS
    Shared PowerShell library for the multi-cloud-deploy scripts.

.DESCRIPTION
    Dot-sourced by every deploy.ps1 / teardown.ps1 under ops/.
    Hosts the single echoed-command helper (Invoke-Echoed), structured logging
    (Write-Step), config loading/validation (Get-CloudConfig), and DB-password
    generation (New-DbPassword).

    This file holds the shared helpers used by every cloud script and by the
    Pester tests.

    These scripts must run on Windows PowerShell 5.1+. Do not use
    syntax newer than 5.1 in this file.
#>

Set-StrictMode -Version Latest

function Invoke-Echoed {
    <#
    .SYNOPSIS
        Echoes an external command line to stdout, then executes it.
    .DESCRIPTION
        Prints "$Exe <args>" before running,
        executes $Exe with $CmdArgs as a discrete argument array (never via a
        shell / Invoke-Expression), throws a terminating error on a non-zero exit
        unless -AllowFail is set, and returns the command's stdout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]   $Exe,
        [Parameter(Mandatory)][string[]] $CmdArgs,
        [switch]                         $AllowFail
    )

    # --- Render each token so the printed line is copyable/runnable ---
    # An argument needs quoting if it is empty, or contains whitespace, a quote,
    # or any shell metacharacter. We quote with double quotes and backslash-escape
    # embedded double quotes and backslashes so the result is a single, runnable
    # manual command. Windows PowerShell 5.1 compatible (no newer syntax).
    function Format-EchoToken {
        param([string] $Token)

        if ($null -eq $Token) { return '""' }
        if ($Token.Length -eq 0) { return '""' }

        # Characters that, if present, force quoting so the token stays one argument.
        $needsQuote = $Token -match '[\s"''`$&|;<>(){}\[\]*?#~!^%,=]'
        if (-not $needsQuote) {
            return $Token
        }

        # Escape backslashes first, then double quotes, then wrap in double quotes.
        $escaped = $Token -replace '\\', '\\\\'
        $escaped = $escaped -replace '"', '\"'
        return '"' + $escaped + '"'
    }

    $displayParts = @($Exe)
    foreach ($a in $CmdArgs) {
        $displayParts += (Format-EchoToken -Token $a)
    }
    $display = $displayParts -join ' '

    # --- Echo the exact command line BEFORE executing it. ---
    Write-Host "> $display" -ForegroundColor Cyan

    # --- Resolve $Exe to the external APPLICATION before invoking it. ---
    # PowerShell command-resolution precedence is Function > Cmdlet > Application,
    # and function names are case-insensitive. The deploy/teardown scripts define
    # convenience wrappers named 'Az', 'AzTry', 'Docker' that themselves call
    # Invoke-Echoed. If we invoked `& $Exe` with $Exe = 'az', PowerShell would
    # resolve 'az' to the local 'Az' FUNCTION (not az.exe), re-entering this
    # helper and recursing until the call stack overflows. Pinning to the
    # Application command type guarantees we run the real external binary and can
    # never be shadowed by a same-named wrapper function.
    $resolved = Get-Command -Name $Exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $resolved) {
        # Fail fast with a readable message instead of falling back to `& $Exe`
        # (which would re-enter a same-named wrapper) or overflowing the stack.
        throw ("Invoke-Echoed: executable '$Exe' was not found on PATH as an external application. " +
               "Install it and ensure its directory is on your PATH (verify with: Get-Command -Name '$Exe' -CommandType Application).")
    }

    # --- Execute with the argument ARRAY as discrete arguments. ---
    # Never Invoke-Expression, never a shell (bash/sh). The splat passes each
    # element of $CmdArgs as its own argument with no string re-parsing. We call
    # the resolved application PATH so a same-named function can never shadow it.
    $global:LASTEXITCODE = 0
    $output = & $resolved.Path @CmdArgs 2>&1
    $code   = $LASTEXITCODE

    # Surface the command's own output so it stays visible to the operator.
    if ($null -ne $output) {
        $output | ForEach-Object { Write-Host $_ }
    }

    # --- Fail-closed on a non-zero exit unless failure is tolerated. ---
    if ($code -ne 0 -and -not $AllowFail) {
        throw "Command failed (exit $code): $display"
    }

    # --- On a tolerated failure, return control and expose the exit
    #     code. $LASTEXITCODE remains set for the caller; also surface it here. ---
    $global:LASTEXITCODE = $code

    # Return the command's stdout so callers can capture values (URLs, endpoints).
    return $output
}

function Write-Step {
    <#
    .SYNOPSIS
        Emits a consistent, greppable step/section banner to stdout.
    .DESCRIPTION
        Prints a fixed-prefix banner so progress is easy to follow and
        grep for across a long deploy/teardown run. Every banner uses the same
        "==> " marker, making `... | Select-String '^==> '` a reliable filter.
        Windows PowerShell 5.1 compatible (no newer syntax).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Message
    )

    # Consistent, fixed marker so all step/section banners share one greppable
    # shape ("==> <message>"). Distinct color from Invoke-Echoed's command echo
    # (Cyan) keeps steps visually separable from the commands they run.
    Write-Host "==> $Message" -ForegroundColor Green
}

function Get-CloudConfig {
    <#
    .SYNOPSIS
        Loads and validates cloud.config.ps1, returning a hashtable.
    .DESCRIPTION
        Loads the config file (default: cloud.config.ps1 beside this library, or an
        explicit -ConfigPath), applies safe Common defaults, and validates it BEFORE
        any external command could run (fail-closed):

          * Required keys for the active cloud (-Cloud) must be present and must not
            be null, empty, or whitespace. Every offending key is named in the error
.
          * The globally-unique suffix must be 3-24 lowercase-alphanumeric characters;
            an invalid suffix stops execution with a message.
          * No password / secret field may appear anywhere in the config; any such
            field stops execution.

        Returns the validated, defaulted hashtable. Windows PowerShell 5.1 compatible
        (no newer syntax).
    .PARAMETER ConfigPath
        Path to the config file. Defaults to cloud.config.ps1 in the parent folder of
        this library (ops/cloud.config.ps1).
    .PARAMETER Cloud
        Which cloud's required keys to validate: Aws, Azure, or Gcp. Only the active
        cloud's keys are checked so a user configured for one cloud is not blocked by
        placeholders left in another. Defaults to Gcp (the reference target).
    #>
    [CmdletBinding()]
    param(
        [string] $ConfigPath = (Join-Path (Join-Path $PSScriptRoot '..') 'cloud.config.ps1'),
        [ValidateSet('Aws', 'Azure', 'Gcp')]
        [string] $Cloud = 'Gcp',
        # 'ecs-eks' (default) keeps the original behaviour. 'ec2' (Aws) and 'vm'
        # (Azure) require the Aws.Ec2 / Azure.Vm sections and do NOT require the
        # container-service keys (EcrRepo/EcsCluster/EksCluster, AcrNameBase/...).
        [ValidateSet('ecs-eks', 'ec2', 'vm')]
        [string] $Modality = 'ecs-eks'
    )

    if ($Modality -eq 'ec2' -and $Cloud -ne 'Aws') {
        throw "Get-CloudConfig: modality 'ec2' is only valid with -Cloud Aws (got '$Cloud')."
    }
    if ($Modality -eq 'vm' -and $Cloud -ne 'Azure') {
        throw "Get-CloudConfig: modality 'vm' is only valid with -Cloud Azure (got '$Cloud')."
    }

    # --- Load per-user values from the config file before anything else. ---
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        throw "Get-CloudConfig: no config path supplied. Copy cloud.config.example.ps1 to cloud.config.ps1 and pass -ConfigPath or run from the cloud folder."
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Get-CloudConfig: config file not found at '$ConfigPath'. Copy cloud.config.example.ps1 to cloud.config.ps1 and fill in your values."
    }

    # Evaluate the config script, which is expected to return an @{ ... } literal.
    # The '&' call operator runs it in a child scope so it cannot leak variables into
    # this function; it is NOT a shell and does not run any external CLI.
    $cfg = & $ConfigPath
    if ($cfg -is [System.Array]) {
        # A config file may emit more than one object (e.g. a stray statement). Keep the
        # last hashtable, matching how PowerShell treats a trailing expression as output.
        $cfg = @($cfg | Where-Object { $_ -is [hashtable] }) | Select-Object -Last 1
    }
    if ($null -eq $cfg -or -not ($cfg -is [hashtable])) {
        throw "Get-CloudConfig: '$ConfigPath' did not return a configuration hashtable (expected a top-level @{ ... })."
    }

    # --- Reject any secret-bearing field anywhere in the config. ---
    # Secrets belong only in the cloud secret manager, never in this file. Match key
    # names case-insensitively against common secret indicators, walking nested
    # hashtables so a secret cannot hide inside a per-cloud section.
    $secretKeyPattern = '(?i)(password|passwd|pwd|secret|token|access[_-]?key|secret[_-]?key|api[_-]?key|connection[_-]?string|connstr|credential)'
    $offendingSecretKeys = New-Object System.Collections.Generic.List[string]

    function Test-SecretKeys {
        param([hashtable] $Table, [string] $Prefix, [System.Collections.Generic.List[string]] $Sink, [string] $Pattern)
        foreach ($entry in $Table.GetEnumerator()) {
            $keyName = [string]$entry.Key
            $path = if ($Prefix) { "$Prefix.$keyName" } else { $keyName }
            if ($keyName -match $Pattern) {
                $Sink.Add($path)
            }
            if ($entry.Value -is [hashtable]) {
                Test-SecretKeys -Table $entry.Value -Prefix $path -Sink $Sink -Pattern $Pattern
            }
        }
    }
    Test-SecretKeys -Table $cfg -Prefix '' -Sink $offendingSecretKeys -Pattern $secretKeyPattern
    if ($offendingSecretKeys.Count -gt 0) {
        throw ("Get-CloudConfig: the config file must not contain secrets, but found secret-like field(s): " +
               ($offendingSecretKeys -join ', ') +
               ". Remove them; the DB password is generated at deploy time and stored only in the cloud secret manager.")
    }

    # --- Apply safe Common defaults (only where the user left a value unset). ---
    if (-not ($cfg.Contains('Common')) -or -not ($cfg['Common'] -is [hashtable])) {
        $cfg['Common'] = @{}
    }
    $commonDefaults = @{
        AppName  = 'sangyshop'
        DbName   = 'sangyshop'
        DbUser   = 'sangyshop'
        ImageTag = 'hardened'
    }
    foreach ($d in $commonDefaults.GetEnumerator()) {
        $present = $cfg['Common'].Contains($d.Key) -and -not [string]::IsNullOrWhiteSpace([string]$cfg['Common'][$d.Key])
        if (-not $present) {
            $cfg['Common'][$d.Key] = $d.Value
        }
    }

    # --- Validate the globally-unique suffix (3-24 lower-alnum). ---
    $suffix = if ($cfg.Contains('UniqueSuffix')) { [string]$cfg['UniqueSuffix'] } else { $null }
    if ([string]::IsNullOrWhiteSpace($suffix) -or ($suffix -cnotmatch '^[a-z0-9]{3,24}$')) {
        throw ("Get-CloudConfig: invalid UniqueSuffix '" + $suffix + "'. It must be 3-24 characters of lowercase letters (a-z) and digits (0-9) only.")
    }

    # --- Required keys for the active cloud must be present & non-blank. ---
    # Only the selected cloud's section is validated so unused clouds' placeholders
    # do not block a correctly-configured deployment.
    $requiredByCloud = @{
        Aws   = @('Region', 'AccountId', 'EcrRepo', 'EcsCluster', 'EksCluster')
        Azure = @('Location', 'ResourceGroup', 'AcrNameBase', 'KeyVaultBase', 'AciName', 'AksCluster')
        Gcp   = @('ProjectId', 'Region', 'ArRepo', 'CloudRunName', 'GkeCluster')
    }
    # Modality overrides: ec2/vm replace the container-service keys with the
    # keys of the new Aws.Ec2 / Azure.Vm sub-sections (validated below).
    $modalitySection = $null
    $modalityRequired = @()
    if ($Modality -eq 'ec2') {
        $requiredByCloud['Aws'] = @('Region', 'AccountId')
        $modalitySection = 'Ec2'
        $modalityRequired = @('InstanceType', 'DbInstanceClass', 'BucketBase', 'VolumeGb')
    }
    elseif ($Modality -eq 'vm') {
        $requiredByCloud['Azure'] = @('Location')
        $modalitySection = 'Vm'
        $modalityRequired = @('VmSize', 'PgSku', 'PgStorageGb', 'ResourceGroupBase', 'EvidenceGroupBase')
    }
    # Common keys are required for every cloud (defaults above guarantee them, but a
    # user who explicitly blanks one must still be caught).
    $commonRequired = @('AppName', 'DbName', 'DbUser', 'ImageTag')

    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($k in $commonRequired) {
        $has = $cfg['Common'].Contains($k) -and -not [string]::IsNullOrWhiteSpace([string]$cfg['Common'][$k])
        if (-not $has) { $missing.Add("Common.$k") }
    }

    $section = $null
    if ($cfg.Contains($Cloud) -and ($cfg[$Cloud] -is [hashtable])) {
        $section = $cfg[$Cloud]
    }
    if ($null -eq $section) {
        $missing.Add("$Cloud (entire section missing)")
    }
    else {
        foreach ($k in $requiredByCloud[$Cloud]) {
            $has = $section.Contains($k) -and -not [string]::IsNullOrWhiteSpace([string]$section[$k])
            if (-not $has) { $missing.Add("$Cloud.$k") }
        }
        if ($modalitySection) {
            $sub = $null
            if ($section.Contains($modalitySection) -and ($section[$modalitySection] -is [hashtable])) {
                $sub = $section[$modalitySection]
            }
            if ($null -eq $sub) {
                $missing.Add("$Cloud.$modalitySection (entire section missing)")
            }
            else {
                foreach ($k in $modalityRequired) {
                    $has = $sub.Contains($k) -and -not [string]::IsNullOrWhiteSpace([string]$sub[$k])
                    if (-not $has) { $missing.Add("$Cloud.$modalitySection.$k") }
                }
            }
        }
    }

    if ($missing.Count -gt 0) {
        throw ("Get-CloudConfig: missing or empty required config key(s) for cloud '$Cloud': " +
               ($missing -join ', ') +
               ". Set each named key in '$ConfigPath' before deploying.")
    }

    # Record which cloud was validated so callers/deploy scripts can key off it.
    $cfg['ActiveCloud'] = $Cloud
    $cfg['Modality']    = $Modality

    return $cfg
}

function New-DbPassword {
    <#
    .SYNOPSIS
        Generates a strong random DB password. Never logged or echoed.
    .DESCRIPTION
        Returns a random password of at least 24
        characters including lowercase, uppercase, digits, and symbols.
    #>
    [CmdletBinding()]
    param(
        [int] $Length = 32
    )

    # --- Enforce a hard floor of 24 characters regardless of -Length. ---
    # A caller passing a smaller (or non-positive) value is silently raised to the
    # minimum rather than producing a weak secret.
    $minLength = 24
    if ($Length -lt $minLength) {
        $Length = $minLength
    }

    # --- Character classes (lowercase, uppercase, digits, symbols). ---
    # The symbol set is deliberately restricted to characters that are safe to pass
    # through PostgreSQL passwords and the cloud CLIs / shells that carry them, so a
    # generated password never needs shell-escaping and never breaks a connection
    # string. Excluded on purpose: quotes, backslash, backtick, $, whitespace, and
    # shell metacharacters (& | ; < > ( ) etc.) and ambiguous @ / : used in URIs.
    $lower   = 'abcdefghijklmnopqrstuvwxyz'.ToCharArray()
    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.ToCharArray()
    $digits  = '0123456789'.ToCharArray()
    $symbols = '-_.=+*#%'.ToCharArray()
    $classes = @($lower, $upper, $digits, $symbols)
    $all     = $lower + $upper + $digits + $symbols

    # --- Cryptographically strong RNG (Windows PowerShell 5.1 compatible). ---
    # RNGCryptoServiceProvider is available on .NET Framework used by PS 5.1.
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    try {
        # Draw an unbiased index in [0, $count) from the CSPRNG using rejection
        # sampling, so the character distribution is not skewed by modulo bias.
        function Get-SecureIndex {
            param([int] $Count)
            if ($Count -le 0) { return 0 }
            # 2^32 does not fit in UInt32, so the rejection-sampling bound is kept in
            # UInt64 (the drawn value itself is a UInt32 in [0, 2^32)).
            $range = [uint64]$Count
            $limit = [uint64]4294967296  # 2^32
            $cap   = $limit - ($limit % $range)
            $buf   = [byte[]]::new(4)
            while ($true) {
                $rng.GetBytes($buf)
                $value = [uint64][System.BitConverter]::ToUInt32($buf, 0)
                if ($value -lt $cap) {
                    return [int]($value % $range)
                }
            }
        }

        # Build the character list: one guaranteed pick from each class,
        # then fill the remainder from the combined set.
        $chars = New-Object System.Collections.Generic.List[char]
        foreach ($class in $classes) {
            $chars.Add($class[(Get-SecureIndex -Count $class.Length)])
        }
        for ($i = $chars.Count; $i -lt $Length; $i++) {
            $chars.Add($all[(Get-SecureIndex -Count $all.Length)])
        }

        # Fisher-Yates shuffle with the CSPRNG so the guaranteed leading picks are
        # not positionally predictable.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-SecureIndex -Count ($i + 1)
            $tmp       = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $tmp
        }

        # --- Return the value as the function's ONLY output. It is never
        #     written to the host, a log, or an echoed command line here. ---
        return (-join $chars)
    }
    finally {
        $rng.Dispose()
    }
}

function Assert-AllowedSource32 {
    <#
    .SYNOPSIS
        Fails closed unless every allowed-source range is a strict single-host IPv4 /32.
    .DESCRIPTION
        Accepts only canonical IPv4 with the exact suffix /32 (octets 0-255, no leading
        zeros), excluding 0.0.0.0/32 and 255.255.255.255/32. Rejects empty/missing input,
        0.0.0.0/0, ::/0, '*', 'Internet', 'Any', IPv6 and any other suffix. Call it
        BEFORE any cloud call. Throws with an English message naming each bad value.
        Windows PowerShell 5.1 compatible.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()]
        [string[]] $Ranges
    )

    # Explicit null check: on Windows PowerShell 5.1 a $null [string[]] argument
    # must not reach .Count (strict mode would throw a confusing property error).
    $values = [string[]]@()
    if ($null -ne $Ranges) { $values = @($Ranges) }
    if ($values.Length -eq 0 -or ($values.Length -eq 1 -and $null -eq $values[0])) {
        throw "Assert-AllowedSource32: no allowed source range supplied. Provide at least one single-host CIDR such as 203.0.113.10/32."
    }

    $octet   = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    $pattern = '^' + $octet + '\.' + $octet + '\.' + $octet + '\.' + $octet + '/32$'
    $bad = New-Object System.Collections.Generic.List[string]

    foreach ($r in $values) {
        $text = if ($null -eq $r) { '<null>' } else { [string]$r }
        if ([string]::IsNullOrWhiteSpace($r) -or
            ($r -cnotmatch $pattern) -or
            $r -ceq '0.0.0.0/32' -or
            $r -ceq '255.255.255.255/32') {
            $bad.Add("'$text'")
        }
    }

    if ($bad.Count -gt 0) {
        throw ("Assert-AllowedSource32: rejected allowed source range(s): " + ($bad -join ', ') +
               ". Only a single IPv4 host in /32 form is accepted (for example 203.0.113.10/32); " +
               "open ranges such as 0.0.0.0/0, ::/0, '*', 'Internet' or 'Any' are never allowed.")
    }
}

function New-RunId {
    <#
    .SYNOPSIS
        Returns a run identifier yyyyMMddTHHmmssZ-xxxx (UTC timestamp + 4 random hex).
    #>
    [CmdletBinding()]
    param()

    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd\THHmmss\Z', [System.Globalization.CultureInfo]::InvariantCulture)
    $bytes = [byte[]]::new(2)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $suffix = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    return "$stamp-$suffix"
}

function Get-LabTags {
    <#
    .SYNOPSIS
        Returns the lab tag hashtable: lab, run-id, component and optional evidence=true.
    .DESCRIPTION
        Plain string key/value pairs, usable to build both AWS (Key=,Value=) and Azure
        (key=value) tag arguments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Lab,
        [Parameter(Mandatory)][string] $RunId,
        [ValidateSet('deploy', 'detection', 'blocker', 'evidence', 'credential')]
        [string] $Component = 'deploy',
        [switch] $Evidence
    )

    if ($RunId -cnotmatch '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$') {
        throw "Get-LabTags: invalid RunId '$RunId'. Expected yyyyMMddTHHmmssZ-xxxx (use New-RunId)."
    }
    if ([string]::IsNullOrWhiteSpace($Lab)) {
        throw 'Get-LabTags: Lab must not be blank.'
    }

    $tags = [ordered]@{
        'lab'       = $Lab
        'run-id'    = $RunId
        'component' = $Component
    }
    if ($Evidence) { $tags['evidence'] = 'true' }
    return $tags
}

function Get-LabManifestPath {
    <#
    .SYNOPSIS
        Resolves the lab manifest path: $env:LAB_MANIFEST_PATH or $HOME/.sangyshop-lab/manifest-<lab>.json.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Lab)

    if (-not [string]::IsNullOrWhiteSpace($env:LAB_MANIFEST_PATH)) {
        return $env:LAB_MANIFEST_PATH
    }
    $homeDir = if ($HOME) { $HOME } else { [Environment]::GetFolderPath('UserProfile') }
    $dir = Join-Path $homeDir '.sangyshop-lab'
    return (Join-Path $dir ("manifest-$Lab.json"))
}

function Find-LabManifestResourceId {
    <#
    .SYNOPSIS
        Returns the id of the newest manifest entry of a type (and component), or $null.
    .DESCRIPTION
        Read only. Used to default parameters such as the app bucket or the instance id from
        what the deploy step recorded. Entries of any ownership count. When -Region is given,
        entries recorded for another region are ignored. A missing or invalid manifest gives $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Type,
        [Parameter(Mandatory)][string] $Lab,
        [string] $Component = 'deploy',
        [string] $Region,
        [string] $ManifestPath
    )

    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Get-LabManifestPath -Lab $Lab }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $null }
    try { $doc = [System.IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json } catch { return $null }
    if ($null -eq $doc -or -not $doc.PSObject.Properties['resources'] -or $null -eq $doc.resources) { return $null }

    $found = $null
    foreach ($e in @($doc.resources)) {
        if (-not $e.PSObject.Properties['type'] -or -not $e.PSObject.Properties['id']) { continue }
        if ("$($e.type)" -cne $Type) { continue }
        if ($Component -and $e.PSObject.Properties['component'] -and "$($e.component)" -cne $Component) { continue }
        if ($Region -and $e.PSObject.Properties['region'] -and "$($e.region)" -and "$($e.region)" -cne $Region) { continue }
        if (-not [string]::IsNullOrWhiteSpace("$($e.id)")) { $found = "$($e.id)" }
    }
    return $found
}

function Add-LabManifestEntry {
    <#
    .SYNOPSIS
        Adds or updates one resource in the lab_manifest (idempotent by (type, id)).
    .DESCRIPTION
        Used for resources that cannot carry tags (access keys, SNS subscriptions, NACL
        entries, service principals...). The file lives outside the repositories. Writes
        are atomic: serialize to a temp file in the same folder, then replace/rename.
        A named mutex serializes concurrent read-modify-write cycles.

        Call this right after each successful mutating cloud call, before the next one,
        so every entry is persisted atomically on its own.

        -Ownership is 'created' (default) or 'reused'. A 'reused' entry records a
        resource that already existed; it never gets a delete block. Entries written
        before this field existed have no 'ownership' and must be read as 'created'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Type,
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Region,
        [Parameter(Mandatory)][string] $RunId,
        [Parameter(Mandatory)][ValidateSet('deploy', 'detection', 'blocker', 'evidence', 'credential')]
        [string] $Component,
        [hashtable] $DeleteHint,
        [ValidateSet('created', 'reused')]
        [string] $Ownership = 'created',
        [string] $Lab = 'sangyshop-lab-aws',
        [string] $ManifestPath
    )

    if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
        $ManifestPath = Get-LabManifestPath -Lab $Lab
    }
    $dir = Split-Path -Parent $ManifestPath
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $nowUtc = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $mutexName = 'Local\sangyshop-lab-manifest-' + ([Math]::Abs($ManifestPath.ToLowerInvariant().GetHashCode()))
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $held = $false
    try {
        try { $held = $mutex.WaitOne([TimeSpan]::FromSeconds(30)) }
        catch [System.Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw "Add-LabManifestEntry: timed out waiting for the manifest lock." }

        # Load existing manifest or start a fresh one.
        $resources = @()
        $header = [ordered]@{
            schema      = 1
            lab         = $Lab
            run_id      = $RunId
            region      = $Region
            created_utc = $nowUtc
        }
        if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
            $raw = [System.IO.File]::ReadAllText($ManifestPath)
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                try { $existing = $raw | ConvertFrom-Json }
                catch { throw "Add-LabManifestEntry: existing manifest '$ManifestPath' is not valid JSON; refusing to overwrite it." }
                foreach ($k in @('schema', 'lab', 'run_id', 'region', 'created_utc')) {
                    if ($existing.PSObject.Properties.Name -contains $k) { $header[$k] = $existing.$k }
                }
                if ($existing.PSObject.Properties.Name -contains 'resources' -and $null -ne $existing.resources) {
                    $resources = @($existing.resources)
                }
            }
        }

        $entry = [ordered]@{
            type        = $Type
            id          = $Id
            region      = $Region
            run_id      = $RunId
            component   = $Component
            created_utc = $nowUtc
        }
        $entry['ownership'] = $Ownership
        # Reused resources pre-existed the lab run and must never be deleted by it,
        # so they carry no delete block even if a hint was passed.
        if ($Ownership -eq 'created' -and $PSBoundParameters.ContainsKey('DeleteHint') -and $null -ne $DeleteHint) {
            $entry['delete'] = $DeleteHint
        }

        # Idempotent by (type, id): replace in place, keep original created_utc.
        $found = $false
        $updated = New-Object System.Collections.Generic.List[object]
        foreach ($r in $resources) {
            if ($r.type -ceq $Type -and $r.id -ceq $Id) {
                if ($r.PSObject.Properties.Name -contains 'created_utc') { $entry['created_utc'] = $r.created_utc }
                $updated.Add([pscustomobject]$entry)
                $found = $true
            }
            else {
                $updated.Add($r)
            }
        }
        if (-not $found) { $updated.Add([pscustomobject]$entry) }

        $doc = [ordered]@{}
        foreach ($k in $header.Keys) { $doc[$k] = $header[$k] }
        $doc['resources'] = $updated.ToArray()
        $json = ConvertTo-Json -InputObject $doc -Depth 10

        # Atomic write: temp file in the same folder, then replace/rename.
        $tmp = $ManifestPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        try {
            [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
            if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
                $bak = $tmp + '.bak'
                [System.IO.File]::Replace($tmp, $ManifestPath, $bak)
                Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
            }
            else {
                [System.IO.File]::Move($tmp, $ManifestPath)
            }
        }
        finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Import-LabDotEnv {
    <#
    .SYNOPSIS
        Loads KEY=VALUE pairs from a .env file into the process environment.
    .DESCRIPTION
        Defaults to ops/.env, resolved relative to this library rather than to the
        calling script. A variable that is already set (non-empty) in the process is
        never overwritten. Blank lines and lines starting with '#' are ignored, an
        optional leading 'export ' is accepted, and matching single or double quotes
        around a value are removed. A missing file is not an error. Values are never
        printed. Returns the names of the variables that were set.
    #>
    [CmdletBinding()]
    param(
        [string] $Path = (Join-Path (Join-Path $PSScriptRoot '..') '.env')
    )

    $loaded = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }

    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $text = $line.Trim()
        if ($text.Length -eq 0 -or $text.StartsWith('#')) { continue }
        if ($text -match '^export\s+') { $text = $text -replace '^export\s+', '' }

        $eq = $text.IndexOf('=')
        if ($eq -lt 1) { continue }
        $name  = $text.Substring(0, $eq).Trim()
        $value = $text.Substring($eq + 1).Trim()
        if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') { continue }

        if ($value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        $current = [Environment]::GetEnvironmentVariable($name, 'Process')
        if ([string]::IsNullOrEmpty($current)) {
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
            $loaded.Add($name)
        }
    }
    return $loaded.ToArray()
}

function Test-LabEmailFormat {
    <#
    .SYNOPSIS
        Returns $true when the text looks like an e-mail address.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $Email
    )

    if ($null -eq $Email) { return $false }
    return ($Email -cmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$')
}

function Resolve-LabAlertEmail {
    <#
    .SYNOPSIS
        Resolves the alert e-mail address for the lab detection stack.
    .DESCRIPTION
        Order: the -Email parameter, then the LAB_ALERT_EMAIL environment variable
        (after loading ops/.env without overriding existing variables), then an
        interactive prompt. With no value and no console, or with a value that fails
        the format check, the process exits with code 2. The address itself is never
        printed: only the source it came from is reported. Returns the trimmed address.
    #>
    [CmdletBinding()]
    param(
        [string] $Email,
        [switch] $NonInteractive,
        [string] $DotEnvPath
    )

    $value  = $null
    $source = $null

    if (-not [string]::IsNullOrWhiteSpace($Email)) {
        $value  = $Email.Trim()
        $source = 'the -Email parameter'
    }

    if ($null -eq $value) {
        if ($PSBoundParameters.ContainsKey('DotEnvPath')) {
            $envBefore = $env:LAB_ALERT_EMAIL
            Import-LabDotEnv -Path $DotEnvPath | Out-Null
        }
        else {
            $envBefore = $env:LAB_ALERT_EMAIL
            Import-LabDotEnv | Out-Null
        }
        if (-not [string]::IsNullOrWhiteSpace($env:LAB_ALERT_EMAIL)) {
            $value  = $env:LAB_ALERT_EMAIL.Trim()
            $source = if ([string]::IsNullOrWhiteSpace($envBefore)) { 'the ops/.env file' } else { 'the LAB_ALERT_EMAIL environment variable' }
        }
    }

    if ($null -eq $value) {
        $canPrompt = (-not $NonInteractive) -and
                     ($null -eq (Get-Variable -Name LabCliHandler -Scope Global -ErrorAction SilentlyContinue)) -and
                     [Environment]::UserInteractive -and
                     (-not [Console]::IsInputRedirected)
        if ($canPrompt) {
            $answer = Read-Host -Prompt 'Alert e-mail address'
            if (-not [string]::IsNullOrWhiteSpace($answer)) {
                $value  = $answer.Trim()
                $source = 'an interactive prompt'
            }
        }
    }

    if ($null -eq $value) {
        [Console]::Error.WriteLine('Resolve-LabAlertEmail: no alert e-mail available. Pass -Email, set LAB_ALERT_EMAIL, or define it in ops/.env (see ops/.env.example).')
        exit 2
    }

    if (-not (Test-LabEmailFormat -Email $value)) {
        [Console]::Error.WriteLine("Resolve-LabAlertEmail: the e-mail from $source is not a valid address.")
        exit 2
    }

    Write-Host "Alert e-mail source: $source"
    return $value
}

function Resolve-LabRegion {
    <#
    .SYNOPSIS
        Resolves the AWS region for the lab scripts.
    .DESCRIPTION
        Order: the -Region parameter, then Aws.Region from the config hashtable
        (as returned by Get-CloudConfig). With neither, an English message is written
        to stderr and the process exits with code 2. Returns the trimmed region.
    #>
    [CmdletBinding()]
    param(
        [string] $Region,
        [hashtable] $Config
    )

    if (-not [string]::IsNullOrWhiteSpace($Region)) {
        return $Region.Trim()
    }

    if ($null -ne $Config -and $Config.Contains('Aws') -and ($Config['Aws'] -is [hashtable]) -and
        $Config['Aws'].Contains('Region') -and
        -not [string]::IsNullOrWhiteSpace([string]$Config['Aws']['Region'])) {
        return ([string]$Config['Aws']['Region']).Trim()
    }

    [Console]::Error.WriteLine('Resolve-LabRegion: no AWS region available. Pass -Region or set Aws.Region in the config file.')
    exit 2
}

function Hide-LabSecrets {
    <#
    .SYNOPSIS
        Minimal secret masking used when the full redaction library is not available.
    .DESCRIPTION
        Masks access key identifiers (AKIA/ASIA plus 16 characters), values labeled
        SecretAccessKey or SessionToken (JSON, key=value or key: value forms), and
        stand-alone 40-character secret key shaped strings. Returns the masked text.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $mask = '[REDACTED]'
    $out = $Text

    # Labeled values: "SecretAccessKey": "value", SecretAccessKey=value, SessionToken: value
    $out = [regex]::Replace($out, '(?i)("?(?:SecretAccessKey|SessionToken|aws_secret_access_key|aws_session_token)"?\s*[:=]\s*"?)([^"\s,}]+)', ('${1}' + $mask))
    # Access key identifiers.
    $out = [regex]::Replace($out, '(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])', $mask)
    # Unlabeled 40-character secret key shape.
    $out = [regex]::Replace($out, '(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])', $mask)
    return $out
}
