<#
.SYNOPSIS
    Shared PowerShell library for the multi-cloud-deploy scripts.

.DESCRIPTION
    Dot-sourced by every deploy.ps1 / teardown.ps1 under deployment-security/cloud/.
    Hosts the single echoed-command helper (Invoke-Echoed), structured logging
    (Write-Step), config loading/validation (Get-CloudConfig), and DB-password
    generation (New-DbPassword).

    This file currently contains STUBS only. Later tasks (see tasks.md task 2.x)
    fill in each function body. Keeping the stubs here lets the cloud scripts and
    Pester tests reference the functions before they are implemented.

    Requirement 6.1: these scripts must run on Windows PowerShell 5.1+. Do not use
    syntax newer than 5.1 in this file.
#>

Set-StrictMode -Version Latest

function Invoke-Echoed {
    <#
    .SYNOPSIS
        Echoes an external command line to stdout, then executes it.
    .DESCRIPTION
        STUB - implemented in task 2.1. Prints "$Exe <args>" before running,
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

    # --- Req 1.2: render each token so the printed line is copyable/runnable ---
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

    # --- Req 1.1: echo the exact command line BEFORE executing it. ---
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

    # --- Req 1.4 / 6.2: execute with the argument ARRAY as discrete arguments. ---
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

    # --- Req 1.5: fail-closed on a non-zero exit unless failure is tolerated. ---
    if ($code -ne 0 -and -not $AllowFail) {
        throw "Command failed (exit $code): $display"
    }

    # --- Req 1.6: on a tolerated failure, return control and expose the exit
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
        Req 1.1: prints a fixed-prefix banner so progress is easy to follow and
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
        any external command could run (Req 7.1, fail-closed):

          * Required keys for the active cloud (-Cloud) must be present and must not
            be null, empty, or whitespace. Every offending key is named in the error
            (Req 7.3).
          * The globally-unique suffix must be 3-24 lowercase-alphanumeric characters;
            an invalid suffix stops execution with a message (Req 7.5, 7.6).
          * No password / secret field may appear anywhere in the config; any such
            field stops execution (Req 7.4).

        Returns the validated, defaulted hashtable. Windows PowerShell 5.1 compatible
        (no newer syntax).
    .PARAMETER ConfigPath
        Path to the config file. Defaults to cloud.config.ps1 in the parent folder of
        this library (deployment-security/cloud/cloud.config.ps1).
    .PARAMETER Cloud
        Which cloud's required keys to validate: Aws, Azure, or Gcp. Only the active
        cloud's keys are checked so a user configured for one cloud is not blocked by
        placeholders left in another. Defaults to Gcp (the reference target).
    #>
    [CmdletBinding()]
    param(
        [string] $ConfigPath = (Join-Path $PSScriptRoot '..' 'cloud.config.ps1'),
        [ValidateSet('Aws', 'Azure', 'Gcp')]
        [string] $Cloud = 'Gcp'
    )

    # --- Req 7.1: load per-user values from the config file before anything else. ---
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

    # --- Req 7.4: reject any secret-bearing field anywhere in the config. ---
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

    # --- Req 7.5 / 7.6: validate the globally-unique suffix (3-24 lower-alnum). ---
    $suffix = if ($cfg.Contains('UniqueSuffix')) { [string]$cfg['UniqueSuffix'] } else { $null }
    if ([string]::IsNullOrWhiteSpace($suffix) -or ($suffix -cnotmatch '^[a-z0-9]{3,24}$')) {
        throw ("Get-CloudConfig: invalid UniqueSuffix '" + $suffix + "'. It must be 3-24 characters of lowercase letters (a-z) and digits (0-9) only.")
    }

    # --- Req 7.3: required keys for the active cloud must be present & non-blank. ---
    # Only the selected cloud's section is validated so unused clouds' placeholders
    # do not block a correctly-configured deployment.
    $requiredByCloud = @{
        Aws   = @('Region', 'AccountId', 'EcrRepo', 'EcsCluster', 'EksCluster')
        Azure = @('Location', 'ResourceGroup', 'AcrNameBase', 'KeyVaultBase', 'AciName', 'AksCluster')
        Gcp   = @('ProjectId', 'Region', 'ArRepo', 'CloudRunName', 'GkeCluster')
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
    }

    if ($missing.Count -gt 0) {
        throw ("Get-CloudConfig: missing or empty required config key(s) for cloud '$Cloud': " +
               ($missing -join ', ') +
               ". Set each named key in '$ConfigPath' before deploying.")
    }

    # Record which cloud was validated so callers/deploy scripts can key off it.
    $cfg['ActiveCloud'] = $Cloud

    return $cfg
}

function New-DbPassword {
    <#
    .SYNOPSIS
        Generates a strong random DB password. Never logged or echoed.
    .DESCRIPTION
        STUB - implemented in task 2.6. Returns a random password of at least 24
        characters including lowercase, uppercase, digits, and symbols.
    #>
    [CmdletBinding()]
    param(
        [int] $Length = 32
    )

    # --- Req 4.4: enforce a hard floor of 24 characters regardless of -Length. ---
    # A caller passing a smaller (or non-positive) value is silently raised to the
    # minimum rather than producing a weak secret.
    $minLength = 24
    if ($Length -lt $minLength) {
        $Length = $minLength
    }

    # --- Character classes (Req 4.4: lowercase, uppercase, digits, symbols). ---
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

        # Build the character list: one guaranteed pick from each class (Req 4.4),
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

        # --- Req 3.2: return the value as the function's ONLY output. It is never
        #     written to the host, a log, or an echoed command line here. ---
        return (-join $chars)
    }
    finally {
        $rng.Dispose()
    }
}
