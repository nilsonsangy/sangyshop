# Cloud deploy test suite (Pester)

Unit and dry-run tests for the `ops/` PowerShell scripts. Everything here runs on
**Windows PowerShell 5.1+** (or PowerShell 7+) with **no cloud access**: the cloud CLIs are never
invoked by these tests.

## Prerequisites: Pester 5.x

These tests use the Pester 5.x syntax (`Describe` / `It` / `Should -Be`, `BeforeAll`, `Mock`). Windows
PowerShell 5.1 ships with the legacy Pester 3.4.0, which is **not** compatible. Confirm your version:

```powershell
Get-Module -ListAvailable Pester | Select-Object Name, Version
```

If the listed version is below 5.0, install the current Pester for the current user (the `-Force` and
`-SkipPublisherCheck` flags are needed to side-step the in-box 3.4.0 signed module on Windows
PowerShell 5.1):

```powershell
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

Then import the 5.x version explicitly if the old one is also present:

```powershell
Import-Module Pester -MinimumVersion 5.0.0
```

## Running the tests

From the repo root (or any directory), run the whole suite:

```powershell
Invoke-Pester -Path ops/tests
```

Or run a single file:

```powershell
Invoke-Pester -Path ops/tests/Common.Smoke.Tests.ps1
```

## Layout

```
tests/
  README.md                   # this file
  Common.Smoke.Tests.ps1      # confirms lib/Common.ps1 dot-sources and exposes the four functions
  Common.InvokeEchoed.Tests.ps1   # task 2.2
  Common.GetCloudConfig.Tests.ps1 # task 2.5
  Common.NewDbPassword.Tests.ps1  # task 2.7
  EchoOnly.Guard.Tests.ps1    # task 3, static echo-only guard (Requirement 1.3)
```

Per-target `-WhatIf` dry-run tests:
- `Azure.Aci.WhatIf.Tests.ps1`: task 11.3, dry-run assertions for the Azure
  Docker-only (ACI) `deploy.ps1` / `teardown.ps1` (Requirements 6.5, 3.1)

Later tasks add the remaining per-target `-WhatIf` dry-run tests (tasks 6.3, 7.4,
9.4, 10.4, 12.4).

### Echo-only guard (`EchoOnly.Guard.Tests.ps1`, Requirement 1.3)

Scans every `deploy.ps1` / `teardown.ps1` found recursively under
`ops/` and fails if any of the five cloud CLIs (`aws`, `az`,
`gcloud`, `kubectl`, `docker`) is invoked directly. The only approved form is a
quoted string argument to the shared helper, e.g. `Invoke-Echoed -Exe "aws" ...`.
Until the deploy/teardown scripts land (later tasks) the scan finds zero scripts
and passes vacuously; it begins catching violations the moment a script exists.

The same check can be run by hand without Pester: see the `.NOTES` block at the
top of `EchoOnly.Guard.Tests.ps1` for the equivalent `ripgrep` and `Select-String`
commands.

> **Note on Pester version here:** this repo currently has Pester 3.4.0 (the in-box
> Windows PowerShell module) **and** a user-scope Pester 6.x. The 5.x syntax these
> tests use runs on either Pester 5.x or 6.x. If only 3.4.0 is present, install a
> current Pester first (see the Prerequisites section above). On a locked-down host
> you may also need to bypass execution policy:
> ```powershell
> powershell -ExecutionPolicy Bypass -Command "Invoke-Pester -Path ops/tests/EchoOnly.Guard.Tests.ps1"
> ```
