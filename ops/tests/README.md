# Cloud deploy and incident response lab test suite (Pester)

Unit, property and dry-run tests for the `ops/` PowerShell scripts. Everything here runs on
Windows PowerShell 5.1+ (or PowerShell 7+) with no cloud access: the cloud CLIs are never
invoked by these tests.

## Prerequisites: Pester 5.x

These tests use the Pester 5.x syntax (`Describe` / `It` / `Should -Be`, `BeforeAll`, `Mock`).
Windows PowerShell 5.1 ships with the legacy Pester 3.4.0, and that version may be the one loaded
by default. It is not compatible. Confirm which versions are installed:

```powershell
Get-Module -ListAvailable Pester | Select-Object Name, Version
```

If nothing at 5.0 or above is listed, install the current Pester for the current user (`-Force` and
`-SkipPublisherCheck` side-step the in-box 3.4.0 signed module on Windows PowerShell 5.1):

```powershell
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

Always import the 5.x version explicitly before running, so the old one is not picked up:

```powershell
Import-Module Pester -MinimumVersion 5.0
```

On a locked-down host you may also need to bypass the execution policy:

```powershell
powershell -ExecutionPolicy Bypass -Command "Import-Module Pester -MinimumVersion 5.0; Invoke-Pester -Path <absolute path to ops/tests>"
```

## Running the tests

Use absolute paths so the command works from any directory. Replace `<repo>` with the absolute
path of your checkout (for example `C:\Users\you\repositories\sangyshop`).

Run the whole suite:

```powershell
Import-Module Pester -MinimumVersion 5.0
Invoke-Pester -Path <repo>\ops\tests
```

Run a single file:

```powershell
Import-Module Pester -MinimumVersion 5.0
Invoke-Pester -Path <repo>\ops\tests\Common.Smoke.Tests.ps1
```

### Long-running suites

These files generate many randomized cases or exercise many retries, so they take noticeably longer
than the rest. Run them on their own when iterating on something else:

- `AwsIrLab.FullTeardown.Properties.Tests.ps1`
- `AzureIrLab.FullTeardown.Properties.Tests.ps1`
- `AwsIrLab.Detection.Idempotent.Tests.ps1`
- `AwsIrLab.Resilience.Tests.ps1`

To run everything except them, list the other files explicitly or filter by path:

```powershell
$long = 'AwsIrLab.FullTeardown.Properties', 'AzureIrLab.FullTeardown.Properties', 'AwsIrLab.Detection.Idempotent', 'AwsIrLab.Resilience'
$files = Get-ChildItem <repo>\ops\tests -Filter *.Tests.ps1 |
    Where-Object { $name = $_.Name; -not ($long | Where-Object { $name -like "$_*" }) }
Invoke-Pester -Path $files.FullName
```

## Python blocker test (pytest)

The Azure-free AWS blocker has a property test written in Python, kept next to the lab scripts at
`ops/aws/ir-lab/tests/test_blocker_properties.py`. It needs `pytest` and `hypothesis`. Run it with
`uvx` (no install step):

```powershell
uvx --with hypothesis pytest <repo>\ops\aws\ir-lab\tests
```

Or install the packages once and call pytest directly:

```powershell
pip install pytest hypothesis
pytest <repo>\ops\aws\ir-lab\tests
```

## Layout

Files currently in this folder. When you add a test file, add one line to the matching group.

Shared helpers and smoke checks:
- `Common.Smoke.Tests.ps1`: confirms `lib/Common.ps1` dot-sources and exposes its functions
- `Common.InvokeEchoed.Tests.ps1`
- `Common.GetCloudConfig.Tests.ps1`
- `Common.NewDbPassword.Tests.ps1`
- `Common.HideSecrets.Tests.ps1`
- `Common.AlertEmail.Tests.ps1`
- `Common.AllowedSource.Tests.ps1`
- `Common.Region.Tests.ps1`
- `Common.LabManifest.Tests.ps1`

Guards:
- `EchoOnly.Guard.Tests.ps1`: static echo-only guard (see below)
- `IrLab.Static.Tests.ps1`: static checks over the incident response lab scripts

Per-target `-WhatIf` dry-run tests:
- `Aws.Ec2.WhatIf.Tests.ps1`, `Aws.Ecs.WhatIf.Tests.ps1`, `Aws.Eks.WhatIf.Tests.ps1`
- `Azure.Aci.WhatIf.Tests.ps1`, `Azure.Aks.WhatIf.Tests.ps1`, `Azure.Vm.WhatIf.Tests.ps1`
- `Gcp.Docker.WhatIf.Tests.ps1`, `Gcp.Kubernetes.WhatIf.Tests.ps1`

AWS incident response lab (`ops/aws/ir-lab`):
- `AwsLabNames.Tests.ps1`
- `AwsIrLab.DetectionCommon.Tests.ps1`
- `AwsIrLab.Detection.ExistenceFirst.Tests.ps1`
- `AwsIrLab.Detection.Idempotent.Tests.ps1` (long)
- `AwsIrLab.Gates.Tests.ps1`
- `AwsIrLab.ManifestMerge.Tests.ps1`
- `AwsIrLab.ReadOnly.Tests.ps1`
- `AwsIrLab.Resilience.Tests.ps1` (long)
- `AwsIrLab.TeardownReused.Tests.ps1`
- `AwsIrLab.FullTeardown.Properties.Tests.ps1` (long)

Azure incident response lab (`ops/azure/ir-lab`):
- `AzureIrLab.Detection.Tests.ps1`
- `AzureIrLab.ReadOnly.Tests.ps1`
- `AzureIrLab.Resilience.Tests.ps1`
- `AzureIrLab.FullTeardown.Properties.Tests.ps1` (long)

IAM lab group and permissions:
- `LabGroup.NameGuard.Tests.ps1`
- `LabGroup.PolicyVersions.Tests.ps1`
- `LabGroup.Safety.Tests.ps1`
- `LabGroup.Templates.Tests.ps1`
- `LabPermissions.Tests.ps1`
- `LabPermissions.Docs.Tests.ps1`: the permission tables in `lib/LabPermissions.ps1` match the README tables
- `LabPreflight.Tests.ps1`


Python (run with pytest, see above):
- `ops/aws/ir-lab/tests/test_blocker_properties.py`

## Echo-only guard (`EchoOnly.Guard.Tests.ps1`)

Scans every `deploy.ps1` and `teardown.ps1` found recursively under `ops/` and fails if any of the
five cloud CLIs (`aws`, `az`, `gcloud`, `kubectl`, `docker`) is invoked directly. The only approved
form is a quoted string argument to the shared helper, for example `Invoke-Echoed -Exe "aws" ...`.

The guard inspects only `deploy.ps1` and `teardown.ps1`. Other scripts, such as the incident
response lab scripts, are not scanned by it and are covered by their own test files instead.

The same check can be run by hand without Pester: see the `.NOTES` block at the top of
`EchoOnly.Guard.Tests.ps1` for the equivalent `ripgrep` and `Select-String` commands.
