# Azure incident response lab

Scripts that add a detection stack, an automatic blocker and a leaked credential to the SangyShop Azure VM deployment, so you can run an attack, detect it and respond to it. Everything is created with the lab tag (`lab=sangyshop-lab-azure`), recorded in a local manifest and removed by one teardown script.

The scripts never grant Azure roles to the operator, never change a resource they did not create, and never run the attack or the response for you.

## Folder layout

```text
ops/azure/ir-lab/
  detection/    enable-*.ps1 and disable-*.ps1, delete-workspace.ps1, remove-sentinel.ps1, queries/*.kql
  blocker/      deploy-blocker.ps1, remove-blocker.ps1, logic-app.template.json, policies/
  check-detection-ready.ps1     read-only readiness check, writes the readiness stamp
  print-response-commands.ps1   prints the response commands, runs nothing
  plant-leaked-credential.ps1   creates the leaked service principal and the /lab/leaked.json file
  use-leaked-credential.ps1     uses that credential (8 calls at most, hard cap 10)
  full-teardown.ps1             removes everything the lab created
  verify-zero-cost.ps1          read-only list of what could still cost money
```

Names (resource group, workspace, the `SangyShopApp_CL` table, VM) are derived from `ops/cloud.config.ps1` through `ops/azure/vm/VmNames.ps1`, so the VM deployment and the lab scripts always agree.

## Prerequisites

- Azure CLI signed in to the lab subscription, and PowerShell 5.1 or later.
- `ops/cloud.config.ps1` copied from `ops/cloud.config.example.ps1`, with the Azure location set.
- The application deployed with `ops/azure/vm/deploy.ps1`.
- `-Subscription` on every script. No default subscription is used, so the lab never touches the wrong one.
- Permissions listed in [Permissions needed before you start](#permissions-needed-before-you-start).

## The four steps

1. Build: deploy the application (`ops/azure/vm/deploy.ps1`).
2. Detect: enable the detection stack and confirm it is ready.
3. Attack: run `attack-simulation/attack.js`.
4. Respond: print the response commands and run the ones you choose.

### 1. Build

```powershell
./ops/azure/vm/deploy.ps1 -WhatIf   # review
./ops/azure/vm/deploy.ps1
```

### 2. Detect

```powershell
./ops/azure/ir-lab/detection/enable-all.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
./ops/azure/ir-lab/detection/enable-all.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus
```

`enable-all.ps1` runs these components with one shared run id: workspace, Activity Log, diagnostics, Entra ID export, VNet flow logs, Defender for Servers, Sentinel and alerts. A failure in one component does not stop the others. Switches: `-SkipFlowLogs`, `-SkipDefender` (the plan is a trial, then billable), `-SkipEntra` (the export needs a Microsoft Entra ID P1 or P2 licence; without it the lab falls back to the Activity Log and resource logs), `-EntraLicense Auto|Yes|No`. Each component also has its own `enable-*.ps1`.

Before anything is created, `enable-all.ps1` checks that the VM exists. If it does not, the script exits with 4 and tells you to run `ops/azure/vm/deploy.ps1`. Component scripts start with a read-only look at the subscription and print one line per resource type with the decision: create, reuse a lab resource, reuse a resource it did not create, or blocked. A read that is denied or fails is treated as blocked, never as "missing".

The alert rule runs the saved query `queries/login-failure-bruteforce.kql` every 5 minutes over a 10 minute window (10 or more failed logins from one IP in one minute) and notifies the Action Group `ag-sangyshop-lab`. The workspace keeps a 1 GB daily ingestion cap.

When the alert e-mail is set up, run the readiness check:

```powershell
./ops/azure/ir-lab/check-detection-ready.ps1 -Subscription <id>
```

It is read-only and passes only when the workspace exists, the Action Group has at least one enabled e-mail receiver, the brute-force alert rule exists and is enabled, and the rule notifies the Action Group. On success (exit 0) it writes the readiness stamp. When something is not ready it exits with 4, names the script that creates it, and writes no stamp.

Optional auto-block of attacking IPs (Logic App with a managed identity that edits only the lab NSG):

```powershell
./ops/azure/ir-lab/blocker/deploy-blocker.ps1 -Subscription <id>             # dry-run, no Azure call
./ops/azure/ir-lab/blocker/deploy-blocker.ps1 -Subscription <id> -Execute
./ops/azure/ir-lab/blocker/remove-blocker.ps1 -Subscription <id> -Execute
```

The blocker scripts are dry-run by default and need `-Execute` to change anything. The custom role can read, write and delete NSG security rules only, and is assignable only on the lab NSG. `remove-blocker.ps1` also removes the block rules unless `-KeepBlockRules` is set.

### 3. Attack

```powershell
node attack-simulation/attack.js
```

`attack.js` reads the readiness stamp before sending any request and refuses to start without a fresh one (see [Readiness stamp](#readiness-stamp)). It never calls a cloud API.

To plant and use the leaked credential:

```powershell
./ops/azure/ir-lab/plant-leaked-credential.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus -WhatIf
./ops/azure/ir-lab/plant-leaked-credential.ps1 -Subscription <id> -ResourceGroup rg-sangyshop-lab -Region eastus
./ops/azure/ir-lab/use-leaked-credential.ps1 -Subscription <id>
```

`plant-leaked-credential.ps1` creates the service principal `sp-lab-leaked` with `Reader` on the lab resource group and `Storage Blob Data Reader` on the application container only, a client secret that lasts 7 days by default (`-SecretDays`; re-running rotates it), and writes the credential to `/lab/leaked.json` on the VM with `az vm run-command invoke`. The secret is never printed or put on a visible command line. Every item is recorded in the manifest. `use-leaked-credential.ps1` signs in with that identity and makes a few calls so the Activity Log and Entra ID sign-in logs record the identity and the source IP; one call (listing storage account keys) is expected to be denied.

### 4. Respond

```powershell
./ops/azure/ir-lab/print-response-commands.ps1 -Subscription <id>
```

It prints ready-to-copy native `az` commands for Activity Log collection, Defender for Cloud alerts, an OS disk snapshot, VM network interface isolation and removal of the leaked service principal credential, with the real lab values filled in (VM, resource group, subscription, region and, when `-Subscription` is given, the OS disk name from `az vm show`). It never runs them. Without `-Subscription` no Azure call is made and placeholders are printed. The snapshot, the network interface change and the credential removal modify the subscription, so review each command before running it. Exit codes: 0 commands printed, 2 configuration problem, 3 a read was denied, 4 the attack evidence file (`attack-simulation/out/attack-steps.jsonl`) is missing.

## Alert e-mail

The address that receives alerts comes from, in order: the `-Email` parameter, the `LAB_ALERT_EMAIL` environment variable, `ops/.env`, then an interactive prompt. Copy `ops/.env.example` to `ops/.env` and fill in the value; `ops/.env` is ignored by Git. The format is validated, and the address is never printed, only the source it came from.

## Readiness stamp

When `check-detection-ready.ps1` exits with 0 it writes `readiness-sangyshop-lab-azure.json` next to the lab manifest (`$HOME/.sangyshop-lab/`, or the folder of `LAB_MANIFEST_PATH`). It holds the lab name, region, a UTC time and the four check results, and never an e-mail address. With any other exit code no stamp is written and an older stamp is left as it was. `attack.js` reads this file and nothing else. `attack.js --ack-no-detection` skips the check; use it only when you accept that the attack will not be detected.

## Reuse of existing infrastructure

The lab is additive. A same-named Action Group or alert rule without the lab tag is reused as it is: it is not tagged, edited or removed, and the lab e-mail is not added to it. A Defender plan that is already `Standard` with sub-plan `P2` is not touched and not recorded. Reused items are recorded in the manifest with ownership `reused`, and teardown removes only items created by the lab or carrying the lab tag. Each resource is written to the manifest right after it is created, so after a failure you can fix the cause and run the same script again. Resources already created are detected and reused.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Done, ready, or nothing to do | Continue with the next step |
| 1 | A component failed, or something is pending or unverified | Read the message |
| 2 | Invalid parameter or configuration (for example a missing `-Subscription`) | Fix the config or pass the parameter |
| 3 | A permission is missing | The message names the denied call and the exact built-in role. Assign it and run the same script again |
| 4 | A step precondition is not met | See below |

Exit code 4 means: the VM is not deployed (run `ops/azure/vm/deploy.ps1`), detection is not ready (run the script named), or the attack evidence file is missing (run the attack). In `full-teardown.ps1`, 5 means the run was cancelled or only resources blocked by a retention or immutability policy remain.

## Permissions needed before you start

Assign roles to the operator at the scope shown. Prefer the lab resource group; only Defender for Cloud plans need the subscription scope. When a call is denied, the script exits with 3 and prints the exact role.

### Required permissions

| Command group | Built-in role | Used for |
|---|---|---|
| group | Contributor | Assign at the lab resource group scope. |
| vm | Virtual Machine Contributor | Assign at the lab resource group scope. |
| network | Network Contributor | Virtual network, NSG and public IP. Assign at the lab resource group scope. |
| storage | Storage Account Contributor | Evidence and trail storage. Assign at the lab resource group scope. |
| postgres | Contributor | No narrower built-in role covers PostgreSQL flexible server. Assign at the lab resource group scope. |
| keyvault | Key Vault Contributor, Key Vault Secrets Officer | Vault management plus secrets. Assign at the lab resource group scope. |
| identity | Managed Identity Contributor | User-assigned managed identity. Assign at the lab resource group scope. |
| acr | Contributor | Container registry. Assign at the lab resource group scope. |
| aks | Contributor | Kubernetes cluster. Assign at the lab resource group scope. |
| container | Contributor | Container instances. Assign at the lab resource group scope. |
| monitor | Monitoring Contributor | Action groups, alert rules and diagnostic settings. |
| loganalytics | Log Analytics Contributor | Log Analytics workspace. |
| sentinel | Microsoft Sentinel Contributor | Sentinel analytics rules. |
| logic | Logic App Contributor | Logic App of the blocker. |
| policy | Resource Policy Contributor | Azure Policy definitions and assignments. |
| role | Role Based Access Control Administrator, User Access Administrator | Role assignments of the blocker. Assign either role at the lab resource group scope, never at subscription scope. |
| security | Security Admin | Defender for Cloud pricing plans. Assign at the subscription scope. |
| account | Reader | Subscription and resource reads. |

Resource provider names map to these groups: `Microsoft.Compute` to vm, `Microsoft.Network` to network, `Microsoft.Storage` to storage, `Microsoft.Insights` to monitor, `Microsoft.OperationalInsights` to loganalytics, `Microsoft.SecurityInsights` to sentinel, `Microsoft.Logic` to logic, `Microsoft.Authorization` to role, and so on.

Notes:

- `enable-entra.ps1` also needs a role that can write tenant diagnostic settings (Global Administrator or Security Administrator) and a Microsoft Entra ID P1 or P2 licence. Without them it exits 0 with no change and prints the limitation and the fallback.
- `plant-leaked-credential.ps1` creates an app registration, so the operator also needs the right to create applications in the tenant.
- `check-detection-ready.ps1` needs only read access: Reader on the lab resource group (Monitoring Reader also covers the Action Group and alert rule reads).

## Cost

All detection components are billable beyond free tiers and trials: Log Analytics ingestion (capped at 1 GB per day), Sentinel after its free trial, Defender for Servers Plan 2 after its 30 day trial, VNet flow logs and the storage behind them. Use `-SkipFlowLogs`, `-SkipDefender` and `-SkipEntra` to reduce cost, and tear down when you finish.

## Teardown

```powershell
./ops/azure/ir-lab/full-teardown.ps1 -Subscription <id> -Region eastus -WhatIf
./ops/azure/ir-lab/full-teardown.ps1 -Subscription <id> -Region eastus
./ops/azure/ir-lab/verify-zero-cost.ps1 -Subscription <id>
```

`full-teardown.ps1` finds resources by the lab tag and by the manifest (for items that cannot carry tags, such as service principals, diagnostic settings, Defender plans and role assignments), not by names you type. It removes things in reverse dependency order: NSG rules, blocker, credential secrets, Sentinel (before the workspace), flow logs, diagnostics, Defender plans back to Free, alerts and Action Groups, the workspace (permanent delete), the VM deployment (`ops/azure/vm/teardown.ps1`), the lab resource group, soft-deleted Key Vault purge, evidence, and service principals last. Evidence is removed by default; `-PreserveEvidence` keeps it and prints the continuing monthly cost. A resource with neither the tag nor a manifest entry is listed as unmarked and left unchanged. Options: `-RunId`, `-AllRuns`, `-NonInteractive`, `-ManifestPath`, `-ConfirmPreservedEvidenceRemoval`.

`verify-zero-cost.ps1` is read-only. It prints `nothing billable remaining` and exits 0, or lists what remains and exits 1. If something could not be read, the result is unverified (exit 1); it never claims a clean subscription when it could not look. `-Json` prints one JSON document.

## Safety

- Run with `-WhatIf` first (the blocker scripts are dry-run unless you pass `-Execute`).
- The scripts never assign roles to the operator. The only role assignments they make are for identities they create.
- A resource without the lab tag is never modified or deleted.
- The leaked credential is a separate read-only identity. Use it only in an isolated lab subscription.
- Secrets are never printed; the built-in masker hides them.
