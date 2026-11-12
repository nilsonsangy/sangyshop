# Azure VM lab (Deploy_VM_Azure)

Deploys the **deliberately vulnerable** SangyShop (`APP_MODE=vulnerable`, all defenses
off, `DB_BACKEND=pg`) to an Azure VM for the Azure incident-response lab, and removes
everything afterwards.

> **Security warning.** SangyShop is intentionally vulnerable. Use a throwaway
> subscription, keep ingress limited to your own single IPv4 address (`/32`) and run
> `teardown.ps1` when the lab ends. These resources are billable.

## What it creates

All resources live in the lab resource group (Grupo_Recursos_Lab) except the evidence
group. Everything that accepts tags gets `lab=sangyshop-lab-azure`, `run-id=<RunId>` and
`component=<...>`. Every resource is also recorded in the Manifesto_Lab
(`$HOME/.sangyshop-lab/manifest-sangyshop-lab-azure.json`, or `$env:LAB_MANIFEST_PATH`).

| Resource | Purpose |
|---|---|
| Resource groups (lab, evidence) | Lab resources / future evidence storage |
| VNet, subnet, NSG, static public IP | NSG allows ports 3000 and 22 only from your `/32` |
| User-assigned managed identity | Identity of the VM |
| Key Vault (Azure RBAC) + secret `db-password` | Generated password (32 chars), never printed |
| PostgreSQL Flexible Server (Burstable) | Firewall rule for the VM public IP only |
| Storage Account + Blob container | App media; shared-key access disabled |
| Role assignments | Storage Blob Data Contributor (container), Key Vault Secrets User (vault) |
| Log Analytics workspace, table `SangyShopApp_CL`, DCR | App logs for the detection lab |
| VM (Ubuntu 22.04) + Azure Monitor Agent extension + DCR association | Runs Docker and the app |

The VM boots with `cloud-init.yaml.tpl`: installs Docker, reads the password from Key
Vault with its managed identity, builds the SangyShop image from the repository and runs
it with `--log-driver syslog`. rsyslog writes the JSON log lines to
`/var/log/sangyshop/app.log`, which the DCR sends to `SangyShopApp_CL`.

## Prerequisites

- Windows PowerShell 5.1+ and the Azure CLI, logged in to your own subscription
  (`az login`, then `az account show` must show it).
- `ops/cloud.config.ps1` with `Azure.Location` and an `Azure.Vm` section
  (`VmSize`, `PgSku`, `PgStorageGb`, `ResourceGroupBase`, `EvidenceGroupBase`); see
  `ops/cloud.config.example.ps1`. Copy it and fill in your values. No secrets in it.
- The DCR commands may need the CLI extension; allow automatic install once:
  `az config set extension.use_dynamic_install=yes_without_prompt`.

## Order of use

1. `deploy.ps1 -AllowedSourceRanges <your-ip>/32` (try `-WhatIf` first).
2. Work in the lab. At the end of each day run `stop-lab.ps1`; next day `start-lab.ps1`.
3. When finished run `teardown.ps1`, then confirm nothing billable remains.

## Scripts and parameters

Every external command is printed before it runs (`> az ...`). Messages are in English.

### `deploy.ps1`

| Parameter | Meaning |
|---|---|
| `-AllowedSourceRanges` | **Required.** Single IPv4 hosts in `/32` form. `0.0.0.0/0`, `::/0`, `*`, `Internet`, `Any`, missing or non-`/32` values abort with exit code 1 before any resource is created. |
| `-ConfigPath` | Config file (default `ops/cloud.config.ps1`). |
| `-WhatIf` | Print the ordered command list, create nothing, write no manifest, exit 0. |
| `-ReuseExisting` | Allow re-running against an existing lab resource group (otherwise deploy aborts if it exists). |
| `-RunId` | Run identifier `yyyyMMddTHHmmssZ-xxxx` (default: generated). |
| `-Repo` / `-RepoUrl` | `github` (default, public SangyShop URL) or `azure-repos` (then `-RepoUrl` is required; the URL must not embed a token). |
| `-SshPublicKeyPath` | Optional SSH key for `azureuser`; otherwise `--generate-ssh-keys` creates one under `~/.ssh` if missing. |
| `-NoLabMode` | Start the app without `LAB_MODE=1`. |

If a resource fails to be created, the script exits with code 1 and prints, on stderr,
the name of the failed resource and the list of resources already created; remove them
with `teardown.ps1`.

### `teardown.ps1`

`[-ConfigPath] [-WhatIf] [-RunId]`. Removes, in order: Microsoft Sentinel (if enabled),
the Log Analytics workspace (permanent delete), the lab resource group, the soft-deleted
Key Vault (purged unless purge protection forbids it, in which case it says so and
prints the scheduled purge date), and the `sp-lab-leaked` service principal. It refuses
to delete a group that lacks the `lab=sangyshop-lab-azure` tag. It exits 0 **only** when
`az group exists` returns `false`. Re-running is safe: it prints "Nothing to remove" and
exits 0. Failed removals are listed on stderr (type and id), other removals continue and
the exit code is non-zero. The evidence group is left to the Full_Teardown_Azure.

### `stop-lab.ps1` / `start-lab.ps1`

`[-ConfigPath] [-RunId] [-WhatIf] [-NonInteractive]`. Stop deallocates the VM and stops
the PostgreSQL server (nothing is deleted); start resumes PostgreSQL first, then the VM.
They warn that Azure restarts a stopped Flexible Server automatically after the period in
the current documentation (7 days at the time of writing, confirm on the execution date),
that disks and the public IP stay billed, and that stopping does not replace teardown.

## Example (fictitious identifiers)

```powershell
cd ops\azure\vm
.\deploy.ps1 -AllowedSourceRanges 203.0.113.10/32 -WhatIf     # review the plan
.\deploy.ps1 -AllowedSourceRanges 203.0.113.10/32             # create
# ... SangyShop (vulnerable): http://198.51.100.20:3000 ...
.\stop-lab.ps1 -NonInteractive                                # end of the day
.\start-lab.ps1 -NonInteractive                               # next morning
.\teardown.ps1 -WhatIf
.\teardown.ps1                                                # ... ends with: Teardown complete: 'az group exists' returned false.
```

Expected tail of a successful teardown on a clean subscription:
`Nothing to remove: no lab resources remain.` (exit code 0).

## Notes

- `VmNames.ps1` holds the resource naming shared by the four scripts. Names that must be
  globally unique append `UniqueSuffix` from the config.
- The DB password is never a command-line argument: it goes to Key Vault with
  `--file` and to PostgreSQL with `@file`, and the VM reads it from Key Vault at boot.
- The AMA agent and the DCR are Azure resources, so `deploy.ps1` installs the
  `AzureMonitorLinuxAgent` extension and the DCR association after the VM exists;
  cloud-init prepares the log file they read. Fallback if the custom table is not
  available: query the `Syslog` table with `ProcessName == "sangyshop"`.
- Prices and the PostgreSQL auto-restart period change; confirm them on the execution
  date.
