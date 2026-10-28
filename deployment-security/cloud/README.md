# SangyShop multi-cloud deploy

PowerShell scripts that deploy the **hardened** SangyShop image to AWS, Azure, and GCP. Every
external cloud command is echoed before it runs, every deploy has a matching teardown, and nothing
touches your cloud account until you explicitly run a deploy without `-WhatIf`.

> SangyShop is a deliberately vulnerable teaching application. The hardened variant is still intended
> for isolated, throwaway cloud accounts only. See the **Cost & teaching-lab safety** section at the
> bottom before you deploy anything.

## Overview

There are **six deploy targets**: three clouds, each in two modalities.

| Cloud | Docker-only (managed container service) | Kubernetes (managed K8s) |
| ----- | --------------------------------------- | ------------------------ |
| GCP   | Cloud Run                               | GKE                      |
| AWS   | ECS Fargate                             | EKS                      |
| Azure | Azure Container Instances (ACI)         | AKS                      |

Every target:

- Deploys **only** the hardened SangyShop image (`:hardened`, `APP_MODE=hardened`), built from
  `deployment-security/docker/hardened/Dockerfile`. The intentionally insecure variant is never
  built, pushed, or deployed.
- Provisions the cloud's **managed** PostgreSQL (Cloud SQL / RDS / Flexible Server) — never a
  Postgres container.
- Generates a DB password at deploy time, stores it only in the cloud's secret manager, and delivers
  it to the container as the file `/run/secrets/db_password` (never a `DB_PASSWORD` env var).
- Ships as a pair of scripts: `deploy.ps1` and `teardown.ps1`.

## Prerequisites

Install these once on your Windows machine. Each row lists a verification command you can run to
confirm the tool is present.

| Tool | Needed for | Minimum version | Verify |
| ---- | ---------- | --------------- | ------ |
| Windows PowerShell | all scripts | 5.1 (or PowerShell 7+) | `$PSVersionTable.PSVersion` |
| Docker Desktop | building/pushing the image (all targets) | 20.10+ | `docker --version` |
| `kubectl` | the Kubernetes targets (GKE/EKS/AKS) | 1.27+ | `kubectl version --client` |
| Pester | running the test suite | 5.x | `Get-Module -ListAvailable Pester` |
| `gcloud` | GCP targets | latest | `gcloud --version` |
| `aws` | AWS targets | v2 | `aws --version` |
| `az` | Azure targets | latest | `az --version` |

You only need the CLI for the cloud(s) you actually deploy to.

### Install the cloud CLIs (Windows)

```powershell
# GCP CLI (Google Cloud SDK)
#   Download the installer from https://cloud.google.com/sdk/docs/install and run it, then:
gcloud --version

# AWS CLI v2
msiexec /i https://awscli.amazonaws.com/AWSCLIV2.msi
aws --version

# Azure CLI
winget install -e --id Microsoft.AzureCLI
az --version
```

### Install Pester 5.x

The library unit tests, the echo-only guard, and all the `-WhatIf` dry-run tests run on Pester 5.x. If
`Get-Module -ListAvailable Pester` does not show a 5.x version, install it:

```powershell
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

## Authentication

Authenticate each CLI to **your own** isolated/throwaway account before deploying. These scripts run
an auth check at the start of every deploy and stop with guidance if you are not signed in.

### GCP

```powershell
gcloud auth login                 # sign in to your Google account
gcloud auth configure-docker      # let Docker push to Artifact Registry
gcloud config set project <your-gcp-project-id>
```

The GCP project must have **billing enabled** and the required APIs enabled:

```powershell
gcloud services enable `
  artifactregistry.googleapis.com `
  run.googleapis.com `
  sqladmin.googleapis.com `
  secretmanager.googleapis.com `
  container.googleapis.com
```

### AWS

```powershell
aws configure                     # static access keys + default region, OR:
aws sso login                     # if your org uses IAM Identity Center (SSO)
aws sts get-caller-identity       # confirm you are authenticated
```

### Azure

```powershell
az login                          # opens a browser to sign in
az account show                   # confirm the active subscription
```

## Configuration

Per-user values live in a **git-ignored** config file. Copy the committed template and fill it in:

```powershell
Copy-Item deployment-security/cloud/cloud.config.example.ps1 `
          deployment-security/cloud/cloud.config.ps1
```

`cloud.config.ps1` is listed in `.gitignore`, so your account details never enter version control.
Edit it and set the values for the cloud(s) you will use:

**Globally-unique suffix (required):**

- `UniqueSuffix` — 3–24 **lowercase letters/digits only**. Appended to names that must be unique
  across the entire cloud (Azure Container Registry, Azure Key Vault, GCP bucket-like names). Pick
  something unlikely to collide, e.g. your initials plus a few digits.

**Common (shared, safe defaults):**

- `AppName`, `DbName`, `DbUser`, `ImageTag` — usually left as-is. `ImageTag` is `hardened`; only the
  hardened variant is ever deployed.

**GCP:**

- `Gcp.ProjectId` — your GCP project id
- `Gcp.Region`, `Gcp.ArRepo`, `Gcp.CloudRunName`, `Gcp.GkeCluster`

**AWS:**

- `Aws.Region`, `Aws.AccountId` (12-digit), `Aws.EcrRepo`, `Aws.EcsCluster`, `Aws.EksCluster`

**Azure:**

- `Azure.Location`, `Azure.ResourceGroup`, `Azure.AcrNameBase`, `Azure.KeyVaultBase`,
  `Azure.AciName`, `Azure.AksCluster`

The loader (`Get-CloudConfig` in `lib/Common.ps1`) validates this before any external command runs: a
missing, empty, or whitespace-only required key stops the run and names the key, and an invalid
`UniqueSuffix` is rejected up front.

### The secret-free config contract

`cloud.config.ps1` **must not contain any password, access key, token, or connection string.** This
is a hard rule the loader enforces.

- The DB password is **generated at deploy time** (random, ≥24 chars, mixed character classes).
- It is stored **only** in the cloud's secret manager (GCP Secret Manager / AWS Secrets Manager /
  Azure Key Vault).
- It is delivered to the running container as the file **`/run/secrets/db_password`** — never as a
  `DB_PASSWORD` environment variable, never written to a committed file, an echoed command line, or a
  log.
- Cloud CLI credentials come from your authenticated CLI session, not from the config file.

### The echo-only rule

Every external CLI call (`aws`, `az`, `gcloud`, `kubectl`, `docker`) is **echoed to stdout before it
runs**, through the single shared helper `Invoke-Echoed` in `lib/Common.ps1`. The printed line is
quoted/escaped so you can copy any single command and run it by hand. A Pester guard
(`tests/EchoOnly.Guard.Tests.ps1`) scans every `deploy.ps1`/`teardown.ps1` and fails if any of those
executables is invoked outside `Invoke-Echoed`.

## How to run

**Always dry-run first.** Every script accepts `-WhatIf`, which prints the full ordered list of
commands it would run and executes **nothing** (exit 0). Review that list, then run for real.

Shared parameters:

- `deploy.ps1`: `-ConfigPath`, `-WhatIf`, `-ReuseExisting`, `-AllowedSourceRanges` (**required** for a
  real deploy)
- `teardown.ps1`: `-ConfigPath`, `-WhatIf`, `-Force`, `-KeepRegistry`

`-AllowedSourceRanges` locks ingress to the source addresses/CIDRs you provide. The ranges `0.0.0.0/0`
and `::/0` are **rejected**; if you omit the set entirely the deploy stops before touching ingress.
Set it to your own public IP, e.g. `@('203.0.113.4/32')`.

`-ConfigPath` defaults to `deployment-security/cloud/cloud.config.ps1`, so you can usually omit it.

When you are done, run the matching `teardown.ps1` so no billable resource is left behind.
`teardown.ps1` is convergent — re-running it is safe and skips anything already gone. `-KeepRegistry`
preserves the image registry; `-Force` skips the interactive confirmation.

### GCP

```powershell
# Cloud Run (Docker-only)
./gcp/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf   # dry run
./gcp/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')           # deploy
./gcp/docker/teardown.ps1 -WhatIf                                          # dry run
./gcp/docker/teardown.ps1 -Force                                           # tear down

# GKE (Kubernetes)
./gcp/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./gcp/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./gcp/kubernetes/teardown.ps1 -Force
```

### AWS

```powershell
# ECS Fargate (Docker-only)
./aws/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./aws/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./aws/docker/teardown.ps1 -Force

# EKS (Kubernetes)
./aws/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./aws/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./aws/kubernetes/teardown.ps1 -Force
```

### Azure

```powershell
# Azure Container Instances (Docker-only)
./azure/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./azure/docker/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./azure/docker/teardown.ps1 -Force

# AKS (Kubernetes)
./azure/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./azure/kubernetes/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./azure/kubernetes/teardown.ps1 -Force
```

## How to run the tests

The library unit tests, the echo-only guard, and every `-WhatIf` dry-run test run on Windows without
any cloud account:

```powershell
Invoke-Pester -Path deployment-security/cloud/tests
```

## Directory map

```
deployment-security/cloud/
├── README.md                       # this guide
├── cloud.config.example.ps1        # committed config template (copy this)
├── cloud.config.ps1                # your git-ignored config (you create it)
├── lib/
│   └── Common.ps1                  # Invoke-Echoed, Write-Step, Get-CloudConfig, New-DbPassword
├── aws/
│   ├── docker/                     # ECS Fargate deploy.ps1 + teardown.ps1 (+ secret entrypoint)
│   └── kubernetes/                 # EKS deploy.ps1 + teardown.ps1
├── azure/
│   ├── docker/                     # ACI deploy.ps1 + teardown.ps1
│   └── kubernetes/                 # AKS deploy.ps1 + teardown.ps1
├── gcp/
│   ├── docker/                     # Cloud Run deploy.ps1 + teardown.ps1
│   └── kubernetes/                 # GKE deploy.ps1 + teardown.ps1
├── manifests/
│   └── overlays/
│       ├── aws/                    # Kustomize overlay: ECR image, LoadBalancer, gp3, secret source
│       ├── azure/                  # Kustomize overlay: ACR image, LoadBalancer, managed-csi, Key Vault CSI
│       └── gcp/                    # Kustomize overlay: AR image, LoadBalancer, standard-rwo, Secret Manager CSI
└── tests/                          # Pester unit tests, echo-only guard, and -WhatIf dry-run tests
```

<!-- =========================================================================
     Cost & teaching-lab safety (task 14.2) goes below this line.
     ========================================================================= -->

## Cost & teaching-lab safety

Read this section before you deploy anything. Every target provisions **billable managed cloud
resources**, and SangyShop is a **deliberately vulnerable** teaching app — the two facts together mean
a forgotten deployment is both a running bill and an exposed known-vulnerable target.

### ⚠️ Cost warning — these targets cost real money

Each deploy creates managed resources that bill **for as long as they exist**, whether or not anyone is
using them:

- **Managed PostgreSQL** — Cloud SQL (GCP), RDS (AWS), Azure DB for PostgreSQL Flexible Server. This is
  the big one: a managed database instance bills **per hour the moment it is created and keeps billing
  until you delete it**, idle or not.
- **Container runtime** — Cloud Run (GCP), ECS Fargate (AWS), Azure Container Instances (Azure).
- **Managed Kubernetes control plane** — GKE / EKS / AKS each bill a **per-cluster-hour** control-plane
  fee on top of the worker nodes, for the Kubernetes targets.
- **Load balancer** — the public ingress each target provisions bills per hour plus traffic.
- **Container registry** — ECR / ACR / Artifact Registry charge for stored image layers.
- **Secret storage** — Secrets Manager / Key Vault / Secret Manager charge per secret and per access.

Leaving any of these running **accrues real charges around the clock**. Skipping teardown does not pause
billing — the resources keep costing money until they are removed.

### Teardown is mandatory

Run the matching `teardown.ps1` **as soon as you finish** with a target. Teardown is not optional
cleanup; it is the step that stops the bill.

- It removes resources in **reverse dependency order** (compute → managed PostgreSQL → stored DB
  password → registry), the inverse of how the deploy created them.
- It is **convergent**: re-running it is always safe. Anything already deleted is skipped and treated as
  success, so a second run exits clean.
- It **reports what it removed**, and if something could not be removed it writes that resource to
  stderr and exits non-zero — so a non-zero teardown means "check these by hand," not "try again blindly."

Useful switches:

- `-WhatIf` — dry-run the teardown first; prints the ordered command list and deletes nothing.
- `-Force` — skip the interactive confirmation. On **Azure**, `-Force` also enables the resource-group
  catch-all (`az group delete`) that sweeps the whole group as a backstop.
- `-KeepRegistry` — keep the image registry (and its pushed layers) so a later redeploy can reuse the
  image instead of rebuilding and repushing.

```powershell
# Example: tear down the GCP Cloud Run target, keeping the registry
./gcp/docker/teardown.ps1 -KeepRegistry -Force

# Azure: full sweep including the resource group
./azure/docker/teardown.ps1 -Force
```

After teardown, **open the cloud console and confirm nothing remains** — especially the managed
PostgreSQL instance and the load balancer, the two most expensive leftovers. Teardown reports what it
did, but a quick console check is the only way to be certain the account is empty.

### Teaching-lab safety

SangyShop is **deliberately vulnerable by design**. The hardened image only improves the *deployment*
posture (secret-as-file, non-root, locked ingress); it does **not** remove the application's
intentional flaws. Treat every deployment as a live, exploitable target:

- **Isolated, throwaway account only.** Deploy exclusively to a cloud account / project / subscription
  that contains **no other workloads and no real data**. Never deploy to a shared or production
  environment.
- **Lock ingress to your own IP.** Always pass `-AllowedSourceRanges` with your own public address
  (e.g. `@('203.0.113.4/32')`). The wildcard ranges `0.0.0.0/0` and `::/0` are **rejected**, and
  omitting the set entirely stops the deploy before it touches ingress. Never expose this app to the
  public internet.
- **No real data.** Do not store real, personal, or sensitive data in a SangyShop deployment — assume
  anything you put in it can be read by an attacker.
- **Tear it down promptly.** The shorter it lives, the smaller both the bill and the exposure window.

### Quick checklist

1. **Authenticate** the right CLI to your **isolated, throwaway** account (see *Authentication* above).
2. **Configure** `cloud.config.ps1` from the template and fill in your values.
3. **Dry-run** the deploy with `-WhatIf` and review the ordered command list.
4. **Deploy** for real with `-AllowedSourceRanges @('<your-ip>/32')` locked to your own IP.
5. **Use** the deployment briefly, with no real data in it.
6. **Tear down** with the matching `teardown.ps1` the moment you are done.
7. **Verify** in the cloud console that the account is empty — no managed PostgreSQL, no load balancer,
   nothing left billing.

_Requirements: 8.5, 8.6, 9.1, 9.2, 9.3 (teaching-lab cost/safety guidance)._
