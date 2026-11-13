# Deployment Security: insecure vs hardened

SangyShop teaches the OWASP Top 10 at the **application** layer. This folder adds the
**deployment** layer: the same application, shipped two ways, so you can *see* what
container and orchestration hardening actually changes.

The idea mirrors the app's Defenses panel, **run it insecure, then run it hardened,
and compare**, but applied to how the app is packaged and run:

- **`docker/`**: the same image run **insecure** (the repo's default build, `sangyshop:insecure`)
  vs a **hardened** one (`docker/hardened/`).
- **`kubernetes/`**: the same app deployed with an **insecure** manifest set vs a
  **hardened** one (RBAC, Network Policies, Pod Security Standards, managed secrets, limits).

> **Warning.** SangyShop is deliberately vulnerable. Run everything here **only in an
> isolated environment** (your laptop / a VM / WSL / a throwaway local cluster), **never**
> exposed to the internet.

## Why two versions of the same app?

The application code is **identical** on both sides. The only thing that changes is the
*deployment posture*. So any difference a scanner, a benchmark or a runtime monitor reports
comes purely from how the app was built and run, which makes the effect of each hardening
measure measurable instead of abstract.

## What you can try

With free, open tools you can measure the difference between the two sides:

| Layer | Tooling (examples) | What the hardened side improves |
|---|---|---|
| Image / dependencies | Trivy, Grype, OSV-Scanner, Snyk | fewer known CVEs; non-root; smaller attack surface |
| Container runtime | the `docker run` flags themselves; Falco | no `--privileged`, dropped capabilities, read-only FS |
| Cluster config | kube-bench (CIS), kube-hunter | fewer FAILs; least-privilege RBAC; admission control |
| Cluster inventory | Trivy KBOM (`trivy k8s`) | visibility into component CVEs |
| Cluster runtime | Falco (DaemonSet) | real-time detection of suspicious behavior |

## Layout

```
(repo root)      Dockerfile + docker-compose.yml   -> sangyshop:insecure  (default, vulnerable)
ops/
  docker/
    hardened/    Dockerfile + docker-compose.yml + seccomp.json -> sangyshop:hardened
  kubernetes/
    insecure/    sangyshop-insecure.yaml
    hardened/    sangyshop-hardened.yaml
    kube-bench/  job-master.yaml + job-node-worker{1,2}.yaml -> CIS audit of the cluster/nodes
    cluster-setup.md
```

The **insecure** variant is the repo's default build at the root (`docker compose up -d --build`
produces `sangyshop:insecure`). The **hardened** counterpart lives in `docker/hardened/`. Each
subfolder has its own README explaining the specific risks and the matching countermeasures.
Build the insecure baseline from the root, then move to `docker/hardened/` and `kubernetes/`.

## A note on the app and a read-only filesystem

SangyShop keeps its data in an in-memory SQLite database (via `sql.js`), so it writes no
database file. It does, however, write two paths at runtime: the Defenses-panel state in `config/defenses.json`
and a `logs/` directory. The hardened examples mount **only those two paths** as writable and
keep the rest of the root filesystem read-only, a realistic "least writable surface" setup.

## Environment variables for the cloud incident-response labs

These variables are optional and default to the previous behavior. Cloud credentials are never
required locally (Docker Compose runs with `OBJECT_STORE=none`). In the cloud, prefer an attached
role or managed identity over static access keys.

| Variable | Default | Description |
|---|---|---|
| `STRUCTURED_LOGS` | `on` | JSON access and login logs on stdout (collected by CloudWatch / Azure Monitor). `off` disables them. |
| `OBJECT_STORE` | `none` | `none`, `s3` or `azure-blob`. Selects the backend for the `/media` routes. |
| `S3_BUCKET` | - | S3 bucket name (`OBJECT_STORE=s3`). |
| `AWS_REGION` | - | AWS region (`OBJECT_STORE=s3`). |
| `AZURE_STORAGE_ACCOUNT` | - | Azure storage account name (`OBJECT_STORE=azure-blob`). |
| `AZURE_STORAGE_CONTAINER` | - | Azure blob container name (`OBJECT_STORE=azure-blob`). |
| `LAB_MODE` | unset | `1` enables the lab routes. Ignored when `APP_MODE=hardened`, so the hardened image never exposes them. |
| `LAB_CLOUD` | unset | Cloud label shown by `/.well-known/sangyshop-lab`. |
| `LAB_LEAKED_FILE` | `/lab/leaked.json` | File returned by `/debug/config` in the lab. |

## Incident response labs (AWS and Azure)

The incident response lab scripts live in this repository, next to the deploy scripts:

```
ops/aws/ir-lab/       # AWS: detection stack, blocker, leaked credential, readiness check, teardown
ops/azure/ir-lab/     # Azure: the same flow for Azure
ops/aws/iam/          # lab IAM group and least-privilege policy templates
```

Generic incident response tools (evidence collection, containment, instance isolation) are not
part of this repository. They live in NimbusDFIR, a separate project.

### The four steps

1. **Deploy** the vulnerable lab: `ops/aws/ec2/deploy.ps1` or `ops/azure/vm/deploy.ps1`.
2. **Enable detection**: `ops/aws/ir-lab/detection/enable-all.ps1` (Azure: `ops/azure/ir-lab/detection/enable-all.ps1`).
   Confirm the e-mail subscription that AWS or Azure sends to the alert address.
3. **Check readiness**: `check-detection-ready.ps1`. It writes the readiness stamp that
   `attack-simulation/attack.js` requires (see `attack-simulation/README.md`).
4. **Attack, then respond**: run `attack-simulation/attack.js`, then `print-response-commands.ps1`
   to print the NimbusDFIR commands for the response.

`verify-lab-state.ps1` (AWS) is a read-only report of which detection components exist.
`full-teardown.ps1` and `verify-zero-cost.ps1` remove the whole lab and confirm nothing billable remains.
See `ops/aws/ir-lab/README.md` and `ops/azure/ir-lab/README.md` for the full walk-through.

### Alert e-mail (`ops/.env`)

The detection scripts need an address for the alerts. It is never stored in the repository.

```powershell
Copy-Item ops/.env.example ops/.env
# edit ops/.env and set: LAB_ALERT_EMAIL=you@example.com
```

`ops/.env` is ignored by Git. The address is resolved in this order: the `-Email` parameter, the
`LAB_ALERT_EMAIL` environment variable, then `ops/.env`. Values already present in the environment are
not overridden by the file. An invalid or missing address stops the script before anything is created.

### Finding NimbusDFIR (`NIMBUSDFIR_PATH`)

The checkout is never guessed and sibling folders are never searched. The path comes from one of
these, in this order:

1. the `-NimbusDfirPath` parameter of the script
2. the `NIMBUSDFIR_PATH` environment variable
3. `Common.NimbusDfirPath` in `ops/cloud.config.ps1`

```powershell
$env:NIMBUSDFIR_PATH = 'C:\path\to\NimbusDFIR'
```

A folder counts as a checkout only if it contains `ir_lab_core\__init__.py` and
`aws\ec2_evidence_preservation.py`. Without a valid path, `print-response-commands.ps1` still prints
the commands, with a placeholder for the checkout folder.

### AWS permissions: the lab IAM group

An IAM user can have at most 10 managed policies attached directly, and the lab services need more
than that. Attach the policies to the lab group `sangyshop-lab-group` instead (quota of 10 per group)
and add your user to it:

```powershell
./ops/aws/iam/ensure-lab-group.ps1 -WhatIf          # review
./ops/aws/iam/ensure-lab-group.ps1                  # create or update the group and 3 minimal policies
./ops/aws/iam/ensure-lab-group.ps1 -AddUser <your-iam-user>
```

Details and the safety properties of the templates are in `ops/aws/iam/README.md`. The scripts never
grant themselves permissions. When a call is denied, they stop with exit code 3 and name the exact
policy or role to ask for. The tables below are the same ones the scripts print.

| AWS service | Managed policy | Used for |
|---|---|---|
| EC2 | `AmazonEC2FullAccess` | network, AMI, flow logs |
| S3 | `AmazonS3FullAccess` | application and trail buckets |
| RDS | `AmazonRDSFullAccess` | lab database |
| CloudWatch Logs | `CloudWatchLogsFullAccess` | log groups, metric filter |
| CloudWatch | `CloudWatchFullAccessV2` | alarms |
| SNS | `AmazonSNSFullAccess` | alert topic and subscription |
| CloudTrail | `AWSCloudTrail_FullAccess` | trail |
| GuardDuty | `AmazonGuardDutyFullAccess_v2` | detector |
| EventBridge | `AmazonEventBridgeFullAccess` | blocker rule |
| Lambda | `AWSLambda_FullAccess` | blocker function |
| Systems Manager | `AmazonSSMReadOnlyAccess` (reads), `AmazonSSMFullAccess` (SendCommand) | reads need the read only policy; SendCommand needs `lab-core.json` (preferred) or the full policy; an AMI fallback exists |
| Secrets Manager | `SecretsManagerReadWrite` | database secret |
| KMS | `AWSKeyManagementServicePowerUser` | keys for RDS and secrets |
| IAM | none fits; use `lab-iam-scoped.json` | roles and profiles named `sangyshop-*` |

| Azure area | Built-in role | Scope |
|---|---|---|
| Resource groups, PostgreSQL, ACR, AKS, ACI | `Contributor` | lab resource group |
| Virtual machines | `Virtual Machine Contributor` | lab resource group |
| Networking | `Network Contributor` | lab resource group |
| Storage | `Storage Account Contributor` | lab resource group |
| Key Vault | `Key Vault Contributor`, `Key Vault Secrets Officer` | lab resource group |
| Managed identity | `Managed Identity Contributor` | lab resource group |
| Monitor, alerts, diagnostics | `Monitoring Contributor` | lab resource group |
| Log Analytics | `Log Analytics Contributor` | lab resource group |
| Sentinel | `Microsoft Sentinel Contributor` | lab resource group |
| Logic App (blocker) | `Logic App Contributor` | lab resource group |
| Azure Policy | `Resource Policy Contributor` | lab resource group |
| Role assignments (blocker) | `Role Based Access Control Administrator` or `User Access Administrator` | lab resource group, never the subscription |
| Defender for Cloud | `Security Admin` | subscription |
| Subscription reads | `Reader` | subscription |

### Exit codes of the lab scripts

| Code | Meaning | What to do |
|---|---|---|
| 0 | Done (for `check-detection-ready.ps1`: ready, stamp written) | Continue with the next step. |
| 1 | A component is missing or not usable (AWS; on Azure this case is code 4) | Run the script it names, then run the check again. |
| 2 | Configuration problem (no region, bad config, invalid e-mail) | Fix `ops/cloud.config.ps1` or `ops/.env`. |
| 3 | Permission missing | Attach the policy or role named in the message, then run the same script again. |
| 4 | A precondition is blocked (e-mail not confirmed, detection not ready on Azure, attack evidence not found, application log group missing) | Do the step the message names, then run the script again. |

### Preflight and existing infrastructure

Before creating anything, the detection scripts read the account (read-only) and classify each
resource type. Anything that already exists and was not created by the lab, such as a multi-region
management trail, is reused and never modified. Teardown removes only what the lab created and lists
the rest as `kept (not created by the lab)`.

---

<!-- Multi-cloud deploy guide, merged into this file -->

## SangyShop multi-cloud deploy

PowerShell scripts that deploy the **hardened** SangyShop image to AWS, Azure, and GCP. Every
external cloud command is echoed before it runs, every deploy has a matching teardown, and nothing
touches your cloud account until you explicitly run a deploy without `-WhatIf`.

> SangyShop is a deliberately vulnerable teaching application. The hardened variant is still intended
> for isolated, throwaway cloud accounts only. See the **Cost & teaching-lab safety** section at the
> bottom before you deploy anything.

### Overview

There are **six deploy targets**: three clouds, each in two modalities.

| Cloud | Docker-only (managed container service) | Kubernetes (managed K8s) |
| ----- | --------------------------------------- | ------------------------ |
| GCP   | Cloud Run                               | GKE                      |
| AWS   | ECS Fargate                             | EKS                      |
| Azure | Azure Container Instances (ACI)         | AKS                      |

Every target:

- Deploys **only** the hardened SangyShop image (`:hardened`, `APP_MODE=hardened`), built from
  `ops/docker/hardened/Dockerfile`. The intentionally insecure variant is never
  built, pushed, or deployed.
- Provisions the cloud's **managed** PostgreSQL (Cloud SQL / RDS / Flexible Server), never a
  Postgres container.
- Generates a DB password at deploy time, stores it only in the cloud's secret manager, and delivers
  it to the container as the file `/run/secrets/db_password` (never a `DB_PASSWORD` env var).
- Ships as a pair of scripts: `deploy.ps1` and `teardown.ps1`.

### Prerequisites

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

#### Install the cloud CLIs (Windows)

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

#### Install Pester 5.x

The library unit tests, the echo-only guard, and all the `-WhatIf` dry-run tests run on Pester 5.x. If
`Get-Module -ListAvailable Pester` does not show a 5.x version, install it:

```powershell
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

### Authentication

Authenticate each CLI to **your own** isolated/throwaway account before deploying. These scripts run
an auth check at the start of every deploy and stop with guidance if you are not signed in.

#### GCP

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

#### AWS

```powershell
aws configure                     # static access keys + default region, OR:
aws sso login                     # if your org uses IAM Identity Center (SSO)
aws sts get-caller-identity       # confirm you are authenticated
```

#### Azure

```powershell
az login                          # opens a browser to sign in
az account show                   # confirm the active subscription
```

### Configuration

Per-user values live in a **git-ignored** config file. Copy the committed template and fill it in:

```powershell
Copy-Item ops/cloud.config.example.ps1 `
          ops/cloud.config.ps1
```

`cloud.config.ps1` is listed in `.gitignore`, so your account details never enter version control.
Edit it and set the values for the cloud(s) you will use:

**Globally-unique suffix (required):**

- `UniqueSuffix`: 3-24 **lowercase letters/digits only**. Appended to names that must be unique
  across the entire cloud (Azure Container Registry, Azure Key Vault, GCP bucket-like names). Pick
  something unlikely to collide, e.g. your initials plus a few digits.

**Common (shared, safe defaults):**

- `AppName`, `DbName`, `DbUser`, `ImageTag`, usually left as-is. `ImageTag` is `hardened`; only the
  hardened variant is ever deployed.

**GCP:**

- `Gcp.ProjectId`: your GCP project id
- `Gcp.Region`, `Gcp.ArRepo`, `Gcp.CloudRunName`, `Gcp.GkeCluster`

**AWS:**

- `Aws.Region`, `Aws.AccountId` (12-digit), `Aws.EcrRepo`, `Aws.EcsCluster`, `Aws.EksCluster`

**Azure:**

- `Azure.Location`, `Azure.ResourceGroup`, `Azure.AcrNameBase`, `Azure.KeyVaultBase`,
  `Azure.AciName`, `Azure.AksCluster`

The loader (`Get-CloudConfig` in `lib/Common.ps1`) validates this before any external command runs: a
missing, empty, or whitespace-only required key stops the run and names the key, and an invalid
`UniqueSuffix` is rejected up front.

#### The secret-free config contract

`cloud.config.ps1` **must not contain any password, access key, token, or connection string.** This
is a hard rule the loader enforces.

- The DB password is **generated at deploy time** (random, ≥24 chars, mixed character classes).
- It is stored **only** in the cloud's secret manager (GCP Secret Manager / AWS Secrets Manager /
  Azure Key Vault).
- It is delivered to the running container as the file **`/run/secrets/db_password`**, never as a
  `DB_PASSWORD` environment variable, never written to a committed file, an echoed command line, or a
  log.
- Cloud CLI credentials come from your authenticated CLI session, not from the config file.

#### The echo-only rule

Every external CLI call (`aws`, `az`, `gcloud`, `kubectl`, `docker`) is **echoed to stdout before it
runs**, through the single shared helper `Invoke-Echoed` in `lib/Common.ps1`. The printed line is
quoted/escaped so you can copy any single command and run it by hand. A Pester guard
(`tests/EchoOnly.Guard.Tests.ps1`) scans every `deploy.ps1`/`teardown.ps1` and fails if any of those
executables is invoked outside `Invoke-Echoed`.


### How to run

**Always dry-run first.** Every script accepts `-WhatIf`, which prints the full ordered list of
commands it would run and executes **nothing** (exit 0). Review that list, then run for real.

Shared parameters:

- `deploy.ps1`: `-ConfigPath`, `-WhatIf`, `-ReuseExisting`, `-AllowedSourceRanges` (**required** for a
  real deploy)
- `teardown.ps1`: `-ConfigPath`, `-WhatIf`, `-Force`, `-KeepRegistry`

`-AllowedSourceRanges` locks ingress to the source addresses/CIDRs you provide. The ranges `0.0.0.0/0`
and `::/0` are **rejected**; if you omit the set entirely the deploy stops before touching ingress.
Set it to your own public IP, e.g. `@('203.0.113.4/32')`.

`-ConfigPath` defaults to `ops/cloud.config.ps1`, so you can usually omit it.

When you are done, run the matching `teardown.ps1` so no billable resource is left behind.
`teardown.ps1` is convergent, re-running it is safe and skips anything already gone. `-KeepRegistry`
preserves the image registry; `-Force` skips the interactive confirmation.

#### GCP

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

#### AWS

```powershell
# ECS Fargate (Docker-only)
./aws/ecs/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./aws/ecs/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./aws/ecs/teardown.ps1 -Force

# EKS (Kubernetes)
./aws/eks/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./aws/eks/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./aws/eks/teardown.ps1 -Force
```

#### Azure

```powershell
# Azure Container Instances (Docker-only)
./azure/aci/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./azure/aci/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./azure/aci/teardown.ps1 -Force

# AKS (Kubernetes)
./azure/aks/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32') -WhatIf
./azure/aks/deploy.ps1 -AllowedSourceRanges @('203.0.113.4/32')
./azure/aks/teardown.ps1 -Force
```

### How to run the tests

The library unit tests, the echo-only guard, and every `-WhatIf` dry-run test run on Windows without
any cloud account:

```powershell
Invoke-Pester -Path ops/tests
```

### Directory map

```
ops/
├── README.md                       # this guide
├── cloud.config.example.ps1        # committed config template (copy this)
├── cloud.config.ps1                # your git-ignored config (you create it)
├── lib/
│   └── Common.ps1                  # Invoke-Echoed, Write-Step, Get-CloudConfig, New-DbPassword
├── .env.example                    # template for ops/.env (alert e-mail), copy it
├── aws/
│   ├── ec2/                        # EC2 + RDS vulnerable lab
│   ├── ecs/                        # ECS Fargate deploy.ps1 + teardown.ps1 (+ secret entrypoint)
│   ├── eks/                        # EKS deploy.ps1 + teardown.ps1 + overlays/ (Kustomize)
│   ├── iam/                        # lab IAM group and policy templates
│   └── ir-lab/                     # AWS incident response lab (detection, blocker, readiness, teardown)
├── azure/
│   ├── aci/                        # ACI deploy.ps1 + teardown.ps1
│   ├── aks/                        # AKS deploy.ps1 + teardown.ps1 + overlays/ (Kustomize)
│   ├── vm/                         # Azure VM vulnerable lab
│   └── ir-lab/                     # Azure incident response lab
├── gcp/
│   ├── docker/                     # Cloud Run deploy.ps1 + teardown.ps1
│   └── kubernetes/                 # GKE deploy.ps1 + teardown.ps1 + overlays/ (Kustomize)
└── tests/                          # Pester unit tests, echo-only guard, and -WhatIf dry-run tests
```

The Kustomize overlays that used to live under a shared `manifests/overlays/` now live inside
each cloud's own Kubernetes folder: `aws/eks/overlays/` (ECR image, LoadBalancer, gp3, secret
source), `azure/aks/overlays/` (ACR image, LoadBalancer, managed-csi, Key Vault CSI), and
`gcp/kubernetes/overlays/` (AR image, LoadBalancer, standard-rwo, Secret Manager CSI).

<!-- =========================================================================
     Cost & teaching-lab safety goes below this line.
     ========================================================================= -->

### Cost & teaching-lab safety

Read this section before you deploy anything. Every target provisions **billable managed cloud
resources**, and SangyShop is a **deliberately vulnerable** teaching app, the two facts together mean
a forgotten deployment is both a running bill and an exposed known-vulnerable target.

#### ⚠️ Cost warning: these targets cost real money

Each deploy creates managed resources that bill **for as long as they exist**, whether or not anyone is
using them:

- **Managed PostgreSQL**: Cloud SQL (GCP), RDS (AWS), Azure DB for PostgreSQL Flexible Server. This is
  the big one: a managed database instance bills **per hour the moment it is created and keeps billing
  until you delete it**, idle or not.
- **Container runtime**: Cloud Run (GCP), ECS Fargate (AWS), Azure Container Instances (Azure).
- **Managed Kubernetes control plane**: GKE / EKS / AKS each bill a **per-cluster-hour** control-plane
  fee on top of the worker nodes, for the Kubernetes targets.
- **Load balancer**: the public ingress each target provisions bills per hour plus traffic.
- **Container registry**: ECR / ACR / Artifact Registry charge for stored image layers.
- **Secret storage**: Secrets Manager / Key Vault / Secret Manager charge per secret and per access.

Leaving any of these running **accrues real charges around the clock**. Skipping teardown does not pause
billing, the resources keep costing money until they are removed.

#### Teardown is mandatory

Run the matching `teardown.ps1` **as soon as you finish** with a target. Teardown is not optional
cleanup; it is the step that stops the bill.

- It removes resources in **reverse dependency order** (compute → managed PostgreSQL → stored DB
  password → registry), the inverse of how the deploy created them.
- It is **convergent**: re-running it is always safe. Anything already deleted is skipped and treated as
  success, so a second run exits clean.
- It **reports what it removed**, and if something could not be removed it writes that resource to
  stderr and exits non-zero, so a non-zero teardown means "check these by hand," not "try again blindly."

Useful switches:

- `-WhatIf`: dry-run the teardown first; prints the ordered command list and deletes nothing.
- `-Force`: skip the interactive confirmation. On **Azure**, `-Force` also enables the resource-group
  catch-all (`az group delete`) that sweeps the whole group as a backstop.
- `-KeepRegistry`: keep the image registry (and its pushed layers) so a later redeploy can reuse the
  image instead of rebuilding and repushing.

```powershell
# Example: tear down the GCP Cloud Run target, keeping the registry
./gcp/docker/teardown.ps1 -KeepRegistry -Force

# Azure: full sweep including the resource group
./azure/docker/teardown.ps1 -Force
```

After teardown, **open the cloud console and confirm nothing remains**, especially the managed
PostgreSQL instance and the load balancer, the two most expensive leftovers. Teardown reports what it
did, but a quick console check is the only way to be certain the account is empty.

#### Teaching-lab safety

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
- **No real data.** Do not store real, personal, or sensitive data in a SangyShop deployment, assume
  anything you put in it can be read by an attacker.
- **Tear it down promptly.** The shorter it lives, the smaller both the bill and the exposure window.

#### Quick checklist

1. **Authenticate** the right CLI to your **isolated, throwaway** account (see *Authentication* above).
2. **Configure** `cloud.config.ps1` from the template and fill in your values.
3. **Dry-run** the deploy with `-WhatIf` and review the ordered command list.
4. **Deploy** for real with `-AllowedSourceRanges @('<your-ip>/32')` locked to your own IP.
5. **Use** the deployment briefly, with no real data in it.
6. **Tear down** with the matching `teardown.ps1` the moment you are done.
7. **Verify** in the cloud console that the account is empty, no managed PostgreSQL, no load balancer,
   nothing left billing.

_Requirements: 8.5, 8.6, 9.1, 9.2, 9.3 (teaching-lab cost/safety guidance)._
