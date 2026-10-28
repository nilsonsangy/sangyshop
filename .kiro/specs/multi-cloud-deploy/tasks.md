# Implementation Plan: multi-cloud-deploy

## Overview

This plan builds the `deployment-security/cloud/` tree of PowerShell deploy/teardown scripts that
deploy the **hardened** SangyShop variant to AWS, Azure, and GCP in two modalities each (Docker-only
managed container service and managed Kubernetes). The work is ordered foundation-first: the shared
`lib/Common.ps1` (the echoed-command helper, logging, config loader/validation, and password
generator) comes before any cloud script, because every script depends on it. The config template and
`.gitignore` wiring follow, then one cloud is implemented end-to-end as a reference (GCP — the simplest
secret-file story), then AWS (which needs the ECS Fargate entrypoint wrapper) and Azure, then the
README with setup/cost/safety guidance.

Everything in this plan is **authored and verified on Windows without cloud access**: the helper,
config loader, and password generator have Pester unit tests; a static grep/Pester check enforces that
no script calls a cloud CLI outside `Invoke-Echoed`; and every deploy/teardown script is exercised with
`-WhatIf` (dry run) so its full ordered command list is asserted without touching any cloud. Tasks that
require **live, billable cloud accounts** are marked optional (`*`) and are manual integration
validation the user runs only in an isolated, throwaway account.

The application code is never modified. Only the hardened image (`:hardened`, `APP_MODE=hardened`) is
ever built, pushed, or deployed.

## Tasks

- [x] 1. Scaffold the cloud folder tree and shared library skeleton
  - Create `deployment-security/cloud/` with subfolders `lib/`, `aws/docker/`, `aws/kubernetes/`,
    `azure/docker/`, `azure/kubernetes/`, `gcp/docker/`, `gcp/kubernetes/`,
    `manifests/overlays/{aws,azure,gcp}/`
  - Create an empty `lib/Common.ps1` with module-style function stubs for `Invoke-Echoed`,
    `Write-Step`, `Get-CloudConfig`, `New-DbPassword` so later tasks fill them in
  - Add a Pester test project layout under `deployment-security/cloud/tests/` and confirm Pester 5.x is
    available on Windows PowerShell 5.1+ (document the `Install-Module Pester` command if absent)
  - _Requirements: 6.1_

- [x] 2. Implement the shared `lib/Common.ps1` library (central, reused component)
  - [x] 2.1 Implement `Invoke-Echoed` echoed-command helper
    - Accept `-Exe`, `-CmdArgs` (array), and `-AllowFail` switch
    - Print the exact command line (executable + every argument in order) to stdout **before**
      executing, prefixed (e.g. `> aws ecr ...`) and copyable
    - Quote/escape any argument containing whitespace, a quote, or a shell metacharacter so the printed
      line is runnable as a single manual command
    - Execute `$Exe @CmdArgs` as a discrete argument array (never `Invoke-Expression`, never a shell)
    - Capture `$LASTEXITCODE`; throw a terminating error including the failed command and exit code when
      non-zero and `-AllowFail` is not set; otherwise return control and expose the exit code
    - Return the command's stdout so callers can capture values (URLs, endpoints)
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6, 6.2_

  - [x] 2.2 Write Pester unit tests for `Invoke-Echoed`
    - Assert the exact command line is printed before execution and is correctly quoted/escaped
    - Assert a non-zero exit throws without `-AllowFail` and returns control with `-AllowFail`
    - Assert arguments are passed as a discrete array (no shell/string evaluation)
    - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6_

  - [x] 2.3 Implement `Write-Step` structured logging
    - Emit consistent, greppable step/section banners to stdout
    - _Requirements: 1.1_

  - [x] 2.4 Implement `Get-CloudConfig` config loader and validator
    - Load `cloud.config.ps1` (or `-ConfigPath`), apply safe defaults, return a hashtable
    - Fail fast before any external command when a required key for the active cloud is missing, empty,
      or whitespace, naming each missing key
    - Validate the globally-unique suffix is 3–24 lowercase-alphanumeric characters; fail fast with a
      message when invalid
    - Reject the presence of any password/secret field in the config
    - _Requirements: 7.1, 7.3, 7.5, 7.6, 7.4_

  - [x] 2.5 Write Pester unit tests for `Get-CloudConfig`
    - Assert missing/empty/whitespace required keys are rejected with the key named
    - Assert invalid globally-unique suffixes are rejected
    - Assert a well-formed config loads with defaults applied
    - _Requirements: 7.1, 7.3, 7.5, 7.6_

  - [x] 2.6 Implement `New-DbPassword` generator
    - Generate a random password of at least 24 characters including lowercase, uppercase, digits, and
      symbols
    - Never log or echo the generated value
    - _Requirements: 4.4, 3.2_

  - [x] 2.7 Write Pester unit tests for `New-DbPassword`
    - Assert length ≥ 24 and presence of all four character classes
    - Assert the value never appears in an echoed-output transcript
    - _Requirements: 4.4, 3.2_

- [x] 3. Enforce the echo-only rule with a static/Pester guard
  - Add a Pester test (and a documented grep command) that scans every `deploy.ps1`/`teardown.ps1` and
    asserts zero direct invocations of `aws`, `az`, `gcloud`, `kubectl`, or `docker` outside
    `Invoke-Echoed`
  - Wire this check so it runs over the whole `deployment-security/cloud/` tree
  - _Requirements: 1.3_

- [x] 4. Checkpoint - foundation verified on Windows
  - Ensure all Pester tests for the shared library and the echo-only guard pass, ask the user if
    questions arise.

- [x] 5. Create the parameterized, secret-free configuration
  - [x] 5.1 Author `cloud.config.example.ps1`
    - Include every configuration key for Common/AWS/Azure/GCP with safe defaults or placeholders and
      no real account identifiers
    - Include the user-supplied globally-unique suffix field (3–24 lowercase-alphanumeric) for
      ACR/Key Vault/GCP names
    - Contain no password, access key, token, or connection-string field
    - _Requirements: 7.2, 7.4, 7.5_

  - [x] 5.2 Add `cloud.config.ps1` to `.gitignore`
    - Ensure the real git-ignored config is excluded from version control
    - _Requirements: 7.2_

- [ ] 6. Implement GCP Docker-only (Cloud Run) as the reference deployment
  - [x] 6.1 Author `gcp/docker/deploy.ps1`
    - Dot-source `lib/Common.ps1`; accept `-ConfigPath`, `-WhatIf`, `-ReuseExisting`, plus an allowed
      source-address set parameter
    - Run `gcloud auth list` / project set as the auth check before any create/modify; on failure stop
      with install + auth guidance and a non-zero exit
    - Create-or-reuse Artifact Registry (describe-then-create via `-AllowFail`), build the hardened
      image from `deployment-security/docker/hardened/Dockerfile`, tag `:hardened`, and push
    - Create-or-reuse Cloud SQL for PostgreSQL (never a container); generate+store the password in GCP
      Secret Manager before provisioning; set the DB user password from the stored secret
    - Deploy Cloud Run with `--set-secrets=/run/secrets/db_password=db_password:latest` (native file
      mount), env `APP_MODE=hardened,DB_BACKEND=pg,DB_HOST,DB_PORT=5432,DB_NAME,DB_USER` and **no**
      `DB_PASSWORD` env; restrict ingress to the provided source set and reject 0.0.0.0/0 and ::/0
    - Restrict Cloud SQL access to the compute target on 5432, not public
    - Print the service URL plus the ingress-lockdown and teardown reminder
    - Abort before any push/deploy if the hardened Dockerfile is missing or a non-`:hardened` image /
      non-`hardened` APP_MODE is referenced
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 6.3, 6.4, 6.5, 9.2, 9.3, 9.4, 9.5_

  - [x] 6.2 Author `gcp/docker/teardown.ps1`
    - Accept `-ConfigPath`, `-Force`, `-KeepRegistry`, `-WhatIf`
    - Remove resources in reverse order: Cloud Run service, Cloud SQL instance, then the stored secret;
      remove Artifact Registry last unless `-KeepRegistry`
    - Use `-AllowFail` so already-deleted resources are skipped and re-runs converge to zero; print each
      removed identifier and exit success; on a real removal failure continue, report to stderr, and
      exit non-success
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.5_

  - [x] 6.3 Add `-WhatIf` dry-run Pester assertions for the GCP Docker-only scripts
    - Assert the full ordered command list is printed and no external command executes under `-WhatIf`
    - Assert no `DB_PASSWORD` env and the `/run/secrets/db_password` secret mount appear in the planned
      command set
    - _Requirements: 6.5, 3.1, 3.3_

  - [ ] 6.4 Manual integration validation (GCP Docker-only, live account)
    - In a throwaway GCP project, run deploy then teardown; confirm the URL serves, the secret is a
      mounted file, idempotent re-deploy converges, and teardown leaves zero billable resources
    - _Requirements: 4.1, 4.7, 5.1_

- [x] 7. Implement GCP Kubernetes (GKE) and the GCP overlay
  - [x] 7.1 Author `manifests/overlays/gcp`
    - Kustomize overlay on the existing hardened manifest changing only: image ref (Artifact Registry),
      `Service type: LoadBalancer`, StorageClass (`standard-rwo`), and the secret source (Secret Manager
      CSI / synced K8s Secret) delivering `/run/secrets/db_password`; leave securityContext/RBAC/
      NetworkPolicies intact
    - _Requirements: 2.5, 3.1, 3.3_

  - [x] 7.2 Author `gcp/kubernetes/deploy.ps1`
    - Reuse the ECR/registry build+push and Cloud SQL + Secret Manager steps; create-or-reuse the GKE
      cluster; `get-credentials`; `kubectl apply -k manifests/overlays/gcp`; wait for rollout; read the
      LoadBalancer external IP as the URL; print lockdown + teardown reminder
    - Keep the auth check, idempotency, hardened-only, ingress lock-down, and non-public Postgres rules
    - _Requirements: 2.1, 2.5, 3.1, 3.2, 3.3, 4.1, 4.5, 4.7, 4.8, 6.3, 6.4, 9.2, 9.3, 9.4, 9.5_

  - [x] 7.3 Author `gcp/kubernetes/teardown.ps1`
    - `kubectl delete -k overlays/gcp` (AllowFail), delete GKE cluster, Cloud SQL, stored secret, and
      (unless `-KeepRegistry`) the registry, in reverse order; converge on re-run; report removed ids
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 7.4 Add `-WhatIf` dry-run Pester assertions for the GCP Kubernetes scripts
    - Assert the ordered command list prints and nothing executes under `-WhatIf`
    - _Requirements: 6.5_

- [ ] 8. Checkpoint - GCP reference complete
  - Ensure all Pester and dry-run tests for GCP pass, ask the user if questions arise.

- [x] 9. Implement AWS Docker-only (ECS Fargate) with the secret-file entrypoint wrapper
  - [x] 9.1 Author the ECS Fargate entrypoint wrapper
    - Provide the task `command`/entrypoint that writes the injected secret env value to
      `/run/secrets/db_password` with surrounding whitespace trimmed, unsets the secret env var, then
      execs `node src/server.js`; use a writable ephemeral path for `/run/secrets`
    - _Requirements: 3.5, 3.1_

  - [x] 9.2 Author `aws/docker/deploy.ps1`
    - `aws sts get-caller-identity` auth check with guidance on failure; create-or-reuse ECR; build the
      hardened image and push; create-or-reuse RDS PostgreSQL (never a container); generate+store the
      password in Secrets Manager before provisioning; set the RDS master password from the secret
    - Register the ECS task definition wiring the secret from Secrets Manager into the entrypoint
      wrapper (task 9.1), with env `APP_MODE=hardened,DB_BACKEND=pg,DB_HOST,DB_PORT=5432,DB_NAME,DB_USER`
      and **no** `DB_PASSWORD` env; create-or-reuse the cluster; run the service with a locked-down
      security group (reject 0.0.0.0/0 and ::/0); restrict RDS to the task on 5432
    - Fetch and print the public URL plus lockdown + teardown reminder; abort before push/deploy on a
      missing hardened Dockerfile or any non-hardened image/mode reference
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 6.3, 6.4, 9.2, 9.3, 9.4, 9.5_

  - [x] 9.3 Author `aws/docker/teardown.ps1`
    - Reverse order: scale/delete the ECS service and cluster and deregister the task definition, delete
      RDS (`--skip-final-snapshot`), delete the Secrets Manager secret, then ECR unless `-KeepRegistry`;
      all with `-AllowFail` so re-runs converge; report removed ids; non-success on a real failure
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 9.4 Add `-WhatIf` dry-run Pester assertions for the AWS Docker-only scripts
    - Assert the ordered command list prints, nothing executes, no `DB_PASSWORD` env is set, and the
      entrypoint wrapper writes `/run/secrets/db_password`
    - _Requirements: 6.5, 3.1, 3.5_

- [x] 10. Implement AWS Kubernetes (EKS) and the AWS overlay
  - [x] 10.1 Author `manifests/overlays/aws`
    - Overlay changing only image ref (ECR), `Service type: LoadBalancer`, StorageClass (`gp3`), and the
      secret source (SecretsStore CSI / External Secrets → K8s Secret → `/run/secrets/db_password`)
    - _Requirements: 2.5, 3.1, 3.3_

  - [x] 10.2 Author `aws/kubernetes/deploy.ps1`
    - Reuse ECR build+push and RDS + Secrets Manager steps; create-or-reuse EKS; `update-kubeconfig`;
      `kubectl apply -k overlays/aws`; wait for rollout; read the LoadBalancer DNS as the URL; print
      lockdown + teardown reminder; keep auth check, idempotency, hardened-only, ingress and Postgres
      lock-down rules
    - _Requirements: 2.1, 2.5, 3.1, 3.2, 3.3, 4.1, 4.5, 4.7, 4.8, 6.3, 6.4, 9.2, 9.3, 9.4, 9.5_

  - [x] 10.3 Author `aws/kubernetes/teardown.ps1`
    - `kubectl delete -k overlays/aws` (AllowFail), delete RDS, Secrets Manager secret, EKS cluster/node
      groups, and ECR unless `-KeepRegistry`, in reverse order; converge on re-run; report removed ids
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 10.4 Add `-WhatIf` dry-run Pester assertions for the AWS Kubernetes scripts
    - Assert the ordered command list prints and nothing executes under `-WhatIf`
    - _Requirements: 6.5_

- [x] 11. Implement Azure Docker-only (ACI) with the native secret volume
  - [x] 11.1 Author `azure/docker/deploy.ps1`
    - `az account show` auth check with guidance on failure; idempotent resource group; create-or-reuse
      ACR; `az acr login`; build the hardened image and push; create-or-reuse Flexible Server (never a
      container); create-or-reuse Key Vault; generate+store the password; set the server admin password
      from Key Vault; add a locked-down firewall rule
    - `az container create` with a **secret volume** mounted so the password lands at
      `/run/secrets/db_password`, env `APP_MODE=hardened,DB_BACKEND=pg,DB_HOST,DB_PORT=5432,DB_NAME,
      DB_USER` and **no** `DB_PASSWORD` env; restrict ingress to the provided source set (reject
      0.0.0.0/0 and ::/0); fetch FQDN as URL; print lockdown + teardown reminder; abort on missing
      hardened Dockerfile or non-hardened reference
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 6.3, 6.4, 9.2, 9.3, 9.4, 9.5_

  - [x] 11.2 Author `azure/docker/teardown.ps1`
    - Reverse order: delete the container group, Flexible Server, Key Vault secret/vault, then ACR
      unless `-KeepRegistry`; offer `az group delete` as the documented catch-all; all `-AllowFail`;
      converge on re-run; report removed ids; non-success on a real failure
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 11.3 Add `-WhatIf` dry-run Pester assertions for the Azure Docker-only scripts
    - Assert the ordered command list prints, nothing executes, no `DB_PASSWORD` env, and the secret
      volume targets `/run/secrets/db_password`
    - _Requirements: 6.5, 3.1_

- [x] 12. Implement Azure Kubernetes (AKS) and the Azure overlay
  - [x] 12.1 Author `manifests/overlays/azure`
    - Overlay changing only image ref (ACR), `Service type: LoadBalancer`, StorageClass (`managed-csi`),
      and the secret source (Key Vault Secrets Store CSI → `/run/secrets/db_password`)
    - _Requirements: 2.5, 3.1, 3.3_

  - [x] 12.2 Author `azure/kubernetes/deploy.ps1`
    - Reuse the resource group / ACR build+push and Flexible Server + Key Vault steps; create-or-reuse
      AKS with `--attach-acr` and the Key Vault secrets provider addon; `get-credentials`;
      `kubectl apply -k overlays/azure`; wait for rollout; read the external IP as URL; print lockdown +
      teardown reminder; keep auth check, idempotency, hardened-only, ingress and Postgres lock-down
    - _Requirements: 2.1, 2.5, 3.1, 3.2, 3.3, 4.1, 4.5, 4.7, 4.8, 6.3, 6.4, 9.2, 9.3, 9.4, 9.5_

  - [x] 12.3 Author `azure/kubernetes/teardown.ps1`
    - `kubectl delete -k overlays/azure` (AllowFail), delete AKS, Flexible Server, Key Vault, and the
      resource group catch-all, in reverse order; converge on re-run; report removed ids
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 12.4 Add `-WhatIf` dry-run Pester assertions for the Azure Kubernetes scripts
    - Assert the ordered command list prints and nothing executes under `-WhatIf`
    - _Requirements: 6.5_

- [x] 13. Checkpoint - all six targets authored and dry-run verified
  - Ensure all Pester tests, the echo-only guard, and every `-WhatIf` dry run pass, ask the user if
    questions arise.

- [x] 14. Author the cloud README and safety documentation
  - [x] 14.1 Write `deployment-security/cloud/README.md` setup and config sections
    - Per-cloud Windows CLI install with a verification command (`aws`, `az`, `gcloud`); authentication
      commands (`aws configure`/`aws sso login`, `az login`, `gcloud auth login` +
      `gcloud auth configure-docker`); shared prerequisites Docker Desktop and `kubectl` with
      verification commands and minimum versions; the copy `cloud.config.example.ps1` →
      `cloud.config.ps1` workflow listing each value the user must set
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 14.2 Write the README cost and teaching-lab safety sections
    - Per-target cost warning naming billable resources and the exact teardown command; the statement
      that skipping teardown keeps billing; the statement that the hardened variant is still
      deliberately vulnerable and must run only in an isolated, throwaway account with no other
      workloads
    - _Requirements: 8.5, 8.6, 9.1_

- [x] 15. Final checkpoint - full suite green
  - Ensure all Pester tests pass, the echo-only guard passes, every `-WhatIf` dry run prints its ordered
    command list without executing, and the README covers all six targets; ask the user if questions
    arise.

## Notes

- Tasks marked with `*` are optional. Dry-run/unit (`-WhatIf`, Pester) optional tasks are fully runnable
  on Windows without cloud access and are recommended. Optional tasks explicitly labeled **manual
  integration validation** require a live, billable, throwaway cloud account and are run by the user.
- Core script-authoring tasks (helpers, config, every deploy/teardown script, overlays, README) are
  required and are authored and statically verifiable on Windows without any cloud account.
- Every external CLI call routes through `Invoke-Echoed` (Requirement 1); task 3 enforces this across
  all scripts and is reviewable by grep.
- The DB password is delivered only as the file `/run/secrets/db_password`, never as a `DB_PASSWORD`
  env var, and is stored only in the cloud secret manager (Requirement 3). GCP and Azure mount it
  natively; AWS Fargate uses the entrypoint wrapper (task 9.1).
- Checkpoints validate incrementally so a broken foundation is caught before the cloud scripts build
  on it.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "5.1", "5.2"] },
    { "id": 1, "tasks": ["2.1", "2.3", "2.4", "2.6"] },
    { "id": 2, "tasks": ["2.2", "2.5", "2.7", "3"] },
    { "id": 3, "tasks": ["6.1", "9.1", "11.1", "7.1", "10.1", "12.1"] },
    { "id": 4, "tasks": ["6.2", "7.2", "9.2", "10.2", "11.2", "12.2"] },
    { "id": 5, "tasks": ["6.3", "6.4", "7.3", "9.3", "10.3", "11.3", "12.3"] },
    { "id": 6, "tasks": ["7.4", "9.4", "10.4", "12.4"] },
    { "id": 7, "tasks": ["14.1", "14.2"] }
  ]
}
```
