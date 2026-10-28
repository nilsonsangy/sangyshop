# Requirements Document

## Introduction

This feature adds a dedicated set of PowerShell deployment scripts that take the existing **hardened**
SangyShop variant and deploy it to **three public clouds** (AWS, Azure, GCP), each in **two
modalities**: a native managed container service ("Docker-only" — AWS ECS Fargate, Azure Container
Instances, GCP Cloud Run) and a managed Kubernetes service (EKS, AKS, GKE) reusing the existing
hardened Kubernetes manifests. Each target provisions the cloud's managed PostgreSQL service and native
image registry, generates a DB password, stores it in the cloud's secret manager, and delivers it to
the running container as the file `/run/secrets/db_password` so the unmodified hardened app
(`src/db/credentials.js` in hardened mode) reads it fail-closed.

The design is script-first and CLI-driven: every cloud CLI command a script runs is echoed to stdout
before it executes, through a single shared helper. Every deploy has a matching teardown so no billable
resource is left behind. SangyShop is a deliberately vulnerable teaching application; these scripts are
intended only for isolated, throwaway cloud accounts with locked-down ingress and mandatory teardown.

The application code is never modified by this feature; the three clouds differ only in how they
provision infrastructure and deliver the secret file.

## Glossary

- **Deploy_Script**: A PowerShell (`.ps1`) script that provisions and deploys one (cloud, modality) target.
- **Teardown_Script**: A PowerShell (`.ps1`) script that removes every resource created by its matching Deploy_Script.
- **Common_Library**: The shared PowerShell library (`lib/Common.ps1`) dot-sourced by every Deploy_Script and Teardown_Script, hosting the echoed-command helper, config loading, and password generation.
- **Invoke_Echoed**: The single shared helper function in the Common_Library that echoes a command line to stdout before executing it.
- **Target**: One combination of a cloud (AWS, Azure, GCP) and a modality (Docker-only or Kubernetes); there are six Targets.
- **Docker_Only_Modality**: Deployment to a native managed container service — ECS Fargate (AWS), Azure Container Instances (Azure), Cloud Run (GCP).
- **Kubernetes_Modality**: Deployment to a managed Kubernetes service — EKS (AWS), AKS (Azure), GKE (GCP) — reusing the existing hardened manifests.
- **Hardened_Variant**: The SangyShop image built from `deployment-security/docker/hardened/Dockerfile`, tagged `:hardened` and run with `APP_MODE=hardened`.
- **Insecure_Variant**: The deliberately misconfigured SangyShop variant, which is local-only and out of scope for cloud deployment.
- **Native_Registry**: The cloud's own image registry — ECR (AWS), ACR (Azure), Artifact Registry (GCP).
- **Managed_Postgres**: The cloud's managed PostgreSQL service — RDS (AWS), Azure DB for PostgreSQL Flexible Server (Azure), Cloud SQL (GCP).
- **Secret_Manager**: The cloud's secret storage service — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager.
- **Secret_File_Path**: The absolute container file path `/run/secrets/db_password` where the trimmed DB password is delivered.
- **DB_Password**: The PostgreSQL password generated for a Target, stored only in the Secret_Manager and surfaced at the Secret_File_Path.
- **Config_File**: The git-ignored PowerShell parameter file (`cloud.config.ps1`) that supplies per-user values; copied from the committed template `cloud.config.example.ps1`.
- **Cloud_README**: The documentation file (`deployment-security/cloud/README.md`) describing per-cloud setup, auth, prerequisites, cost, and teardown.

## Requirements

### Requirement 1: Echoed-command transparency

**User Story:** As a student following a cloud lab, I want every cloud command a script runs to be printed before it executes, so that I can see exactly what is done to my cloud account and copy any single command to run manually.

#### Acceptance Criteria

1. WHEN a Deploy_Script or Teardown_Script runs any external command (`aws`, `az`, `gcloud`, `kubectl`, or `docker`), THE Invoke_Echoed SHALL print the exact command line, consisting of the executable name followed by every argument in the order passed, to stdout before executing that command.
2. WHEN Invoke_Echoed prints a command line that contains an argument with whitespace, a quote character, or a shell metacharacter, THE Invoke_Echoed SHALL quote or escape that argument so that the printed line is directly copyable and runnable as a single manual command without modification.
3. THE Deploy_Script and THE Teardown_Script SHALL issue every `aws`, `az`, `gcloud`, `kubectl`, and `docker` invocation exclusively through Invoke_Echoed, with zero direct invocations of those five executables outside Invoke_Echoed.
4. THE Common_Library SHALL execute each external command using the argument array passed to Invoke_Echoed as discrete arguments, without passing the command through string evaluation or a shell interpreter.
5. IF an external command exits with a non-zero exit code AND the call did not request failure tolerance, THEN THE Invoke_Echoed SHALL raise a terminating error that stops the script before any subsequent command is printed or executed, and SHALL include in the error an indication of the failed command and its exit code.
6. WHEN an external command exits with a non-zero exit code AND the call requested failure tolerance, THE Invoke_Echoed SHALL return control to the caller without raising a terminating error and SHALL make the command's exit code available to the caller.

### Requirement 2: Hardened-only deployment scope

**User Story:** As a lab maintainer, I want only the hardened variant deployed to the cloud, so that the intentionally insecure variant is never exposed on a public cloud.

#### Acceptance Criteria

1. WHEN the Deploy_Script executes for a Target, THE Deploy_Script SHALL build, push, and deploy only the Hardened_Variant, using image tag `:hardened` and setting `APP_MODE=hardened`.
2. IF a build, push, or deploy step references the Insecure_Variant (any image tag other than `:hardened` or any `APP_MODE` value other than `hardened`), THEN THE Deploy_Script SHALL abort the operation before any push or deploy step, perform no push or deploy, and return a non-zero exit status with an error indicating that only the Hardened_Variant may be deployed.
3. THE Deploy_Script SHALL build the deployed image exclusively from `deployment-security/docker/hardened/Dockerfile`.
4. IF the file `deployment-security/docker/hardened/Dockerfile` is absent or unreadable at build time, THEN THE Deploy_Script SHALL abort before any push or deploy step, perform no push or deploy, and return a non-zero exit status with an error indicating the missing hardened Dockerfile.
5. WHERE the Target uses the Kubernetes_Modality, THE Deploy_Script SHALL deploy the existing hardened Kubernetes manifests, applying only the following per-cloud overlay adaptations and no other manifest changes: registry image reference, LoadBalancer Service, StorageClass, and secret source.

### Requirement 3: Secret-file injection and no secret leakage

**User Story:** As a security instructor, I want the database password delivered to the container as a mounted file and never as an environment variable or committed text, so that the hardened fail-closed secret contract is honored and no secret leaks.

#### Acceptance Criteria

1. WHEN a Target is deployed, THE Deploy_Script SHALL deliver the DB_Password to the running container at the Secret_File_Path as plain file content with all leading and trailing whitespace removed, and SHALL NOT set an environment variable named `DB_PASSWORD` on the container.
2. THE Deploy_Script SHALL store the DB_Password only in the cloud's Secret_Manager and SHALL NOT write the DB_Password value into any Config_File, committed file, echoed command line, or log output.
3. THE Deploy_Script SHALL set the non-secret connection environment for every Target to exactly `APP_MODE=hardened`, `DB_BACKEND=pg`, `DB_HOST`, `DB_PORT=5432`, `DB_NAME`, and `DB_USER`, and SHALL NOT include the DB_Password value among these environment variables.
4. IF the DB_Password cannot be retrieved from the Secret_Manager or cannot be written to the Secret_File_Path, THEN THE Deploy_Script SHALL abort the deployment without starting the container, SHALL emit an error indicating that secret delivery failed, and SHALL NOT include the DB_Password value in that error.
5. WHERE the Target is the AWS Docker_Only_Modality that receives the secret as an environment value, THE Deploy_Script SHALL use an entrypoint wrapper that writes that value to the Secret_File_Path with all leading and trailing whitespace removed and unsets the secret environment variable before starting the application.

### Requirement 4: Managed cloud services per Target

**User Story:** As a user running a cloud lab, I want each Target to use the cloud's managed PostgreSQL, native registry, secret manager, and the specified compute service, so that the deployment reflects real managed-service practice rather than self-hosted containers.

#### Acceptance Criteria

1. WHEN a Deploy_Script is run a second time with the same Config_File, THE Deploy_Script SHALL reuse existing resources by preceding each create with a describe or show check, converging to a single set of resources without erroring on an already-existing resource.
2. IF a describe or show check fails for a reason other than the resource not existing, THEN THE Deploy_Script SHALL halt before creating or modifying that resource, preserve all existing resource state, and print an error message to stderr indicating the check that failed.
3. THE Deploy_Script SHALL provision the DB_Password-holding database as the cloud's Managed_Postgres service and SHALL NOT run PostgreSQL as a container in the cloud.
4. WHEN a Deploy_Script needs a DB_Password that is not yet stored, THE Deploy_Script SHALL generate a random DB_Password of at least 24 characters that includes lowercase letters, uppercase letters, digits, and symbols, and SHALL store it in the cloud's Secret_Manager before provisioning the Managed_Postgres service.
5. THE Deploy_Script SHALL build the Hardened_Variant image and push it to the cloud's Native_Registry.
6. IF the Hardened_Variant image build fails or the push to the Native_Registry fails, THEN THE Deploy_Script SHALL halt before deploying the compute Target, perform no partial deploy of the compute Target, and print an error message to stderr indicating whether the build or the push failed.
7. WHEN a Deploy_Script completes, THE Deploy_Script SHALL print the deployed public URL and an ingress-lockdown reminder to stdout.
8. THE Deploy_Script SHALL deploy the compute Target as ECS Fargate, Azure Container Instances, or Cloud Run for the Docker_Only_Modality, and as EKS, AKS, or GKE for the Kubernetes_Modality, matching the cloud.

### Requirement 5: Teardown completeness

**User Story:** As a cost-conscious user, I want every deploy to have a matching teardown that removes all its resources, so that no billable resource is silently left running.

#### Acceptance Criteria

1. WHEN a Teardown_Script completes successfully within 600 seconds, THE Teardown_Script SHALL have removed every resource its matching Deploy_Script created, leaving zero billable resources associated with that Target.
2. THE Teardown_Script SHALL remove resources in reverse dependency order: first compute, then Managed_Postgres, then the stored DB_Password.
3. WHERE the Native_Registry was created by the matching Deploy_Script, THE Teardown_Script SHALL remove the Native_Registry after removing the stored DB_Password.
4. WHEN a Teardown_Script encounters an already-deleted resource, THE Teardown_Script SHALL skip that resource, treat it as successfully removed, and continue, so that any re-run of the Teardown_Script converges to zero remaining resources and exits with a success status.
5. WHEN a Teardown_Script completes successfully, THE Teardown_Script SHALL write to stdout the identifier of each resource removed and exit with a success status.
6. IF a resource other than an already-deleted resource fails to be removed, THEN THE Teardown_Script SHALL continue attempting to remove the remaining resources, write to stderr an error indication identifying each resource that could not be removed, and exit with a non-success status.

### Requirement 6: PowerShell scripts using cloud CLIs

**User Story:** As a Windows user, I want the scripts to run natively on Windows PowerShell using each cloud's own CLI, so that I can run the labs without a different shell or toolchain.

#### Acceptance Criteria

1. THE Deploy_Script and THE Teardown_Script SHALL be PowerShell (`.ps1`) scripts runnable on Windows PowerShell version 5.1 or later.
2. THE Deploy_Script and THE Teardown_Script SHALL perform all cloud operations using the target cloud's CLI (`aws`, `az`, or `gcloud`) together with `kubectl` for the Kubernetes_Modality, and SHALL NOT invoke any non-PowerShell shell (such as `bash` or `sh`) to perform those operations.
3. WHEN a Deploy_Script starts, THE Deploy_Script SHALL run an authentication check for the target cloud before performing any create or modify operation.
4. IF the authentication check fails, THEN THE Deploy_Script SHALL stop before performing any create or modify operation, SHALL emit a message identifying the missing CLI or failed authentication, SHALL include install and authentication guidance for the target cloud, and SHALL exit with a non-zero exit code.
5. WHEN a Deploy_Script or Teardown_Script is run with a dry-run switch, THE script SHALL write the full ordered list of external commands it would run to output, SHALL NOT execute any external command (`aws`, `az`, `gcloud`, or `kubectl`), and SHALL exit with a zero exit code.

### Requirement 7: Parameterized, secret-free configuration

**User Story:** As a user with my own cloud account, I want per-user values supplied through a git-ignored config file with safe defaults and no secrets, so that my account details and generated names never enter version control.

#### Acceptance Criteria

1. WHEN the Deploy_Script or the Teardown_Script starts, THE Common_Library SHALL read per-user values (region, resource group or project id, and resource names) from the Config_File before any external command runs.
2. THE repository SHALL include a committed config template `cloud.config.example.ps1` containing every configuration key with safe default or placeholder values and no real account identifiers, and the real Config_File `cloud.config.ps1` SHALL be listed in `.gitignore` so it is excluded from version control.
3. IF a required configuration key for the active cloud is missing, is an empty string, or contains only whitespace, THEN THE Common_Library SHALL stop execution before any external command runs and emit an error message that names each missing key.
4. THE Config_File SHALL NOT contain any password, access key, token, connection string, or other secret field.
5. WHERE a resource name must be globally unique (such as ACR, Key Vault, or GCP bucket-like names), THE Config_File SHALL supply a user-provided unique suffix of 3 to 24 characters consisting only of lowercase letters and digits.
6. IF a required globally-unique suffix is missing, empty, or does not meet the 3 to 24 lowercase-alphanumeric character rule, THEN THE Common_Library SHALL stop execution before any external command runs and emit an error message indicating the invalid suffix.

### Requirement 8: Per-cloud setup and teardown documentation

**User Story:** As a user starting a cloud lab, I want per-cloud documentation of CLI install, authentication, prerequisites, cost, and teardown, so that I can set up and clean up each cloud correctly.

#### Acceptance Criteria

1. THE Cloud_README SHALL document, for each of AWS, Azure, and GCP, the Windows CLI installation steps, including the command or installer to run and a verification command that confirms the CLI is installed.
2. THE Cloud_README SHALL document how to authenticate to the user's own account for each cloud, including the exact commands `aws configure` or `aws sso login` for AWS, `az login` for Azure, and `gcloud auth login` plus `gcloud auth configure-docker` for GCP.
3. THE Cloud_README SHALL document the shared prerequisites Docker Desktop and `kubectl`, including for each a verification command that confirms it is installed and the minimum required version.
4. THE Cloud_README SHALL document the parameterized config workflow of copying `cloud.config.example.ps1` to `cloud.config.ps1`, including each configuration value the user must set in `cloud.config.ps1` before deployment.
5. THE Cloud_README SHALL include, for each Target, a cost warning identifying the billable resources created, and the mandatory teardown step with the exact command used to remove those resources.
6. THE Cloud_README SHALL state, for each Target, that failure to run the teardown step leaves billable resources running and continues to incur cost until they are removed.

### Requirement 9: Teaching-lab safety constraints

**User Story:** As an instructor, I want the scripts and documentation to enforce isolated, locked-down, short-lived cloud use, so that a known-vulnerable application is never left exposed on the public internet.

#### Acceptance Criteria

1. THE Cloud_README SHALL state that the Hardened_Variant remains a deliberately vulnerable application and SHALL state that it must be deployed only to a cloud account or project that contains no other workloads or data.
2. WHEN a Deploy_Script prints the deployed URL, THE Deploy_Script SHALL also print a reminder instructing the operator to restrict ingress to the operator's own source address and to run the teardown command when finished.
3. THE Deploy_Script SHALL configure the compute Target's ingress to allow only an explicitly specified set of source addresses and SHALL prohibit the source ranges 0.0.0.0/0 and ::/0.
4. IF no allowed source address set is provided to the Deploy_Script, THEN THE Deploy_Script SHALL stop without applying any ingress change and SHALL emit an error message indicating that an allowed source address set is required.
5. THE Deploy_Script SHALL configure network access so the Managed_Postgres instance is reachable by the compute Target only on port 5432 and SHALL prohibit public exposure via the source ranges 0.0.0.0/0 and ::/0.
