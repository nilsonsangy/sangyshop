# Azure (AKS) Kustomize overlay

Per-cloud adaptation of the hardened SangyShop manifest for Azure Kubernetes
Service (AKS) with Azure Database for PostgreSQL Flexible Server and Azure Key
Vault. The base manifest
(`ops/kubernetes/hardened/sangyshop-hardened.yaml`) stays the
single source of truth and is **not modified**; this overlay references it as a
kustomize resource by relative path (`../../../kubernetes/hardened/sangyshop-hardened.yaml`)
and layers only the per-cloud deltas.

## What this overlay changes (and only this)

| Delta | How | File |
|---|---|---|
| Image ref → Azure Container Registry | `images:` transformer rewrites `sangyshop` → `<ACR path>:hardened` | `kustomization.yaml` |
| Web Service → `LoadBalancer` | strategic-merge patch on the `sangyshop` Service | `patch-service-lb.yaml` |
| Secret source → Azure Key Vault | Secrets Store CSI driver (Azure Key Vault provider) syncs the DB-password secret into the `sangyshop-db` K8s Secret; app keeps reading `/run/secrets/db_password` | `secret-provider-class.yaml`, `patch-deployment.yaml` |
| DB host → managed Flexible Server | `DB_HOST` env repointed; in-cluster Postgres removed | `patch-deployment.yaml`, `delete-db-*.yaml` |
| StorageClass → `managed-csi` | canonical delta, documented but not wired in (the only PVC is dropped) | `patch-pvc-storageclass.yaml` |

Because Azure Database for PostgreSQL Flexible Server (managed PostgreSQL)
replaces the self-hosted database, the overlay drops the in-cluster Postgres
**StatefulSet**, its **PVC**, the `sangyshop-db` **Service**, and the base
placeholder **Secret**.

Left intact: pod/container `securityContext`, RBAC
(`ServiceAccount`/`Role`/`RoleBinding`), and all three `NetworkPolicies`.

## Placeholders (substituted by `azure/aks/deploy.ps1`, task 12.2)

The overlay keeps literal `__TOKEN__` placeholders so it stays kustomize-
buildable for review. The deploy script renders the overlay, replaces the
tokens with values from `cloud.config.ps1`, then applies:

| Token | Meaning | Source |
|---|---|---|
| `__ACR_IMAGE_NAME__` | ACR image path, no tag (`<acrName>.azurecr.io/sangyshop`) | `Azure.AcrName` |
| `__PG_HOST__` | Flexible Server host reachable on 5432 (`<server>.postgres.database.azure.com`) | `az postgres flexible-server show` |
| `__KEYVAULT_NAME__` | Key Vault holding the DB-password secret | `Azure.KeyVaultName` |
| `__KV_SECRET__` | Key Vault secret name (default `db-password`) | deploy script |
| `__KV_TENANT_ID__` | Azure AD tenant id of the Key Vault | `az account show` / config |
| `__KV_IDENTITY_CLIENTID__` | client id of the user-assigned managed identity the Key Vault provider uses | AKS addon identity |

The image **tag** is fixed to `hardened` in `kustomization.yaml` (not a
placeholder) to keep the hardened-only rule visible.

## Build / apply

The base is outside the overlay directory, so build with load restrictions
disabled and pipe to apply (`kubectl apply -k` cannot pass that flag):

```powershell
kubectl kustomize --load-restrictor LoadRestrictionsNone `
  ops/azure/aks/overlays |
  kubectl apply -f -
```

The deploy script performs the placeholder substitution between these two
steps.

## Cluster prerequisites (handled by the deploy script)

- AKS created with the `azure-keyvault-secrets-provider` addon (Secrets Store
  CSI driver + Azure Key Vault provider).
- A user-assigned managed identity granted `get` on the Key Vault secret and
  bound to the workload, so the Key Vault provider can read the secret
  (`__KV_IDENTITY_CLIENTID__`).
- The cluster attached to the ACR (`az aks ... --attach-acr`) so the image pull
  succeeds.
