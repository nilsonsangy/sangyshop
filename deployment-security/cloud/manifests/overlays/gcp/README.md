# GCP (GKE) Kustomize overlay

Per-cloud adaptation of the hardened SangyShop manifest for Google Kubernetes
Engine (GKE) with Cloud SQL and Secret Manager. The base manifest
(`deployment-security/kubernetes/hardened/sangyshop-hardened.yaml`) stays the
single source of truth and is **not modified**; this overlay references it as a
kustomize resource by relative path and layers only the per-cloud deltas.

## What this overlay changes (and only this)

| Delta | How | File |
|---|---|---|
| Image ref → Artifact Registry | `images:` transformer rewrites `sangyshop` → `<AR path>:hardened` | `kustomization.yaml` |
| Web Service → `LoadBalancer` | strategic-merge patch on the `sangyshop` Service | `patch-service-lb.yaml` |
| Secret source → GCP Secret Manager | Secrets Store CSI driver (GCP provider) syncs the `db_password` secret into the `sangyshop-db` K8s Secret; app keeps reading `/run/secrets/db_password` | `secret-provider-class.yaml`, `patch-deployment.yaml` |
| DB host → managed Cloud SQL | `DB_HOST` env repointed; in-cluster Postgres removed | `patch-deployment.yaml`, `delete-db-*.yaml` |
| StorageClass → `standard-rwo` | canonical delta, documented but not wired in (the only PVC is dropped) | `patch-pvc-storageclass.yaml` |

Because Cloud SQL (managed PostgreSQL) replaces the self-hosted database, the
overlay drops the in-cluster Postgres **StatefulSet**, its **PVC**, the
`sangyshop-db` **Service**, and the base placeholder **Secret**.

Left intact: pod/container `securityContext`, RBAC
(`ServiceAccount`/`Role`/`RoleBinding`), and all three `NetworkPolicies`.

## Placeholders (substituted by `gcp/kubernetes/deploy.ps1`, task 7.2)

The overlay keeps literal `__TOKEN__` placeholders so it stays kustomize-
buildable for review. The deploy script renders the overlay, replaces the
tokens with values from `cloud.config.ps1`, then applies:

| Token | Meaning | Source |
|---|---|---|
| `__AR_IMAGE_NAME__` | Artifact Registry image path, no tag (`<region>-docker.pkg.dev/<projectId>/<ArRepo>/sangyshop`) | `Gcp.Region`, `Gcp.ProjectId`, `Gcp.ArRepo` |
| `__CLOUDSQL_HOST__` | Cloud SQL host reachable on 5432 (instance private IP or Auth Proxy address) | `gcloud sql instances describe` |
| `__GCP_PROJECT_ID__` | Project owning the Secret Manager secret | `Gcp.ProjectId` |
| `__GSM_SECRET__` | Secret Manager secret name (default `db_password`) | deploy script |

The image **tag** is fixed to `hardened` in `kustomization.yaml` (not a
placeholder) to keep the hardened-only rule visible.

## Build / apply

The base is outside the overlay directory, so build with load restrictions
disabled and pipe to apply (`kubectl apply -k` cannot pass that flag):

```powershell
kubectl kustomize --load-restrictor LoadRestrictionsNone `
  deployment-security/cloud/manifests/overlays/gcp |
  kubectl apply -f -
```

The deploy script performs the placeholder substitution between these two
steps.

## Cluster prerequisites (handled by the deploy script)

- Secrets Store CSI driver + GCP provider installed on the GKE cluster.
- Workload Identity bound so the `sangyshop` ServiceAccount can read the
  Secret Manager secret.
