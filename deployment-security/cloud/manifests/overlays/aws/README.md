# AWS / EKS Kustomize overlay

Per-cloud adaptation of the shared hardened manifest for Amazon EKS. The base
manifest is the single source of truth and is **never modified** — this overlay
references it by relative path and layers only the AWS-specific deltas on top.

**Base:** `../../../../kubernetes/hardened/sangyshop-hardened.yaml`

## What this overlay changes (and only this)

| # | Delta | File |
|---|-------|------|
| 1 | Image ref → Amazon ECR | `kustomization.yaml` (`images:` transformer) |
| 2 | Web `sangyshop` Service → `type: LoadBalancer` | `service-loadbalancer.yaml` |
| 3 | StorageClass `gp3` (encrypted EBS) | `storageclass-gp3.yaml` |
| 4 | Secret source → SecretsStore CSI / External Secrets → K8s Secret `sangyshop-db` → file `/run/secrets/db_password` | `secretproviderclass.yaml` + `app-rds.yaml` |
| — | Drop in-cluster Postgres (StatefulSet + PVC + `sangyshop-db` Service); repoint `DB_HOST` at managed RDS | `delete-postgres.yaml` + `app-rds.yaml` |

**Left intact (inherited from the base, unchanged):** the hardened
`securityContext` (non-root, read-only root FS, dropped capabilities,
seccomp), RBAC (`ServiceAccount` / `Role` / `RoleBinding`), and the
default-deny + allow `NetworkPolicies`.

The DB-password **file contract is preserved**: the password still arrives in
the container as the trimmed plain-text file `/run/secrets/db_password` (read by
`src/db/credentials.js`). Only the *source* of that file changes — the
SecretsStore CSI driver pulls it from AWS Secrets Manager and syncs it into the
`sangyshop-db` Kubernetes Secret the base already mounts. `DB_PASSWORD` is never
set as an environment variable.

## Placeholders and substitution

This overlay is committed with **placeholders only** — no account IDs, hosts, or
secrets. `aws/kubernetes/deploy.ps1` (task 10.2) renders a throwaway copy with
the values below substituted from `cloud.config.ps1`, then runs
`kubectl apply -k` on the rendered copy. The committed files stay
placeholder-only.

| Placeholder | Example | Source |
|-------------|---------|--------|
| `__ECR_IMAGE_NAME__` | `1234567890.dkr.ecr.us-east-1.amazonaws.com/sangyshop` | `Aws.AccountId` + `Aws.Region` + `Aws.EcrRepo` (repo path, no tag; tag pinned to `hardened`) |
| `__RDS_HOST__` | `sangyshop-lab.abc123.us-east-1.rds.amazonaws.com` | managed RDS instance endpoint |
| `__AWS_REGION__` | `us-east-1` | `Aws.Region` |
| `__SECRET_ARN__` | `arn:aws:secretsmanager:us-east-1:1234567890:secret:sangyshop/db_password` | Secrets Manager secret holding the DB password |

### Example render + apply (what deploy.ps1 does, via `Invoke-Echoed`)

```powershell
# Render a temp copy with placeholders replaced (committed files untouched)...
# ...then:
kubectl apply -k <rendered-overlay-dir>
kubectl -n sangyshop-hardened rollout status deploy/sangyshop
kubectl -n sangyshop-hardened get svc sangyshop -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

## Cluster prerequisites (wired by deploy.ps1)

- `aws-ebs-csi-driver` addon (for the `gp3` StorageClass).
- SecretsStore CSI Driver + `aws-secrets-manager` provider.
- An IRSA role bound to the `sangyshop` ServiceAccount granting read on the
  Secrets Manager secret (the base RBAC is untouched).
