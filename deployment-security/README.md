# Deployment Security: insecure vs hardened

SangyShop teaches the OWASP Top 10 at the **application** layer. This folder adds the
**deployment** layer: the same application, shipped two ways, so you can *see* what
container and orchestration hardening actually changes.

The idea mirrors the app's Defenses panel — **run it insecure, then run it hardened,
and compare** — but applied to how the app is packaged and run:

- **`docker/`** — the same image run **insecure** (the repo's default build, `sangyshop:insecure`)
  vs a **hardened** one (`docker/hardened/`).
- **`kubernetes/`** — the same app deployed with an **insecure** manifest set vs a
  **hardened** one (RBAC, Network Policies, Pod Security Standards, managed secrets, limits).

> **Warning.** SangyShop is deliberately vulnerable. Run everything here **only in an
> isolated environment** (your laptop / a VM / WSL / a throwaway local cluster), **never**
> exposed to the internet.

## Why two versions of the same app?

The application code is **identical** on both sides. The only thing that changes is the
*deployment posture*. So any difference a scanner, a benchmark or a runtime monitor reports
comes purely from how the app was built and run — which makes the effect of each hardening
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
deployment-security/
  docker/
    hardened/    Dockerfile + docker-compose.yml + seccomp.json -> sangyshop:hardened
  kubernetes/
    insecure/    sangyshop-insecure.yaml
    hardened/    sangyshop-hardened.yaml
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
keep the rest of the root filesystem read-only — a realistic "least writable surface" setup.
