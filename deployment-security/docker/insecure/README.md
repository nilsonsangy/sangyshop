# Docker - insecure container (teaching baseline)

This builds and runs SangyShop the loose way, so you have a baseline to compare the
hardened version against. **Everything here is insecure on purpose.**

## Run it

```
docker compose -f deployment-security/docker/insecure/docker-compose.yml up -d --build
# app on http://localhost:3000
```

## What makes it insecure

| Weakness | Where | Why it matters |
|---|---|---|
| Runs as **root** (uid 0) | `Dockerfile` has no `USER` | a compromise of the app inherits the container's root |
| `privileged: true` | compose | removes isolation; a path toward the host |
| **Secret in plaintext** | `DB_PASSWORD` env in compose | the secret travels in every copy of the manifest/image |
| **No resource limits** | compose | a runaway/compromised container can starve the host |
| **No capability drop / read-only FS** | compose | nothing reduces what the process can do at runtime |
| **Outdated dependencies** | `package.json` (lodash/minimist/marked) | known CVEs ship inside the image |

## Measure it

```
# known CVEs in the image
trivy image sangyshop:insecure
grype sangyshop:insecure

# dependency CVEs from the lockfile
osv-scanner --lockfile=package-lock.json
snyk test --severity-threshold=high          # requires auth (see note below)

# prove it runs as root
docker exec sangyshop-insecure id            # uid=0(root)
```

> **Snyk auth.** Snyk needs an account. Either run `snyk auth` (interactive browser login)
> or use an API token from app.snyk.io (Account settings -> Auth Token) via the
> `SNYK_TOKEN` environment variable: `export SNYK_TOKEN=<your-token>`.

Now compare with [`../hardened`](../hardened).
