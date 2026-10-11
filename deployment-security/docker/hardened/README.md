# Docker - hardened container

The same app as [`../insecure`](../insecure), run with container hardening applied.
Compare the two side by side.

## Run it

```
# provide the secret out-of-band (never commit the real value)
cp deployment-security/docker/hardened/db_password.txt.example \
   deployment-security/docker/hardened/db_password.txt

docker compose -f deployment-security/docker/hardened/docker-compose.yml up -d --build
# app on http://localhost:3000
```

## Risk -> countermeasure

| Insecure baseline | Hardened here |
|---|---|
| root (uid 0) | `USER 10001` + `user: "10001"` (non-root) |
| `privileged: true` | `cap_drop: [ALL]` + `no-new-privileges` |
| writable root FS | `read_only: true` + writable `tmpfs /tmp` and volumes only for `/app/config` and `/app/logs` |
| no syscall filter | `security_opt: seccomp=./seccomp.json` |
| secret in plaintext env | `secrets:` from an out-of-band file (git-ignored) |
| no limits | `mem_limit`, `cpus`, `pids_limit` |

## Why `/app/config` and `/app/logs` are writable

SangyShop writes `config/defenses.json` (the Defenses panel) and creates a `logs/` directory
at startup. Under a read-only root filesystem those two paths must remain writable, so each is
mounted as a named volume. Everything else stays immutable - a realistic "least writable surface".

## Measure the difference

```
# fewer CVEs than the insecure image once the base/deps are current
trivy image sangyshop:hardened
grype sangyshop:hardened

# prove it is NOT root
docker exec sangyshop-hardened id        # uid=10001
```
