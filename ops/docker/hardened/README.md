# Docker - hardened container

The same app as the repo's default (insecure) build at the root, run with container hardening
applied. Compare the two side by side.

## Run it

```
# provide the DB_Secret out-of-band (never commit the real value). This file is
# git-ignored; Postgres and the app both read the password from it.
cp ops/docker/hardened/db_password.txt.example ops/docker/hardened/db_password.txt
# edit db_password.txt and set a strong password before starting

docker compose -f ops/docker/hardened/docker-compose.yml up -d --build
# app on http://localhost:7010, backed by a persistent PostgreSQL service
```

## PostgreSQL + the DB_Secret (no plaintext password)

This stack runs the app against a persistent PostgreSQL service (`db`), with its
data kept in a named volume (`db-data`) so it survives container restarts. The app
talks to Postgres through the `pg` driver, pinned in the hardened `package.json` at
the same exact version as the repo root (`pg` `8.23.1`) and installed by `npm ci`
during the image build.

The database password (the DB_Secret) is never kept in plaintext here:

- It lives only in the git-ignored `db_password.txt`, fed in through Docker's
  `secrets` mechanism — not baked into the image and not passed as a plaintext env var.
- Postgres reads it from the mounted secret file via `POSTGRES_PASSWORD_FILE`.
- The app runs in hardened mode (`APP_MODE=hardened`, `DB_BACKEND=pg`) and reads the
  password from `/run/secrets/db_password` in `src/db/credentials.js`. Only the
  non-secret connection parameters (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`) are
  passed as env vars.
- Fail-closed: if the secret file is missing or effectively empty, the app logs an
  error and exits without opening the connection.

## Risk -> countermeasure

| Insecure baseline | Hardened here |
|---|---|
| root (uid 0) | `USER 10001` + `user: "10001"` (non-root) |
| `privileged: true` | `cap_drop: [ALL]` + `no-new-privileges` |
| writable root FS | `read_only: true` + writable `tmpfs /tmp` and volumes only for `/app/config` and `/app/logs` |
| no syscall filter | `security_opt: seccomp=./seccomp.json` |
| DB password in plaintext env | DB_Secret via Docker `secrets`, read from `/run/secrets/db_password` (git-ignored source file) |
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
