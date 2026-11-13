# AWS ECS Fargate secret→file entrypoint wrapper

This folder holds the thin **entrypoint wrapper** that lets the unmodified
**hardened** SangyShop image run on **AWS ECS Fargate** while still honoring the
fail-closed secret-file contract in `src/db/credentials.js`.

- `secret-entrypoint.sh`: the wrapper.
- `deploy.ps1` / `teardown.ps1`, the ECS Fargate deploy/teardown scripts (task
  9.2 / 9.3) that wire the wrapper into the task definition.

## Why a wrapper is needed on Fargate (and nowhere else)

The hardened app reads the PostgreSQL password **only** from the file
`/run/secrets/db_password` and fail-closes if it is missing or empty. It
deliberately ignores any `DB_PASSWORD` environment variable.

| Docker-only target | How the secret reaches `/run/secrets/db_password` | Wrapper? |
| ------------------ | ------------------------------------------------- | -------- |
| GCP Cloud Run      | native secret **file mount**                      | no       |
| Azure ACI          | native **secret volume**                          | no       |
| **AWS ECS Fargate**| Secrets Manager injects the value as an **env var** | **yes** |

Fargate maps a Secrets Manager secret to an **environment variable**, not a
file. The wrapper bridges that gap **without changing the app image or app
code**: the task definition overrides the container `command` to run the wrapper
instead of the image's default `CMD ["node","src/server.js"]`. The wrapper:

1. reads the injected env var `DB_PASSWORD_SECRET`,
2. writes its value to `/run/secrets/db_password` with **all leading/trailing
   whitespace removed**,
3. **unsets** `DB_PASSWORD_SECRET` so the secret no longer lives in the app's
   environment,
4. `exec`s `node src/server.js`.

It fail-closes (non-zero exit, non-secret error, no file written) when the env
var is unset, empty, or whitespace-only, and it never prints the secret value.

## Required task-definition wiring (for `deploy.ps1`)

The deploy script's `aws ecs register-task-definition` call MUST set the
following on the single app container.

### 1. Make `/run/secrets` a writable ephemeral path

The hardened image runs as **non-root UID 10001**, so `/run/secrets` must be a
writable mount. Fargate provides per-task ephemeral storage; mount a `tmpfs`-style
volume at `/run/secrets`:

```jsonc
// top-level task definition
"volumes": [
  { "name": "run-secrets" }        // ephemeral, backed by Fargate task storage
],
// on the container
"mountPoints": [
  { "sourceVolume": "run-secrets", "containerPath": "/run/secrets", "readOnly": false }
]
```

### 2. Inject the secret as the env var the wrapper reads

```jsonc
"secrets": [
  { "name": "DB_PASSWORD_SECRET", "valueFrom": "<db_password secret ARN>" }
]
```

### 3. Set the non-secret env (NO `DB_PASSWORD`)

```jsonc
"environment": [
  { "name": "APP_MODE",   "value": "hardened" },
  { "name": "DB_BACKEND", "value": "pg" },
  { "name": "DB_HOST",    "value": "<rds endpoint>" },
  { "name": "DB_PORT",    "value": "5432" },
  { "name": "DB_NAME",    "value": "<cfg db name>" },
  { "name": "DB_USER",    "value": "<cfg db user>" }
]
```

### 4. Override the container `command` to run the wrapper

The task-definition `command` is an **ordered JSON array** that is passed to the
image's `ENTRYPOINT` as arguments; for this image (no custom ENTRYPOINT) it
becomes the process argv. There are two supported forms. **Form A is the
canonical one for this task** (it embeds the whole wrapper inline so the running
image needs no extra file); Form B is available if the wrapper file is baked
into / mounted onto the image.

#### Form A: inline wrapper (recommended, self-contained)

The wrapper reduced to a single POSIX `sh -c` program. `command` is the exact
three-element array below. The deploy script builds the inner program string
from `secret-entrypoint.sh` so the two never drift; the equivalent one-liner is:

```json
"command": [
  "sh",
  "-c",
  "set -eu; v=\"${DB_PASSWORD_SECRET:-}\"; [ -n \"$v\" ] || { echo 'secret-entrypoint: DB_PASSWORD_SECRET unset/empty' >&2; exit 1; }; ws=\"$(printf ' \\t\\r\\n_')\"; ws=\"${ws%_}\"; while [ -n \"$v\" ]; do c=\"${v%\"${v#?}\"}\"; case \"$ws\" in *\"$c\"*) v=\"${v#?}\" ;; *) break ;; esac; done; while [ -n \"$v\" ]; do c=\"${v#\"${v%?}\"}\"; case \"$ws\" in *\"$c\"*) v=\"${v%?}\" ;; *) break ;; esac; done; [ -n \"$v\" ] || { echo 'secret-entrypoint: DB_PASSWORD_SECRET whitespace-only' >&2; exit 1; }; mkdir -p /run/secrets; (umask 077; printf '%s' \"$v\" > /run/secrets/db_password); chmod 600 /run/secrets/db_password 2>/dev/null || true; unset v; unset DB_PASSWORD_SECRET; exec node src/server.js"
]
```

This matches the design's starting point
(`sh -c 'printf "%s" "$DB_PASSWORD_SECRET" > /run/secrets/db_password && exec node src/server.js'`)
but additionally **trims whitespace**, **unsets the env var**, creates the dir,
restricts the file mode, and fail-closes.

#### Form B: reference the committed wrapper file

If `secret-entrypoint.sh` is present inside the container (e.g. copied in by a
derived image or supplied via a mount), the `command` is simply:

```json
"command": ["sh", "/app/ops/aws/ecs/secret-entrypoint.sh"]
```

> Note: the **base hardened image is not modified by this feature** (Requirement
> 2.3 builds only from `ops/docker/hardened/Dockerfile`). The
> app image does not contain this script by default, so `deploy.ps1` uses
> **Form A** (inline) unless a path that mounts the script is explicitly
> arranged. Either way the app image's default `CMD` is left untouched.

## Secret safety

- The password value is never written to a config file, a committed file, an
  echoed command line, or a log. The deploy script passes it to Secrets Manager
  via stdin, and the task definition references it only by secret **ARN**.
- The wrapper only ever redirects the value into the file; it never echoes it.
  On error it prints the **variable name**, never the value.

## Verifying the wrapper on Windows (no cloud needed)

The wrapper is plain POSIX `sh` and can be exercised locally with Git Bash's
`sh` (or any `sh`) by pointing `SECRET_DIR` at a temp folder and stubbing the
final `exec`. Checks performed: exact trimming of spaces/tabs/CR/LF, that
`DB_PASSWORD_SECRET` is unset in the launched process, restrictive file mode,
and fail-closed exits on unset/empty/whitespace-only input.
