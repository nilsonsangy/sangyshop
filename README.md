# SangyShop

A **deliberately vulnerable** web application for teaching the **OWASP Top 10:2025** from a
**defensive (Blue Team) perspective**. Unlike a target meant only for attacking, SangyShop
ships a **Defenses panel**: each vulnerability has a *toggle*. The teaching flow is always the
same: **attack with the defense off, turn the defense on, and replay the same attack to see
the block**, comparing the behavior and inspecting the code on both sides.

> **Warning.** This application contains real vulnerabilities on purpose. Use it **only in an
> isolated environment** (your laptop / VM / WSL), **never** exposed to the internet. It is
> security training material, not a production example.

## Vulnerabilities covered (5 of the 10 categories)

| OWASP 2025 category | Where | Defense (toggle) |
|---|---|---|
| **A01** Broken Access Control (IDOR) | `/api/orders/:id`, `/api/users/:id` | resource ownership check |
| **A02** Security Misconfiguration | HTTP headers, error page | security headers + generic error |
| **A03** Software Supply Chain Failures | `package.json` | `npm audit` + version pinning |
| **A05** Injection (SQL) | login and product search | parameterized query (prepared statement) |
| **A09** Security Logging & Alerting Failures | login / brute force | authentication logging + alert |

## How to run

### Option 1 - Docker (recommended, lightest)

```
git clone https://github.com/nilsonsangy/sangyshop
cd sangyshop
docker compose up -d --build
```

Open **http://localhost:7000** (the vulnerable baseline).

To run the **hardened** variant alongside it (each variant is its own isolated Compose
project — `sangyshop-insecure` and `sangyshop-hardened` — with separate networks and volumes):

```
cp ops/docker/hardened/db_password.txt.example ops/docker/hardened/db_password.txt
# set a strong password in db_password.txt, then:
docker compose -f ops/docker/hardened/docker-compose.yml up -d --build
```

Open **http://localhost:7010** (hardened). The two Postgres services are published on `7001`
(vulnerable) and `7011` (hardened) for optional inspection.

### Option 2 - Local Node

```
git clone https://github.com/nilsonsangy/sangyshop
cd sangyshop
npm install        # note the vulnerability warning: that is the A03 exercise
npm start
```

## Application map

- `/` and `/products` - catalog (and the search vulnerable to SQLi).
- `/login` - authentication (SQLi + brute force). Accounts: `alice/alice123`, `bob/bob123`, `admin/SangyAdmin!2025`.
- `/orders` - **My Orders**: the logged-in user's orders, the visual starting point for the A01/IDOR exercise. Each order links to `/api/orders/:id`.
- `/api/orders/:id`, `/api/users/:id` - API with IDOR.
- `/defenses` - **Defenses panel**: toggles each mitigation on/off.
- `/logs` - authentication events (only appear with the A09 defense on).
- `/debug/boom` - route that raises an error, to demonstrate A02.

The navigation bar is consistent across every page and reflects the login state: when signed
out it shows **Store**, **Defenses**, **Logs** and **Login**; when signed in it also shows
**My Orders**, the current user (name and role) and **Logout**.

You can also toggle the defenses from the command line:

```
curl -X POST http://localhost:7000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
```

## Optional environment variables (cloud incident-response labs)

All of these are optional. With none of them set, SangyShop behaves exactly as before and
needs no cloud credentials.

| Variable | Default | Description |
|---|---|---|
| `STRUCTURED_LOGS` | `on` | One JSON log line per HTTP request and login attempt on stdout. Set to `off` to disable. |
| `OBJECT_STORE` | `none` | Object store provider: `none`, `s3` or `azure-blob`. With `none`, the `/media` routes are not registered. |
| `S3_BUCKET` | - | Bucket name used when `OBJECT_STORE=s3`. |
| `AWS_REGION` | - | AWS region used when `OBJECT_STORE=s3`. |
| `AZURE_STORAGE_ACCOUNT` | - | Storage account name used when `OBJECT_STORE=azure-blob`. |
| `AZURE_STORAGE_CONTAINER` | - | Blob container name used when `OBJECT_STORE=azure-blob`. |
| `LAB_MODE` | unset | Set to `1` to enable the lab routes (`/.well-known/sangyshop-lab`, `/debug/config`). Only honored when `APP_MODE` is vulnerable (the default). |
| `LAB_CLOUD` | unset | Cloud label (for example `aws` or `azure`) reported by the lab marker route. |
| `LAB_LEAKED_FILE` | `/lab/leaked.json` | File served by `/debug/config` (the "forgotten" configuration leak used in the lab). |

## For the instructor

The full step-by-step attack and defense walkthrough for each vulnerability is in
[`GABARITO.md`](GABARITO.md).

## License

MIT. Author: Prof. Nilson Sangy.
