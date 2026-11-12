# attack-simulation

A cloud-provider-independent, controlled attack script for the SangyShop
teaching lab (Requirement 13). It depends only on the HTTP address of the
student's own SangyShop **Variante_Vulneravel** instance, never on any cloud
SDK or cloud credential.

## Security

**Only run this against a SangyShop instance you started yourself, in your
own isolated lab account or subscription, with network access restricted to
your own IP.** Running `attack.js` against any target outside the lab,
including production systems, third-party systems, or any SangyShop instance
that is not yours, is prohibited. Before running the Ataque_Simulado, consult
the AWS acceptable use policy and the AWS penetration testing policy (or the
equivalent Azure policies) currently in force, as instructed in the course's
Sessao_Laboratorio_IR.

Before sending any attack request, `attack.js` calls the target's lab marker
endpoint and refuses to continue if the marker does not match (see "The lab
marker gate" below). This is a safety check for the classroom exercise. It
is not a substitute for restricting network access to your own lab, and it
does not make it acceptable to point the script at a target outside your
lab.

The script never uses a real cloud credential. The `credential-discovery`
step only reads a Placeholder_Credencial exposed by the SangyShop lab's
`/debug/config` endpoint; it never calls a real cloud API. Any further use of
that credential against an actual AWS or Azure account is performed by a
separate, cloud-specific script in `aws/ir-lab/` or `azure/ir-lab/` (in the
NimbusDFIR repository), not by this script.

## Purpose

`attack.js` drives a short, numbered sequence of attack steps against the
SangyShop lab so that students have a realistic incident to detect and
analyze in CloudTrail, CloudWatch Logs, VPC Flow Logs, GuardDuty, or the
Azure equivalents. All output and error messages are in English.

## Parameters

| Flag | Required | Description |
|---|---|---|
| `--target <url>` | yes | Base URL of the SangyShop lab instance, e.g. `http://localhost:3000` or `http://<lab-ip>:3000`. Missing or empty exits with code 2 and sends no request. |
| `--dry-run` | no | Plans and logs steps without sending any real HTTP request and without checking the lab marker. |
| `--rate-rps <n>` | no | Max requests per second. Default 5. Hard ceiling 10 (`lib/plan.js`). |
| `--total-requests <n>` | no | Max total requests across all steps. Default 150. Hard ceiling 300. |
| `--username <name>` | no | Username to target in the bruteforce step. Default `admin`. |
| `--out <dir>` | no | Output directory for the step log and the exposed-credential file. Default `attack-simulation/out/`. |
| `-h`, `--help` | no | Prints usage and exits 0. |

## The lab marker gate

Before any attack step runs, `attack.js` sends `GET /.well-known/sangyshop-lab`
to the target and checks the response with `lib/marker.js`'s `isLabMarker()`.
The target must respond with HTTP 200, a JSON body with `app: "sangyshop"`
and `mode: "vulnerable"`, and the `X-SangyShop-Lab: vulnerable-lab` header.
If any of these do not match, the script exits with code 4 before sending any
attack request (Requirement 13.4). This endpoint is served by
`src/routes/lab.js` in the sangyshop repository when the app is started with
`LAB_MODE=1` and `APP_MODE=vulnerable`.

## The step log

Every step writes a `start` and an `end` line (as JSON, one object per line,
UTC timestamps) to `out/attack-steps.jsonl`. This file is meant to be
correlated with cloud logs during the detection and analysis exercise
(Requirement 13.6). The schema is defined in `lib/steplog.js`:

```json
{"ts":"2026-11-11T12:00:00.000Z","step":1,"name":"recon","target":"http://localhost:3000","phase":"start","outcome":null,"requestCount":0,"errorCount":0}
{"ts":"2026-11-11T12:00:01.000Z","step":1,"name":"recon","target":"http://localhost:3000","phase":"end","outcome":"ok","requestCount":1,"errorCount":0}
```

When all steps finish, the script prints a summary (total steps executed,
start time, end time) built by `lib/steplog.js`'s `summarize()` (Requirement
13.11).

## Steps

The Ataque_Simulado runs the following steps, in this fixed order, numbered
1 to 5:

1. `recon`: fetches the product listing page to confirm the target responds.
2. `bruteforce`: attempts login at `POST /login` with the configured
   username against the passwords in `wordlists/passwords.txt`, stopping at
   the step's request budget or on a successful login.
3. `sqli`: sends SQL injection payloads to the product search
   (`GET /products?q=...`), exercising the A05 Injection vulnerability.
4. `idor`: requests `/api/orders/:id` and `/api/users/:id` for a small range
   of ids without authorization, exercising the A01 Broken Access Control
   (IDOR) vulnerability.
5. `credential-discovery`: requests `GET /debug/config`, the lab's
   leaked-config endpoint. If a credential is found, it is written to
   `out/exposed-credential.json` with owner-only file permissions (mode
   `0600`). The credential content is never printed to stdout or stderr;
   only a confirmation that something was, or was not, found is printed.

Per-step and overall request budgets are enforced by `lib/plan.js` and never
exceed the hard ceilings of 10 requests per second and 300 requests in total,
regardless of `--rate-rps` and `--total-requests` (Requirement 13.5).

## Example usage

```sh
# Start your own lab instance first (see the sangyshop README), then:
node attack-simulation/attack.js --target http://localhost:3000

# Plan the steps without sending real requests:
node attack-simulation/attack.js --target http://localhost:3000 --dry-run
```

If the `credential-discovery` step finds a credential, `out/exposed-credential.json`
will contain something shaped like the lab's leaked-config file, for example:

```json
{
  "cloud": "aws",
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "note": "placeholder lab credential, not a real AWS key"
}
```

`AKIAIOSFODNN7EXAMPLE` is the Placeholder_Credencial convention used
throughout this course; it is never a real cloud credential.

## Output files

| File | Contents |
|---|---|
| `out/attack-steps.jsonl` | One JSON line per step start/end event, UTC timestamps. |
| `out/exposed-credential.json` | The Placeholder_Credencial found by the `credential-discovery` step, if any, written with owner-only permissions. |

Both files are generated per run and are excluded from version control (see
`attack-simulation/out/` in the repository's `.gitignore`).
