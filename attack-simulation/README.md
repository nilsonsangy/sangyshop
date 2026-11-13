# attack-simulation

A cloud-provider-independent, controlled attack script for the SangyShop
teaching lab. It depends only on the HTTP address of the
user's own SangyShop **vulnerable variant** instance, never on any cloud
SDK or cloud credential.

## Security

**Only run this against a SangyShop instance you started yourself, in your
own isolated lab account or subscription, with network access restricted to
your own IP.** Running `attack.js` against any target outside the lab,
including production systems, third-party systems, or any SangyShop instance
that is not yours, is prohibited. Before running the simulated attack, consult
the AWS acceptable use policy and the AWS penetration testing policy (or the
equivalent Azure policies) currently in force, as instructed in the lab documentation.

Before sending any attack request, `attack.js` calls the target's lab marker
endpoint and refuses to continue if the marker does not match (see "The lab
marker gate" below). This is a safety check for the lab exercise. It
is not a substitute for restricting network access to your own lab, and it
does not make it acceptable to point the script at a target outside your
lab.

The script never uses a real cloud credential. The `credential-discovery`
step only reads a placeholder credential exposed by the SangyShop lab's
`/debug/config` endpoint; it never calls a real cloud API. Any further use of
that credential against an actual AWS or Azure account is performed by a
separate, cloud-specific script in `ops/aws/ir-lab/` or `ops/azure/ir-lab/`
(in this repository), not by this script.

## Purpose

`attack.js` drives a short, numbered sequence of attack steps against the
SangyShop lab so that users have a realistic incident to detect and
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
| `--readiness-max-age-hours <n>` | no | Maximum age of the readiness stamp, in hours. Default 24. See "The detection readiness gate". |
| `--ack-no-detection` | no | Run even without a valid readiness stamp. Prints a prominent warning and records it in the step log. See "The detection readiness gate". |
| `--out <dir>` | no | Output directory for the step log and the exposed-credential file. Default `attack-simulation/out/`. |
| `-h`, `--help` | no | Prints usage and exits 0. |

## The lab marker gate

Before any attack step runs, `attack.js` sends `GET /.well-known/sangyshop-lab`
to the target and checks the response with `lib/marker.js`'s `isLabMarker()`.
The target must respond with HTTP 200, a JSON body with `app: "sangyshop"`
and `mode: "vulnerable"`, and the `X-SangyShop-Lab: vulnerable-lab` header.
If any of these do not match, the script exits with code 4 before sending any
attack request. This endpoint is served by
`src/routes/lab.js` in the sangyshop repository when the app is started with
`LAB_MODE=1` and `APP_MODE=vulnerable`.

```js
// attack.js, main(): runs BEFORE any attack step, only when --dry-run is NOT set.
const markerResponse = await request(`${target}/.well-known/sangyshop-lab`, { method: "GET" });
if (!isLabMarker(markerResponse)) {
  // status !== 200, or body.app !== "sangyshop", or body.mode !== "vulnerable",
  // or the X-SangyShop-Lab header does not match "vulnerable-lab"
  return 4; // no attack request was sent
}
```

## The detection readiness gate

An attack that nobody can see teaches nothing. So, right after the lab marker
check and before any other request, `attack.js` looks for a readiness stamp on
the local file system. It makes no network call and uses no cloud CLI.

1. Run the readiness check first, from the repository root:

   ```powershell
   ./ops/aws/ir-lab/check-detection-ready.ps1 -Region us-east-1
   # Azure: ./ops/azure/ir-lab/check-detection-ready.ps1
   ```

   It is read-only. It confirms that the alert e-mail subscription is confirmed,
   the brute-force alarm has a notification action, the application log group
   exists and the trail is logging. When all four pass it exits 0 and writes the
   readiness stamp `readiness-<lab>.json` next to the lab manifest
   (`$HOME/.sangyshop-lab/`, or the folder of `LAB_MANIFEST_PATH`). The stamp
   holds the lab name, region, UTC time and the four results. It never holds the
   e-mail address.

2. Run `attack.js`. It refuses to start, with a non-zero exit code and a message
   that names `check-detection-ready.ps1`, when the stamp is missing, belongs to
   another lab or region, is older than 24 hours (change this with
   `--readiness-max-age-hours`), or records a failed check.

3. To run anyway, pass `--ack-no-detection`. The script prints a prominent
   warning, writes the warning to `out/attack-steps.jsonl` and continues. Expect
   no alert and no useful logs in that case.

`check-detection-ready.ps1` exit codes on AWS: 0 ready (stamp written), 1 a
component is missing or unusable, 2 configuration problem, 3 permission
missing, 4 the e-mail subscription is still pending confirmation. On Azure: 0
ready (stamp written), 2 configuration problem, 3 permission missing, 4 something
is not ready (the message names the script that creates it). No stamp is
written on any code other than 0.

## The attacks, step by step

The simulated attack runs five fixed, numbered steps, always in this order.
Each step is a small, pure-ish function in `attack.js` that sends a bounded
number of HTTP requests (its budget, from `lib/plan.js`'s `STEP_BUDGETS`) and
returns an outcome. Steps 2 to 5 map directly to specific OWASP Top 10:2025
categories that SangyShop teaches in its Defenses panel.

### 1. `recon`, target recognition (budget: 6 requests)

```js
async function stepRecon(step, target, limiter) {
  await limiter.acquire();
  const response = await request(`${target}/products`, { method: "GET" });
  if (response.status >= 500) errorCount++;
  ...
}
```

Sends a single `GET /products` to the product listing page. This is the
least invasive step: it only confirms the target responds and gives the
class a baseline "normal-looking" request to contrast against the noisier
steps that follow. In the logs, this is the one request that should NOT
trigger any alert; it is the control case for "what ordinary traffic looks
like."

### 2. `bruteforce`, credential stuffing against `/login` (budget: 60 requests, OWASP A07)

```js
async function stepBruteforce(step, target, limiter, username, wordlist) {
  for (const password of wordlist) {
    if (requestCount >= step.maxRequests) break;
    await limiter.acquire();
    const response = await request(`${target}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    });
    if (response.status === 302 || response.status === 200) {
      outcome = "ok"; // a login attempt "succeeded" (redirect or 200)
      break;
    }
    ...
  }
}
```

Tries to log in as `--username` (default `admin`) by posting each password
from `wordlists/passwords.txt` (20 common passwords, e.g. `123456`,
`password`, `admin123`, `sangyshop`) to `POST /login`, one request per
password, until either a password "succeeds" (HTTP 302 or 200, which
SangyShop's A09 defense treats as a logged-in redirect) or the step's
60-request budget is exhausted. This is exactly the pattern the lab's
detection stack is built to catch: the SangyShop access log records one
`auth_login` / `result=failure` line per attempt, and the CloudWatch Logs
metric filter (or Log Analytics KQL query, on Azure) counts failures per
source IP to trigger the brute-force alarm that later drives the automatic
block.

### 3. `sqli`, SQL injection on product search (budget: 12 requests, OWASP A05)

```js
const payloads = [
  "' OR '1'='1",
  "' UNION SELECT id,username,password,id FROM users --",
];
for (const payload of payloads) {
  const response = await request(`${target}/products?q=${encodeURIComponent(payload)}`, { method: "GET" });
  ...
}
```

Sends two classic SQL injection payloads as the `q` query parameter to
`GET /products`: a tautology (`' OR '1'='1`) that would widen a vulnerable
`WHERE` clause to return every row, and a `UNION SELECT` that would try to
smuggle the `users` table (including password hashes) into the product
search results. With SangyShop's A05 defense OFF, the vulnerable
parameterless query concatenates `q` directly into SQL; with the defense ON,
the parameterized query treats the payload as a literal string and returns
no matches. This is the step users replay with the defense toggled to see
the before/after contrast this lab is built around.

### 4. `idor`, insecure direct object reference (budget: 30 requests, OWASP A01)

```js
const ids = [1, 2, 3, 4, 5];
for (const id of ids) {
  const response = await request(`${target}/api/orders/${id}`, { method: "GET" });
  ...
  const response = await request(`${target}/api/users/${id}`, { method: "GET" });
  ...
}
```

Walks a small, predictable range of numeric ids (1 through 5) and requests
`GET /api/orders/:id` and `GET /api/users/:id` for each one, WITHOUT ever
authenticating or proving ownership of that id. With SangyShop's A01 defense
OFF, these endpoints return any order or user record regardless of who is
asking, exposing other customers' data. With the defense ON, each request is
checked against the caller's own identity and denied (or scoped) for ids
that are not theirs. This is the enumeration pattern of a real IDOR attack:
simply counting up through object ids and reading whatever comes back.

### 5. `credential-discovery`, reading the leaked config file (budget: 4 requests, OWASP A02/A05)

```js
const response = await request(`${target}/debug/config`, { method: "GET" });
if (response.status === 200 && response.body && typeof response.body === "object") {
  writeExposedCredential(credentialPath, response.body); // mode 0600, never printed
  found = true;
}
```

Requests `GET /debug/config`, an endpoint the lab intentionally exposes
(`src/routes/lab.js`, only when `LAB_MODE=1` and the vulnerable variant is
running) to simulate a forgotten debug/config route that leaks whatever is
in the lab's "leaked file" (`LAB_LEAKED_FILE`, a placeholder credential such
as `AKIAIOSFODNN7EXAMPLE`, never a real cloud key). If the response is a
JSON object, it is written to `out/exposed-credential.json` with owner-only
permissions (mode `0600`) and the script prints only a found/not-found
confirmation; the credential value itself is never printed to stdout or
stderr. This step stops at the discovery of the credential; it never calls
a real AWS or Azure API with it. Actually USING that leaked credential
against the cloud account is a separate, deliberate exercise performed with
`ops/aws/ir-lab/use-leaked-credential.ps1` or
`ops/azure/ir-lab/use-leaked-credential.ps1` (this repository), capped at
10 API calls and printing only operation name + status.

## Rate and volume limits

Every step's request count is capped by its own fixed budget (`recon` 6,
`bruteforce` 60, `sqli` 12, `idor` 30, `credential-discovery` 4), and the
rate of requests is throttled by a token-bucket `RateLimiter` (`lib/http.js`)
at `--rate-rps` requests per second (default 5). No matter what
`--rate-rps`/`--total-requests` are passed, `lib/plan.js` always rejects
values above the rigid ceilings of 10 requests/second and 300 requests in
total before any request is sent.

## The step log

Every step writes a `start` and an `end` line (as JSON, one object per line,
UTC timestamps) to `out/attack-steps.jsonl`. This file is meant to be
correlated with cloud logs during the detection and analysis exercise
. The schema is defined in `lib/steplog.js`:

```json
{"ts":"2026-11-11T12:00:00.000Z","step":1,"name":"recon","target":"http://localhost:3000","phase":"start","outcome":null,"requestCount":0,"errorCount":0}
{"ts":"2026-11-11T12:00:01.000Z","step":1,"name":"recon","target":"http://localhost:3000","phase":"end","outcome":"ok","requestCount":1,"errorCount":0}
```

When all steps finish, the script prints a summary (total steps executed,
start time, end time) built by `lib/steplog.js`'s `summarize()` (Requirement
13.11).

## How to run the attack

1. Make sure your SangyShop lab instance is already deployed and reachable
   (for example, after `ops/aws/ec2/deploy.ps1` or a local
   `LAB_MODE=1 APP_MODE=vulnerable` instance), and that you know its base
   URL (e.g. `http://<lab-ip>:3000` or `http://localhost:3000`).

2. From the `sangyshop` repository root, run:

   ```sh
   node attack-simulation/attack.js --target http://<lab-ip>:3000
   ```

   This runs all five steps above, in order, at the default rate (5 requests
   per second) and default total budget (150 requests), logging every step
   to `attack-simulation/out/attack-steps.jsonl`.

3. Optional flags, combined as needed:

   ```sh
   # Plan the steps without sending any real request (no marker check either):
   node attack-simulation/attack.js --target http://<lab-ip>:3000 --dry-run

   # Target a different account username in the bruteforce step:
   node attack-simulation/attack.js --target http://<lab-ip>:3000 --username alice

   # Slow the attack down (useful to watch the detection stack react in near real time):
   node attack-simulation/attack.js --target http://<lab-ip>:3000 --rate-rps 1

   # Write the logs somewhere else:
   node attack-simulation/attack.js --target http://<lab-ip>:3000 --out /tmp/my-run
   ```

4. The script refuses to run (exit code 4) if the target does not answer the
   lab marker check, so it is safe to leave the target URL as the only thing
   you have to get right. It also refuses to run without a fresh readiness
   stamp: run `ops/aws/ir-lab/check-detection-ready.ps1` (or the Azure
   equivalent) before the attack, or pass `--ack-no-detection` to proceed
   knowingly without detection.

5. After the run, open `attack-simulation/out/attack-steps.jsonl` to see the
   exact timeline (UTC) of every step, and check
   `attack-simulation/out/exposed-credential.json` if the
   `credential-discovery` step found something.

6. Now move to the incident response side: correlate this timeline against
   the cloud detection stack (CloudTrail / CloudWatch Logs / VPC Flow Logs /
   GuardDuty on AWS, or Activity Log / Log Analytics / Defender for Cloud /
   Sentinel on Azure). Run `ops/aws/ir-lab/print-response-commands.ps1` (or the
   Azure equivalent in `ops/azure/ir-lab/`) to print the matching
   native cloud CLI commands for evidence collection and containment. The commands are only
   printed, never run.

If the `credential-discovery` step finds a credential, `out/exposed-credential.json`
will contain something shaped like the lab's leaked-config file, for example:

```json
{
  "cloud": "aws",
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "note": "placeholder lab credential, not a real AWS key"
}
```

`AKIAIOSFODNN7EXAMPLE` is the placeholder credential convention used
throughout this documentation; it is never a real cloud credential.

## Output files

| File | Contents |
|---|---|
| `out/attack-steps.jsonl` | One JSON line per step start/end event, UTC timestamps. |
| `out/exposed-credential.json` | The placeholder credential found by the `credential-discovery` step, if any, written with owner-only permissions. |

Both files are generated per run and are excluded from version control (see
`attack-simulation/out/` in the repository's `.gitignore`).