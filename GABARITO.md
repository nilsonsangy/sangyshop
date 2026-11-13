# ANSWER KEY - SangyShop (OWASP Top 10:2025 from a defensive perspective)

Instructor document. Each section is an exercise: first the **attack** (defense OFF), then the
**defense** (toggle ON), and the **proof** that the same attack now fails. Every command has
been validated. Base URL: `http://localhost:7000` (the vulnerable variant; the hardened variant runs on `http://localhost:7010`). Under Docker each variant is its own isolated Compose project (`sangyshop-insecure` and `sangyshop-hardened`), with separate networks and volumes; containers are `sangyshop-app-insecure` / `sangyshop-db-insecure` and `sangyshop-app-hardened` / `sangyshop-db-hardened`.

## Data backend: persistent PostgreSQL

The app now runs on a real **PostgreSQL 16** backend (driver `pg`), not an in-memory store.
Data lives in a named Docker volume (`db-data`), so the `users`, `products` and `orders`
rows created while using the app **survive a container restart**. The schema and seed are created
only once: a second boot over the same volume reuses the existing data without duplicating
the seed. This makes SQLi and IDOR impact concrete against a realistic, persistent database.

> Note: the automated test suite (`npm test`) runs against an in-memory backend selected by
> `DB_BACKEND=memory`, so tests stay fast and need no Docker. That in-memory backend is a
> test harness only, it is **not** the application's storage. In every deployment (insecure
> or hardened) the running app talks to PostgreSQL.

## The DB secret: insecure vs. secure

The PostgreSQL connection credentials (the **DB_Secret**) are handled two ways, on purpose,
to contrast the antipattern with the secure pattern:

- **Insecure (default / `sangyshop:insecure`).** The password sits in **plaintext** in the
  repo-root `docker-compose.yml` (`DB_PASSWORD: SangyDbPass!2025`) and there is a **hardcoded
  fallback** in the source (`src/db/credentials.js`: user `sangyshop`, password
  `SangyDbPass!2025`). The app reads the password only from the plaintext env var or that
  code fallback, it never consults a secret file. The express-session secret in
  `src/server.js` is likewise hardcoded as a secondary example of the same antipattern.
- **Secure (`sangyshop:hardened`).** The password is read **exclusively** from a Docker
  secret mounted at `/run/secrets/db_password` (`APP_MODE=hardened`), trimmed, and resolution
  is **fail-closed**: if the secret file is missing or empty after trimming, the app logs the
  error and exits non-zero instead of falling back to env or code. The hardened compose sources
  that secret from a local `db_password.txt`, which is git-ignored and never committed.

Talking point: "vulnerable apps store secrets insecurely", compare the two compose files and
the two credential paths side by side.

## "View Code" button

Every page that hosts a vulnerability shows a **"View Code"** button (present in both the
insecure and hardened builds). Clicking it opens a panel with the **real source snippet** for
that vulnerability, read live from the running code, via `GET /code/:vuln`. The highlight
follows the vulnerability's defense toggle (the Defenses Panel is the source of truth):

- Defense **OFF** -> the **vulnerable** block is highlighted (where the flaw lives).
- Defense **ON** -> the **secure** block is highlighted (the fixed code).

A03 (supply chain) has no toggle, so its snippet always highlights the dependencies block in
`package.json`. Use "View Code" during each exercise to show users exactly which lines
change between the attack and the defense.

## Resetting defenses (initial attack state)

Set every defense back to OFF before running the attacks. POST `value:false` to each key at
`/api/defenses/<key>` (keys: `A05_injection`, `A01_access_control`, `A02_misconfiguration`,
`A09_logging`). This is the reliable reset path: the defense state lives in
`config/defenses.json`, independent of the database, and the PostgreSQL volume now persists
data across restarts, so don't rely on a container restart to clear toggles.

```
curl -X POST http://localhost:7000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":false}"
curl -X POST http://localhost:7000/api/defenses/A01_access_control -H "Content-Type: application/json" -d "{\"value\":false}"
curl -X POST http://localhost:7000/api/defenses/A02_misconfiguration -H "Content-Type: application/json" -d "{\"value\":false}"
curl -X POST http://localhost:7000/api/defenses/A09_logging -H "Content-Type: application/json" -d "{\"value\":false}"
```

---

## Exercise 1 - A05:2025 Injection (SQL Injection)

**Target:** login (`/login`) and product search (`/products?q=`). Backend: PostgreSQL.

### Attack (defense OFF)
- **Login bypass:** user `admin'--` with any password. The query is built by direct string
  concatenation and becomes `... WHERE username = 'admin'--' AND password = '...'`; the `--`
  comments out the rest and authenticates as admin. Against PostgreSQL the injected statement
  runs for real.
- **Extraction via UNION in the search:**
  `/products?q=' UNION SELECT id,username,password,id FROM users --`
  Every user's password shows up as if it were a product, read straight out of the persistent
  `users` table.

### Defense
Turn on `A05_injection`. The code switches to a **prepared statement**
(`db.prepare("... WHERE username = ? AND password = ?").get(username, password)`). The data
layer translates the `?` placeholders to PostgreSQL's `$1, $2` and binds the input as
parameters, so it is never interpreted as SQL. Use **"View Code"** on the login/search page
to show the vulnerable concatenation (OFF) versus the parameterized query (ON).

```
curl -X POST http://localhost:7000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
- Login with `admin'--` returns **401**.
- The UNION search returns no password at all.
- **Criterion:** explain why parameterization separates code from data and neutralizes the vector.

---

## Exercise 2 - A01:2025 Broken Access Control (IDOR)

**Target:** `/api/orders/:id` (and `/api/users/:id`).

### Attack (defense OFF)
1. Log in as `alice` (who only has orders 1 and 2).
2. In the interface, the starting point is the **My Orders** page (`/orders`): alice sees her
   own orders and, for each one, a "View (API)" link to `/api/orders/:id`.
3. `GET /api/orders/3` - alice sees **bob**'s order. Opening a link from My Orders and changing
   the id navigates through other users' resources (IDOR). At `/api/users/3` another user's
   email and credit card leak. The rows come from the persistent PostgreSQL store.

### Defense
Turn on `A01_access_control`. The backend now **checks ownership**: it compares
`order.user_id` with the authenticated session user's id; only the owner (or admin) gets access.
"View Code" on the orders page highlights the missing check (OFF) versus the ownership check (ON).

```
curl -X POST http://localhost:7000/api/defenses/A01_access_control -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
- `GET /api/orders/3` as alice returns **403**.
- `GET /api/orders/1` (alice's own) still returns **200**: the defense does not break the legitimate function.
- **Criterion:** authorization must happen server-side, binding the resource to its owner; the
  id coming from the client is never trustworthy on its own.

---

## Exercise 3 - A03:2025 Software Supply Chain Failures

**Target:** the dependencies in `package.json` (lodash 4.17.11, minimist 1.2.0, marked 0.3.6).
Note `pg`, the PostgreSQL driver, is pinned to an exact version on purpose (version pinning is
part of the defense discussion below).

### Attack / diagnosis
```
npm install          # already prints the vulnerability warning
npm audit            # detailed report: severity, CWE, dependency path
```
Identify the vulnerabilities (e.g., prototype pollution in lodash/minimist, ReDoS in marked)
and understand the risk of outdated and transitive dependencies. "View Code" on the A03 entry
shows the `package.json` dependencies block (no toggle here).

### Defense
- `npm audit fix` (or manually update to the fixed versions and pin them in the lockfile).
- Discuss version pinning (the exact-pinned `pg` is a good example), committing
  `package-lock.json`, SBOM generation, and automated checks in CI.

### Proof
```
npm audit            # after the fix, the number of vulnerabilities drops (ideally to zero)
```
- **Criterion:** show the `npm audit` before/after and explain the update and pinning policy
  that prevents regression.

---

## Exercise 4 - A02:2025 Security Misconfiguration

**Target:** HTTP headers and the error page.

### Attack (defense OFF)
```
curl -I http://localhost:7000/products
```
- The `X-Powered-By: Express 4.18 / SangyShop 1.0` header reveals the stack.
- Missing `Content-Security-Policy`, `X-Content-Type-Options`, etc.
- `GET /debug/boom` returns the **full stack trace** (information disclosure). In the insecure
  build, a raw SQL error from the vulnerable path can also leak PostgreSQL details.

### Defense
Turn on `A02_misconfiguration`: it applies the security headers (CSP, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy), removes `X-Powered-By`, and replaces the detailed error with
a generic message. "View Code" on the diag / error page contrasts the leaky setup (OFF) with
the hardened headers and generic error (ON).

```
curl -X POST http://localhost:7000/api/defenses/A02_misconfiguration -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
```
curl -I http://localhost:7000/products   # X-Powered-By is gone; CSP and nosniff present
curl http://localhost:7000/debug/boom    # "Internal error. Please try again later."
```
- **Criterion:** compare the headers before/after and the silenced error.

---

## Exercise 5 - A09:2025 Security Logging & Alerting Failures

**Target:** login under brute force. (Detection of this pattern is a typical SIEM use case, for example with Wazuh.)

### Attack (defense OFF)
Repeat several login attempts with the wrong password for `alice`:
```
for /l %i in (1,1,6) do curl -s -X POST http://localhost:7000/login -d "username=alice&password=wrong%i" -o nul
```
Open `/logs`: **nothing appears**. Without a record, the attack goes unnoticed (infinite
detection time).

### Defense
Turn on `A09_logging`: each attempt is recorded in `logs/auth.log` and, when it exceeds 5
failures in 60s for the same user/IP, it fires `ALERT brute_force_suspected`. "View Code" on
the `/logs` page shows the no-op path (OFF) versus the recording + alerting path (ON).

```
curl -X POST http://localhost:7000/api/defenses/A09_logging -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
Repeat the brute force and open `/logs`: the `FAILURE` lines and the
`ALERT brute_force_suspected` line appear. The attack is now **visible and detectable**.
- **Criterion:** no log means no detection; with log + alert, the detect -> respond cycle
  closes. Discuss shipping these logs to a SIEM (Wazuh) as a follow-up.

---

## Notes

- Passwords are stored in plaintext in the seed on purpose (it makes the impact of SQLi and
  IDOR easier to read). In production, discuss hashing with bcrypt/argon2 (related to A07).
- The database is persistent: rows created in one session (orders, etc.) are still there after
  `docker compose restart`. To start fresh, remove the `db-data` volume
  (`docker compose down -v`) so the seed is re-applied on the next boot.
- SSRF, which was its own category until 2021, was consolidated into A01 in the 2025 version.
- The two new 2025 categories are A03 (Software Supply Chain Failures) and A10 (Mishandling of
  Exceptional Conditions). The lab covers A03; A10 is discussed in theory.
