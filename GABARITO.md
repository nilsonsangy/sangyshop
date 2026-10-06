# ANSWER KEY - SangyShop (OWASP Top 10:2025 from a defensive perspective)

Instructor document. Each section is an exercise: first the **attack** (defense OFF), then the
**defense** (toggle ON), and the **proof** that the same attack now fails. Every command has
been validated. Base URL: `http://localhost:3000`.

Reset all defenses to OFF (initial attack state): restart the container, or POST `value:false`
to each key at `/api/defenses/<key>`.

---

## Exercise 1 - A05:2025 Injection (SQL Injection)

**Target:** login (`/login`) and product search (`/products?q=`).

### Attack (defense OFF)
- **Login bypass:** user `admin'--` with any password. The query becomes
  `... WHERE username = 'admin'--' AND password = '...'`; the `--` comments out the rest and
  authenticates as admin.
- **Extraction via UNION in the search:**
  `/products?q=' UNION SELECT id,username,password,role FROM users --`
  Every user's password shows up as if it were a product.

### Defense
Turn on `A05_injection`. The code switches to a **prepared statement**
(`db.prepare("... WHERE username = ? AND password = ?").get(username, password)`): the input
is never interpreted as SQL.

```
curl -X POST http://localhost:3000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
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
   email and credit card leak.

### Defense
Turn on `A01_access_control`. The backend now **checks ownership**: it compares
`order.user_id` with the authenticated session user's id; only the owner (or admin) gets access.

```
curl -X POST http://localhost:3000/api/defenses/A01_access_control -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
- `GET /api/orders/3` as alice returns **403**.
- `GET /api/orders/1` (alice's own) still returns **200**: the defense does not break the legitimate function.
- **Criterion:** authorization must happen server-side, binding the resource to its owner; the
  id coming from the client is never trustworthy on its own.

---

## Exercise 3 - A03:2025 Software Supply Chain Failures

**Target:** the dependencies in `package.json` (lodash 4.17.11, minimist 1.2.0, marked 0.3.6).

### Attack / diagnosis
```
npm install          # already prints the vulnerability warning
npm audit            # detailed report: severity, CWE, dependency path
```
Identify the vulnerabilities (e.g., prototype pollution in lodash/minimist, ReDoS in marked)
and understand the risk of outdated and transitive dependencies.

### Defense
- `npm audit fix` (or manually update to the fixed versions and pin them in the lockfile).
- Discuss version pinning, committing `package-lock.json`, SBOM generation, and automated
  checks in CI.

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
curl -I http://localhost:3000/products
```
- The `X-Powered-By: Express 4.18 / SangyShop 1.0` header reveals the stack.
- Missing `Content-Security-Policy`, `X-Content-Type-Options`, etc.
- `GET /debug/boom` returns the **full stack trace** (information disclosure).

### Defense
Turn on `A02_misconfiguration`: it applies the security headers (CSP, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy), removes `X-Powered-By`, and replaces the detailed error with
a generic message.

```
curl -X POST http://localhost:3000/api/defenses/A02_misconfiguration -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Proof
```
curl -I http://localhost:3000/products   # X-Powered-By is gone; CSP and nosniff present
curl http://localhost:3000/debug/boom    # "Internal error. Please try again later."
```
- **Criterion:** compare the headers before/after and the silenced error.

---

## Exercise 5 - A09:2025 Security Logging & Alerting Failures

**Target:** login under brute force. (Ties back to lesson 12 - Wazuh/SIEM.)

### Attack (defense OFF)
Repeat several login attempts with the wrong password for `alice`:
```
for /l %i in (1,1,6) do curl -s -X POST http://localhost:3000/login -d "username=alice&password=wrong%i" -o nul
```
Open `/logs`: **nothing appears**. Without a record, the attack goes unnoticed (infinite
detection time).

### Defense
Turn on `A09_logging`: each attempt is recorded in `logs/auth.log` and, when it exceeds 5
failures in 60s for the same user/IP, it fires `ALERT brute_force_suspected`.

```
curl -X POST http://localhost:3000/api/defenses/A09_logging -H "Content-Type: application/json" -d "{\"value\":true}"
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
- SSRF, which was its own category until 2021, was consolidated into A01 in the 2025 version.
- The two new 2025 categories are A03 (Software Supply Chain Failures) and A10 (Mishandling of
  Exceptional Conditions). The lab covers A03; A10 is discussed in theory.
