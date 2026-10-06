# SangyShop

A **deliberately vulnerable** web application for teaching the **OWASP Top 10:2025** from a
**defensive (Blue Team) perspective**. Unlike a target meant only for attacking, SangyShop
ships a **Defenses panel**: each vulnerability has a *toggle*. The teaching flow is always the
same: **attack with the defense off, turn the defense on, and replay the same attack to see
the block**, comparing the behavior and inspecting the code on both sides.

> **Warning.** This application contains real vulnerabilities on purpose. Use it **only in an
> isolated environment** (your laptop / VM / WSL), **never** exposed to the internet. It is
> teaching material from the Blue Team course by Strong Security Brasil.

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

Open **http://localhost:3000**.

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
curl -X POST http://localhost:3000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
```

## For the instructor

The full step-by-step attack and defense walkthrough for each vulnerability is in
[`GABARITO.md`](GABARITO.md).

## License

MIT. Author: Prof. Nilson Sangy. Blue Team course material.
