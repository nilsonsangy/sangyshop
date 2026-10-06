// test/navbar.example.test.js
// Example and edge-case tests for the unified navbar and the logout flow
// (task 2.7). Covers:
//   EXAMPLE   - anonymous navbar shows "Login" and omits "My Orders" (Req 2.2/2.4)
//   EXAMPLE   - the SangyShop brand (href="/products") is on every page (Req 1.5)
//   EXAMPLE   - logout while logged in -> 302 to /login (Req 2.7)
//   EDGE_CASE - rendering partials/navbar.ejs WITHOUT `user` in scope does not
//               throw and falls back to the anonymous variant (Req 1.4)
//   EDGE_CASE - logout whose session.destroy fails -> 500, error message, user
//               stays authenticated (no redirect) (Req 2.8)
//
// Uses the native node:test runner + supertest, reusing test/helpers.js
// (createTestApp, agent, login, SEED). The isolated partial render uses ejs
// directly against src/views/partials/navbar.ejs.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const ejs = require("ejs");
const express = require("express");
const request = require("supertest");

const { createTestApp, agent, login, SEED } = require("./helpers");

const SRC = path.join(__dirname, "..", "src");
const VIEWS = path.join(SRC, "views");
const NAVBAR_PARTIAL = path.join(VIEWS, "partials", "navbar.ejs");

// ---------------------------------------------------------------------------
// EXAMPLE: anonymous navbar shows "Login" and omits "My Orders" (Req 2.2/2.4)
// ---------------------------------------------------------------------------
test("EXAMPLE: anonymous navbar on GET /login shows Login and omits My Orders", async () => {
  const app = await createTestApp();
  // No login performed: the request is anonymous.
  const res = await request(app).get("/login");

  assert.equal(res.status, 200);
  // Anonymous variant exposes a login link...
  assert.match(res.text, /href="\/login"/);
  assert.match(res.text, />\s*Login\s*</);
  // ...and must NOT expose the authenticated-only My Orders entry.
  assert.doesNotMatch(res.text, /My Orders/);
  assert.doesNotMatch(res.text, /href="\/orders"/);
});

// ---------------------------------------------------------------------------
// EXAMPLE: brand present on every page with href="/products" (Req 1.5)
// ---------------------------------------------------------------------------
test('EXAMPLE: SangyShop brand with href="/products" is present on every page', async () => {
  const app = await createTestApp();

  // Anonymous pages.
  const anonPages = ["/products", "/defenses", "/logs", "/login"];
  for (const url of anonPages) {
    const res = await request(app).get(url);
    assert.equal(res.status, 200, `expected 200 for ${url}`);
    assert.match(
      res.text,
      /<a href="\/products" class="brand">SangyShop<\/a>/,
      `brand missing on ${url}`
    );
  }

  // Authenticated page: /orders requires a logged-in session (alice).
  const a = agent(app);
  await login(a, "alice", SEED.credentials.alice);
  const orders = await a.get("/orders");
  assert.equal(orders.status, 200, "expected 200 for /orders after login");
  assert.match(
    orders.text,
    /<a href="\/products" class="brand">SangyShop<\/a>/,
    "brand missing on /orders"
  );
});

// ---------------------------------------------------------------------------
// EXAMPLE: logout while logged in -> 302 to /login (Req 2.7)
// ---------------------------------------------------------------------------
test("EXAMPLE: logout while logged in redirects 302 to /login", async () => {
  const app = await createTestApp();
  const a = agent(app);
  await login(a, "alice", SEED.credentials.alice);

  const res = await a.get("/logout");
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, "/login");
});

// ---------------------------------------------------------------------------
// EDGE_CASE: rendering navbar.ejs WITHOUT `user` in scope does not throw and
// falls back to the anonymous variant (Req 1.4)
// ---------------------------------------------------------------------------
test("EDGE_CASE: navbar partial renders without `user` and falls back to anonymous", () => {
  const template = fs.readFileSync(NAVBAR_PARTIAL, "utf8");

  let html;
  // locals {} => `user` is not defined in scope. Must not throw.
  assert.doesNotThrow(() => {
    html = ejs.render(template, {}, { filename: NAVBAR_PARTIAL });
  });

  // Falls back to the anonymous variant: login link present, orders absent.
  assert.match(html, /href="\/login"/);
  assert.doesNotMatch(html, /href="\/orders"/);
  assert.doesNotMatch(html, /My Orders/);
});

// ---------------------------------------------------------------------------
// EDGE_CASE: logout whose session.destroy fails -> 500, error message, user
// stays authenticated (no redirect) (Req 2.8)
// ---------------------------------------------------------------------------
test("EDGE_CASE: logout with session.destroy error returns 500 and keeps the user authenticated", async () => {
  // Minimal Express app wired ONLY with the auth router. A middleware injects a
  // session whose destroy() always fails, so GET /logout exercises the error
  // branch. auth.js renders the `products` view on error, so the view engine
  // and views dir must be configured for the render to succeed.
  const app = express();
  app.set("view engine", "ejs");
  app.set("views", VIEWS);

  const sessionUser = { id: 2, username: "alice", role: "customer" };
  app.use((req, res, next) => {
    req.session = {
      user: sessionUser,
      destroy: (cb) => cb(new Error("boom")),
    };
    next();
  });

  app.use("/", require(path.join(SRC, "routes", "auth.js")));

  const res = await request(app).get("/logout");

  // Logout could not be completed: 500, with the error message, and no redirect.
  assert.equal(res.status, 500);
  assert.match(res.text, /Logout could not be completed\. Please try again\./);
  // The user remains authenticated: the authenticated navbar variant is shown
  // (username/role and the logout control) rather than a redirect to /login.
  assert.equal(res.headers.location, undefined);
  assert.match(res.text, /alice \(customer\)/);
  assert.match(res.text, /href="\/logout"/);
});
