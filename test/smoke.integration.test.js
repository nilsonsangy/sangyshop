// test/smoke.integration.test.js
// Integration / smoke tests for the English navigation + session feature
// (task 17.1). Boots the full in-memory app via test/helpers.js and exercises
// the real route/template stack end to end. Covers:
//   INTEGRATION - the 5 pages render without a template error: anonymous
//                 GET /products, /defenses, /logs, /login -> 200, and after
//                 logging in as alice, GET /orders -> 200. No 500 and no
//                 template stack trace. (Req 8.3)
//   INTEGRATION - login state persists across the 5 pages in one session
//                 (cookie jar): the authenticated navbar ("alice (customer)",
//                 href /logout and /orders) is present on every page. (Req 8.5)
//   EDGE_CASE   - template-failure isolation: a route that renders a missing
//                 view falls into the error handler (500) while GET /products
//                 keeps returning 200 on the same app instance. (Req 8.4)
//
// Uses the native node:test runner + supertest and node:assert/strict,
// reusing test/helpers.js (createTestApp, agent, login, SEED).

const { test } = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");

const { createTestApp, agent, login, SEED } = require("./helpers");

// Markers that would appear in an EJS/view-engine stack trace leaking into the
// response body (vulnerable-mode error handler echoes err.stack). Their absence
// confirms no template blew up during rendering.
const TEMPLATE_STACK_MARKERS = [
  /at exports\.compile/i,
  /ejs\.js/i,
  /Could not find the include file/i,
  /Failed to lookup view/i,
  /ERROR 500 - SangyShop/i,
];

function assertNoTemplateStackTrace(res, url) {
  for (const marker of TEMPLATE_STACK_MARKERS) {
    assert.doesNotMatch(
      res.text,
      marker,
      `unexpected template/error stack trace on ${url} (matched ${marker})`
    );
  }
}

// ---------------------------------------------------------------------------
// INTEGRATION: the 5 pages render without a template error (Req 8.3)
// ---------------------------------------------------------------------------
test("INTEGRATION: all 5 pages respond 200 with no template error", async () => {
  const app = await createTestApp();

  // Anonymous pages: no session required.
  const anonPages = ["/products", "/defenses", "/logs", "/login"];
  for (const url of anonPages) {
    const res = await request(app).get(url);
    assert.equal(res.status, 200, `expected 200 for ${url}, got ${res.status}`);
    assertNoTemplateStackTrace(res, url);
  }

  // Authenticated page: /orders requires a logged-in session (alice).
  const a = agent(app);
  await login(a, "alice", SEED.credentials.alice);
  const orders = await a.get("/orders");
  assert.equal(orders.status, 200, `expected 200 for /orders, got ${orders.status}`);
  assertNoTemplateStackTrace(orders, "/orders");
});

// ---------------------------------------------------------------------------
// INTEGRATION: login state persists across the 5 pages in one session (Req 8.5)
// ---------------------------------------------------------------------------
test("INTEGRATION: login persists the authenticated navbar across all 5 pages", async () => {
  const app = await createTestApp();
  const a = agent(app); // single cookie jar => one session across all requests.

  await login(a, "alice", SEED.credentials.alice);

  // All five pages, visited within the same authenticated session.
  const pages = ["/products", "/defenses", "/logs", "/orders", "/login"];
  for (const url of pages) {
    const res = await a.get(url);
    assert.equal(res.status, 200, `expected 200 for ${url}, got ${res.status}`);

    // Authenticated navbar variant: username/role, logout control, My Orders.
    assert.match(
      res.text,
      /alice \(customer\)/,
      `expected "alice (customer)" in navbar on ${url}`
    );
    assert.match(res.text, /href="\/logout"/, `expected logout link on ${url}`);
    assert.match(res.text, /href="\/orders"/, `expected orders link on ${url}`);
  }
});

// ---------------------------------------------------------------------------
// EDGE_CASE: template-failure isolation (Req 8.4)
//
// Isolation comes from Express's per-request error handling: an exception while
// rendering one request's view is routed to the app error handler for THAT
// request only (status 500). It does not corrupt the app instance, so other
// requests keep rendering normally. We prove this on a single app instance by
// registering (ONLY in this test) a route that renders a non-existent view and
// confirming it returns 500, while GET /products still returns 200.
// ---------------------------------------------------------------------------
test("EDGE_CASE: a failing template is isolated per-request; /products still 200", async () => {
  const app = await createTestApp();

  // Test-only route: render a view that does not exist. The view engine raises
  // an error, which Express forwards to the error handler (defined in
  // createTestApp) for this request alone.
  app.get("/__render_boom__", (req, res) => {
    res.render("__inexistente__");
  });

  const boom = await request(app).get("/__render_boom__");
  assert.equal(boom.status, 500, "expected the missing-view route to return 500");

  // Same app instance: a healthy page is unaffected by the failed render above.
  const products = await request(app).get("/products");
  assert.equal(products.status, 200, "expected /products to still return 200");
  assert.match(products.text, /SangyShop/);
});
