// test/orders.example.test.js
// Example and edge-case tests for the "My Orders" page (GET /orders) of the
// sangyshop-sessao-navegacao-ingles feature (task 4.7).
//
// Covers Requirements 3.1, 3.2, 3.3, 3.4 and 3.5:
//   - 3.1/3.2/3.5: a logged-in user sees ONLY their own orders, each with a
//                  "View (API)" link to /api/orders/:id, under the headers
//                  Product / Quantity / Total.
//   - 3.3: a user without orders sees "You have no orders yet." and no rows.
//   - 3.4: an anonymous request is redirected to /login and leaks no orders.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  createTestApp,
  agent,
  login,
  resetToggles,
  request,
  SEED,
} = require("./helpers");

// EXAMPLE -------------------------------------------------------------------
// alice (id 2) owns orders 1 and 2; order 3 belongs to bob and must not leak.
test("EXAMPLE: alice sees exactly her own orders (1 and 2) with API links and headers", async () => {
  resetToggles();
  const app = await createTestApp();
  const a = agent(app);

  const loginRes = await login(a, "alice", SEED.credentials.alice);
  assert.equal(loginRes.status, 302);
  assert.equal(loginRes.headers.location, "/products");

  const res = await a.get("/orders");
  assert.equal(res.status, 200);

  // Req 3.5: table headers present.
  assert.match(res.text, /<th>Product<\/th>/);
  assert.match(res.text, /<th>Quantity<\/th>/);
  assert.match(res.text, /<th>Total<\/th>/);

  // Req 3.1/3.2: her orders (1 and 2) are shown, each with a View (API) link.
  assert.match(res.text, /href="\/api\/orders\/1"/);
  assert.match(res.text, /href="\/api\/orders\/2"/);
  assert.match(res.text, /View \(API\)/);

  // Req 3.2: another user's order (3) must NOT be shown.
  assert.doesNotMatch(res.text, /href="\/api\/orders\/3"/);

  // Exactly two order links (1 and 2) are rendered.
  const links = res.text.match(/href="\/api\/orders\/\d+"/g) || [];
  assert.deepEqual(links.sort(), [
    'href="/api/orders/1"',
    'href="/api/orders/2"',
  ]);
});

// EDGE CASE -----------------------------------------------------------------
// admin (id 1) owns no orders in the seed -> empty-state message, no rows.
test("EDGE: admin without orders gets the empty-state message and no order rows (Req 3.3)", async () => {
  resetToggles();
  const app = await createTestApp();
  const a = agent(app);

  const loginRes = await login(a, "admin", SEED.credentials.admin);
  assert.equal(loginRes.status, 302);

  const res = await a.get("/orders");
  assert.equal(res.status, 200);
  assert.match(res.text, /You have no orders yet\./);
  // No order rows: no "View (API)" link to a concrete /api/orders/<id>.
  // (The hint paragraph legitimately mentions the literal "/api/orders/:id",
  //  so we must match the numeric-id link form, not that explanatory text.)
  assert.doesNotMatch(res.text, /href="\/api\/orders\/\d+"/);
});

// EDGE CASE -----------------------------------------------------------------
// Anonymous request -> redirected to /login, no orders leaked (Req 3.4).
test("EDGE: anonymous request to /orders redirects to /login and leaks no orders (Req 3.4)", async () => {
  resetToggles();
  const app = await createTestApp();

  const res = await request(app).get("/orders").redirects(0);
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, "/login");
  // The redirect body must not leak any order (no concrete /api/orders/<id> link).
  assert.doesNotMatch(res.text, /href="\/api\/orders\/\d+"/);
});
