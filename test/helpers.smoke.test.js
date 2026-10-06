// test/helpers.smoke.test.js
// Smoke test for the test infrastructure (task 1). It does NOT exercise feature
// behaviour yet; it only proves the helper boots an in-memory app, the session
// cookie jar works, and the A01 toggle stub flips response behaviour WITHOUT
// writing config/defenses.json.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  createTestApp,
  agent,
  login,
  setToggle,
  resetToggles,
  request,
  SEED,
} = require("./helpers");

test("createTestApp boots and serves the products page", async () => {
  const app = await createTestApp();
  const res = await request(app).get("/products");
  assert.equal(res.status, 200);
  assert.match(res.text, /SangyShop/);
});

test("cookie jar keeps the session across requests (login persists)", async () => {
  resetToggles();
  const app = await createTestApp();
  const a = agent(app);

  const loginRes = await login(a, "alice", SEED.credentials.alice);
  // Successful login redirects to /products.
  assert.equal(loginRes.status, 302);
  assert.equal(loginRes.headers.location, "/products");

  // The same agent is now authenticated: /api/my/orders must not be 401.
  const mine = await a.get("/api/my/orders");
  assert.equal(mine.status, 200);
  assert.ok(Array.isArray(mine.body));
  // alice (id 2) owns orders 1 and 2.
  assert.deepEqual(
    mine.body.map((o) => o.id).sort((x, y) => x - y),
    [1, 2]
  );
});

test("A01 toggle stub flips IDOR behaviour without writing defenses.json", async () => {
  const app = await createTestApp();
  const a = agent(app);
  await login(a, "alice", SEED.credentials.alice);

  // A01 OFF (stubbed): IDOR present -> alice can read bob's order (id 3).
  setToggle("A01_access_control", false);
  const idor = await a.get("/api/orders/3");
  assert.equal(idor.status, 200);
  assert.equal(idor.body.id, 3);

  // A01 ON (stubbed): ownership enforced -> 403 for someone else's order.
  setToggle("A01_access_control", true);
  const blocked = await a.get("/api/orders/3");
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.id, undefined);

  resetToggles();
});
