// test/idor.property.test.js
// Property-based tests for the A01 IDOR on GET /api/orders/:id.
//
// These tests exercise the authorization behaviour of /api/orders/:id, which is
// controlled EXCLUSIVELY by the A01_access_control defense toggle:
//   - A01 OFF -> IDOR present: any logged-in user reads any order by id.
//   - A01 ON  -> ownership enforced: non-owners (except admin) get 403.
//
// The toggle is stubbed in memory via setToggle (no writes to defenses.json) and
// cleared with resetToggles() at the end of every test. Nothing in production is
// modified; this file only observes behaviour.
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const {
  createTestApp,
  agent,
  login,
  setToggle,
  resetToggles,
  SEED,
} = require("./helpers");

const RUNS = 100;

// All usernames and the full set of existing order ids from the seed.
const USERS = ["alice", "bob", "carol", "admin"];
const ORDER_IDS = SEED.orders.map((o) => o.id); // [1, 2, 3, 4]

// Fresh session per iteration: build the app once per test for isolation, then
// log in a fresh agent so each (user, id) pair starts from a clean session.
async function loginAs(app, username) {
  const a = agent(app);
  const res = await login(a, username, SEED.credentials[username]);
  // Successful login redirects to /products (302).
  assert.equal(res.status, 302, `login for ${username} should succeed`);
  return a;
}

afterEach(resetToggles);

// Feature: sangyshop-sessao-navegacao-ingles, Property 7: IDOR preservado com A01 desligado
// Validates: Requirements 3.6, 3.7
test("Property 7: with A01 OFF, any logged-in user reads any order by id (IDOR)", async () => {
  const app = await createTestApp();
  setToggle("A01_access_control", false);

  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(...USERS),
      fc.constantFrom(...ORDER_IDS),
      async (username, id) => {
        const a = await loginAs(app, username);
        const res = await a.get(`/api/orders/${id}`);
        // IDOR: returns the order regardless of ownership.
        assert.equal(res.status, 200);
        assert.equal(res.body.id, id);
      }
    ),
    { numRuns: RUNS }
  );

  resetToggles();
});

// Feature: sangyshop-sessao-navegacao-ingles, Property 8: Bloqueio de recurso alheio com A01 ligado
// Validates: Requirements 3.8
test("Property 8: with A01 ON, a non-admin user is blocked from another user's order", async () => {
  const app = await createTestApp();
  setToggle("A01_access_control", true);

  // (non-admin user) -> order ids that do NOT belong to them.
  // Seed ownership: 1,2 -> alice(id2); 3 -> bob(id3); 4 -> carol(id4).
  const foreign = {
    alice: [3, 4],
    bob: [1, 2, 4],
    carol: [1, 2, 3],
  };
  const pairs = Object.entries(foreign).flatMap(([username, ids]) =>
    ids.map((id) => ({ username, id }))
  );

  await fc.assert(
    fc.asyncProperty(fc.constantFrom(...pairs), async ({ username, id }) => {
      const a = await loginAs(app, username);
      const res = await a.get(`/api/orders/${id}`);
      // Ownership enforced: access to a foreign order is denied.
      assert.equal(res.status, 403);
      assert.equal(res.body.id, undefined);
      assert.ok(res.body.error, "a 403 response must carry an error message");
    }),
    { numRuns: RUNS }
  );

  resetToggles();
});

// Feature: sangyshop-sessao-navegacao-ingles, Property 9: Acesso legítimo preservado com A01 ligado
// Validates: Requirements 3.9
test("Property 9: with A01 ON, a user still reads their own order", async () => {
  const app = await createTestApp();
  setToggle("A01_access_control", true);

  // (user) -> order ids they legitimately own.
  const own = {
    alice: [1, 2],
    bob: [3],
    carol: [4],
  };
  const pairs = Object.entries(own).flatMap(([username, ids]) =>
    ids.map((id) => ({ username, id }))
  );

  await fc.assert(
    fc.asyncProperty(fc.constantFrom(...pairs), async ({ username, id }) => {
      const a = await loginAs(app, username);
      const res = await a.get(`/api/orders/${id}`);
      // Legitimate access preserved: the owner reads their own order.
      assert.equal(res.status, 200);
      assert.equal(res.body.id, id);
    }),
    { numRuns: RUNS }
  );

  resetToggles();
});
