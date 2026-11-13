// test/database.init.property.test.js
// Property-based test for the idempotency of init() and the seed on the
// Data_Access_Module (src/db/database.js), memory backend.
//
// The memory backend guarantees idempotency BY DESIGN: init() short-circuits on
// a `ready` flag (no schema re-creation) and the seed is applied only when the
// users table is empty (seedOnce via usersIsEmpty). This test exercises that
// invariant end to end: after the first init()+seed, calling init() any number
// of additional times must leave the row counts of users/products/orders
// unchanged (4/5/4) and must not recreate the schema or duplicate seed rows.
//
// DB_BACKEND must be "memory" BEFORE database.js is require()d (the backend is
// chosen once at module load from process.env.DB_BACKEND), matching the
// test/helpers.js pattern. The facade is a module singleton, and that singleton
// is exactly what carries the idempotency state we want to verify, so the
// property is asserted on the shared instance (that is the mechanism under
// test, not an artifact to work around).
//
// Credentials/env/filesystem are not touched and no temp files are created
// (R8.4, nothing to clean up).

// Select the in-memory backend before loading the module under test.
if (!process.env.DB_BACKEND) {
  process.env.DB_BACKEND = "memory";
}

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const db = require("../src/db/database.js");

const RUNS = 100;

// Expected seed counts (mirrors SEED_* in src/db/database.js): 4 users, 5
// products, 4 orders.
const EXPECTED = { users: 4, products: 5, orders: 4 };

async function countOf(table) {
  // The table name is a fixed literal from our own list, never user input.
  const row = await db.prepare(`SELECT count(*) AS n FROM ${table}`).get();
  return row.n;
}

async function counts() {
  return {
    users: await countOf("users"),
    products: await countOf("products"),
    orders: await countOf("orders"),
  };
}

// First init establishes schema + seed exactly once; capture the baseline so
// the property can assert the counts never drift from it.
before(async () => {
  await db.init();
  const baseline = await counts();
  assert.deepEqual(
    baseline,
    EXPECTED,
    "baseline seed counts must be users=4, products=5, orders=4"
  );
});

// Idempotence of initialization and seed
test("repeated init() never changes users/products/orders counts (idempotent init + seed)", async () => {
  await fc.assert(
    // N = number of ADDITIONAL init() invocations after the first seed.
    fc.asyncProperty(fc.integer({ min: 1, max: 10 }), async (n) => {
      for (let i = 0; i < n; i++) {
        await db.init();
      }
      // No schema re-creation and no seed re-insertion: counts stay at the
      // first-seed values regardless of how many times init() runs.
      const after = await counts();
      assert.deepEqual(after, EXPECTED);
    }),
    { numRuns: RUNS }
  );
});
