// test/database.contract.property.test.js
// Property-based test for the Data_Access_Module contract (src/db/database.js).
//
// Feature: sangyshop-postgres-secret-ver-codigo, Property 2: Equivalence of the
// data access contract between backends.
//
// Property 2 states that, for any valid sequence of get/all/run/exec
// operations, the backends produce equivalent results (same rows for all, same
// single row or absence for get, same counting effect for run), preserving the
// semantics of prepare(sql).get()/.all()/.run() and exec(sql).
//
// Per the task, the pg backend is exercised only in the Docker-dependent
// integration suite; here we pin DB_BACKEND=memory and verify that the memory
// backend HONOURS that contract consistently: a run()-inserted row is then
// returned by get/all, get on an existing id returns that row, and all returns
// the full set. This is the sql.js-equivalent semantics the design documents.
//
// DB_BACKEND=memory is set at the very top, BEFORE database.js is required, so
// the facade selects the in-memory backend. No temp files are created, so there
// is nothing to clean up (R8.4).
process.env.DB_BACKEND = "memory";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const db = require("../src/db/database.js");

const RUNS = 100;

// A single shared, initialized backend. init() is idempotent (Property 1), so
// awaiting it once is enough; every property run reuses the same seeded store.
let initialized = false;
async function ready() {
  if (!initialized) {
    await db.init();
    initialized = true;
  }
}

// Seed facts (mirror src/db/database.js) used to query KNOWN rows by id/username.
const SEED_USERNAMES = ["admin", "alice", "bob", "carol"];
const SEED_USER_IDS = [1, 2, 3, 4];

// Feature: sangyshop-postgres-secret-ver-codigo, Property 2: Equivalence of the data access contract between backends
// Validates: Requirements 2.2, 8.2
test("Property 2: the data-access contract behaves consistently for get/all/run/exec sequences", async () => {
  await ready();

  // Generator over VALID operations against known seed rows plus insert-and-
  // read-back cycles. Each op is a tagged object interpreted by the model.
  const op = fc.oneof(
    // get a seed user by id (exists) -> one row with that id
    fc.constantFrom(...SEED_USER_IDS).map((id) => ({ kind: "getById", id })),
    // get a seed user by username (exists) -> one row with that username
    fc.constantFrom(...SEED_USERNAMES).map((u) => ({ kind: "getByUsername", username: u })),
    // get a user by an id that cannot exist (<= 0) -> undefined
    fc.integer({ min: -1000, max: 0 }).map((id) => ({ kind: "getMissing", id })),
    // insert a product via run(), then read it back via get/all
    fc.record({
      name: fc.string({ minLength: 1, maxLength: 40 }),
      description: fc.string({ maxLength: 60 }),
      price: fc.double({ min: 0, max: 100000, noNaN: true }),
    }).map((p) => ({ kind: "insertProduct", product: p }))
  );

  await fc.assert(
    fc.asyncProperty(fc.array(op, { minLength: 1, maxLength: 12 }), async (ops) => {
      for (const o of ops) {
        if (o.kind === "getById") {
          const row = await db.prepare("SELECT * FROM users WHERE id = ?").get(o.id);
          // get() returns ONE row (an object), matching the requested id.
          assert.equal(typeof row, "object");
          assert.ok(row);
          assert.equal(row.id, o.id);
        } else if (o.kind === "getByUsername") {
          const row = await db
            .prepare("SELECT * FROM users WHERE username = ?")
            .get(o.username);
          assert.ok(row, "existing username must return a row");
          assert.equal(row.username, o.username);
        } else if (o.kind === "getMissing") {
          const row = await db.prepare("SELECT * FROM users WHERE id = ?").get(o.id);
          // No matching row -> empty (undefined), without throwing.
          assert.equal(row, undefined);
        } else if (o.kind === "insertProduct") {
          const { name, description, price } = o.product;

          // Count before, so we can assert all() returns the FULL set after.
          const beforeAll = await db.prepare("SELECT * FROM products").all();
          assert.ok(Array.isArray(beforeAll), "all() returns an array");
          const before = beforeAll.length;

          const result = await db
            .prepare(
              "INSERT INTO products (name,description,price) VALUES (?,?,?)"
            )
            .run(name, description, price);

          // run() reports {changes} and the insert changed exactly one row.
          assert.equal(typeof result, "object");
          assert.equal(result.changes, 1);

          // all() now returns the full set: exactly one more product.
          const afterAll = await db.prepare("SELECT * FROM products").all();
          assert.equal(afterAll.length, before + 1);

          // The run()-inserted row is then returned by get/all: find it back.
          const got = await db
            .prepare(
              "SELECT * FROM products WHERE name = ? AND description = ? ORDER BY id DESC"
            )
            .get(name, description);
          assert.ok(got, "run()-inserted row must be readable via get()");
          assert.equal(got.name, name);
          assert.equal(got.description, description);

          const inAll = afterAll.some((p) => p.id === got.id);
          assert.ok(inAll, "inserted row must appear in the full all() set");
        }
      }
      return true;
    }),
    { numRuns: RUNS }
  );
});

// exec(sql) runs direct SQL (DDL/statement) honouring the same contract: it
// completes without returning rows, and its effect is visible through the
// get/all read operations. We create an auxiliary table, exec an INSERT, then
// read it back, exercising exec() alongside get/all in one sequence.
// Feature: sangyshop-postgres-secret-ver-codigo, Property 2: Equivalence of the data access contract between backends
// Validates: Requirements 2.2, 8.2
test("Property 2: exec() runs direct SQL whose effect is observable via get/all", async () => {
  await ready();

  await db.exec(
    "CREATE TABLE IF NOT EXISTS prop2_kv (k TEXT PRIMARY KEY, v TEXT)"
  );

  const kvKey = fc
    .string({ minLength: 1, maxLength: 20 })
    .map((s) => s.replace(/['\\]/g, ""))
    .filter((s) => s.length > 0);
  const kvVal = fc.string({ maxLength: 20 }).map((s) => s.replace(/['\\]/g, ""));

  await fc.assert(
    fc.asyncProperty(kvKey, kvVal, async (k, v) => {
      // Direct SQL via exec() (no bound params), equivalent to running raw SQL.
      await db.exec(
        `INSERT OR REPLACE INTO prop2_kv (k,v) VALUES ('${k}','${v}')`
      );

      // The effect is observable through the parameterized read contract.
      const row = await db.prepare("SELECT * FROM prop2_kv WHERE k = ?").get(k);
      assert.ok(row, "exec()-inserted row must be readable via get()");
      assert.equal(row.k, k);
      assert.equal(row.v, v);

      const all = await db.prepare("SELECT * FROM prop2_kv WHERE k = ?").all(k);
      assert.ok(Array.isArray(all));
      assert.equal(all.length, 1);
      return true;
    }),
    { numRuns: RUNS }
  );
});
