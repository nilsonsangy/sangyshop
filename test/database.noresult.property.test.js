// test/database.noresult.property.test.js
// Property-based test for the Data_Access_Module read-with-no-match behaviour.
//
//
// Read with no match returns empty
//   For any single-row read whose condition matches no row, get(...) returns an
//   empty value (absence of a record) WITHOUT throwing.
//
// This exercises the facade in src/db/database.js against the `memory` backend,
// which honours the same async contract (init/get/all/run/exec) as the `pg`
// backend. DB_BACKEND is forced to "memory" BEFORE database.js is required, so
// the suite runs without a PostgreSQL in Docker (R8).

// Force the memory backend before the Data_Access_Module (which reads
// DB_BACKEND at load time) is required.
process.env.DB_BACKEND = "memory";

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fc = require("fast-check");

const db = require(path.join(__dirname, "..", "src", "db", "database.js"));

const RUNS = 100;

// Seed facts (mirror src/db/database.js): user ids 1..4, product ids 1..5,
// order ids 1..4, and the four seed usernames. Generators below stay OUTSIDE
// these ranges so every generated condition is guaranteed to match no row.
const SEED_USERNAMES = ["admin", "alice", "bob", "carol"];

before(async () => {
  // Boot + seed the in-memory backend once; the contract is async.
  await db.init();
});

// Read with no match returns empty
test("get() with no matching row returns empty (undefined) without throwing", async () => {
  await fc.assert(
    fc.asyncProperty(
      // ids guaranteed not to exist in any seed table (all seed ids are <= 5).
      fc.integer({ min: 10001, max: 2_000_000_000 }),
      // usernames guaranteed not to match any seed user: a non-empty string
      // that is not one of the four seed usernames.
      fc
        .string({ minLength: 1, maxLength: 40 })
        .filter((s) => !SEED_USERNAMES.includes(s)),
      async (nonExistentId, nonExistentUser) => {
        // 1) Read by a non-existent id across every seeded table.
        for (const tableQuery of [
          "SELECT * FROM users WHERE id = ?",
          "SELECT * FROM products WHERE id = ?",
          "SELECT * FROM orders WHERE id = ?",
        ]) {
          const row = await db.prepare(tableQuery).get(nonExistentId);
          assert.equal(
            row,
            undefined,
            `expected undefined for "${tableQuery}" with id=${nonExistentId}`
          );
        }

        // 2) Read by a non-existent username (string condition).
        const byName = await db
          .prepare("SELECT * FROM users WHERE username = ?")
          .get(nonExistentUser);
        assert.equal(
          byName,
          undefined,
          `expected undefined for username=${JSON.stringify(nonExistentUser)}`
        );
      }
    ),
    { numRuns: RUNS }
  );
});
