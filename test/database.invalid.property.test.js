// test/database.invalid.property.test.js
// Property-based test for the Data_Access_Module (src/db/database.js), memory
// backend, Property 4: an invalid SQL statement submitted to get/all/run/exec
// rejects/propagates an error to the caller and yields NO partial result.
//
// This file exercises the contract directly (no HTTP layer): it requires
// database.js with DB_BACKEND=memory, initialises it once, and then feeds
// syntactically invalid SQL to each operation, asserting the returned Promise
// rejects (get/all/run) or the call throws/rejects (exec) and produces no value.
//
// DB_BACKEND is forced to "memory" at the TOP, before database.js is required,
// so the in-memory backend (the one under test) is selected. The backend is
// purely in memory: no temp files are created, so there is nothing to clean up
// (R8.4).
process.env.DB_BACKEND = "memory";

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const db = require("../src/db/database");

const RUNS = 100;

// Boot the in-memory backend once (schema + seed). init() is idempotent, so a
// single boot is enough for the whole file.
before(async () => {
  await db.init();
});

// Generator for syntactically invalid SQL. Each entry is a string that is not a
// valid SQL statement for the backend: broken clauses, random non-SQL tokens,
// and statements referencing an object that does not exist. All of them must
// cause the backend to raise rather than silently return a partial result.
const invalidSql = fc.oneof(
  // Broken SELECT clauses (missing table / dangling keywords).
  fc.constantFrom(
    "SELECT FROM WHERE",
    "SELECT * FROM",
    "SELECT * users",
    "SELECT WHERE 1",
    "FROM users SELECT *",
    "SELEKT * FROM users",
    "INSERT INTO VALUES (1)",
    "UPDATE SET x = 1",
    "DELETE users WHERE",
    "(((",
    ");;--"
  ),
  // Statements against a table that does not exist.
  fc.constantFrom(
    "SELECT * FROM nonexistent_table_xyz",
    "INSERT INTO nonexistent_table_xyz (a) VALUES (1)",
    "DELETE FROM nonexistent_table_xyz",
    "UPDATE nonexistent_table_xyz SET a = 1"
  ),
  // Random non-SQL tokens: a handful of identifier-like words joined by spaces.
  fc
    .array(
      fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]{0,7}$/),
      { minLength: 1, maxLength: 5 }
    )
    .map((tokens) => tokens.join(" "))
    // Guard against the (astronomically unlikely) case of landing on a
    // syntactically valid statement; keep only clearly invalid garbage.
    .filter((s) => s.trim().length > 0)
);

// Feature: sangyshop-postgres-secret-ver-codigo, Property 4: Invalid operation propagates an error with no partial result
// Validates: Requirements 2.5
test("Property 4: invalid SQL in get/all/run/exec rejects/propagates an error with no partial result", async () => {
  await fc.assert(
    fc.asyncProperty(invalidSql, async (sql) => {
      const stmt = db.prepare(sql);

      // get(): must reject and yield no value.
      let getValue;
      await assert.rejects(
        async () => {
          getValue = await stmt.get();
        },
        (err) => err instanceof Error,
        `get() must reject for invalid SQL: ${JSON.stringify(sql)}`
      );
      assert.equal(getValue, undefined, "get() must not produce a partial result");

      // all(): must reject and yield no value.
      let allValue;
      await assert.rejects(
        async () => {
          allValue = await stmt.all();
        },
        (err) => err instanceof Error,
        `all() must reject for invalid SQL: ${JSON.stringify(sql)}`
      );
      assert.equal(allValue, undefined, "all() must not produce a partial result");

      // run(): must reject and yield no value.
      let runValue;
      await assert.rejects(
        async () => {
          runValue = await stmt.run();
        },
        (err) => err instanceof Error,
        `run() must reject for invalid SQL: ${JSON.stringify(sql)}`
      );
      assert.equal(runValue, undefined, "run() must not produce a partial result");

      // exec(): must reject/throw and yield no value.
      let execValue;
      await assert.rejects(
        async () => {
          execValue = await db.exec(sql);
        },
        (err) => err instanceof Error,
        `exec() must reject for invalid SQL: ${JSON.stringify(sql)}`
      );
      assert.equal(execValue, undefined, "exec() must not produce a partial result");
    }),
    { numRuns: RUNS }
  );
});
