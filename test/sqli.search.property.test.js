// test/sqli.search.property.test.js
// Property-based test for the A05 Injection authenticity on GET /products
// (product search exfiltration path), with the defense TURNED ON.
//
// This test exercises the parameterized product-search path, controlled
// EXCLUSIVELY by the A05_injection defense toggle:
//   - A05 ON -> Parameterized_Query: the search term is bound as a parameter
//     ("... WHERE name LIKE ? OR description LIKE ?"), so a UNION SELECT payload
//     is treated as a literal LIKE value and matches no product. It therefore
//     never exfiltrates rows from the `users` table.
//
// We assert HTTP 200 AND that the response body contains NO data originating
// from the `users` table. Care is taken because the search term itself is
// echoed back into the page (the <input value="<%= q %>"> of the search form),
// so the raw UNION SELECT string naturally appears in the HTML. We do NOT
// assert on the absence of the echoed query; instead we assert on the absence
// of actual leaked users ROWS/values — the seed passwords, credit-card numbers
// and emails, none of which are ever rendered by the products view and none of
// which appear in any product's name/description.
//
// The toggle is stubbed in memory via setToggle (no writes to defenses.json)
// and cleared with resetToggles() in afterEach. Nothing in production is
// modified; this file only observes behaviour. Runs against DB_BACKEND=memory.
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const {
  createTestApp,
  agent,
  setToggle,
  resetToggles,
} = require("./helpers");

const RUNS = 100;

// Values that live ONLY in the `users` table seed (src/db/database.js). None of
// these strings is rendered by the products view, nor is any of them present in
// a product's name/description, so if any appeared in the body it could only be
// a leaked `users` row. We check passwords, credit cards and emails — the raw
// echoed search term never contains these literals.
const USERS_SECRETS = [
  "SangyAdmin!2025",
  "alice123",
  "bob123",
  "carol123",
  "4111-1111-1111-1111",
  "5500-0000-0000-0004",
  "6011-0000-0000-0004",
  "3400-000000-00009",
  "admin@sangyshop.local",
  "alice@mail.local",
  "bob@mail.local",
  "carol@mail.local",
];

afterEach(resetToggles);

// Generator: UNION SELECT exfiltration payloads referencing the `users` table.
// We vary the leading break-out, the set/order of columns selected from users,
// and the trailing comment, to cover a broad space of classic exfiltration
// attempts — all of which must be neutralised when A05 is ON.
const unionSelectPayload = fc
  .record({
    breakout: fc.constantFrom("'", "%'", "' ", "x'", "' OR 1=1"),
    columns: fc.subarray(
      ["id", "username", "password", "email", "credit_card", "role"],
      { minLength: 1 }
    ),
    comment: fc.constantFrom("--", "-- ", "#", ""),
  })
  .map(
    ({ breakout, columns, comment }) =>
      `${breakout} UNION SELECT ${columns.join(",")} FROM users ${comment}`
  );

// Feature: sangyshop-postgres-secret-ver-codigo, Property 8: Busca parametrizada não vaza dados com defesa ligada
// Validates: Requirements 3.4, 3.6, 3.7
test("Property 8: with A05 ON, a UNION SELECT search returns 200 and leaks no users data", async () => {
  const app = await createTestApp();
  setToggle("A05_injection", true);

  await fc.assert(
    fc.asyncProperty(unionSelectPayload, async (payload) => {
      const a = agent(app);

      const res = await a.get("/products").query({ q: payload });

      // The payload is treated as a literal LIKE value: HTTP 200, no SQL error.
      assert.equal(
        res.status,
        200,
        "parameterized search must respond 200 (payload treated as a literal)"
      );

      // No value that lives only in the `users` table may appear in the body.
      // (The raw echoed search term never contains these literals.)
      for (const secret of USERS_SECRETS) {
        assert.ok(
          !res.text.includes(secret),
          `response body must not leak users data: found "${secret}"`
        );
      }
    }),
    { numRuns: RUNS }
  );

  resetToggles();
});
