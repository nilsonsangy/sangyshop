// test/sqli.login.property.test.js
// Property-based test for the A05 Injection authenticity on POST /login
// (login bypass path).
//
// This test exercises the vulnerable login path, controlled EXCLUSIVELY by the
// A05_injection defense toggle:
//   - A05 OFF -> Vulnerable_Query: user input is concatenated into the SQL
//     string, so the payload `admin'--` comments out the password check and
//     authenticates as admin regardless of the password supplied.
//
// The login POST authenticates and redirects (302) to /products. Following the
// redirect lands on /products (200), whose authenticated navbar shows the
// logged-in user. We assert HTTP 200 after following the redirect AND that the
// authenticated state is the admin user ("admin (admin)" in the navbar).
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
  login,
  setToggle,
  resetToggles,
} = require("./helpers");

const RUNS = 100;

// The classic SQLi login-bypass payload: the trailing `--` comments out the
// `' AND password = '...'` tail of the concatenated query, so authentication
// succeeds as admin for ANY password.
const BYPASS_USERNAME = "admin'--";

afterEach(resetToggles);

// Authentic SQLi on login with the defense off (bypass)
test("with A05 OFF, admin'-- + any password authenticates as admin (200)", async () => {
  const app = await createTestApp();
  setToggle("A05_injection", false);

  await fc.assert(
    fc.asyncProperty(fc.string(), async (password) => {
      // Fresh cookie jar per iteration => independent session state.
      const a = agent(app);

      // The vulnerable concatenated query turns `admin'--` into a successful
      // login regardless of the password; login replies with a 302 redirect.
      const res = await login(a, BYPASS_USERNAME, password);
      assert.equal(
        res.status,
        302,
        "vulnerable login bypass should redirect (302) on success"
      );
      assert.equal(
        res.headers.location,
        "/products",
        "successful login redirects to /products"
      );

      // Follow the redirect: the authenticated page returns HTTP 200 and its
      // navbar reflects the established session user, admin.
      const page = await a.get("/products");
      assert.equal(page.status, 200, "authenticated page should return 200");
      assert.match(
        page.text,
        /admin \(admin\)/,
        "authenticated session user must be admin"
      );
    }),
    { numRuns: RUNS }
  );

  resetToggles();
});
