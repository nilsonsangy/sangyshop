// test/auth.param.property.test.js
// Property-based test for the A05 Injection defense on POST /login.
//
// This test verifies the AUTHENTIC parameterized-query behaviour: with the
// A05_injection defense ON, the classic SQL injection login payload
// `admin'--` can no longer bypass authentication. The user input is bound as a
// data literal (placeholders $1/$2), so the payload never executes as SQL and
// the wrong password fails the credential check.
//
// The toggle is stubbed in memory via setToggle (no writes to defenses.json)
// and cleared with resetToggles() at the end of every test. Nothing in
// production is modified; this file only observes behaviour.
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const {
  createTestApp,
  agent,
  setToggle,
  resetToggles,
  SEED,
} = require("./helpers");

const RUNS = 100;

// The real admin password must be excluded from the generated wrong passwords,
// otherwise a correct credential pair would legitimately authenticate.
const ADMIN_PASSWORD = SEED.credentials.admin; // "SangyAdmin!2025"

afterEach(resetToggles);

// Feature: sangyshop-postgres-secret-ver-codigo, Property 7: Login parametrizado
// rejeita a injeção com defesa ligada
// Validates: Requirements 3.4, 3.5, 3.7 (also covers R8.3)
test("Property 7: with A05 ON, admin'-- plus a wrong password returns 401 and no session", async () => {
  const app = await createTestApp();
  setToggle("A05_injection", true);

  await fc.assert(
    fc.asyncProperty(
      // Any password that is NOT the real admin password.
      fc.string().filter((p) => p !== ADMIN_PASSWORD),
      async (password) => {
        const a = agent(app);

        // Classic injection username with a wrong password. With the
        // parameterized query, the payload is treated as a literal and the
        // credential check fails.
        const res = await a
          .post("/login")
          .type("form")
          .send({ username: "admin'--", password });

        // R3.4/R3.5/R3.7: the injection is rejected -> 401, not a 200/302.
        assert.equal(res.status, 401, "parameterized login must reject the injection");

        // No authenticated session was established: an authenticated-only route
        // rejects the follow-up request from the same cookie jar with 401.
        const after = await a.get("/api/orders/1");
        assert.equal(
          after.status,
          401,
          "no authenticated session should exist after a rejected login"
        );
      }
    ),
    { numRuns: RUNS }
  );

  resetToggles();
});
