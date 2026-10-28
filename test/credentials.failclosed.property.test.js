// test/credentials.failclosed.property.test.js
// Property-based test for the fail-closed behaviour of the hardened DB secret.
//
// In hardened mode the password is read EXCLUSIVELY from the Docker secret file
// at /run/secrets/db_password. The resolution must be fail-closed: if the file
// content is composed only of whitespace/newlines (empty after trim), OR the
// file is absent (fs.readFileSync throws ENOENT), resolve('hardened', ...) must
// throw an Error and MUST NOT return any credentials object (Requirements 5.6).
//
// fs is injected so the test never touches the real filesystem; there are no
// temporary files to clean up.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { resolve, SECRET_PATH } = require("../src/db/credentials");

const RUNS = 100;

// Arbitrary environment, including the case where DB_PASSWORD is set, to prove
// that fail-closed resolution never falls back to env or the hardcoded value.
const envArb = fc.record(
  {
    DB_HOST: fc.string(),
    DB_PORT: fc.integer({ min: 1, max: 65535 }).map(String),
    DB_NAME: fc.string(),
    DB_USER: fc.string(),
    DB_PASSWORD: fc.string(),
  },
  { requiredKeys: [] }
);

// A whitespace-only secret file content: any non-empty combination of spaces,
// tabs, carriage returns and newlines. Empty-after-trim must fail closed too.
const whitespaceArb = fc
  .array(fc.constantFrom(" ", "\t", "\r", "\n", "\f", "\v"), { minLength: 1, maxLength: 20 })
  .map((parts) => parts.join(""));

// fs stub whose readFileSync returns the given whitespace-only content.
function fsReturning(content) {
  return {
    readFileSync(path) {
      assert.equal(path, SECRET_PATH, "hardened mode must read the Docker secret path");
      return content;
    },
  };
}

// fs stub whose readFileSync throws ENOENT, simulating a missing secret file.
function fsMissing() {
  return {
    readFileSync() {
      const err = new Error("ENOENT: no such file or directory, open '" + SECRET_PATH + "'");
      err.code = "ENOENT";
      throw err;
    },
  };
}

// Assert that resolve threw and produced no credentials.
function assertFailClosed(fsStub, env) {
  let result;
  assert.throws(
    () => {
      result = resolve("hardened", { fs: fsStub, env });
    },
    Error,
    "hardened mode must throw (fail-closed) when the secret is invalid or missing"
  );
  assert.equal(result, undefined, "no credentials object may be returned when failing closed");
}

// Feature: sangyshop-postgres-secret-ver-codigo, Property 12: Fail-closed do segredo robustecido
// Validates: Requirements 5.6
test("Property 12: hardened mode fails closed for whitespace-only or missing secret", async () => {
  await fc.assert(
    fc.asyncProperty(envArb, whitespaceArb, async (env, whitespace) => {
      // Case (a): file content is only whitespace/newlines -> empty after trim.
      assertFailClosed(fsReturning(whitespace), env);

      // Case (b): secret file is absent (readFileSync throws ENOENT).
      assertFailClosed(fsMissing(), env);
    }),
    { numRuns: RUNS }
  );
});
