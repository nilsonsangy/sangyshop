// test/credentials.secretpath.property.test.js
// Property-based tests for the CONFIGURABLE hardened secret FILE path in
// src/db/credentials.js.
//
// Hardened mode reads the PostgreSQL password EXCLUSIVELY from a secret FILE.
// By default that file is the Docker secret at /run/secrets/db_password, but the
// path is configurable via env.DB_PASSWORD_FILE, which names WHERE the file is
// (like Postgres' POSTGRES_PASSWORD_FILE), NOT the value. This is used by AWS
// ECS Fargate, where the non-root container user (UID 10001) cannot write under
// the root-owned /run/secrets volume and instead uses an app-owned directory
// such as /app/secrets/db_password.
//
// These properties verify, with fs/env injected (never touching the real disk):
//   (a) when DB_PASSWORD_FILE = P (non-empty), hardened reads EXCLUSIVELY from P,
//       still trims, and still ignores env.DB_PASSWORD;
//   (b) hardened still fails closed from P on a missing file or empty-after-trim;
//   (c) when DB_PASSWORD_FILE is absent / empty / whitespace-only, hardened falls
//       back to the default /run/secrets/db_password.
//
// Validates: Requirements 5.1, 5.2, 5.5, 5.6
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { resolve, SECRET_PATH, HARDCODED_PASSWORD } = require("../src/db/credentials");

const RUNS = 100;

// A non-empty, non-whitespace file PATH that differs from the default secret
// path, so we can prove the resolver reads from exactly this path.
const customPathArb = fc
  .string({ minLength: 1, maxLength: 40 })
  .map((s) => "/app/secrets/" + s.replace(/\s/gu, "_"))
  .filter((p) => p.trim().length > 0 && p !== SECRET_PATH);

// A core password with NO whitespace, so trimming a padded value recovers it.
const corePassword = fc
  .string({ minLength: 1, maxLength: 40 })
  .filter((s) => s.length > 0 && !/\s/.test(s));

const edgeWhitespace = fc
  .array(fc.constantFrom(" ", "\t", "\r", "\n"), { maxLength: 8 })
  .map((chars) => chars.join(""));

// Whitespace-only content (non-empty) -> empty after trim.
const whitespaceArb = fc
  .array(fc.constantFrom(" ", "\t", "\r", "\n", "\f", "\v"), { minLength: 1, maxLength: 20 })
  .map((parts) => parts.join(""));

// Absent / empty / whitespace-only DB_PASSWORD_FILE values that must trigger the
// fallback to the default secret path.
const emptyishFileEnvArb = fc.oneof(
  fc.constant(undefined),
  fc.constant(""),
  fc.array(fc.constantFrom(" ", "\t", "\r", "\n"), { minLength: 1, maxLength: 8 }).map((p) => p.join(""))
);

// fs stub that returns `content` ONLY for `expectedPath`, throwing ENOENT for
// any other path. If the resolver ever reads a different path, the test fails.
function fsOnlyAt(expectedPath, content) {
  return {
    readFileSync(path) {
      if (path === expectedPath) return content;
      const err = new Error("ENOENT: no such file or directory, open '" + path + "'");
      err.code = "ENOENT";
      throw err;
    },
  };
}

// fs stub that throws ENOENT for every path (missing secret file).
function fsMissing() {
  return {
    readFileSync(path) {
      const err = new Error("ENOENT: no such file or directory, open '" + path + "'");
      err.code = "ENOENT";
      throw err;
    },
  };
}

// Property A: with DB_PASSWORD_FILE = P, hardened reads EXCLUSIVELY from P,
// trims, and ignores env.DB_PASSWORD.
test("hardened mode reads exclusively from DB_PASSWORD_FILE path, trimmed, ignoring env.DB_PASSWORD", async () => {
  await fc.assert(
    fc.property(
      customPathArb,
      corePassword,
      edgeWhitespace,
      edgeWhitespace,
      fc.string(), // an env DB_PASSWORD that must be IGNORED
      (customPath, core, left, right, envPassword) => {
        const padded = left + core + right;
        const env = { DB_PASSWORD_FILE: customPath, DB_PASSWORD: envPassword };
        // The file content is readable ONLY at customPath; reading the default
        // path would throw, so a pass proves exclusivity.
        const creds = resolve("hardened", { fs: fsOnlyAt(customPath, padded), env });

        assert.equal(creds.password, core, "must be the trimmed file content at DB_PASSWORD_FILE");

        if (core !== envPassword) {
          assert.notEqual(creds.password, envPassword, "env.DB_PASSWORD must be ignored");
        }
        if (core !== HARDCODED_PASSWORD) {
          assert.notEqual(creds.password, HARDCODED_PASSWORD, "hardcoded fallback must never leak");
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// Property B: with DB_PASSWORD_FILE = P, hardened fails closed when P is missing
// or empty-after-trim, and never falls back to env/default.
test("hardened mode fails closed on missing or empty DB_PASSWORD_FILE", async () => {
  await fc.assert(
    fc.property(customPathArb, whitespaceArb, fc.string(), (customPath, whitespace, envPassword) => {
      const env = { DB_PASSWORD_FILE: customPath, DB_PASSWORD: envPassword };

      // Case (a): file at P is whitespace-only -> empty after trim -> throws.
      let r1;
      assert.throws(() => {
        r1 = resolve("hardened", { fs: fsOnlyAt(customPath, whitespace), env });
      }, Error);
      assert.equal(r1, undefined);

      // Case (b): file at P is absent -> throws (fail-closed), never fallback.
      let r2;
      assert.throws(() => {
        r2 = resolve("hardened", { fs: fsMissing(), env });
      }, Error);
      assert.equal(r2, undefined);
    }),
    { numRuns: RUNS }
  );
});

// Property C: when DB_PASSWORD_FILE is absent / empty / whitespace-only, hardened
// falls back to the default /run/secrets/db_password.
test("hardened mode falls back to the default secret path when DB_PASSWORD_FILE is empty/absent", async () => {
  await fc.assert(
    fc.property(emptyishFileEnvArb, corePassword, (fileEnv, core) => {
      const env = {};
      if (fileEnv !== undefined) env.DB_PASSWORD_FILE = fileEnv;

      // Content is readable ONLY at the default path; if the resolver used the
      // (empty/whitespace) DB_PASSWORD_FILE value as a path, the read would
      // throw and the property would fail.
      const creds = resolve("hardened", { fs: fsOnlyAt(SECRET_PATH, core), env });
      assert.equal(creds.password, core);
    }),
    { numRuns: RUNS }
  );
});
