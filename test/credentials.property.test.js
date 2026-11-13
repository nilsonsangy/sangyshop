// test/credentials.property.test.js
// Property-based tests for credentials.resolve(), the single dimension
// "where does the DB password come from" (src/db/credentials.js).
//
// This file covers the HARDENED mode source invariant: the
// password must come EXCLUSIVELY from the Docker secret file, even when the
// environment also defines a plaintext DB_PASSWORD. The hardcoded fallback and
// env.DB_PASSWORD must never leak into the resolved password.
//
// The filesystem and environment are injected (deps.fs / deps.env), so these
// tests never touch the real filesystem, never create temp files, and never
// open a real PostgreSQL connection (R8.4, nothing to clean up).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const {
  resolve,
  HARDCODED_PASSWORD,
  SECRET_PATH,
} = require("../src/db/credentials");

const RUNS = 100;

// A fake fs whose readFileSync returns the given secret content for the Docker
// secret path, and throws for anything else (mirrors real fs ENOENT behaviour).
function fakeFs(secretContent) {
  return {
    readFileSync(path) {
      if (path === SECRET_PATH) return secretContent;
      const err = new Error("ENOENT: no such file or directory, open " + path);
      err.code = "ENOENT";
      throw err;
    },
  };
}

// Non-whitespace secret content: at least one printable, non-whitespace char.
// We build it from a core of non-whitespace characters, optionally padded with
// surrounding whitespace, so the trimmed result is always non-empty.
const nonWhitespaceChar = fc
  .string({ minLength: 1, maxLength: 24, unit: "binary" })
  .map((s) => s.replace(/\s/gu, ""))
  .filter((s) => s.length > 0);

// Origem do segredo no modo robustecido
test("hardened mode sources the password exclusively from the secret file, ignoring env.DB_PASSWORD", async () => {
  await fc.assert(
    fc.property(
      nonWhitespaceChar, // core secret in the file (no leading/trailing whitespace)
      fc.string(), // an env DB_PASSWORD that must be IGNORED in hardened mode
      (coreSecret, envPassword) => {
        const env = {
          DB_PASSWORD: envPassword,
          // Non-secret connection params left to defaults.
        };
        const creds = resolve("hardened", { fs: fakeFs(coreSecret), env });

        // The password is exactly the (trimmed) file content.
        assert.equal(creds.password, coreSecret.trim());

        // It is NEVER the env value nor the hardcoded fallback, unless the
        // file content happens to coincide with them (which is still sourced
        // from the file, so we only assert inequality when they differ).
        if (coreSecret.trim() !== envPassword) {
          assert.notEqual(creds.password, envPassword);
        }
        if (coreSecret.trim() !== HARDCODED_PASSWORD) {
          assert.notEqual(creds.password, HARDCODED_PASSWORD);
        }
      }
    ),
    { numRuns: RUNS }
  );
});
