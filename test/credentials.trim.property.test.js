// test/credentials.trim.property.test.js
// Property-based test for the trim normalization of the hardened DB_Secret in
// src/db/credentials.js.
//
// This test exercises how the hardened mode normalizes the PostgreSQL password
// read from the Docker secret file: leading/trailing whitespace and line
// endings must be stripped before the value is used as the connection password
// (Requirements 5.5). The filesystem (fs) is injected, so nothing on the real
// disk is read or written and there are no temporary files to clean up.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { resolve, SECRET_PATH } = require("../src/db/credentials");

const RUNS = 100;

/**
 * Build an injectable fs-like object whose readFileSync returns a fixed string
 * for the Docker secret path (and throws ENOENT for anything else, mirroring a
 * missing file). This keeps the test off the real filesystem.
 */
function fsReturning(content) {
  return {
    readFileSync(caminho) {
      if (caminho === SECRET_PATH) return content;
      const e = new Error("ENOENT: no such file, open " + caminho);
      e.code = "ENOENT";
      throw e;
    },
  };
}

// A core password with NO whitespace of any kind, so that trimming the padded
// value recovers exactly this core. Non-empty to stay inside the valid input
// space (empty cores are covered by the fail-closed property, not here).
const corePassword = fc
  .string({ minLength: 1, maxLength: 40 })
  .filter((s) => s.length > 0 && !/\s/.test(s));

// Arbitrary runs of edge whitespace: spaces, tabs, carriage returns, newlines.
const edgeWhitespace = fc
  .array(fc.constantFrom(" ", "\t", "\r", "\n"), { maxLength: 8 })
  .map((chars) => chars.join(""));

// Feature: sangyshop-postgres-secret-ver-codigo, Property 11: Normalization (trim) of the hardened secret
// Validates: Requirements 5.5
//
// For any non-blank core password surrounded by any combination of
// spaces and end-of-line characters at the start and end, resolution in
// `hardened` mode uses as the connection password exactly the core password with
// the edge whitespace removed.
test("Property 11: hardened mode trims edge whitespace/newlines to recover the core secret", async () => {
  await fc.assert(
    fc.asyncProperty(
      corePassword,
      edgeWhitespace,
      edgeWhitespace,
      async (core, left, right) => {
        // The secret file content is the core password padded with arbitrary
        // whitespace/newlines on both ends.
        const padded = left + core + right;
        const deps = { fs: fsReturning(padded), env: {} };

        const creds = resolve("hardened", deps);

        // The resolved password must be exactly the core with edge whitespace
        // stripped -- never the padded value, never partially trimmed.
        assert.equal(creds.password, core);
      }
    ),
    { numRuns: RUNS }
  );
});
