// test/snippets.livesource.property.test.js
// Property-based test for the "View Code" catalog, the invariant
// that the snippet returned by getSnippet(vuln) is a LITERAL subset of the real
// source file read live from disk (src/lib/snippets.js).
//
// getSnippet reads the mapped source file live (fs.promises.readFile) and slices
// it by textual anchors. This test independently reads the SAME source file(s)
// with fs and asserts that every piece of code the catalog returns
// (vulnRange.code, secureRange.code, and the A05 secondary ranges) is a literal
// substring of the live file content, i.e. the panel never shows text that
// diverges from the code that is actually running (R7.2).
//
// The test only reads existing source files; it creates no temp files and needs
// no cleanup (R8.4).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const path = require("path");
const fs = require("fs");

const { CATALOG, getSnippet } = require("../src/lib/snippets");

const RUNS = 100;

// Repository root of the SangyShop app (test/ -> ../).
const APP_ROOT = path.join(__dirname, "..");

// Catalog vulnerability keys: A01, A02, A03, A05, A09.
const vulnKeys = Object.keys(CATALOG);

// Read a mapped source file independently (live) so we compare getSnippet's
// output against a fresh, independent read of the same file.
function readLive(relFile) {
  return fs.readFileSync(path.join(APP_ROOT, relFile), "utf8");
}

// Feature: sangyshop-postgres-secret-ver-codigo, Property 13: Snippet matches the real source code
// Validates: Requirements 7.2
test("Property 13: every snippet range returned by getSnippet is a literal substring of the live source file", async () => {
  await fc.assert(
    fc.asyncProperty(fc.constantFrom(...vulnKeys), async (vuln) => {
      const snippet = await getSnippet(vuln);

      // The mapped primary file matches the catalog entry.
      assert.equal(snippet.file, CATALOG[vuln].file);

      // Read the primary source file independently (live from disk).
      const livePrimary = readLive(snippet.file);

      // The highlighted ranges must be literal substrings of the live file.
      assert.ok(
        livePrimary.includes(snippet.vulnRange.code),
        `vulnRange.code for ${vuln} is not a literal substring of ${snippet.file}`
      );
      assert.ok(
        livePrimary.includes(snippet.secureRange.code),
        `secureRange.code for ${vuln} is not a literal substring of ${snippet.file}`
      );

      // The ranges are non-empty (a real slice, not an empty string that would
      // trivially satisfy includes()).
      assert.ok(snippet.vulnRange.code.length > 0);
      assert.ok(snippet.secureRange.code.length > 0);

      // A05 carries a secondary example (products.js) with its own ranges; it
      // too must be a literal subset of its own live source file.
      if (snippet.secondary) {
        const liveSecondary = readLive(snippet.secondary.file);
        assert.ok(
          liveSecondary.includes(snippet.secondary.vulnRange.code),
          `secondary vulnRange.code for ${vuln} is not a literal substring of ${snippet.secondary.file}`
        );
        assert.ok(
          liveSecondary.includes(snippet.secondary.secureRange.code),
          `secondary secureRange.code for ${vuln} is not a literal substring of ${snippet.secondary.file}`
        );
        assert.ok(snippet.secondary.vulnRange.code.length > 0);
        assert.ok(snippet.secondary.secureRange.code.length > 0);
      }
    }),
    { numRuns: RUNS }
  );
});
