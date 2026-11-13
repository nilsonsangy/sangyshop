// test/code.unavailable.property.test.js
// Property-based test for the SangyShop "View Code" feature, the
// resilience of GET /code/:vuln when the backing source file cannot be loaded.
//
// Snippet unavailability does not bring the application down
//
// R7.7 (design "navigable fail-open"): IF the source file that backs a
// Code_Snippet cannot be loaded when the View_Code_Control is triggered, THEN
// the app shows an unavailability message, keeps the page navigable, and does
// NOT terminate the process. The seam is src/lib/snippets.js getSnippet(vuln,
// deps): deps.fs is injectable (defaults to fs.promises) so a read failure can
// be forced; the route src/routes/code.js converts the thrown error into a 200
// render of code-fragment.ejs with the `unavailable` branch (role="alert").
//
// Two complementary angles prove the property across all catalog vulns:
//
//   (a) UNIT: for every catalog vuln, calling getSnippet(vuln, { fs: a readFile
//       that always throws }) REJECTS (throws), no partial snippet is returned.
//       This is the exact seam R7.7 depends on: getSnippet must fail loudly so
//       the route can degrade gracefully.
//
//   (b) ROUTE (end to end): the live route calls getSnippet() with the DEFAULT
//       fs (no injection wired into the route), so to exercise R7.7 faithfully
//       and deterministically we temporarily repoint the catalog entry's mapped
//       file at a non-existent path. Because src/routes/code.js and
//       src/lib/snippets.js share the SAME CATALOG object instance, the live
//       GET /code/:vuln then genuinely hits readFile's ENOENT failure. We assert
//       it answers 200 (never 500), renders the unavailability alert, and that a
//       follow-up navigation still succeeds, i.e. the process stayed up and the
//       app is still navigable. The catalog mutation is always restored in a
//       finally block so no test state leaks between runs.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { CATALOG, getSnippet } = require("../src/lib/snippets");
const { createTestApp, request } = require("./helpers");

const RUNS = 100;

// All vulnerabilities in the catalog (A01, A02, A03, A05, A09). Each is a valid
// :vuln the route accepts; the unknown-vuln (404) path is out of scope here.
const CATALOG_VULNS = Object.keys(CATALOG);

// An arbitrary readFile failure: both the classic ENOENT (file missing) and a
// permission-style EACCES, as either may occur at trigger time (design table:
// "Snippet source cannot be loaded"). The stub ignores its args and always
// throws, so the forced failure is deterministic regardless of path.
const failureKind = fc.constantFrom(
  { code: "ENOENT", msg: "ENOENT: no such file or directory" },
  { code: "EACCES", msg: "EACCES: permission denied" }
);

function makeFailingFs(kind) {
  return {
    readFile: async () => {
      const err = new Error(kind.msg);
      err.code = kind.code;
      throw err;
    },
  };
}

// ---------------------------------------------------------------------------
// (a) UNIT angle: getSnippet rejects for every catalog vuln when fs read fails.
// ---------------------------------------------------------------------------
//
// For any catalog vulnerability and any forced read failure, getSnippet must
// reject (throw) rather than return a partial/empty snippet. This is the
// contract the route relies on to render the unavailability message.
test("unit: getSnippet throws for every catalog vuln when fs read fails", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(...CATALOG_VULNS),
      failureKind,
      async (vuln, kind) => {
        const deps = { fs: makeFailingFs(kind) };

        let threw = false;
        let result;
        try {
          result = await getSnippet(vuln, deps);
        } catch (_err) {
          threw = true;
        }

        assert.ok(
          threw,
          `getSnippet(${vuln}) must throw when the injected fs.readFile fails, ` +
            `but it returned: ${JSON.stringify(result)}`
        );
      }
    ),
    { numRuns: RUNS }
  );
});

// ---------------------------------------------------------------------------
// (b) ROUTE angle: GET /code/:vuln degrades to 200 + unavailability, app stays
//     navigable, process does not crash, for every catalog vuln.
// ---------------------------------------------------------------------------
//
// The route uses the default fs, so we force the failure by temporarily
// repointing the catalog entry's mapped `file` at a path that cannot be read.
// The same CATALOG instance backs both the route and getSnippet, so the live
// read genuinely fails. We restore the original file in finally on every run.
test("route: GET /code/:vuln answers 200 with unavailability and stays navigable when the source is unreadable", async () => {
  // Build the app once and reuse it across every run (performance). The catalog
  // is mutated per run and always restored, so reuse is safe.
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(...CATALOG_VULNS),
      // A non-existent target path (sentinel component ensures it never exists).
      fc.string({ minLength: 4, maxLength: 16 }).filter((s) => /^[A-Za-z0-9]+$/.test(s)),
      async (vuln, nonce) => {
        const entry = CATALOG[vuln];
        const originalFile = entry.file;
        try {
          // Repoint the mapped file at a path that cannot be loaded. ENOENT at
          // readFile time makes getSnippet throw, exercising the route's R7.7
          // fail-open branch exactly as a real missing file would.
          entry.file = `src/__no_such_dir__/${nonce}-${vuln}.missing.js`;

          const res = await request(app).get(`/code/${vuln}`);

          // Never a 500: the route converts the failure into a 200 render.
          assert.equal(
            res.status,
            200,
            `expected 200 (fail-open) for /code/${vuln} with unreadable source, got ${res.status}`
          );

          // The unavailability branch of code-fragment.ejs renders an alert.
          const body = res.text || "";
          assert.match(
            body,
            /role="alert"/,
            `unavailability alert not rendered for /code/${vuln}`
          );
          assert.match(
            body,
            /unavailable/i,
            `unavailability message not present for /code/${vuln}`
          );
          // Fail-open means NO source snippet leaked despite the read failure.
          assert.ok(
            !body.includes("code-active"),
            `a highlighted snippet was rendered despite the source being unreadable for /code/${vuln}`
          );

          // App stays navigable + process is up: a follow-up request to an
          // unrelated, healthy route still succeeds in this same process.
          const nav = await request(app).get("/products");
          assert.ok(
            nav.status < 500,
            `app not navigable after /code/${vuln} unavailability (GET /products -> ${nav.status})`
          );
        } finally {
          // Always restore the catalog so no run leaks state into the next.
          entry.file = originalFile;
        }
      }
    ),
    { numRuns: RUNS }
  );
});
