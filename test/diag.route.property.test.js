// test/diag.route.property.test.js
// Property-based tests for the SangyShop /_diag route (src/routes/diag.js),
// the HTTP surface of the posture diagnostic endpoint.
//
// Unlike test/posture.property.test.js (which drives the PURE collectors with a
// mocked `deps` layer), these tests exercise the ROUTE end to end via supertest.
// The route calls buildPostureReport() with no deps, so it reads the REAL
// process.env. To simulate "inside vs outside Kubernetes" we vary the env
// entries the collectors read (POD_NAME, POD_NAMESPACE, NODE_NAME, DB_PASSWORD)
// around each run, always saving and restoring the originals so the real
// environment is never permanently polluted. We also vary the negotiated
// representation (Accept header + ?format query).
//
// The Express app is built ONCE and reused across all runs for performance; the
// per-run variation is entirely in process.env and the request shape.
//
// Later properties are appended below.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { createTestApp, request } = require("./helpers");

const RUNS = 100;

// Env keys the posture collectors read. We snapshot/restore exactly these around
// every run so the predicate leaves process.env as it found it, even on failure.
const ENV_KEYS = ["POD_NAME", "POD_NAMESPACE", "NODE_NAME", "DB_PASSWORD"];

/** Capture the current values (or absence) of the env keys we will mutate. */
function snapshotEnv(keys) {
  const snap = {};
  for (const k of keys) {
    snap[k] = Object.prototype.hasOwnProperty.call(process.env, k)
      ? process.env[k]
      : undefined;
  }
  return snap;
}

/** Restore env keys to a previously captured snapshot (delete if was absent). */
function restoreEnv(snap) {
  for (const k of Object.keys(snap)) {
    if (snap[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = snap[k];
    }
  }
}

/**
 * Apply a simulated environment: for each key, either set it to the provided
 * value (present) or delete it (absent). Mutates process.env in place.
 */
function applyEnv(simulated) {
  for (const k of ENV_KEYS) {
    const v = simulated[k];
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
}

// An arbitrary env signal: present with an arbitrary string value, or absent
// (undefined). Covers both "inside the cluster" (Downward API injected) and
// "outside Kubernetes" (vars missing) across runs.
const envSignal = fc.option(fc.string(), { nil: undefined });

// Endpoint always responds 200 and never throws
//
// For every combination of simulated environment (inside or outside Kubernetes), a
// GET /_diag request responds with HTTP 200 and does not propagate an exception,
// regardless of which signals could be collected or which
// representation (json/html) is negotiated.
test("GET /_diag always responds 200 and never throws", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      // Simulated environment: each signal present (arbitrary value) or absent.
      fc.record({
        POD_NAME: envSignal,
        POD_NAMESPACE: envSignal,
        NODE_NAME: envSignal,
        DB_PASSWORD: envSignal,
      }),
      // Representation negotiation: vary both the ?format query and the Accept
      // header so JSON and HTML paths are both exercised.
      fc.constantFrom("json", "html", "none"),
      fc.constantFrom(
        "application/json",
        "text/html",
        "*/*",
        "application/xml",
        ""
      ),
      async (simulatedEnv, formatQuery, acceptHeader) => {
        // Snapshot BEFORE mutating so we can always roll back, even if the
        // assertion below throws (try/finally). Never pollute the real env.
        const snap = snapshotEnv(ENV_KEYS);
        try {
          applyEnv(simulatedEnv);

          let req = request(app).get("/_diag");
          if (formatQuery !== "none") {
            req = req.query({ format: formatQuery });
          }
          if (acceptHeader !== "") {
            req = req.set("Accept", acceptHeader);
          }

          // supertest resolves on any HTTP response; it only rejects on a
          // transport-level error or if the handler lets an exception escape
          // without a response. Awaiting here therefore also asserts "never
          // throws": an uncaught handler error would reject this promise.
          const res = await req;

          assert.equal(
            res.status,
            200,
            `expected 200 for /_diag (format=${formatQuery}, accept=${acceptHeader}), got ${res.status}`
          );
        } finally {
          restoreEnv(snap);
        }
      }
    ),
    { numRuns: RUNS }
  );
});
// Non-exfiltration
//
// The sensitive variables and token collectors report only PRESENCE
// (booleans), never the VALUE. This property exercises the GET /_diag route end
// to end, injecting a random DB_PASSWORD secret into process.env (with a distinct
// sentinel prefix so it does not coincide with schema keys) and a synthetic
// token value, and checks that NONE of these secret values
// appears, neither in the JSON response (?format=json) nor in the rendered HTML
// (?format=html). The token collector only checks the existence of a path and never
// reads content, so the real exfiltration surface is the DB_PASSWORD value;
// we still assert the synthetic token as well to cover any accidental
// reflection of env in the response body.

// Env keys injected by this property. Snapshot/restore exactly these
// keys to never pollute the real environment, even on failure.
const SECRET_ENV_KEYS = ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"];

/** Secret generator with a distinct sentinel prefix + random suffix. */
const dbPasswordSecret = fc
  .string({ minLength: 8, maxLength: 24 })
  .map((suffix) => `SECRET-PASSWORD-${suffix}`);

/** Synthetic token value (not read by the app, but asserted anyway). */
const syntheticToken = fc
  .string({ minLength: 8, maxLength: 24 })
  .map((suffix) => `SYNTHETIC-TOKEN-${suffix}`);

test("/_diag never exfiltrates secret values (DB_PASSWORD/token)", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      dbPasswordSecret,
      syntheticToken,
      async (dbPassword, token) => {
        // Snapshot BEFORE mutating so we can always roll back, even if the
        // assertion below throws (try/finally). Never pollute the real env.
        const snap = snapshotEnv(SECRET_ENV_KEYS);
        try {
          process.env.DB_PASSWORD = dbPassword;
          process.env.AWS_SECRET_ACCESS_KEY = token;

          // Request BOTH representations.
          const jsonRes = await request(app).get("/_diag").query({ format: "json" });
          const htmlRes = await request(app).get("/_diag").query({ format: "html" });

          // Gather all observable text from both representations.
          const jsonBody = JSON.stringify(jsonRes.body) + (jsonRes.text || "");
          const htmlBody = htmlRes.text || "";

          for (const [repr, body] of [
            ["json", jsonBody],
            ["html", htmlBody],
          ]) {
            assert.ok(
              !body.includes(dbPassword),
              `DB_PASSWORD secret value leaked into ${repr} response`
            );
            assert.ok(
              !body.includes(token),
              `synthetic token value leaked into ${repr} response`
            );
          }
        } finally {
          restoreEnv(snap);
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// Arbitrary parameters do not read paths
//
// The GET /_diag endpoint reports a FIXED set of posture signals: no
// querystring can change that set or make the route read/reflect paths
// supplied by the client. On each run, this property generates an arbitrary
// querystring that may contain keys such as `path`, `file`, `dir` (plus random
// keys) with sensitive path values (`/etc/shadow`, `/etc/passwd`,
// arbitrary strings), always carrying a distinct SENTINEL so that the
// reflection assertion is precise and not a false positive from a common substring.
//
// Assertions:
//   1. The top-level JSON keys (with arbitrary params) are EXACTLY the
//      same as a baseline request without params: only `format` changes the
//      representation, never the set of signals.
//   2. The sentinel value of the injected path does NOT appear in the JSON body or in the
//      rendered HTML: the endpoint never reads or reflects the client's path.

/**
 * Generator of a "sensitive" path value carrying a unique sentinel, so
 * that the non-reflection assertion is precise. E.g.: "/etc/SENTINEL-abc123".
 * Some values imitate classic real paths but always with the sentinel
 * embedded, so that any echo of the value in the body is detectable without
 * colliding with common substrings ("/etc", "passwd", etc.) that the app may use.
 */
const sentinelPath = fc
  .string({ minLength: 6, maxLength: 16 })
  .filter((s) => /^[A-Za-z0-9]+$/.test(s))
  .map((id) => {
    const marker = `SENTINEL-${id}`;
    return fc.sample(
      fc.constantFrom(
        `/etc/${marker}/shadow`,
        `/etc/${marker}/passwd`,
        `../../${marker}/secret`,
        `/proc/self/${marker}`,
        `${marker}-arbitrary-value`
      ),
      1
    )[0];
  });

/**
 * Generator of an arbitrary querystring (key-to-string-value object). Guarantees the
 * presence of at least one "path" key (`path`/`file`/`dir`) with a
 * sentinel value, and adds extra random pairs. Returns
 * `{ query, sentinels }`, where `sentinels` is the list of sentinel values that
 * must NOT appear in the response.
 */
const sentinelQuery = fc
  .record({
    pathKey: fc.constantFrom("path", "file", "dir"),
    pathValue: sentinelPath,
    extras: fc.dictionary(
      fc.string({ minLength: 1, maxLength: 12 }).filter((k) => k !== "format"),
      fc.oneof(fc.string({ maxLength: 20 }), sentinelPath),
      { maxKeys: 4 }
    ),
  })
  .map(({ pathKey, pathValue, extras }) => {
    const query = { ...extras, [pathKey]: pathValue };
    // Collect all sentinel values present (path key + extras).
    const sentinels = Object.values(query).filter(
      (v) => typeof v === "string" && v.includes("SENTINEL-")
    );
    return { query, sentinels };
  });

test("/_diag ignores arbitrary params: fixed signal set, never reads/reflects paths", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  // Baseline: the fixed set of top-level keys with NO query params at all.
  // Derived at runtime so the expectation tracks the real report shape
  // (meta + the 7 posture signals) without hardcoding.
  const baselineRes = await request(app).get("/_diag").query({ format: "json" });
  const expectedKeys = Object.keys(baselineRes.body).sort();

  await fc.assert(
    fc.asyncProperty(sentinelQuery, async ({ query, sentinels }) => {
      // JSON representation with arbitrary params (plus format=json).
      const jsonRes = await request(app)
        .get("/_diag")
        .query({ ...query, format: "json" });

      assert.equal(
        jsonRes.status,
        200,
        `expected 200 for /_diag with arbitrary params, got ${jsonRes.status}`
      );

      // 1. The top-level signal set is EXACTLY the baseline set, no arbitrary
      //    param can add, drop, or alter which signals are reported.
      assert.deepEqual(
        Object.keys(jsonRes.body).sort(),
        expectedKeys,
        "arbitrary query params changed the fixed set of posture signals"
      );

      // HTML representation with the same arbitrary params (plus format=html).
      const htmlRes = await request(app)
        .get("/_diag")
        .query({ ...query, format: "html" });

      const jsonText = JSON.stringify(jsonRes.body) + (jsonRes.text || "");
      const htmlText = htmlRes.text || "";

      // 2. No injected sentinel path value is ever read into or reflected by the
      //    response, neither in the JSON body nor in the rendered HTML.
      for (const sentinel of sentinels) {
        assert.ok(
          !jsonText.includes(sentinel),
          `injected path value was reflected in the JSON response: ${sentinel}`
        );
        assert.ok(
          !htmlText.includes(sentinel),
          `injected path value was reflected in the HTML response: ${sentinel}`
        );
      }
    }),
    { numRuns: RUNS }
  );
});
