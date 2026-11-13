// test/diag.example.test.js
// Example tests for the posture diagnostic page (GET /_diag).
//
// human-readable HTML view:
//   With a FIXED environment, GET /_diag negotiated to HTML must return an
//   HTML page (status 200) that contains the label of EVERY signal section
//   and marks the unavailable signals with an "unavailable" marker.
//
//   The fixed environment deliberately leaves POD_NAMESPACE and NODE_NAME
//   unset so that the "Pod identity" namespace/node fields are
//   unavailable and the page renders at least one "unavailable" marker.
//
// Any env mutated here is snapshotted and restored so the real process env is
// never polluted across tests.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createTestApp, request } = require("./helpers");

// Section labels rendered by src/views/diag.ejs (one <h2> per signal group).
const SIGNAL_LABELS = [
  "Execution identity",
  "Privilege indicators",
  "Filesystem",
  "ServiceAccount token",
  "Network and host",
  "Pod identity",
  "Sensitive variables",
];

// Snapshot/restore helper for the env keys this test cares about, so the real
// process env is left exactly as it was found.
function withFixedEnv(overrides, fn) {
  const keys = Object.keys(overrides);
  const saved = {};
  for (const k of keys) {
    saved[k] = Object.prototype.hasOwnProperty.call(process.env, k)
      ? process.env[k]
      : undefined;
    if (overrides[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = overrides[k];
    }
  }
  const restore = () => {
    for (const k of keys) {
      if (saved[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = saved[k];
      }
    }
  };
  return Promise.resolve()
    .then(fn)
    .finally(restore);
}

// EXAMPLE -------------------------------------------------------------------
// With POD_NAMESPACE and NODE_NAME unset (POD_NAME set), the HTML page lists
// every signal section label and marks the missing Pod fields "unavailable".
test("EXAMPLE: GET /_diag (HTML) lists all signal labels and marks unavailable signals", async () => {
  // FIXED environment: ensure the Pod namespace and node are NOT injected so
  // those fields render as unavailable; POD_NAME is present.
  await withFixedEnv(
    { POD_NAME: "sangyshop-diag-test", POD_NAMESPACE: undefined, NODE_NAME: undefined },
    async () => {
      const app = await createTestApp();

      // Negotiate HTML two ways to be robust: explicit ?format=html.
      const res = await request(app)
        .get("/_diag")
        .query({ format: "html" })
        .set("Accept", "text/html");

      // the endpoint returns an HTML page.
      assert.equal(res.status, 200);
      assert.match(res.headers["content-type"] || "", /text\/html/);
      assert.match(res.text, /<!doctype html>/i);

      // every signal section label appears on the page.
      for (const label of SIGNAL_LABELS) {
        assert.ok(
          res.text.includes(label),
          `HTML page is missing the signal label "${label}"`
        );
      }

      // unavailable signals are marked with an "unavailable" marker.
      // POD_NAMESPACE and NODE_NAME are unset, so at least the Pod
      // namespace/node fields render this marker.
      assert.match(res.text, /unavailable/i);
    }
  );
});

// EXAMPLE -------------------------------------------------------------------
// coexistence with the POD_NAME feature:
//   With POD_NAME set, hitting GET /_diag (which reads POD_NAME via the posture
//   collector and passes req.app.locals.podName to its own view) must NOT
//   mutate the shared app.locals.podName. A subsequent GET /products must still
//   render the shared header Pod badge with the pod name intact.
//
//   The test harness (createTestApp) does not wire app.locals.podName, only
//   the production src/server.js does, so we mirror that wiring explicitly
//   (app.locals.podName = process.env.POD_NAME) before exercising the routes.
test("EXAMPLE: GET /_diag does not mutate app.locals.podName and /products keeps the Pod badge", async () => {
  await withFixedEnv({ POD_NAME: "sangyshop-pod-xyz" }, async () => {
    const app = await createTestApp();

    // Mirror src/server.js wiring: the shared header Pod badge renders from the
    // global app.locals.podName (EJS views receive app.locals automatically).
    app.locals.podName = process.env.POD_NAME;
    const before = app.locals.podName;
    assert.equal(before, "sangyshop-pod-xyz");

    // Hit the diagnostic endpoint first: it reads POD_NAME and passes
    // req.app.locals.podName to its view, but must not change the shared local.
    const diagRes = await request(app).get("/_diag");
    assert.equal(diagRes.status, 200);

    // Then hit a regular page that renders the shared navbar partial.
    const productsRes = await request(app).get("/products");
    assert.equal(productsRes.status, 200);

    // the shared app.locals.podName is unchanged by the diag route.
    assert.equal(
      app.locals.podName,
      before,
      "GET /_diag must not mutate app.locals.podName"
    );
    assert.equal(app.locals.podName, "sangyshop-pod-xyz");

    // the /products header still shows the Pod badge with the pod
    // name (navbar.ejs renders <span class="pod" ...>Pod: <podName></span>).
    assert.match(
      productsRes.text,
      /class="pod"/,
      "/products is missing the Pod badge element"
    );
    assert.ok(
      productsRes.text.includes("Pod: sangyshop-pod-xyz"),
      "/products Pod badge does not show the pod name"
    );
  });
});

// SMOKE / STATIC -----------------------------------------------------------
// no external database:
//   This is a STATIC/SMOKE test (no HTTP, no server). It guards the invariant
//   that the posture module stays database-free and that the DB_PASSWORD
//   collector only probes presence.
//
//   Part A (static source scan): read the source of src/lib/posture.js and
//   assert it does NOT require/import any known database driver (nor the app's
//   own db module). Only Node core modules (fs, os, path) may be required.
//   This keeps the diagnostic operating on process + local filesystem only,
//   never on an external DB.
//
//   Part B (presence-only collector): require the module and call
//   coletarVariaveisSensiveis with an injected env holding a secret
//   DB_PASSWORD. Assert the result reports presence only
//   ({disponivel:true, dbPasswordPresente:true}) and that the serialized
//   result NEVER contains the secret value, and with DB_PASSWORD absent the
//   flag is false. No DB connection is ever opened.
const fs = require("node:fs");
const path = require("node:path");

// Absolute path to the module under test (test/ -> ../src/lib/posture.js).
const POSTURE_SRC_PATH = path.join(__dirname, "..", "src", "lib", "posture.js");

// Known database drivers (and the app's own db module) that the posture module
// must never import. If any of these appears in a require(...) call, the module
// would depend on a database.
const DB_DRIVER_DENYLIST = [
  "sql.js",
  "better-sqlite3",
  "sqlite3",
  "pg",
  "mysql",
  "mysql2",
  "mongodb",
  "mongoose",
  "sequelize",
  "knex",
  "typeorm",
  "../db/database",
];

// Core modules the posture module is allowed to require.
const CORE_ALLOWLIST = new Set(["fs", "os", "path"]);

// Extract the string literal passed to every require("...")/require('...') call
// in the given source text. Returns an array of module specifiers.
function extractRequireSpecifiers(source) {
  const specs = [];
  const re = /require\(\s*(['"])([^'"]+)\1\s*\)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    specs.push(m[2]);
  }
  return specs;
}

test("SMOKE/STATIC: src/lib/posture.js imports no database driver", () => {
  const source = fs.readFileSync(POSTURE_SRC_PATH, "utf8");
  const specifiers = extractRequireSpecifiers(source);

  // There must be at least one require() (the module requires fs/os/path).
  assert.ok(
    specifiers.length > 0,
    "expected posture.js to require its core dependencies"
  );

  // No required specifier may match the database-driver denylist.
  for (const spec of specifiers) {
    assert.ok(
      !DB_DRIVER_DENYLIST.includes(spec),
      `posture.js must not require database module "${spec}"`
    );
  }

  // Every required specifier must be one of the permitted core modules. This
  // is the strong form of the invariant: only fs/os/path are imported.
  for (const spec of specifiers) {
    assert.ok(
      CORE_ALLOWLIST.has(spec),
      `posture.js requires unexpected module "${spec}"; only ${[...CORE_ALLOWLIST].join(", ")} are allowed`
    );
  }
});

test("SMOKE/STATIC: coletarVariaveisSensiveis reports DB_PASSWORD by presence only, never the value", () => {
  const { coletarVariaveisSensiveis } = require("../src/lib/posture");

  const SECRET = "SUPER-SECRETO-123";

  // Present: an injected env carrying a secret DB_PASSWORD. The collector must
  // report presence only and never open a connection nor surface the value.
  const comSenha = coletarVariaveisSensiveis({
    process: { env: { DB_PASSWORD: SECRET } },
  });
  assert.deepEqual(comSenha, { disponivel: true, dbPasswordPresente: true });

  // The serialized result must NOT leak the secret value anywhere.
  assert.ok(
    !JSON.stringify(comSenha).includes(SECRET),
    "DB_PASSWORD value must never appear in the collector output"
  );

  // Absent: with no DB_PASSWORD in env, presence is reported as false.
  const semSenha = coletarVariaveisSensiveis({ process: { env: {} } });
  assert.deepEqual(semSenha, { disponivel: true, dbPasswordPresente: false });
});
