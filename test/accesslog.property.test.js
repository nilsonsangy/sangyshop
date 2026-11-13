// test/accesslog.property.test.js
// Property-based tests for the structured access log (src/lib/accesslog.js).
// stdout is captured in memory; the real defenses config file is never written
// (the A09 toggle is simulated by patching defenses.isOn in memory).
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const defenses = require("../src/lib/defenses");
const { logAuth, buildRecord, accessLogMiddleware } = require("../src/lib/accesslog");

const RUNS = 100;
const FORBIDDEN_KEYS = ["password", "cookie", "cookies", "authorization", "body", "set-cookie"];
const SECRET = "S3CR3T-SENTINEL-VALUE";

// Run fn with STRUCTURED_LOGS set; capture stdout writes. Restores everything.
function withCapture(structured, fn) {
  const prevEnv = process.env.STRUCTURED_LOGS;
  const origWrite = process.stdout.write;
  const lines = [];
  if (structured === undefined) delete process.env.STRUCTURED_LOGS;
  else process.env.STRUCTURED_LOGS = structured;
  process.stdout.write = (chunk) => {
    lines.push(String(chunk));
    return true;
  };
  let result;
  try {
    result = fn();
  } finally {
    process.stdout.write = origWrite;
    if (prevEnv === undefined) delete process.env.STRUCTURED_LOGS;
    else process.env.STRUCTURED_LOGS = prevEnv;
  }
  return { result, lines };
}

// Run fn with the A09 toggle simulated as `on`, restoring isOn afterwards.
function withA09(on, fn) {
  const orig = defenses.isOn;
  defenses.isOn = (key) => (key === "A09_logging" ? on : orig(key));
  try {
    return fn();
  } finally {
    defenses.isOn = orig;
  }
}

const smuggled = fc.record({
  password: fc.constant(SECRET),
  cookie: fc.constant(SECRET),
  cookies: fc.constant(SECRET),
  authorization: fc.constant(SECRET),
  Authorization: fc.constant(SECRET),
  body: fc.constant({ password: SECRET }),
  headers: fc.constant({ authorization: SECRET, cookie: SECRET }),
});

const authInput = fc
  .record({
    ip: fc.string({ maxLength: 100 }),
    username: fc.string({ maxLength: 200 }),
    result: fc.oneof(fc.constantFrom("success", "failure"), fc.string()),
    status: fc.option(fc.integer({ min: 100, max: 599 }), { nil: undefined }),
    request_id: fc.string({ maxLength: 16 }),
  })
  .chain((base) => smuggled.map((extra) => ({ ...base, ...extra })));

const httpInput = fc
  .record({
    ip: fc.string({ maxLength: 100 }),
    method: fc.string({ maxLength: 30 }),
    path: fc.string({ maxLength: 200 }),
    query: fc.string({ maxLength: 400 }),
    status: fc.integer({ min: 100, max: 599 }),
    duration_ms: fc.nat({ max: 100000 }),
    request_id: fc.string({ maxLength: 16 }),
  })
  .chain((base) => smuggled.map((extra) => ({ ...base, ...extra })));

function assertNoSecrets(record, line) {
  for (const k of Object.keys(record)) {
    assert.ok(!FORBIDDEN_KEYS.includes(k.toLowerCase()), "forbidden key: " + k);
  }
  assert.ok(!line.includes(SECRET), "smuggled secret leaked into output");
}

// Registro estruturado
test("auth records are valid JSON with required fields and no secrets", () => {
  fc.assert(
    fc.property(authInput, (input) => {
      const { result, lines } = withCapture("on", () => logAuth(input));
      assert.equal(lines.length, 1);
      assert.ok(lines[0].endsWith("\n"));
      assert.equal(lines[0].slice(0, -1).includes("\n"), false, "single line");
      const parsed = JSON.parse(lines[0]);
      assert.deepEqual(parsed, result);
      for (const f of ["ts", "level", "event", "ip", "username", "result", "request_id"]) {
        assert.ok(f in parsed, "missing " + f);
      }
      assert.ok(!Number.isNaN(Date.parse(parsed.ts)));
      assert.equal(parsed.event, "auth_login");
      assert.ok(parsed.result === "success" || parsed.result === "failure");
      assertNoSecrets(parsed, lines[0]);
    }),
    { numRuns: RUNS }
  );
});

test("http_request records are valid JSON with required fields and no secrets", () => {
  fc.assert(
    fc.property(httpInput, (input) => {
      const record = buildRecord("http_request", input);
      const line = JSON.stringify(record);
      const parsed = JSON.parse(line);
      for (const f of ["ts", "level", "event", "ip", "method", "path", "query", "status", "duration_ms", "request_id"]) {
        assert.ok(f in parsed, "missing " + f);
      }
      assert.equal(parsed.event, "http_request");
      assert.ok(parsed.query.length <= 256);
      assertNoSecrets(parsed, line);
    }),
    { numRuns: RUNS }
  );
});

test("middleware output never contains cookies or Authorization header", () => {
  fc.assert(
    fc.property(fc.string({ maxLength: 100 }), (path) => {
      const handlers = {};
      const req = {
        method: "GET",
        originalUrl: "/" + path.replace(/\?/g, ""),
        ip: "1.2.3.4",
        headers: { cookie: SECRET, authorization: SECRET },
        body: { password: SECRET },
      };
      const res = { statusCode: 200, on: (ev, cb) => (handlers[ev] = cb) };
      const { lines } = withCapture("on", () => {
        accessLogMiddleware(req, res, () => {});
        handlers.finish();
      });
      assert.equal(lines.length, 1);
      const parsed = JSON.parse(lines[0]);
      assertNoSecrets(parsed, lines[0]);
    }),
    { numRuns: RUNS }
  );
});

test("record structure is independent of the A09 defense toggle", () => {
  fc.assert(
    fc.property(authInput, (input) => {
      const run = (on) =>
        withA09(on, () => withCapture("on", () => logAuth(input)));
      const on = run(true);
      const off = run(false);
      assert.equal(on.lines.length, 1);
      assert.equal(off.lines.length, 1);
      const a = JSON.parse(on.lines[0]);
      const b = JSON.parse(off.lines[0]);
      assert.deepEqual(Object.keys(a), Object.keys(b));
      delete a.ts;
      delete b.ts;
      assert.deepEqual(a, b);
    }),
    { numRuns: RUNS }
  );
});

test("STRUCTURED_LOGS=off disables output", () => {
  fc.assert(
    fc.property(
      authInput,
      fc.constantFrom("off", "OFF", " Off "),
      (input, flag) => {
        const { result, lines } = withCapture(flag, () => logAuth(input));
        assert.equal(result, null);
        assert.equal(lines.length, 0);

        // Middleware: no listener registered, next still called.
        let nextCalled = false;
        let registered = false;
        const res = { statusCode: 200, on: () => (registered = true) };
        const mw = withCapture(flag, () =>
          accessLogMiddleware({ method: "GET", url: "/" }, res, () => (nextCalled = true))
        );
        assert.equal(nextCalled, true);
        assert.equal(registered, false);
        assert.equal(mw.lines.length, 0);
      }
    ),
    { numRuns: RUNS }
  );
});
