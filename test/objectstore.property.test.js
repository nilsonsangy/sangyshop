// test/objectstore.property.test.js
// Property-based tests for the opt-in object store layer.
//
// Feature: cloud-incident-response,
// Object store disabled by default.
//
//   1. Without OBJECT_STORE (or "none"): no AWS/Azure SDK is loaded and
//      mountMedia registers no routes.
//   2. With a provider active but misconfigured or failing: errors have the
//      fixed shape { ok:false, code, message } and never carry credentials.
//   3. With the store disabled or failing, login and product listing keep
//      working.
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const express = require("express");
const fc = require("fast-check");
const { createTestApp, agent, login, resetToggles, SEED } = require("./helpers");

const RUNS = 50;
const SRC = path.join(__dirname, "..", "src");
const { createStore } = require(path.join(SRC, "lib", "objectstore", "index.js"));
const { mountMedia } = require(path.join(SRC, "routes", "media.js"));

function loadedSdkModules() {
  return Object.keys(require.cache).filter((k) =>
    /[\\/]node_modules[\\/](@aws-sdk[\\/]client-s3|@azure[\\/](storage-blob|identity))[\\/]/.test(k)
  );
}

// Installs a fake SDK module in require.cache; returns a restore function.
function fakeModule(name, exports) {
  const resolved = require.resolve(name);
  const previous = require.cache[resolved];
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [] };
  return () => {
    if (previous) require.cache[resolved] = previous;
    else delete require.cache[resolved];
  };
}

const safeToken = fc.stringMatching(/^[A-Za-z0-9]{16,40}$/).map((s) => "SECRET" + s);
const validKey = fc.stringMatching(/^[a-z0-9._-]{1,64}$/);
const disabledValue = fc.constantFrom(undefined, "", "none", "NONE", " none ");

function assertSafeFailure(result, secrets) {
  assert.equal(result.ok, false);
  assert.deepEqual(Object.keys(result).sort(), ["code", "message", "ok"]);
  assert.equal(typeof result.code, "string");
  assert.equal(typeof result.message, "string");
  const dump = JSON.stringify(result);
  for (const s of secrets) assert.ok(!dump.includes(s), "credential value leaked in error");
}

afterEach(resetToggles);

test("OBJECT_STORE unset or none loads no cloud SDK and mounts no routes", async () => {
  assert.deepEqual(loadedSdkModules(), [], "precondition: no SDK loaded yet");

  await fc.assert(
    fc.asyncProperty(disabledValue, validKey, async (value, key) => {
      const env = value === undefined ? {} : { OBJECT_STORE: value };
      const store = createStore(env);
      assert.equal(store.provider, "none");

      const app = express();
      const before = app._router ? app._router.stack.length : 0;
      assert.equal(mountMedia(app, store), false);
      const after = app._router ? app._router.stack.length : 0;
      assert.equal(after, before, "route table must be unchanged");

      assertSafeFailure(await store.get(key), []);
      assertSafeFailure(await store.put(key, Buffer.from("x")), []);
      assert.deepEqual(await store.health(), { ok: true, provider: "none", enabled: false });

      assert.deepEqual(loadedSdkModules(), [], "no SDK module may be loaded");
    }),
    { numRuns: RUNS }
  );

  // Unknown values also fall back to none and stay SDK-free.
  const unknown = createStore({ OBJECT_STORE: "ftp" });
  assert.equal(unknown.provider, "none");
  assert.deepEqual(loadedSdkModules(), []);
});

test("active but misconfigured provider returns only the fixed error shape, no credentials", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom("s3", "azure-blob"),
      safeToken,
      safeToken,
      safeToken,
      validKey,
      async (provider, a, b, c, key) => {
        // Credentials are set, but the required bucket/account settings are not.
        const env =
          provider === "s3"
            ? { OBJECT_STORE: "s3", AWS_ACCESS_KEY_ID: a, AWS_SECRET_ACCESS_KEY: b, AWS_SESSION_TOKEN: c }
            : { OBJECT_STORE: "azure-blob", AZURE_STORAGE_KEY: a, AZURE_STORAGE_SAS_TOKEN: b, AZURE_CLIENT_SECRET: c };
        const warn = console.warn;
        const warnings = [];
        console.warn = (...args) => warnings.push(args.join(" "));
        let store;
        try {
          store = createStore(env);
        } finally {
          console.warn = warn;
        }
        assert.equal(store.provider, provider);
        // The startup warning names variables but never prints values.
        for (const w of warnings) for (const s of [a, b, c]) assert.ok(!w.includes(s));

        for (const result of [
          await store.put(key, Buffer.from("x")),
          await store.get(key),
          await store.list(""),
          await store.health(),
        ]) {
          assertSafeFailure(result, [a, b, c]);
          assert.equal(result.code, "STORE_MISCONFIGURED");
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("SDK errors that echo credentials are mapped to fixed messages", async () => {
  await fc.assert(
    fc.asyncProperty(
      safeToken,
      safeToken,
      fc.constantFrom("CredentialsProviderError", "AccessDenied", "NoSuchKey", "TimeoutError", "Error"),
      validKey,
      async (secret, keyId, errName, key) => {
        class S3Client {
          async send() {
            const e = new Error("boom " + secret + " " + keyId);
            e.name = errName;
            throw e;
          }
        }
        const noop = class {};
        const restore = fakeModule("@aws-sdk/client-s3", {
          S3Client,
          PutObjectCommand: noop,
          GetObjectCommand: noop,
          ListObjectsV2Command: noop,
          HeadBucketCommand: noop,
        });
        const warn = console.warn;
        console.warn = () => {};
        try {
          const store = createStore({ OBJECT_STORE: "s3", S3_BUCKET: "lab-bucket", AWS_SECRET_ACCESS_KEY: secret });
          for (const result of [
            await store.put(key, Buffer.from("x")),
            await store.get(key),
            await store.list(""),
            await store.health(),
          ]) {
            assertSafeFailure(result, [secret, keyId]);
          }
        } finally {
          console.warn = warn;
          restore();
        }
      }
    ),
    { numRuns: RUNS }
  );
});

test("login and product listing keep working when the store is disabled or failing", async () => {
  const app = await createTestApp();

  // Failing store (S3 selected, SDK stubbed to fail): media routes answer 502 only.
  const secret = "SECRETfailingstorecredential";
  class S3Client {
    async send() {
      throw new Error("denied " + secret);
    }
  }
  const noop = class {};
  const restore = fakeModule("@aws-sdk/client-s3", {
    S3Client, PutObjectCommand: noop, GetObjectCommand: noop, ListObjectsV2Command: noop, HeadBucketCommand: noop,
  });

  try {
    const failing = createStore({ OBJECT_STORE: "s3", S3_BUCKET: "lab-bucket" });
    const disabled = createStore({});
    assert.equal(mountMedia(app, disabled), false);
    assert.equal(mountMedia(app, failing), true);

    // Disabled-store behaviour: no media route exists on a plain app.
    const plain = await createTestApp();
    assert.equal((await agent(plain).get("/media/abc")).status, 404);

    await fc.assert(
      fc.asyncProperty(fc.constantFrom("alice", "bob", "carol", "admin"), validKey, async (user, key) => {
        // The failing store answers 502 with the fixed shape and no secret.
        const res = await agent(app).get("/media/" + key);
        assert.equal(res.status, 502);
        assert.deepEqual(Object.keys(res.body).sort(), ["code", "message", "ok"]);
        assert.ok(!JSON.stringify(res.body).includes(secret));

        // Unrelated routes still behave normally on both apps.
        for (const target of [app, plain]) {
          const a = agent(target);
          const loginPage = await a.get("/login");
          assert.equal(loginPage.status, 200);
          const res2 = await login(a, user, SEED.credentials[user]);
          assert.equal(res2.status, 302);
          const products = await a.get("/products");
          assert.equal(products.status, 200);
        }
      }),
      { numRuns: 10 }
    );
  } finally {
    restore();
  }
});
