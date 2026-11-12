// src/lib/objectstore/s3.js
// AWS S3 provider. Credentials come from the SDK default chain (instance
// profile / task role), never from the application.
// Env: S3_BUCKET (required), AWS_REGION.
// Static long-lived credentials trigger a startup warning:
//   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
const { isValidKey, fail, invalidKey, mapError, lazyRequire, warnStaticCredentials } = require("./common");

const STATIC_CREDENTIAL_VARS = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"];

function create(env) {
  warnStaticCredentials(
    env,
    "s3",
    STATIC_CREDENTIAL_VARS,
    "Prefer short-lived credentials from an instance profile or IAM role instead of static access keys."
  );

  const bucket = env.S3_BUCKET;
  const region = env.AWS_REGION || undefined;
  let sdk = null;
  let client = null;

  // Late require: the AWS SDK is only loaded when this provider is used.
  function load() {
    if (!client) {
      sdk = lazyRequire("@aws-sdk/client-s3");
      client = new sdk.S3Client(region ? { region } : {});
    }
    return { sdk, client };
  }

  function misconfigured() {
    return !bucket ? fail("STORE_MISCONFIGURED", "S3_BUCKET is not set.") : null;
  }

  return {
    provider: "s3",

    async put(key, body, opts = {}) {
      if (!isValidKey(key)) return invalidKey();
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const { sdk: s, client: c } = load();
        await c.send(new s.PutObjectCommand({
          Bucket: bucket, Key: key, Body: body, ContentType: opts.contentType || "application/octet-stream",
        }));
        return { ok: true, key };
      } catch (e) {
        return mapError(e);
      }
    },

    async get(key) {
      if (!isValidKey(key)) return invalidKey();
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const { sdk: s, client: c } = load();
        const out = await c.send(new s.GetObjectCommand({ Bucket: bucket, Key: key }));
        const chunks = [];
        for await (const chunk of out.Body) chunks.push(Buffer.from(chunk));
        return { ok: true, key, body: Buffer.concat(chunks), contentType: out.ContentType || "application/octet-stream" };
      } catch (e) {
        return mapError(e);
      }
    },

    async list(prefix = "") {
      if (prefix && !/^[a-z0-9._-]{0,64}$/.test(prefix)) return invalidKey();
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const { sdk: s, client: c } = load();
        const out = await c.send(new s.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, MaxKeys: 100 }));
        return { ok: true, keys: (out.Contents || []).map((o) => o.Key) };
      } catch (e) {
        return mapError(e);
      }
    },

    async health() {
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const { sdk: s, client: c } = load();
        await c.send(new s.HeadBucketCommand({ Bucket: bucket }));
        return { ok: true, provider: "s3", enabled: true };
      } catch (e) {
        return mapError(e);
      }
    },
  };
}

module.exports = { create, STATIC_CREDENTIAL_VARS };
