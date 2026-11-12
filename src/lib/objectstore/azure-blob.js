// src/lib/objectstore/azure-blob.js
// Azure Blob Storage provider. Authenticates with DefaultAzureCredential
// (managed identity on the VM); no account keys, connection strings or SAS.
// Env: AZURE_STORAGE_ACCOUNT (required), AZURE_STORAGE_CONTAINER (required).
// Static credentials trigger a startup warning:
//   AZURE_STORAGE_KEY, AZURE_STORAGE_CONNECTION_STRING, AZURE_STORAGE_SAS_TOKEN,
//   AZURE_CLIENT_SECRET
const { isValidKey, fail, invalidKey, mapError, lazyRequire, warnStaticCredentials } = require("./common");

const STATIC_CREDENTIAL_VARS = [
  "AZURE_STORAGE_KEY",
  "AZURE_STORAGE_CONNECTION_STRING",
  "AZURE_STORAGE_SAS_TOKEN",
  "AZURE_CLIENT_SECRET",
];

function create(env) {
  warnStaticCredentials(
    env,
    "azure-blob",
    STATIC_CREDENTIAL_VARS,
    "Prefer a managed identity (short-lived tokens) instead of account keys, connection strings, SAS tokens or client secrets."
  );

  const account = env.AZURE_STORAGE_ACCOUNT;
  const containerName = env.AZURE_STORAGE_CONTAINER;
  let container = null;

  // Late require: the Azure SDKs are only loaded when this provider is used.
  function load() {
    if (!container) {
      const blob = lazyRequire("@azure/storage-blob");
      const identity = lazyRequire("@azure/identity");
      const service = new blob.BlobServiceClient(
        "https://" + account + ".blob.core.windows.net",
        new identity.DefaultAzureCredential()
      );
      container = service.getContainerClient(containerName);
    }
    return container;
  }

  function misconfigured() {
    return !account || !containerName
      ? fail("STORE_MISCONFIGURED", "AZURE_STORAGE_ACCOUNT and AZURE_STORAGE_CONTAINER must be set.")
      : null;
  }

  return {
    provider: "azure-blob",

    async put(key, body, opts = {}) {
      if (!isValidKey(key)) return invalidKey();
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const data = Buffer.isBuffer(body) ? body : Buffer.from(body);
        await load().getBlockBlobClient(key).uploadData(data, {
          blobHTTPHeaders: { blobContentType: opts.contentType || "application/octet-stream" },
        });
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
        const client = load().getBlockBlobClient(key);
        const buf = await client.downloadToBuffer();
        const props = await client.getProperties();
        return { ok: true, key, body: buf, contentType: props.contentType || "application/octet-stream" };
      } catch (e) {
        return mapError(e);
      }
    },

    async list(prefix = "") {
      if (prefix && !/^[a-z0-9._-]{0,64}$/.test(prefix)) return invalidKey();
      const bad = misconfigured();
      if (bad) return bad;
      try {
        const keys = [];
        for await (const item of load().listBlobsFlat({ prefix })) {
          keys.push(item.name);
          if (keys.length >= 100) break;
        }
        return { ok: true, keys };
      } catch (e) {
        return mapError(e);
      }
    },

    async health() {
      const bad = misconfigured();
      if (bad) return bad;
      try {
        await load().getProperties();
        return { ok: true, provider: "azure-blob", enabled: true };
      } catch (e) {
        return mapError(e);
      }
    },
  };
}

module.exports = { create, STATIC_CREDENTIAL_VARS };
