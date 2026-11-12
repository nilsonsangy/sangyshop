// src/lib/objectstore/index.js
// Object store factory. OBJECT_STORE = none (default) | s3 | azure-blob.
// Only the selected provider module is required; the cloud SDKs are loaded
// lazily inside the provider on first use.
//
// Store API: { provider, put(key, body, {contentType}), get(key), list(prefix), health() }
// Every failure is { ok:false, code, message } and never contains credentials.

function createStore(env = process.env) {
  const choice = String(env.OBJECT_STORE || "none").trim().toLowerCase();
  switch (choice) {
    case "":
    case "none":
      return require("./none").create(env);
    case "s3":
      return require("./s3").create(env);
    case "azure-blob":
      return require("./azure-blob").create(env);
    default:
      console.warn("[objectstore] Unknown OBJECT_STORE value; falling back to 'none'.");
      return require("./none").create(env);
  }
}

module.exports = { createStore };
