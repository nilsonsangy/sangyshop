// src/lib/objectstore/common.js
// Shared helpers for the object store providers: key validation, error shape
// and credential-safe error mapping. Zero dependencies.

const KEY_PATTERN = /^[a-z0-9._-]{1,64}$/;

function isValidKey(key) {
  return typeof key === "string" && KEY_PATTERN.test(key);
}

function fail(code, message) {
  return { ok: false, code, message };
}

function invalidKey() {
  return fail("INVALID_KEY", "Object key must match ^[a-z0-9._-]{1,64}$.");
}

// Maps a provider SDK error to a fixed code and a FIXED message. The original
// error message is never copied, because SDK messages can echo request
// details, endpoints or credential material.
function mapError(err) {
  const name = String((err && (err.name || err.code)) || "");
  const status = err && ((err.$metadata && err.$metadata.httpStatusCode) || err.statusCode);
  if (err && err.code === "SDK_UNAVAILABLE") {
    return fail("SDK_UNAVAILABLE", "Object store SDK is not installed.");
  }
  if (/NoSuchKey|NotFound|BlobNotFound/i.test(name) || status === 404) {
    return fail("NOT_FOUND", "Object not found.");
  }
  if (/Credential|AccessDenied|Forbidden|Authentication|Unauthorized/i.test(name) || status === 401 || status === 403) {
    return fail("ACCESS_DENIED", "Object store denied access or credentials are unavailable.");
  }
  return fail("STORE_UNAVAILABLE", "Object store is unavailable.");
}

// Loads an SDK lazily. Failure becomes a coded error without leaking details.
function lazyRequire(name) {
  try {
    return require(name);
  } catch (e) {
    const err = new Error("sdk unavailable");
    err.code = "SDK_UNAVAILABLE";
    throw err;
  }
}

// Emits a startup warning (never an error) listing only the NAMES of static
// credential variables that are set, never their values.
function warnStaticCredentials(env, provider, names, recommendation) {
  const present = names.filter((n) => env[n]);
  if (present.length > 0) {
    console.warn(
      "[objectstore] WARNING: static credentials detected for provider '" +
        provider + "' (" + present.join(", ") + "). " + recommendation
    );
  }
  return present;
}

module.exports = { KEY_PATTERN, isValidKey, fail, invalidKey, mapError, lazyRequire, warnStaticCredentials };
