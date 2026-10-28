// src/db/credentials.js
// Resolves the PostgreSQL connection credentials (DB_Secret) according to the
// application mode. This module isolates the single dimension "where does the
// secret come from", so it can be unit/property-tested without opening a real
// connection and without touching the real filesystem (fs/env are injectable).
//
//  - vulnerable mode (antipattern, on purpose): the password comes ONLY from a
//    plaintext environment variable or a hardcoded fallback baked into the code.
//    It NEVER reads the Docker secret file. This demonstrates "vulnerable apps
//    store secrets insecurely" (Requirements 4.2, 4.4).
//  - hardened mode (secure pattern): the password is read EXCLUSIVELY from the
//    Docker secret file mounted at /run/secrets/db_password, trimmed, and the
//    resolution is fail-closed: a missing file, or content that is empty after
//    trimming, throws a descriptive Error instead of falling back to env/code
//    (Requirements 5.1, 5.2, 5.5, 5.6).
const nodeFs = require("fs");

// Path of the Docker secret file consumed only by the hardened deployment.
const SECRET_PATH = "/run/secrets/db_password";

// Hardcoded plaintext fallback (INTENTIONAL ANTIPATTERN) used by the vulnerable
// mode when the environment does not provide credentials. Never used by the
// hardened mode.
const HARDCODED_USER = "sangyshop";
const HARDCODED_PASSWORD = "SangyDbPass!2025";
const HARDCODED_DATABASE = "sangyshop";

// Non-secret connection parameters, shared by both modes. These come from the
// environment (set by docker-compose / Kubernetes) with sensible defaults.
function connectionTarget(env) {
  return {
    host: env.DB_HOST || "localhost",
    port: Number(env.DB_PORT) || 5432,
    database: env.DB_NAME || HARDCODED_DATABASE,
    user: env.DB_USER || HARDCODED_USER,
  };
}

// resolve(mode, deps) -> { host, port, database, user, password } or throws.
// deps.fs   : filesystem-like object exposing readFileSync (injectable for tests)
// deps.env  : environment object (injectable; defaults to process.env)
function resolve(mode, deps = {}) {
  const fs = deps.fs || nodeFs;
  const env = deps.env || process.env;

  if (mode === "vulnerable") {
    // Password comes ONLY from plaintext env or the hardcoded fallback.
    // The Docker secret file is never consulted in this mode (R4.4).
    const password = env.DB_PASSWORD ?? HARDCODED_PASSWORD;
    return { ...connectionTarget(env), password };
  }

  if (mode === "hardened") {
    // Password comes EXCLUSIVELY from the Docker secret file (R5.2).
    // env.DB_PASSWORD is deliberately ignored here.
    let raw;
    try {
      raw = fs.readFileSync(SECRET_PATH, "utf8");
    } catch (err) {
      // Missing/unreadable secret file -> fail-closed (R5.6).
      throw new Error(
        "Hardened mode requires the Docker secret at " + SECRET_PATH +
        " but it could not be read: " + err.message
      );
    }

    // Normalize: strip leading/trailing whitespace and line endings (R5.5).
    const password = raw.trim();
    if (password.length === 0) {
      // Empty after trimming -> fail-closed (R5.6).
      throw new Error(
        "Hardened mode secret at " + SECRET_PATH +
        " is empty after trimming; refusing to start without a valid DB password"
      );
    }

    return { ...connectionTarget(env), password };
  }

  throw new Error("Unknown credentials mode: " + String(mode));
}

module.exports = { resolve, SECRET_PATH, HARDCODED_USER, HARDCODED_PASSWORD, HARDCODED_DATABASE };
