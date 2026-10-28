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
//  - hardened mode (secure pattern): the password is read EXCLUSIVELY from a
//    secret FILE, trimmed, and the resolution is fail-closed: a missing file, or
//    content that is empty after trimming, throws a descriptive Error instead of
//    falling back to env/code (Requirements 5.1, 5.2, 5.5, 5.6).
//
//    By default the file is the Docker secret mounted at /run/secrets/db_password
//    (local docker-compose, GCP, Azure, EKS). The path is configurable via the
//    env var DB_PASSWORD_FILE, which names WHERE the file lives (like Postgres'
//    POSTGRES_PASSWORD_FILE), NOT the value. This lets targets such as AWS ECS
//    Fargate -- where the ephemeral /run/secrets volume is owned by root but the
//    image runs as a non-root user (UID 10001) -- point the app at an app-owned
//    directory the container user can write/read (e.g. /app/secrets/db_password)
//    WITHOUT weakening the posture: it is still a FILE (never an env var carrying
//    the value), still trimmed, still fail-closed. env.DB_PASSWORD is still
//    ignored in hardened mode.
const nodeFs = require("fs");

// Default path of the Docker secret file consumed by the hardened deployment
// when DB_PASSWORD_FILE is not set.
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
    // Password comes EXCLUSIVELY from the secret FILE (R5.2).
    // env.DB_PASSWORD is deliberately ignored here.
    //
    // DB_PASSWORD_FILE (when set to a non-empty, non-whitespace value) names
    // WHERE the file lives; otherwise fall back to the default SECRET_PATH. It
    // is the PATH, never the value, so the secret is still delivered as a file.
    const secretPath =
      env.DB_PASSWORD_FILE && String(env.DB_PASSWORD_FILE).trim().length > 0
        ? String(env.DB_PASSWORD_FILE)
        : SECRET_PATH;

    let raw;
    try {
      raw = fs.readFileSync(secretPath, "utf8");
    } catch (err) {
      // Missing/unreadable secret file -> fail-closed (R5.6).
      throw new Error(
        "Hardened mode requires the secret file at " + secretPath +
        " but it could not be read: " + err.message
      );
    }

    // Normalize: strip leading/trailing whitespace and line endings (R5.5).
    const password = raw.trim();
    if (password.length === 0) {
      // Empty after trimming -> fail-closed (R5.6).
      throw new Error(
        "Hardened mode secret at " + secretPath +
        " is empty after trimming; refusing to start without a valid DB password"
      );
    }

    return { ...connectionTarget(env), password };
  }

  throw new Error("Unknown credentials mode: " + String(mode));
}

module.exports = { resolve, SECRET_PATH, HARDCODED_USER, HARDCODED_PASSWORD, HARDCODED_DATABASE };
