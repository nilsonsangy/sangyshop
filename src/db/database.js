// src/db/database.js
// Data_Access_Module: single facade over a data backend, selected by the
// DB_BACKEND environment variable.
//
//   DB_BACKEND=pg      (default)  real, persistent PostgreSQL via the `pg` driver
//   DB_BACKEND=memory             in-memory backend used by the test suite,
//                                 so `npm test` runs without a PostgreSQL in Docker
//
// The contract is ASYNC (the `pg` driver is async), and every backend exposes
// the SAME shape so the rest of the application does not care which one is
// running:
//
//   isReady(): boolean
//   async init(): Promise<api>                 // connect, ensure schema+seed, signal ready
//   async exec(sql): Promise<void>             // direct DDL/statement
//   prepare(sql) => {
//     async get(...params): Promise<object|undefined>,  // one row or undefined
//     async all(...params): Promise<object[]>,          // N rows
//     async run(...params): Promise<{ changes: number }>,
//   }
//
// Placeholder semantics (critical for the A05 SQLi lesson): when get/all/run
// are called WITH params the statement is parameterized (the payload is a data
// literal, never executed as SQL); when called WITHOUT params the RAW sql
// string (already carrying concatenated user input in the vulnerable path) is
// executed as-is, so the injection stays authentic. Each backend replicates
// this dual behaviour.

const BACKEND = process.env.DB_BACKEND === "memory" ? "memory" : "pg";

// ---------------------------------------------------------------------------
// Shared seed data.
//
// Mirrors exactly the data the application has always shipped with: 4 users
// (ids 1..4, same plaintext passwords), 5 products and 4 orders. Kept here so
// every backend seeds identical rows (the test SEED in test/helpers.js is the
// human-readable mirror of this).
// ---------------------------------------------------------------------------

const SEED_USERS = [
  ["admin", "SangyAdmin!2025", "admin", "admin@sangyshop.local", "4111-1111-1111-1111"],
  ["alice", "alice123", "customer", "alice@mail.local", "5500-0000-0000-0004"],
  ["bob", "bob123", "customer", "bob@mail.local", "6011-0000-0000-0004"],
  ["carol", "carol123", "customer", "carol@mail.local", "3400-000000-00009"],
];

const SEED_PRODUCTS = [
  ["SangyShop T-Shirt", "Cotton, Blue Team print", 79.9],
  ["Hacker Mug", "300ml ceramic, OWASP theme", 49.9],
  ["Sticker Pack", "10 offensive/defensive security stickers", 19.9],
  ["DFIR Hoodie", "Hooded, digital forensics", 189.9],
  ["Token Keychain", "OTP-token-shaped keychain", 29.9],
];

const SEED_ORDERS = [
  [2, 1, 2, 159.8],
  [2, 3, 1, 19.9],
  [3, 4, 1, 189.9],
  [4, 2, 3, 149.7],
];

// ===========================================================================
// Backend: memory (sql.js encapsulated behind the contract).
//
// Design option (a): keep sql.js (already a dependency) behind the contract.
// This reproduces sql.js semantics faithfully, which the A05 lesson relies on
// (UNION SELECT exfiltration and `admin'--` bypass travel through real SQL).
// The facade makes the synchronous sql.js API async by wrapping each call in a
// resolved Promise, so the test backend honours the same async contract the
// `pg` backend will.
// ===========================================================================

function createMemoryBackend() {
  const initSqlJs = require("sql.js");

  let rawDb = null;
  let ready = false;

  function createSchema() {
    // sql.js (SQLite) schema; SERIAL/TIMESTAMP of PostgreSQL map to
    // AUTOINCREMENT / datetime('now') here. Idempotent via IF NOT EXISTS so a
    // repeated init() never recreates the tables.
    rawDb.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        email TEXT,
        credit_card TEXT
      );
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL
      );
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        total REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }

  function usersIsEmpty() {
    const stmt = rawDb.prepare("SELECT count(*) AS n FROM users");
    try {
      stmt.step();
      return stmt.getAsObject().n === 0;
    } finally {
      stmt.free();
    }
  }

  function seedOnce() {
    // Seed only when the users table is empty, so a second init() over the
    // same backend never duplicates rows.
    if (!usersIsEmpty()) return;

    SEED_USERS.forEach((r) =>
      rawDb.run(
        "INSERT INTO users (username,password,role,email,credit_card) VALUES (?,?,?,?,?)",
        r
      )
    );
    SEED_PRODUCTS.forEach((r) =>
      rawDb.run("INSERT INTO products (name,description,price) VALUES (?,?,?)", r)
    );
    SEED_ORDERS.forEach((r) =>
      rawDb.run(
        "INSERT INTO orders (user_id,product_id,quantity,total) VALUES (?,?,?,?)",
        r
      )
    );
  }

  return {
    isReady() {
      return ready;
    },

    async init() {
      if (ready) return; // idempotent: no re-create, no re-seed
      const SQL = await initSqlJs();
      rawDb = new SQL.Database();
      createSchema();
      seedOnce();
      ready = true;
    },

    async exec(sql) {
      rawDb.exec(sql);
    },

    prepare(sql) {
      return {
        async get(...params) {
          const stmt = rawDb.prepare(sql);
          try {
            if (params.length) stmt.bind(params);
            if (stmt.step()) return stmt.getAsObject();
            return undefined;
          } finally {
            stmt.free();
          }
        },
        async all(...params) {
          const stmt = rawDb.prepare(sql);
          const rows = [];
          try {
            if (params.length) stmt.bind(params);
            while (stmt.step()) rows.push(stmt.getAsObject());
            return rows;
          } finally {
            stmt.free();
          }
        },
        async run(...params) {
          rawDb.run(sql, params.length ? params : undefined);
          return { changes: rawDb.getRowsModified() };
        },
      };
    },
  };
}

// ===========================================================================
// Backend: pg (real, persistent PostgreSQL via the `pg` driver).
//
// init() resolves credentials for the current APP_MODE (vulnerable | hardened)
// through src/db/credentials.js, opens a connection Pool with a 30s connection
// timeout, then runs the idempotent schema and the conditional seed. A
// connection failure/timeout rejects init() with a descriptive error (logged
// at the source); server.js already turns that into console.error +
// process.exit(1) in its .catch.
//
// The `prepare(sql)` shim preserves the dual A05 behaviour:
//   - WITH params  -> translate each `?` into `$1,$2,...` and run parameterized
//                     (the payload is a data literal, never executed as SQL)
//   - WITHOUT params -> pass the RAW sql to pool.query(sql) (the vulnerable
//                     path, where user input was already concatenated in)
// ===========================================================================

// APP_MODE selects where the DB_Secret comes from (R4 vs R5). Only relevant to
// the pg backend. Defaults to the vulnerable deployment.
const APP_MODE = process.env.APP_MODE === "hardened" ? "hardened" : "vulnerable";

// Translate SQLite-style `?` placeholders into PostgreSQL `$1,$2,...` ones, in
// order of appearance. Exported for isolated unit testing.
function translatePlaceholders(sql) {
  let n = 0;
  return sql.replace(/\?/g, () => "$" + ++n);
}

function createPgBackend() {
  const credentials = require("./credentials");
  const { Pool } = require("pg");

  let pool = null;
  let ready = false;

  // PostgreSQL schema, idempotent (CREATE TABLE IF NOT EXISTS). A repeated
  // init() never recreates the tables. SERIAL/TEXT/
  // DOUBLE PRECISION/TIMESTAMP per design.md Data Models.
  async function createSchema() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id          SERIAL PRIMARY KEY,
        username    TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'customer',
        email       TEXT,
        credit_card TEXT
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id          SERIAL PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT,
        price       DOUBLE PRECISION NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id          SERIAL PRIMARY KEY,
        user_id     INTEGER NOT NULL,
        product_id  INTEGER NOT NULL,
        quantity    INTEGER NOT NULL DEFAULT 1,
        total       DOUBLE PRECISION NOT NULL,
        created_at  TIMESTAMP NOT NULL DEFAULT now()
      );
    `);
  }

  async function usersIsEmpty() {
    const res = await pool.query("SELECT count(*)::int AS n FROM users");
    return res.rows[0].n === 0;
  }

  // Seed only when the users table is empty, so a second init() over the same
  // Data_Volume never duplicates rows. Inserts use
  // parameterized values ($1,$2,...).
  async function seedOnce() {
    if (!(await usersIsEmpty())) return;

    for (const r of SEED_USERS) {
      await pool.query(
        "INSERT INTO users (username,password,role,email,credit_card) VALUES ($1,$2,$3,$4,$5)",
        r
      );
    }
    for (const r of SEED_PRODUCTS) {
      await pool.query(
        "INSERT INTO products (name,description,price) VALUES ($1,$2,$3)",
        r
      );
    }
    for (const r of SEED_ORDERS) {
      await pool.query(
        "INSERT INTO orders (user_id,product_id,quantity,total) VALUES ($1,$2,$3,$4)",
        r
      );
    }
  }

  // Run a statement honouring the dual placeholder semantics and return the pg
  // result. WITH params -> parameterized ($n); WITHOUT params -> raw sql.
  async function query(sql, params) {
    if (params && params.length) {
      return pool.query(translatePlaceholders(sql), params);
    }
    // Authentic vulnerable path: the sql string already carries the user input
    // concatenated in; pass it raw so the injection stays real.
    return pool.query(sql);
  }

  return {
    isReady() {
      return ready;
    },

    async init() {
      if (ready) return; // idempotent: no re-create, no re-seed

      // Resolve the DB_Secret for the current mode. In hardened mode this is
      // fail-closed (throws if the secret is missing/empty); in vulnerable mode
      // it falls back to the hardcoded plaintext credentials.
      const creds = credentials.resolve(APP_MODE);

      // SSL is opt-in via DB_SSL so local docker-compose and the other clouds
      // are unaffected by default. AWS RDS enforces TLS (rds.force_ssl) and
      // rejects a non-SSL connection, so the Fargate task sets DB_SSL=require.
      // When unset/empty, ssl stays undefined => current (no-SSL) behavior.
      const sslMode = (process.env.DB_SSL || "").trim().toLowerCase();
      const useSsl = sslMode === "require" || sslMode === "true" || sslMode === "1";

      pool = new Pool({
        host: creds.host,
        port: creds.port,
        database: creds.database,
        user: creds.user,
        password: creds.password,
        connectionTimeoutMillis: 30000, // R1.5: 30s connection timeout
        // rejectUnauthorized:false is appropriate for this teaching lab: it
        // establishes the encrypted channel RDS requires without bundling the
        // RDS CA. A production-grade setup would pin the RDS CA bundle, but
        // encryption-in-transit is what RDS enforces here.
        ssl: useSsl ? { rejectUnauthorized: false } : undefined,
      });

      try {
        // Force an actual connection so a failure/timeout surfaces here
        // rather than lazily on the first query.
        const client = await pool.connect();
        client.release();
      } catch (err) {
        // Log at the source; server.js turns the rejection into exit(1).
        console.error(
          "Failed to connect to PostgreSQL within 30s (host=" +
            creds.host +
            ", port=" +
            creds.port +
            ", database=" +
            creds.database +
            "): " +
            err.message
        );
        // Avoid leaking an open pool on a failed boot.
        try {
          await pool.end();
        } catch (_) {
          /* ignore cleanup errors */
        }
        pool = null;
        throw new Error("PostgreSQL connection failed: " + err.message);
      }

      await createSchema();
      await seedOnce();
      ready = true;
    },

    async exec(sql) {
      await pool.query(sql);
    },

    prepare(sql) {
      return {
        async get(...params) {
          const res = await query(sql, params);
          return res.rows.length ? res.rows[0] : undefined;
        },
        async all(...params) {
          const res = await query(sql, params);
          return res.rows;
        },
        async run(...params) {
          const res = await query(sql, params);
          return { changes: res.rowCount };
        },
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Facade: pick the backend once and delegate the whole contract to it.
// ---------------------------------------------------------------------------

const backend = BACKEND === "memory" ? createMemoryBackend() : createPgBackend();

const api = {
  isReady() {
    return backend.isReady();
  },

  async init() {
    await backend.init();
    return api;
  },

  async exec(sql) {
    return backend.exec(sql);
  },

  prepare(sql) {
    return backend.prepare(sql);
  },
};

module.exports = api;
// Exposed for isolated unit testing of the `?`->`$n` translation.
module.exports.translatePlaceholders = translatePlaceholders;
