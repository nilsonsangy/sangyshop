// test/helpers.js
// Minimal, pragmatic test stack for SangyShop.
//
// The app under test is Node/Express/EJS with express-session and an in-memory
// sql.js (WASM) database. The production entry point (src/server.js) calls
// app.listen() at module load, so it cannot be required directly in tests.
// This helper rebuilds an equivalent Express app WITHOUT listening, seeds the
// in-memory database via db.init() (async), and exposes utilities:
//
//   - createTestApp():   builds and returns the Express app (awaits db.init()).
//   - agent(app):        a supertest cookie jar that keeps the session across
//                        requests (supertest.agent).
//   - setToggle(key, v): stubs a defense toggle (e.g. "A01_access_control")
//                        IN MEMORY, without touching config/defenses.json.
//   - resetToggles():    clears all in-memory toggle stubs.
//   - login(agent, u, p):helper that performs POST /login on an agent.
//   - SEED:              reference data mirroring the database seed.
//
// IMPORTANT: this helper changes NO vulnerability logic. The toggle stub only
// swaps where isOn() reads its value FROM (an in-memory map that falls back to
// the real defenses.json), so A01/A02/A05/A09 behaviour is unchanged.

const path = require("path");
const express = require("express");
const session = require("express-session");
const request = require("supertest");

const SRC = path.join(__dirname, "..", "src");

// ---------------------------------------------------------------------------
// Toggle stub.
//
// Every route destructures `const { isOn } = require("../lib/defenses")` at load
// time, capturing the function reference. To make a toggle stub effective for
// those routes, we wrap the defenses module in the require cache BEFORE any
// route module is loaded, so the captured `isOn` is our override-aware wrapper.
// ---------------------------------------------------------------------------

const DEFENSES_PATH = require.resolve(path.join(SRC, "lib", "defenses.js"));

// In-memory overrides: key -> boolean. When a key is present here, isOn() uses
// this value instead of reading config/defenses.json.
const toggleOverrides = new Map();

let defensesWrapped = false;

function wrapDefenses() {
  if (defensesWrapped) return require.cache[DEFENSES_PATH].exports;

  // Load the real module first so we keep its genuine implementations.
  const real = require(DEFENSES_PATH);

  const wrapper = {
    ...real,
    isOn(key) {
      if (toggleOverrides.has(key)) return toggleOverrides.get(key) === true;
      return real.isOn(key);
    },
  };

  // Replace the cached module exports so later `require("../lib/defenses")`
  // calls (from the route modules) receive the wrapper.
  require.cache[DEFENSES_PATH].exports = wrapper;
  defensesWrapped = true;
  return wrapper;
}

/** Force a defense toggle on/off in memory (no file writes). */
function setToggle(key, value) {
  wrapDefenses();
  toggleOverrides.set(key, value === true);
}

/** Clear all in-memory toggle stubs (fall back to config/defenses.json). */
function resetToggles() {
  toggleOverrides.clear();
}

// ---------------------------------------------------------------------------
// App builder.
// Mirrors src/server.js wiring (session, view engine, A02 header middleware,
// routes, debug route and error handler) but never calls app.listen().
// ---------------------------------------------------------------------------

async function createTestApp() {
  // Ensure the defenses module is wrapped before the routes capture isOn.
  wrapDefenses();

  const { isOn } = require(DEFENSES_PATH);
  const db = require(path.join(SRC, "db", "database.js"));

  // sql.js initialization is async; wait for the seeded in-memory DB.
  await db.init();

  const app = express();
  app.set("view engine", "ejs");
  app.set("views", path.join(SRC, "views"));
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(express.static(path.join(SRC, "..", "public")));

  app.use(
    session({
      secret: "sangyshop-test-secret",
      resave: false,
      saveUninitialized: false,
    })
  );

  // A02 header middleware (same shape as server.js).
  app.use((req, res, next) => {
    if (isOn("A02_misconfiguration")) {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Content-Security-Policy", "default-src 'self'");
      res.setHeader("Referrer-Policy", "no-referrer");
      res.removeHeader("X-Powered-By");
    } else {
      res.setHeader("X-Powered-By", "Express 4.18 / SangyShop 1.0");
    }
    next();
  });

  app.get("/", (req, res) => res.redirect("/products"));
  app.use("/", require(path.join(SRC, "routes", "auth.js")));
  app.use("/", require(path.join(SRC, "routes", "products.js")));
  app.use("/api", require(path.join(SRC, "routes", "api.js")));
  app.use("/", require(path.join(SRC, "routes", "admin.js")));

  // Orders page route is added later in the feature (task 4). Mount it when it
  // exists so this helper keeps working as the feature grows.
  try {
    const ordersRoute = require.resolve(path.join(SRC, "routes", "orders.js"));
    app.use("/", require(ordersRoute));
  } catch (_) {
    /* orders.js not present yet */
  }

  app.get("/debug/boom", (req, res) => {
    throw new Error("Simulated internal failure in /debug/boom (null object)");
  });

  app.use((err, req, res, next) => {
    if (isOn("A02_misconfiguration")) {
      res.status(500).send("Internal error. Please try again later.");
    } else {
      res
        .status(500)
        .type("text/plain")
        .send("ERROR 500 - SangyShop (vulnerable mode)\n\n" + (err.stack || err.message));
    }
  });

  return app;
}

/** supertest cookie jar: keeps the session cookie across requests. */
function agent(app) {
  return request.agent(app);
}

/** Convenience: perform a login on an existing agent. */
function login(testAgent, username, password) {
  return testAgent.post("/login").type("form").send({ username, password });
}

// Reference seed data (mirrors src/db/database.js) for building expectations.
const SEED = {
  users: {
    admin: { id: 1, username: "admin", role: "admin" },
    alice: { id: 2, username: "alice", role: "customer" },
    bob: { id: 3, username: "bob", role: "customer" },
    carol: { id: 4, username: "carol", role: "customer" },
  },
  credentials: {
    admin: "SangyAdmin!2025",
    alice: "alice123",
    bob: "bob123",
    carol: "carol123",
  },
  // order id -> owner user_id
  orders: [
    { id: 1, user_id: 2, product_id: 1, quantity: 2, total: 159.8 },
    { id: 2, user_id: 2, product_id: 3, quantity: 1, total: 19.9 },
    { id: 3, user_id: 3, product_id: 4, quantity: 1, total: 189.9 },
    { id: 4, user_id: 4, product_id: 2, quantity: 3, total: 149.7 },
  ],
};

module.exports = {
  createTestApp,
  agent,
  login,
  setToggle,
  resetToggles,
  request,
  SEED,
};
