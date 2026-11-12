// src/routes/lab.js
// Opt-in laboratory routes (design D-12):
//   GET /.well-known/sangyshop-lab   lab marker (JSON + X-SangyShop-Lab header)
//   GET /debug/config                returns the "forgotten" LAB_LEAKED_FILE
//
// The routes are mounted ONLY when LAB_MODE=1 AND APP_MODE is vulnerable.
// Otherwise nothing is registered and Express answers 404 on its own.

const fs = require("fs");

const DEFAULT_LEAKED_FILE = "/lab/leaked.json";

// Same rule as src/db/database.js: anything other than "hardened" is vulnerable.
function resolveMode(env) {
  return env.APP_MODE === "hardened" ? "hardened" : "vulnerable";
}

function isLabEnabled(env = process.env) {
  return env.LAB_MODE === "1" && resolveMode(env) === "vulnerable";
}

// Returns an Express router, or null when the lab routes are disabled.
function createLabRouter(env = process.env) {
  if (!isLabEnabled(env)) return null;

  const express = require("express");
  const router = express.Router();

  router.get("/.well-known/sangyshop-lab", (req, res) => {
    res.set("X-SangyShop-Lab", "vulnerable-lab");
    res.json({
      app: "sangyshop",
      lab: "sangyshop",
      mode: "vulnerable",
      cloud: env.LAB_CLOUD || null,
    });
  });

  router.get("/debug/config", (req, res) => {
    const file = env.LAB_LEAKED_FILE || DEFAULT_LEAKED_FILE;
    fs.readFile(file, "utf8", (err, content) => {
      if (err) {
        const missing = err.code === "ENOENT";
        return res.status(missing ? 404 : 500).json({
          ok: false,
          error: missing ? "leaked file not found" : "leaked file unreadable",
        });
      }
      res.type("application/json").send(content);
    });
  });

  return router;
}

// Convenience: mounts the lab routes on the app only when enabled.
function mountLab(app, env = process.env) {
  const router = createLabRouter(env);
  if (router) app.use("/", router);
  return !!router;
}

module.exports = { createLabRouter, mountLab, isLabEnabled };
