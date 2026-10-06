// src/routes/auth.js
// A05 Injection (login via SQL) + A09 Logging & Alerting (attempt recording).
const express = require("express");
const router = express.Router();
const db = require("../db/database");
const { isOn } = require("../lib/defenses");
const { recordLogin } = require("../lib/logger");

router.get("/login", (req, res) => {
  res.render("login", { error: null, user: req.session.user || null });
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  let user = null;

  if (isOn("A05_injection")) {
    // DEFENSE ON: parameterized query (prepared statement).
    // User input is never interpreted as SQL code.
    user = db
      .prepare("SELECT * FROM users WHERE username = ? AND password = ?")
      .get(username, password);
  } else {
    // VULNERABLE: direct concatenation. Classic payload: admin' -- or ' OR '1'='1
    const sql =
      "SELECT * FROM users WHERE username = '" +
      username +
      "' AND password = '" +
      password +
      "'";
    try {
      user = db.prepare(sql).get();
    } catch (e) {
      // In vulnerable mode, the SQL error may leak (tied to A02 as well).
      return res.status(500).render("login", {
        error: isOn("A02_misconfiguration")
          ? "Invalid credentials."
          : "SQL error: " + e.message,
        user: null,
      });
    }
  }

  const success = !!user;
  recordLogin({ username, ip, success });

  if (success) {
    req.session.user = { id: user.id, username: user.username, role: user.role };
    return res.redirect("/products");
  }
  return res.status(401).render("login", { error: "Invalid credentials.", user: null });
});

router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      // Keep the user authenticated and signal that logout failed.
      return res.status(500).render("products", {
        products: [],
        q: "",
        sqlShown: null,
        error: "Logout could not be completed. Please try again.",
        user: req.session.user || null,
      });
    }
    res.redirect("/login");
  });
});

module.exports = router;
