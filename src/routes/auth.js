// src/routes/auth.js
// A05 Injection (login via SQL) + A09 Logging & Alerting (registro de tentativas).
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
  const ip = req.ip || req.connection.remoteAddress || "desconhecido";
  let user = null;

  if (isOn("A05_injection")) {
    // DEFESA LIGADA: consulta parametrizada (prepared statement).
    // A entrada do usuario nunca e interpretada como codigo SQL.
    user = db
      .prepare("SELECT * FROM users WHERE username = ? AND password = ?")
      .get(username, password);
  } else {
    // VULNERAVEL: concatenacao direta. Payload classico: admin' -- ou ' OR '1'='1
    const sql =
      "SELECT * FROM users WHERE username = '" +
      username +
      "' AND password = '" +
      password +
      "'";
    try {
      user = db.prepare(sql).get();
    } catch (e) {
      // Em modo vulneravel, o erro de SQL pode vazar (ligado ao A02 tambem).
      return res.status(500).render("login", {
        error: isOn("A02_misconfiguration")
          ? "Credenciais invalidas."
          : "Erro de SQL: " + e.message,
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
  return res.status(401).render("login", { error: "Credenciais invalidas.", user: null });
});

router.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

module.exports = router;
