// src/routes/admin.js
// Defenses panel (turn each toggle on/off) and log viewer (A09).
// This is the area that makes the "attack -> defend -> prove" flow visible to the student.
const express = require("express");
const router = express.Router();
const { readAll, setDefense } = require("../lib/defenses");
const { tail } = require("../lib/logger");

const LABELS = {
  A05_injection: "A05:2025 Injection (parameterized SQL on login and search)",
  A01_access_control: "A01:2025 Broken Access Control (ownership check / IDOR)",
  A02_misconfiguration: "A02:2025 Security Misconfiguration (generic errors + security headers)",
  A09_logging: "A09:2025 Security Logging & Alerting (login logging + brute-force alert)",
};

router.get("/defenses", (req, res) => {
  res.render("defenses", { defenses: readAll(), labels: LABELS, user: req.session.user || null });
});

router.post("/defenses", (req, res) => {
  // Receives the state of each toggle from the form (checked checkbox = on).
  Object.keys(LABELS).forEach((key) => {
    setDefense(key, req.body[key] === "on");
  });
  res.redirect("/defenses");
});

// API to toggle via command line (curl), used in the exercises.
router.post("/api/defenses/:key", (req, res) => {
  try {
    const value = req.body && req.body.value;
    const all = setDefense(req.params.key, value);
    res.json({ ok: true, defenses: all });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

router.get("/logs", (req, res) => {
  res.render("logs", { lines: tail(80), user: req.session.user || null });
});

module.exports = router;
