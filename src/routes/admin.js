// src/routes/admin.js
// Painel de defesas (liga/desliga cada toggle) e visualizacao dos logs (A09).
// Esta e a area que torna o fluxo "ataca -> defende -> comprova" visivel ao aluno.
const express = require("express");
const router = express.Router();
const { readAll, setDefense } = require("../lib/defenses");
const { tail } = require("../lib/logger");

const LABELS = {
  A05_injection: "A05:2025 Injection (SQL parametrizado no login e na busca)",
  A01_access_control: "A01:2025 Broken Access Control (verificacao de propriedade / IDOR)",
  A02_misconfiguration: "A02:2025 Security Misconfiguration (erros genericos + security headers)",
  A09_logging: "A09:2025 Security Logging & Alerting (registro de login + alerta de brute force)",
};

router.get("/defenses", (req, res) => {
  res.render("defenses", { defenses: readAll(), labels: LABELS });
});

router.post("/defenses", (req, res) => {
  // Recebe o estado de cada toggle do formulario (checkbox marca = on).
  Object.keys(LABELS).forEach((key) => {
    setDefense(key, req.body[key] === "on");
  });
  res.redirect("/defenses");
});

// API para alternar via linha de comando (curl), usada nos exercicios.
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
  res.render("logs", { lines: tail(80) });
});

module.exports = router;
