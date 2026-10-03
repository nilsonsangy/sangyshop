// src/routes/api.js
// A01 Broken Access Control (IDOR). O recurso e acessado pelo id da URL
// sem verificar se pertence ao usuario autenticado.
const express = require("express");
const router = express.Router();
const db = require("../db/database");
const { isOn } = require("../lib/defenses");

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Faca login primeiro." });
  next();
}

// Pedido por id: /api/orders/:id
router.get("/orders/:id", requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  if (!order) return res.status(404).json({ error: "Pedido nao encontrado." });

  if (isOn("A01_access_control")) {
    // DEFESA LIGADA: verifica a propriedade do recurso.
    // So o dono (ou admin) ve o pedido. O id do cliente nao e confiavel sozinho.
    const u = req.session.user;
    if (order.user_id !== u.id && u.role !== "admin") {
      return res.status(403).json({ error: "Acesso negado: este pedido nao e seu." });
    }
  }
  // VULNERAVEL (defesa off): devolve o pedido de qualquer id (IDOR).
  res.json(order);
});

// Perfil por id: /api/users/:id (expoe dados sensiveis em modo vulneravel)
router.get("/users/:id", requireLogin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare("SELECT id, username, role, email, credit_card FROM users WHERE id = ?").get(id);
  if (!row) return res.status(404).json({ error: "Usuario nao encontrado." });

  if (isOn("A01_access_control")) {
    const u = req.session.user;
    if (row.id !== u.id && u.role !== "admin") {
      return res.status(403).json({ error: "Acesso negado: este perfil nao e seu." });
    }
    // Mesmo autorizado, nao expor o cartao a nao ser para o proprio dono.
  }
  res.json(row);
});

// Lista os proprios pedidos (rota legitima de referencia)
router.get("/my/orders", requireLogin, (req, res) => {
  const rows = db.prepare("SELECT * FROM orders WHERE user_id = ?").all(req.session.user.id);
  res.json(rows);
});

module.exports = router;
