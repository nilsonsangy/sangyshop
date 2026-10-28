// src/routes/api.js
// A01 Broken Access Control (IDOR). The resource is accessed by the id in the URL
// without checking whether it belongs to the authenticated user.
const express = require("express");
const router = express.Router();
const db = require("../db/database");
const { isOn } = require("../lib/defenses");

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}

// Order by id: /api/orders/:id
router.get("/orders/:id", requireLogin, async (req, res) => {
  const id = Number(req.params.id);
  const order = await db.prepare("SELECT * FROM orders WHERE id = ?").get(id);
  if (!order) return res.status(404).json({ error: "Order not found." });

  if (isOn("A01_access_control")) {
    // secure:start
    // DEFENSE ON: checks resource ownership.
    // Only the owner (or admin) sees the order. The client-provided id is not trustworthy on its own.
    const u = req.session.user;
    if (order.user_id !== u.id && u.role !== "admin") {
      return res.status(403).json({ error: "Access denied: this order is not yours." });
    }
    // secure:end
  }
  // vuln:start
  // VULNERABLE (defense off): returns the order for any id (IDOR).
  res.json(order);
  // vuln:end
});

// Profile by id: /api/users/:id (exposes sensitive data in vulnerable mode)
router.get("/users/:id", requireLogin, async (req, res) => {
  const id = Number(req.params.id);
  const row = await db.prepare("SELECT id, username, role, email, credit_card FROM users WHERE id = ?").get(id);
  if (!row) return res.status(404).json({ error: "User not found." });

  if (isOn("A01_access_control")) {
    const u = req.session.user;
    if (row.id !== u.id && u.role !== "admin") {
      return res.status(403).json({ error: "Access denied: this profile is not yours." });
    }
    // Even when authorized, do not expose the card except to the owner.
  }
  res.json(row);
});

// Lists the user's own orders (legitimate reference route)
router.get("/my/orders", requireLogin, async (req, res) => {
  const rows = await db.prepare("SELECT * FROM orders WHERE user_id = ?").all(req.session.user.id);
  res.json(rows);
});

module.exports = router;
