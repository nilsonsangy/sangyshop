// src/routes/orders.js
// Authenticated user's orders page. Starting point for the A01/IDOR exercise:
// each order links to /api/orders/:id, where the id can be tampered with.
const express = require("express");
const router = express.Router();
const db = require("../db/database");

function requireLogin(req, res, next) {
  // Page route: redirect to the login page when there is no session
  // (unlike the API's requireLogin in api.js, which responds with 401 JSON).
  if (!req.session.user) return res.redirect("/login");
  next();
}

router.get("/orders", requireLogin, (req, res) => {
  // Same ownership logic as /api/my/orders: only the session user's orders.
  const orders = db
    .prepare(
      `SELECT o.id AS id, o.quantity AS quantity, o.total AS total,
              p.name AS product_name
       FROM orders o
       JOIN products p ON p.id = o.product_id
       WHERE o.user_id = ?
       ORDER BY o.id`
    )
    .all(req.session.user.id);

  res.render("orders", { orders, user: req.session.user });
});

module.exports = router;
