// src/routes/products.js
// A05 Injection (product search via SQL).
const express = require("express");
const router = express.Router();
const db = require("../db/database");
const { isOn } = require("../lib/defenses");

router.get("/products", async (req, res) => {
  const q = req.query.q;
  let products = [];
  let sqlShown = null;

  if (!q) {
    products = await db.prepare("SELECT * FROM products").all();
  } else if (isOn("A05_injection")) {
    // secure:start
    // DEFENSE ON: parameter bound with a placeholder; safe LIKE.
    products = await db
      .prepare("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?")
      .all(`%${q}%`, `%${q}%`);
    // secure:end
  } else {
    // vuln:start
    // VULNERABLE: concatenation. Allows UNION SELECT to extract users.
    // E.g.: ' UNION SELECT id,username,password,id FROM users --
    const sql =
      "SELECT id, name, description, price FROM products WHERE name LIKE '%" +
      q +
      "%'";
    sqlShown = sql;
    try {
      products = await db.prepare(sql).all();
    } catch (e) {
      return res.render("products", {
        products: [],
        q,
        sqlShown,
        error: isOn("A02_misconfiguration") ? "Invalid search." : "SQL error: " + e.message,
        user: req.session.user || null,
      });
    }
    // vuln:end
  }

  res.render("products", {
    products,
    q: q || "",
    sqlShown,
    error: null,
    user: req.session.user || null,
  });
});

module.exports = router;
