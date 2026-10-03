// src/db/database.js
// Banco SQLite em memoria via sql.js (WebAssembly) - sem compilacao nativa,
// roda em qualquer ambiente. Executa SQL real, entao a SQL Injection e autentica.
// Expoe uma API minima compativel: db.prepare(sql).get(...)/.all(...)/.run(...)
// e db.exec(sql). A inicializacao e sincrona na carga do modulo (initSqlJs e
// resolvido com um pequeno loop de espera no boot do servidor).
const initSqlJs = require("sql.js");

let SQL = null;
let rawDb = null;
let ready = false;

const api = {
  isReady() { return ready; },

  exec(sql) {
    return rawDb.exec(sql);
  },

  // Retorna um objeto com get/all/run para um SQL (com ou sem placeholders ?).
  prepare(sql) {
    return {
      get(...params) {
        const stmt = rawDb.prepare(sql);
        try {
          if (params.length) stmt.bind(params);
          if (stmt.step()) return stmt.getAsObject();
          return undefined;
        } finally {
          stmt.free();
        }
      },
      all(...params) {
        const stmt = rawDb.prepare(sql);
        const rows = [];
        try {
          if (params.length) stmt.bind(params);
          while (stmt.step()) rows.push(stmt.getAsObject());
          return rows;
        } finally {
          stmt.free();
        }
      },
      run(...params) {
        rawDb.run(sql, params.length ? params : undefined);
        return { changes: rawDb.getRowsModified() };
      },
    };
  },
};

function createSchemaAndSeed() {
  rawDb.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      email TEXT,
      credit_card TEXT
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      total REAL NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const u = [
    ["admin", "SangyAdmin!2025", "admin", "admin@sangyshop.local", "4111-1111-1111-1111"],
    ["alice", "alice123", "customer", "alice@mail.local", "5500-0000-0000-0004"],
    ["bob", "bob123", "customer", "bob@mail.local", "6011-0000-0000-0004"],
    ["carol", "carol123", "customer", "carol@mail.local", "3400-000000-00009"],
  ];
  u.forEach((r) => rawDb.run("INSERT INTO users (username,password,role,email,credit_card) VALUES (?,?,?,?,?)", r));

  const p = [
    ["Camiseta SangyShop", "Algodao, estampa do curso Blue Team", 79.9],
    ["Caneca Hacker", "Ceramica 300ml, tema OWASP", 49.9],
    ["Adesivo Pack", "10 adesivos de seguranca ofensiva/defensiva", 19.9],
    ["Moletom DFIR", "Capuz, forense digital", 189.9],
    ["Chaveiro Token", "Chaveiro em formato de token OTP", 29.9],
  ];
  p.forEach((r) => rawDb.run("INSERT INTO products (name,description,price) VALUES (?,?,?)", r));

  const o = [
    [2, 1, 2, 159.8],
    [2, 3, 1, 19.9],
    [3, 4, 1, 189.9],
    [4, 2, 3, 149.7],
  ];
  o.forEach((r) => rawDb.run("INSERT INTO orders (user_id,product_id,quantity,total) VALUES (?,?,?,?)", r));
}

api.init = async function init() {
  if (ready) return api;
  SQL = await initSqlJs();
  rawDb = new SQL.Database();
  createSchemaAndSeed();
  ready = true;
  return api;
};

module.exports = api;
