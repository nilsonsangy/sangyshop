// src/server.js
// Servidor principal da SangyShop. Amarra as rotas e implementa o A02
// (Security Misconfiguration) via toggle: headers de seguranca e tratamento de erro.
const express = require("express");
const session = require("express-session");
const path = require("path");
const { isOn, readAll } = require("./lib/defenses");
const db = require("./db/database");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

app.use(
  session({
    secret: "sangyshop-demo-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// A02: headers de seguranca aplicados somente quando a defesa esta LIGADA.
app.use((req, res, next) => {
  if (isOn("A02_misconfiguration")) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "default-src 'self'");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.removeHeader("X-Powered-By");
  } else {
    res.setHeader("X-Powered-By", "Express 4.18 / SangyShop 1.0");
  }
  next();
});

// Rotas
app.get("/", (req, res) => res.redirect("/products"));
app.use("/", require("./routes/auth"));
app.use("/", require("./routes/products"));
app.use("/api", require("./routes/api"));
app.use("/", require("./routes/admin"));

// Rota que gera erro de proposito, para demonstrar o A02 (stack trace exposto).
app.get("/debug/boom", (req, res) => {
  throw new Error("Falha interna simulada em /debug/boom (objeto nulo)");
});

// Handler de erro: A02 controla se o stack trace vaza ou nao.
app.use((err, req, res, next) => {
  if (isOn("A02_misconfiguration")) {
    res.status(500).send("Erro interno. Tente novamente mais tarde.");
  } else {
    res.status(500).type("text/plain").send(
      "ERRO 500 - SangyShop (modo vulneravel)\n\n" + (err.stack || err.message)
    );
  }
});

// Inicializa o banco (async, sql.js/WASM) e so entao comeca a ouvir.
db.init()
  .then(() => {
    app.listen(PORT, () => {
      console.log("SangyShop rodando em http://localhost:" + PORT);
      console.log("Defesas atuais:", JSON.stringify(readAll()));
    });
  })
  .catch((e) => {
    console.error("Falha ao inicializar o banco:", e);
    process.exit(1);
  });
