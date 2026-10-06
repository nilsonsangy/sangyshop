// src/server.js
// SangyShop main server. Wires up the routes and implements A02
// (Security Misconfiguration) via toggle: security headers and error handling.
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

// A02: security headers applied only when the defense is ON.
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

// Routes
app.get("/", (req, res) => res.redirect("/products"));
app.use("/", require("./routes/auth"));
app.use("/", require("./routes/products"));
app.use("/api", require("./routes/api"));
app.use("/", require("./routes/admin"));
app.use("/", require("./routes/orders"));

// Route that throws an error on purpose, to demonstrate A02 (exposed stack trace).
app.get("/debug/boom", (req, res) => {
  throw new Error("Simulated internal failure in /debug/boom (null object)");
});

// Error handler: A02 controls whether the stack trace leaks or not.
app.use((err, req, res, next) => {
  if (isOn("A02_misconfiguration")) {
    res.status(500).send("Internal error. Please try again later.");
  } else {
    res.status(500).type("text/plain").send(
      "ERROR 500 - SangyShop (vulnerable mode)\n\n" + (err.stack || err.message)
    );
  }
});

// Initialize the database (async, sql.js/WASM) and only then start listening.
db.init()
  .then(() => {
    app.listen(PORT, () => {
      console.log("SangyShop running at http://localhost:" + PORT);
      console.log("Current defenses:", JSON.stringify(readAll()));
    });
  })
  .catch((e) => {
    console.error("Failed to initialize the database:", e);
    process.exit(1);
  });
