// src/lib/accesslog.js
// Structured JSON logs written to stdout (one line per event).
// Independent of the A09 defense toggle. Disabled only with STRUCTURED_LOGS=off.
// Never logs: password, request body, cookies, Authorization header.
const crypto = require("crypto");

const MAX_QUERY = 256;
const MAX_USERNAME = 64;

function enabled() {
  return String(process.env.STRUCTURED_LOGS || "on").trim().toLowerCase() !== "off";
}

function truncate(value, max) {
  const s = value === undefined || value === null ? "" : String(value);
  return s.length > max ? s.slice(0, max) : s;
}

function newRequestId() {
  return crypto.randomBytes(4).toString("hex");
}

// Pure: builds the record object. kind: "http_request" | "auth_login".
function buildRecord(kind, fields = {}) {
  const base = {
    ts: new Date().toISOString(),
    level: "info",
    event: kind,
    ip: truncate(fields.ip, 64) || "unknown",
  };
  if (kind === "auth_login") {
    base.username = truncate(fields.username, MAX_USERNAME);
    base.result = fields.result === "success" ? "success" : "failure";
    if (fields.status !== undefined) base.status = fields.status;
  } else {
    base.method = truncate(fields.method, 16);
    base.path = String(fields.path === undefined || fields.path === null ? "" : fields.path);
    base.query = truncate(fields.query, MAX_QUERY);
    base.status = fields.status;
    base.duration_ms = fields.duration_ms;
  }
  base.request_id = fields.request_id || "";
  return base;
}

function emit(record) {
  // JSON.stringify escapes newlines, so injected line breaks cannot forge lines.
  process.stdout.write(JSON.stringify(record) + "\n");
}

function accessLogMiddleware(req, res, next) {
  if (!enabled()) return next();
  const start = process.hrtime.bigint();
  const requestId = newRequestId();
  req.requestId = requestId;

  res.on("finish", () => {
    const url = req.originalUrl || req.url || "";
    const idx = url.indexOf("?");
    emit(
      buildRecord("http_request", {
        ip: req.ip || (req.connection && req.connection.remoteAddress),
        method: req.method,
        path: idx === -1 ? url : url.slice(0, idx),
        query: idx === -1 ? "" : url.slice(idx + 1),
        status: res.statusCode,
        duration_ms: Number((process.hrtime.bigint() - start) / 1000000n),
        request_id: requestId,
      })
    );
  });
  next();
}

// One line per login attempt. result: "success" | "failure".
function logAuth({ ip, username, result, status, request_id } = {}) {
  if (!enabled()) return null;
  const record = buildRecord("auth_login", { ip, username, result, status, request_id });
  emit(record);
  return record;
}

module.exports = { accessLogMiddleware, logAuth, buildRecord };
