// src/routes/media.js
// Opt-in media routes backed by the object store (S3 or Azure Blob).
//   POST /admin/media   upload (admin only)
//   GET  /media/:key    download
// The routes are mounted ONLY when the active provider is not "none"; with
// "none" nothing is registered and Express answers 404 on its own.
// A store failure becomes HTTP 502 on these two routes only.
const express = require("express");
const { isValidKey } = require("../lib/objectstore/common");

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

// Returns an Express router, or null when the provider is "none".
function createMediaRouter(store) {
  if (!store || store.provider === "none") return null;

  const router = express.Router();

  function sendFailure(res, result) {
    const status =
      result.code === "INVALID_KEY" ? 400 : result.code === "NOT_FOUND" ? 404 : 502;
    if (status === 502) {
      // Log without credentials: only the code and the fixed message.
      console.error("[media] object store failure: " + result.code + " - " + result.message);
    }
    return res.status(status).json({ ok: false, code: result.code, message: result.message });
  }

  function requireAdmin(req, res, next) {
    const user = req.session && req.session.user;
    if (!user) return res.status(401).json({ ok: false, code: "UNAUTHENTICATED", message: "Login required." });
    if (user.role !== "admin") return res.status(403).json({ ok: false, code: "FORBIDDEN", message: "Admin only." });
    next();
  }

  // Raw bodies (any content type except JSON/urlencoded, already parsed globally).
  const rawBody = express.raw({ type: (req) => !req.is("json") && !req.is("urlencoded"), limit: MAX_UPLOAD_BYTES });

  // Upload: raw body with ?key=name, or JSON { key, content_base64, content_type }.
  router.post("/admin/media", requireAdmin, rawBody, async (req, res) => {
    const body = req.body;
    const key = (req.query && req.query.key) || (body && !Buffer.isBuffer(body) && body.key);
    if (!isValidKey(key)) {
      return sendFailure(res, { code: "INVALID_KEY", message: "Object key must match ^[a-z0-9._-]{1,64}$." });
    }
    let data;
    let contentType;
    if (Buffer.isBuffer(body) && body.length > 0) {
      data = body;
      contentType = req.get("content-type");
    } else if (body && typeof body.content_base64 === "string") {
      data = Buffer.from(body.content_base64, "base64");
      contentType = body.content_type;
    } else {
      return res.status(400).json({ ok: false, code: "EMPTY_BODY", message: "No content to upload." });
    }
    if (data.length > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ ok: false, code: "TOO_LARGE", message: "Upload exceeds the size limit." });
    }
    const result = await store.put(key, data, { contentType });
    if (!result.ok) return sendFailure(res, result);
    return res.status(201).json({ ok: true, key: result.key });
  });

  router.get("/media/:key", async (req, res) => {
    const result = await store.get(req.params.key);
    if (!result.ok) return sendFailure(res, result);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Disposition", "attachment");
    res.type("application/octet-stream");
    return res.send(result.body);
  });

  return router;
}

// Convenience: mounts the media routes on the app only when the provider is active.
function mountMedia(app, store) {
  const router = createMediaRouter(store);
  if (router) app.use("/", router);
  return !!router;
}

module.exports = { createMediaRouter, mountMedia };
