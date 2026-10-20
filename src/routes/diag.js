// src/routes/diag.js
// GET /_diag — posture diagnostic endpoint with content negotiation.
// Always responds HTTP 200 and never throws: buildPostureReport() is total,
// and the HTML render is wrapped so a view failure falls back to minimal JSON.
const express = require("express");
const router = express.Router();
const { buildPostureReport } = require("../lib/posture");

router.get("/_diag", (req, res) => {
  const report = buildPostureReport();

  // Content negotiation: only `format` changes the representation; any other
  // query param is ignored. ?format=json → JSON; ?format=html → HTML; absent →
  // honor Accept header via req.accepts(["html","json"]).
  const wantsJson =
    req.query.format === "json" ||
    (req.query.format !== "html" && req.accepts(["html", "json"]) === "json");

  if (wantsJson) {
    return res.status(200).json(report);
  }

  // Defensive render: if the view throws for any reason, degrade to minimal
  // JSON so the endpoint never returns a 500.
  try {
    return res.status(200).render("diag", {
      report,
      podName: req.app.locals.podName,
      user: req.session.user || null,
    });
  } catch (err) {
    return res.status(200).json(report);
  }
});

module.exports = router;
