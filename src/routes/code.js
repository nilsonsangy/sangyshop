// src/routes/code.js
// "Ver código" (View Code) route — R7.
//
// GET /code/:vuln returns an HTML fragment (for the modal/panel opened by the
// view-code partial) showing the REAL source snippet for a vulnerability, with
// the resolved range highlighted:
//   - defense OFF -> highlight the vulnerable block
//   - defense ON  -> highlight the secure block
// A03 has no toggle (defenseKey null) and uses a fixed convention: the single
// dependencies block is always highlighted.
//
// Behaviour:
//   - unknown :vuln               -> 404 JSON (not in the catalog)
//   - source file not loadable    -> 200 + unavailability message (R7.7); the
//                                     process never crashes
//   - success                     -> 200 HTML fragment; all source text is
//                                     HTML-escaped by the view via <%= %> (R7)
const express = require("express");
const router = express.Router();
const { CATALOG, getSnippet } = require("../lib/snippets");
const { isOn } = require("../lib/defenses");

// Resolve which block to emphasize. When the vulnerability has an associated
// defense, the Defenses_Panel state is the authoritative source (R7.6):
// secure when the defense is ON, vulnerable when OFF (R7.3/R7.4). When there is
// no toggle (A03, defenseKey null), use the fixed convention: highlight the
// (single) vulnerable/dependencies block.
function resolveHighlight(defenseKey) {
  if (!defenseKey) return "vulnerable";
  return isOn(defenseKey) ? "secure" : "vulnerable";
}

// Split the live file content into ordered, non-overlapping sections so the
// view can render the whole snippet with exactly one highlighted block. Each
// section carries { state, label, code, active }. `state` is "context",
// "vulnerable" or "secure". The active section matches the resolved highlight.
//
// For A03 (json-deps) vulnRange and secureRange are the SAME object; in that
// case we emit a single highlighted block (active when highlight is anything,
// since there is no secure counterpart).
function buildBlocks(snippet, highlight) {
  const { code, vulnRange, secureRange } = snippet;

  // A03 fixed convention: one block, always active.
  if (vulnRange === secureRange || vulnRange.start === secureRange.start) {
    return [
      {
        state: "vulnerable",
        label: "Dependências (trecho fixo, sem toggle)",
        code: vulnRange.code,
        active: true,
      },
    ];
  }

  // Order the two ranges by position in the file.
  const first = vulnRange.start <= secureRange.start ? vulnRange : secureRange;
  const second = first === vulnRange ? secureRange : vulnRange;
  const firstIsVuln = first === vulnRange;

  const sections = [];
  const pushContext = (from, to) => {
    if (to > from) {
      const text = code.slice(from, to);
      if (text.trim().length > 0 || text.includes("\n")) {
        sections.push({ state: "context", label: "contexto", code: text, active: false });
      }
    }
  };

  pushContext(0, first.start);
  sections.push({
    state: firstIsVuln ? "vulnerable" : "secure",
    label: firstIsVuln ? "trecho vulnerável" : "trecho seguro",
    code: first.code,
    active: firstIsVuln ? highlight === "vulnerable" : highlight === "secure",
  });
  pushContext(first.end, second.start);
  sections.push({
    state: firstIsVuln ? "secure" : "vulnerable",
    label: firstIsVuln ? "trecho seguro" : "trecho vulnerável",
    code: second.code,
    active: firstIsVuln ? highlight === "secure" : highlight === "vulnerable",
  });
  pushContext(second.end, code.length);

  return sections;
}

router.get("/code/:vuln", async (req, res) => {
  const vuln = req.params.vuln;
  const entry = CATALOG[vuln];

  // Unknown vulnerability -> 404 JSON.
  if (!entry) {
    return res.status(404).json({ error: "Unknown vulnerability: " + vuln });
  }

  const highlight = resolveHighlight(entry.defenseKey);

  let snippet;
  try {
    snippet = await getSnippet(vuln);
  } catch (err) {
    // R7.7: source not loadable -> 200 with unavailability message, never 500,
    // process stays up and the page stays navigable.
    return res.status(200).render("code-fragment", {
      vuln,
      file: entry.file,
      highlight,
      defenseKey: entry.defenseKey,
      blocks: [],
      unavailable: err.message,
    });
  }

  let blocks;
  try {
    blocks = buildBlocks(snippet, highlight);
  } catch (err) {
    return res.status(200).render("code-fragment", {
      vuln,
      file: entry.file,
      highlight,
      defenseKey: entry.defenseKey,
      blocks: [],
      unavailable: err.message,
    });
  }

  // Success: render the fragment. The view escapes all source text via <%= %>.
  // A render failure degrades to the unavailability message so the process and
  // page survive (R7.7), mirroring the defensive render in diag.js.
  try {
    return res.status(200).render("code-fragment", {
      vuln,
      file: snippet.file,
      highlight,
      defenseKey: entry.defenseKey,
      blocks,
      unavailable: null,
    });
  } catch (err) {
    return res.status(200).render("code-fragment", {
      vuln,
      file: entry.file,
      highlight,
      defenseKey: entry.defenseKey,
      blocks: [],
      unavailable: "falha ao renderizar o trecho",
    });
  }
});

module.exports = router;
