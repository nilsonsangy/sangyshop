// src/lib/snippets.js
// Catalog for the "Ver código" (View Code) feature.
//
// Each vulnerability maps to a real source file. The snippet shown to the
// instructor is read LIVE from that file (via fs.promises.readFile) and sliced
// by textual anchors, so the "Ver código" panel always reflects the code that
// is actually running (R7.2, design Property 13: the returned code is a literal
// substring of the live file).
//
// Anchor convention (comment markers placed in the mapped source files):
//   // vuln:start   ... // vuln:end     -> the vulnerable code block
//   // secure:start ... // secure:end   -> the fixed / safe code block
//
// For files where comments are impossible (package.json, A03), there is no
// toggle and no comment markers; instead a fixed textual convention delimits
// the relevant section (the `dependencies` block, which holds the outdated /
// vulnerable dependencies). In that case `vuln` and `secure` share the same
// range object and both point to the dependencies block.
//
// getSnippet(vuln, deps) reads the mapped file live, locates the anchors and
// returns { file, code, vulnRange, secureRange }. `deps.fs` is injectable
// (defaults to fs.promises) so tests can force a read failure (Property 15).
// If the source file cannot be loaded, getSnippet throws; the caller (the
// /code/:vuln route) converts that into an "indisponível" message (R7.7).

"use strict";

const fs = require("fs");
const path = require("path");

// Repository root of the SangyShop app (src/lib/snippets.js -> ../../).
const APP_ROOT = path.join(__dirname, "..", "..");

// Anchor markers. For comment-bearing source files these are literal comments.
const VULN_START = "// vuln:start";
const VULN_END = "// vuln:end";
const SECURE_START = "// secure:start";
const SECURE_END = "// secure:end";

// Fixed-convention anchors for A03 / package.json (JSON cannot carry comments).
// We slice the whole `dependencies` block, which holds the outdated libraries.
const JSON_DEPS_START = '"dependencies": {';
const JSON_DEPS_END = "}";

// Catalog: each entry maps a vulnerability id to its source file, the defense
// toggle key (null when there is no toggle) and the anchor convention to use.
//
//   markers: 'comment' -> use // vuln:/secure: comment anchors
//   markers: 'json-deps' -> use the fixed dependencies-block convention
const CATALOG = {
  // A01 Broken Access Control (IDOR) in the orders API.
  A01: {
    file: "src/routes/api.js",
    defenseKey: "A01_access_control",
    markers: "comment",
  },
  // A02 Security Misconfiguration (security headers / X-Powered-By).
  A02: {
    file: "src/server.js",
    defenseKey: "A02_misconfiguration",
    markers: "comment",
  },
  // A03 Software Supply Chain: outdated dependencies in package.json.
  // No toggle in the Defenses_Panel -> defenseKey is null and both ranges
  // point to the same dependencies block (fixed convention, R7.6 n/a).
  A03: {
    file: "package.json",
    defenseKey: null,
    markers: "json-deps",
  },
  // A05 Injection (SQL). Primary source is the login (auth.js); the product
  // search (products.js) carries the same anchors as a secondary example.
  A05: {
    file: "src/routes/auth.js",
    secondaryFile: "src/routes/products.js",
    defenseKey: "A05_injection",
    markers: "comment",
  },
  // A09 Security Logging & Alerting (login attempt recording / brute force).
  A09: {
    file: "src/lib/logger.js",
    defenseKey: "A09_logging",
    markers: "comment",
  },
};

// Locate a range delimited by a start and end marker. Returns the literal slice
// of `content` from the start of the start-marker line through the end of the
// end-marker line (so the returned text is always a substring of `content`),
// plus the character offsets. Returns null when either marker is absent.
function sliceByMarkers(content, startMarker, endMarker) {
  const startIdx = content.indexOf(startMarker);
  if (startIdx === -1) return null;
  const endMarkerIdx = content.indexOf(endMarker, startIdx + startMarker.length);
  if (endMarkerIdx === -1) return null;

  // Expand the start back to the beginning of its line.
  const lineStart = content.lastIndexOf("\n", startIdx) + 1;
  // Expand the end forward to the end of the end-marker's line.
  let lineEnd = content.indexOf("\n", endMarkerIdx + endMarker.length);
  if (lineEnd === -1) lineEnd = content.length;

  return {
    start: lineStart,
    end: lineEnd,
    code: content.slice(lineStart, lineEnd),
  };
}

// Fixed convention for package.json: slice the whole `dependencies` block, from
// the line that opens it through its matching closing brace line.
function sliceJsonDependencies(content) {
  const startIdx = content.indexOf(JSON_DEPS_START);
  if (startIdx === -1) return null;
  const endIdx = content.indexOf(JSON_DEPS_END, startIdx + JSON_DEPS_START.length);
  if (endIdx === -1) return null;

  const lineStart = content.lastIndexOf("\n", startIdx) + 1;
  let lineEnd = content.indexOf("\n", endIdx);
  if (lineEnd === -1) lineEnd = content.length;

  return {
    start: lineStart,
    end: lineEnd,
    code: content.slice(lineStart, lineEnd),
  };
}

// Read and slice a single mapped file according to the entry's marker convention.
async function readAndSlice(entry, relFile, readFile) {
  const absPath = path.join(APP_ROOT, relFile);
  let content;
  try {
    content = await readFile(absPath, "utf8");
  } catch (e) {
    const err = new Error(
      `Snippet source not loadable: ${relFile} (${e.code || e.message})`
    );
    err.cause = e;
    throw err;
  }

  if (entry.markers === "json-deps") {
    const range = sliceJsonDependencies(content);
    if (!range) {
      throw new Error(`Snippet anchors not found in ${relFile} (dependencies block)`);
    }
    // No toggle: vulnerable and secure highlight the same dependencies block.
    return { content, vulnRange: range, secureRange: range };
  }

  const vulnRange = sliceByMarkers(content, VULN_START, VULN_END);
  const secureRange = sliceByMarkers(content, SECURE_START, SECURE_END);
  if (!vulnRange || !secureRange) {
    throw new Error(`Snippet anchors not found in ${relFile}`);
  }
  return { content, vulnRange, secureRange };
}

// getSnippet(vuln, deps) -> { file, code, vulnRange, secureRange }
//
// Reads the mapped source file LIVE and returns the catalog entry's snippet.
// `code` is the full file content (so vulnRange/secureRange offsets index into
// it), and both ranges carry the literal sliced `code` text. Throws when the
// vulnerability is unknown or the source file cannot be loaded (R7.7).
//
// deps.fs defaults to fs.promises; pass a stub to force a read failure in tests
// (Property 15).
async function getSnippet(vuln, deps = {}) {
  const entry = CATALOG[vuln];
  if (!entry) {
    throw new Error(`Unknown vulnerability: ${vuln}`);
  }
  const readFile = (deps.fs && deps.fs.readFile) || fs.promises.readFile;

  const primary = await readAndSlice(entry, entry.file, readFile);

  const result = {
    file: entry.file,
    defenseKey: entry.defenseKey,
    code: primary.content,
    vulnRange: primary.vulnRange,
    secureRange: primary.secureRange,
  };

  // A05 carries a secondary example (products.js) with the same anchors.
  if (entry.secondaryFile) {
    const secondary = await readAndSlice(entry, entry.secondaryFile, readFile);
    result.secondary = {
      file: entry.secondaryFile,
      code: secondary.content,
      vulnRange: secondary.vulnRange,
      secureRange: secondary.secureRange,
    };
  }

  return result;
}

module.exports = { CATALOG, getSnippet };
