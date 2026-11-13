// attack-simulation/lib/readiness.js
// Pure module: decides whether a parsed readiness stamp is valid for the
// current attack run, and finds/loads/parses the stamp file from disk.
//
// The stamp is written by ops/aws/ir-lab/check-detection-ready.ps1 or
// ops/azure/ir-lab/check-detection-ready.ps1 (Write-LabReadinessStamp /
// the Azure inline writer), as readiness-<lab>.json next to the lab
// manifest ($HOME/.sangyshop-lab/, or the folder of LAB_MANIFEST_PATH).
// This module never makes a network call and never shells out to a cloud
// CLI; it only reads a local JSON file.
//
// Stamp shape (both clouds):
// {
//   "schema": 1,
//   "lab": "sangyshop-lab-aws" | "sangyshop-lab-azure",
//   "region": "<aws region or azure location>",
//   "checked_utc": "2026-11-11T12:00:00Z",
//   "checks": { <four boolean fields, one per cloud's checklist> }
// }

const fs = require("fs");
const path = require("path");
const os = require("os");

const AWS_LAB = "sangyshop-lab-aws";
const AZURE_LAB = "sangyshop-lab-azure";
const DEFAULT_MAX_AGE_HOURS = 24;

// Resolves the directory the stamp lives in: $LAB_MANIFEST_PATH's folder if
// set, else $HOME/.sangyshop-lab (mirrors Get-LabManifestPath in
// ops/lib/Common.ps1).
function readinessDir(env = process.env) {
  const manifestPath = env.LAB_MANIFEST_PATH;
  if (manifestPath && manifestPath.trim().length > 0) {
    return path.dirname(manifestPath);
  }
  return path.join(os.homedir(), ".sangyshop-lab");
}

function readinessStampPath(lab, env = process.env) {
  return path.join(readinessDir(env), `readiness-${lab}.json`);
}

// Reads and parses the stamp file for `lab`. Returns { ok: true, stamp } on
// success, or { ok: false, reason } when the file is missing, unreadable or
// not valid JSON. Never throws.
function loadReadinessStamp(lab, env = process.env) {
  const stampPath = readinessStampPath(lab, env);
  let text;
  try {
    text = fs.readFileSync(stampPath, "utf8");
  } catch (err) {
    if (err && err.code === "ENOENT") {
      return { ok: false, reason: "missing", path: stampPath };
    }
    return { ok: false, reason: "unreadable", path: stampPath, error: err.message };
  }
  try {
    const stamp = JSON.parse(text);
    return { ok: true, stamp, path: stampPath };
  } catch (err) {
    return { ok: false, reason: "invalid-json", path: stampPath, error: err.message };
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Checks every value under stamp.checks is strictly boolean true. An empty
// or missing checks object is not valid (nothing was actually checked).
function allChecksTrue(checks) {
  if (!isPlainObject(checks)) return false;
  const keys = Object.keys(checks);
  if (keys.length === 0) return false;
  return keys.every((key) => checks[key] === true);
}

// Parses an ISO 8601 UTC timestamp (expects a trailing "Z", as written by
// both check-detection-ready.ps1 scripts). Returns milliseconds since epoch,
// or null when the value is not a valid timestamp.
function parseCheckedUtc(value) {
  if (typeof value !== "string" || value.trim().length === 0) return null;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return null;
  return ms;
}

// Validates a parsed stamp against the expected lab, region and max age.
// Returns { valid: true } or { valid: false, reason } where reason is one
// of: "wrong-lab", "wrong-region", "malformed", "stale", "checks-failed".
//
// region is optional: when omitted (or empty), the region field is not
// checked, matching an attack.js run where the operator did not pass a
// region to compare against.
function validateReadinessStamp(stamp, { lab, region, maxAgeHours = DEFAULT_MAX_AGE_HOURS, now = Date.now() } = {}) {
  if (!isPlainObject(stamp)) return { valid: false, reason: "malformed" };

  if (typeof stamp.lab !== "string" || stamp.lab !== lab) {
    return { valid: false, reason: "wrong-lab" };
  }

  if (region && region.trim().length > 0) {
    if (typeof stamp.region !== "string" || stamp.region !== region) {
      return { valid: false, reason: "wrong-region" };
    }
  }

  const checkedAtMs = parseCheckedUtc(stamp.checked_utc);
  if (checkedAtMs === null) return { valid: false, reason: "malformed" };

  if (!allChecksTrue(stamp.checks)) {
    return { valid: false, reason: "checks-failed" };
  }

  const ageHours = (now - checkedAtMs) / (1000 * 60 * 60);
  if (!Number.isFinite(ageHours) || ageHours < 0 || ageHours > maxAgeHours) {
    return { valid: false, reason: "stale" };
  }

  return { valid: true };
}

// One-call convenience: loads the stamp for `lab` and validates it. Returns
// the same shape as validateReadinessStamp, plus "missing" / "unreadable" /
// "invalid-json" reasons bubbled up from loadReadinessStamp, and the
// resolved stamp path for error messages.
function checkReadiness({ lab, region, maxAgeHours = DEFAULT_MAX_AGE_HOURS, now = Date.now(), env = process.env } = {}) {
  const loaded = loadReadinessStamp(lab, env);
  if (!loaded.ok) {
    return { valid: false, reason: loaded.reason, path: loaded.path };
  }
  const result = validateReadinessStamp(loaded.stamp, { lab, region, maxAgeHours, now });
  return { ...result, path: loaded.path, stamp: loaded.stamp };
}

module.exports = {
  AWS_LAB,
  AZURE_LAB,
  DEFAULT_MAX_AGE_HOURS,
  readinessDir,
  readinessStampPath,
  loadReadinessStamp,
  allChecksTrue,
  parseCheckedUtc,
  validateReadinessStamp,
  checkReadiness,
};
