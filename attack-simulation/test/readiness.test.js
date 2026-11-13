// attack-simulation/test/readiness.test.js
// Unit tests for lib/readiness.js, the detection readiness gate used by
// attack.js.
//
// Property-based coverage for the same gate lives in
// readiness.property.test.js.

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
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
} = require("../lib/readiness");

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sangyshop-readiness-"));
}

function writeStamp(dir, lab, overrides = {}) {
  const stamp = {
    schema: 1,
    lab,
    region: "us-east-1",
    checked_utc: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    checks: {
      subscription_confirmed: true,
      alarm_has_action: true,
      log_group_exists: true,
      trail_logging: true,
    },
    ...overrides,
  };
  const stampPath = path.join(dir, `readiness-${lab}.json`);
  fs.writeFileSync(stampPath, JSON.stringify(stamp), "utf8");
  return stampPath;
}

test("readinessDir defaults to $HOME/.sangyshop-lab when LAB_MANIFEST_PATH is unset", () => {
  const dir = readinessDir({});
  assert.equal(dir, path.join(os.homedir(), ".sangyshop-lab"));
});

test("readinessDir follows LAB_MANIFEST_PATH's folder when set", () => {
  const manifestPath = path.join("C", "custom", "manifest-sangyshop-lab-aws.json");
  const dir = readinessDir({ LAB_MANIFEST_PATH: manifestPath });
  assert.equal(dir, path.dirname(manifestPath));
});

test("readinessStampPath names the file readiness-<lab>.json", () => {
  const p = readinessStampPath(AWS_LAB, {});
  assert.equal(path.basename(p), `readiness-${AWS_LAB}.json`);
});

test("loadReadinessStamp reports 'missing' when the file does not exist", () => {
  const dir = makeTempDir();
  const result = loadReadinessStamp(AWS_LAB, { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "missing");
});

test("loadReadinessStamp reports 'invalid-json' on a malformed file", () => {
  const dir = makeTempDir();
  fs.writeFileSync(path.join(dir, `readiness-${AWS_LAB}.json`), "{ not json", "utf8");
  const result = loadReadinessStamp(AWS_LAB, { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "invalid-json");
});

test("loadReadinessStamp parses a well-formed stamp", () => {
  const dir = makeTempDir();
  writeStamp(dir, AWS_LAB);
  const result = loadReadinessStamp(AWS_LAB, { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") });
  assert.equal(result.ok, true);
  assert.equal(result.stamp.lab, AWS_LAB);
});

test("allChecksTrue is true only when every value is strictly boolean true", () => {
  assert.equal(allChecksTrue({ a: true, b: true }), true);
  assert.equal(allChecksTrue({ a: true, b: false }), false);
  assert.equal(allChecksTrue({ a: true, b: "true" }), false);
  assert.equal(allChecksTrue({}), false);
  assert.equal(allChecksTrue(null), false);
  assert.equal(allChecksTrue("nope"), false);
});

test("parseCheckedUtc parses a Z-suffixed ISO timestamp and rejects garbage", () => {
  assert.equal(parseCheckedUtc("2026-11-11T12:00:00Z"), Date.parse("2026-11-11T12:00:00Z"));
  assert.equal(parseCheckedUtc("not a date"), null);
  assert.equal(parseCheckedUtc(""), null);
  assert.equal(parseCheckedUtc(undefined), null);
});

test("validateReadinessStamp accepts a fresh, matching, fully-passing stamp", () => {
  const now = Date.now();
  const stamp = {
    lab: AWS_LAB,
    region: "us-east-1",
    checked_utc: new Date(now - 60 * 1000).toISOString(),
    checks: { a: true, b: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB, region: "us-east-1", now });
  assert.equal(result.valid, true);
});

test("validateReadinessStamp rejects a stamp for a different lab", () => {
  const stamp = {
    lab: AZURE_LAB,
    region: "us-east-1",
    checked_utc: new Date().toISOString(),
    checks: { a: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "wrong-lab");
});

test("validateReadinessStamp rejects a stamp for a different region when region is given", () => {
  const stamp = {
    lab: AWS_LAB,
    region: "eu-west-1",
    checked_utc: new Date().toISOString(),
    checks: { a: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB, region: "us-east-1" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "wrong-region");
});

test("validateReadinessStamp ignores region comparison when no region is requested", () => {
  const stamp = {
    lab: AWS_LAB,
    region: "eu-west-1",
    checked_utc: new Date().toISOString(),
    checks: { a: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB });
  assert.equal(result.valid, true);
});

test("validateReadinessStamp rejects a stamp older than maxAgeHours", () => {
  const now = Date.now();
  const stamp = {
    lab: AWS_LAB,
    region: "us-east-1",
    checked_utc: new Date(now - 25 * 60 * 60 * 1000).toISOString(),
    checks: { a: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB, region: "us-east-1", now, maxAgeHours: DEFAULT_MAX_AGE_HOURS });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "stale");
});

test("validateReadinessStamp honors a custom --readiness-max-age-hours", () => {
  const now = Date.now();
  const stamp = {
    lab: AWS_LAB,
    region: "us-east-1",
    checked_utc: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
    checks: { a: true },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB, region: "us-east-1", now, maxAgeHours: 1 });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "stale");
});

test("validateReadinessStamp rejects a stamp that records a failed check", () => {
  const stamp = {
    lab: AWS_LAB,
    region: "us-east-1",
    checked_utc: new Date().toISOString(),
    checks: { subscription_confirmed: true, alarm_has_action: false },
  };
  const result = validateReadinessStamp(stamp, { lab: AWS_LAB, region: "us-east-1" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "checks-failed");
});

test("validateReadinessStamp rejects a malformed stamp (not an object, or missing checked_utc)", () => {
  assert.equal(validateReadinessStamp(null, { lab: AWS_LAB }).reason, "malformed");
  assert.equal(validateReadinessStamp("x", { lab: AWS_LAB }).reason, "malformed");
  assert.equal(
    validateReadinessStamp({ lab: AWS_LAB, checks: { a: true } }, { lab: AWS_LAB }).reason,
    "malformed"
  );
});

test("checkReadiness end to end: missing stamp file", () => {
  const dir = makeTempDir();
  const result = checkReadiness({ lab: AWS_LAB, env: { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") } });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "missing");
});

test("checkReadiness end to end: valid fresh stamp on disk", () => {
  const dir = makeTempDir();
  writeStamp(dir, AWS_LAB);
  const result = checkReadiness({
    lab: AWS_LAB,
    region: "us-east-1",
    env: { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") },
  });
  assert.equal(result.valid, true);
});

test("checkReadiness end to end: stale stamp on disk is rejected", () => {
  const dir = makeTempDir();
  writeStamp(dir, AWS_LAB, {
    checked_utc: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
  });
  const result = checkReadiness({
    lab: AWS_LAB,
    env: { LAB_MANIFEST_PATH: path.join(dir, "manifest-x.json") },
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "stale");
});
