// attack-simulation/test/marker.property.test.js
// Attack script gate
//
// isLabMarker is the gate: true iff status === 200, body.app === "sangyshop",
// body.mode === "vulnerable" and header X-SangyShop-Lab === "vulnerable-lab".
// Value comparisons are strict (no trim, no case folding); only the header NAME
// is case-insensitive.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const {
  isLabMarker,
  EXPECTED_HEADER_NAME,
  EXPECTED_HEADER_VALUE,
  EXPECTED_APP,
  EXPECTED_MODE,
} = require("../lib/marker");

const RUNS = 100;

// Header name casings (name lookup is case-insensitive).
const headerNameArb = fc
  .array(fc.boolean(), {
    minLength: EXPECTED_HEADER_NAME.length,
    maxLength: EXPECTED_HEADER_NAME.length,
  })
  .map((flags) =>
    [...EXPECTED_HEADER_NAME]
      .map((c, i) => (flags[i] ? c.toUpperCase() : c))
      .join("")
  );

// Near-miss and arbitrary variants for each field (always != the expected value).
function variantArb(expected) {
  return fc.oneof(
    fc.string().filter((s) => s !== expected),
    fc.constantFrom(
      expected.toUpperCase(),
      expected[0].toUpperCase() + expected.slice(1),
      ` ${expected}`,
      `${expected} `,
      `${expected}\n`,
      `${expected}x`,
      expected.slice(0, -1),
      "",
      "lab"
    ),
    fc.constantFrom(null, undefined, 0, 1, true, false, [expected], {})
  );
}

const statusBadArb = fc.oneof(
  fc.integer({ min: 100, max: 599 }).filter((n) => n !== 200),
  fc.constantFrom(201, 204, 301, 302, 403, 404, 500, "200", 200.5, null, undefined, NaN)
);

const extraHeadersArb = fc.dictionary(
  fc.string({ minLength: 1, maxLength: 12 }).filter(
    (k) => k.toLowerCase() !== EXPECTED_HEADER_NAME
  ),
  fc.string()
);
const extraBodyArb = fc.dictionary(
  fc.string({ minLength: 1, maxLength: 12 }).filter((k) => k !== "app" && k !== "mode"),
  fc.jsonValue()
);

// Fully valid response, with arbitrary noise around the required fields.
const validArb = fc
  .record({
    name: headerNameArb,
    extraHeaders: extraHeadersArb,
    extraBody: extraBodyArb,
  })
  .map(({ name, extraHeaders, extraBody }) => ({
    status: 200,
    headers: { ...extraHeaders, [name]: EXPECTED_HEADER_VALUE },
    body: { ...extraBody, app: EXPECTED_APP, mode: EXPECTED_MODE },
  }));

test("all four conditions hold => true (any header-name casing, extra fields)", () => {
  fc.assert(
    fc.property(validArb, (res) => {
      assert.equal(isLabMarker(res), true);
    }),
    { numRuns: RUNS }
  );
});

test("wrong status => false", () => {
  fc.assert(
    fc.property(validArb, statusBadArb, (res, status) => {
      assert.equal(isLabMarker({ ...res, status }), false);
    }),
    { numRuns: RUNS }
  );
});

test("wrong body.app => false", () => {
  fc.assert(
    fc.property(validArb, variantArb(EXPECTED_APP), (res, app) => {
      assert.equal(isLabMarker({ ...res, body: { ...res.body, app } }), false);
    }),
    { numRuns: RUNS }
  );
});

test("wrong body.mode => false", () => {
  fc.assert(
    fc.property(validArb, variantArb(EXPECTED_MODE), (res, mode) => {
      assert.equal(isLabMarker({ ...res, body: { ...res.body, mode } }), false);
    }),
    { numRuns: RUNS }
  );
});

test("missing or wrong X-SangyShop-Lab header => false", () => {
  fc.assert(
    fc.property(
      validArb,
      variantArb(EXPECTED_HEADER_VALUE),
      fc.boolean(),
      (res, value, remove) => {
        const headers = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (k.toLowerCase() !== EXPECTED_HEADER_NAME) headers[k] = v;
        }
        if (!remove) headers[EXPECTED_HEADER_NAME] = value;
        assert.equal(isLabMarker({ ...res, headers }), false);
      }
    ),
    { numRuns: RUNS }
  );
});

test("missing/malformed body, headers or response => false", () => {
  fc.assert(
    fc.property(
      validArb,
      fc.constantFrom(null, undefined, "sangyshop", 42, true),
      (res, junk) => {
        assert.equal(isLabMarker({ ...res, body: junk }), false);
        assert.equal(isLabMarker({ ...res, headers: junk }), false);
        assert.equal(isLabMarker(junk), false);
      }
    ),
    { numRuns: RUNS }
  );
});

test("iff: result equals the conjunction of the four conditions", () => {
  const maybe = (good, bad) => fc.oneof(fc.constant(good), bad);
  fc.assert(
    fc.property(
      maybe(200, statusBadArb),
      maybe(EXPECTED_APP, variantArb(EXPECTED_APP)),
      maybe(EXPECTED_MODE, variantArb(EXPECTED_MODE)),
      maybe(EXPECTED_HEADER_VALUE, variantArb(EXPECTED_HEADER_VALUE)),
      headerNameArb,
      (status, app, mode, hv, name) => {
        const res = { status, headers: { [name]: hv }, body: { app, mode } };
        const expected =
          status === 200 &&
          app === EXPECTED_APP &&
          mode === EXPECTED_MODE &&
          hv === EXPECTED_HEADER_VALUE;
        assert.equal(isLabMarker(res), expected);
      }
    ),
    { numRuns: RUNS }
  );
});
