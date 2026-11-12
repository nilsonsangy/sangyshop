// test/code.highlight.property.test.js
// Property-based test for the SangyShop "View Code" route
// (src/routes/code.js), rendering src/views/code-fragment.ejs.
//
// Feature: sangyshop-postgres-secret-ver-codigo, Property 14:
//   Highlight selection by defense state.
// Validates: Requirements 7.3, 7.4, 7.6
//
// The route resolves which code block to emphasize from the Defenses_Panel
// state of the vulnerability's associated defense (the authoritative source,
// R7.6): secure when the defense is ON (R7.4), vulnerable when OFF (R7.3).
//
// The rendered fragment carries, on its <section>, data-highlight="secure" or
// "vulnerable", and renders one <span class="code-section" data-state="..."> per
// block; the emphasized block additionally carries the class "code-active".
//
// Property (for every pair of a vuln-WITH-defense and a boolean toggle state):
//   - the resolved highlight is "secure" iff the toggle is ON, else "vulnerable";
//   - the single active block (class code-active) has data-state equal to that
//     resolved highlight;
//   - no block of the opposite state is marked active.
//
// A03 (package.json) has NO defense toggle, this property is specifically
// "WHERE a defense exists" (R7.6), so A03 is excluded from this generator; its
// fixed convention is out of scope here.
//
// Backend: DB_BACKEND=memory (set by test/helpers.js at load). resetToggles()
// runs in afterEach so no in-memory toggle stub leaks between runs/tests.
"use strict";

const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { createTestApp, agent, setToggle, resetToggles } = require("./helpers");

const RUNS = 100;

// Vulnerabilities that HAVE an associated defense toggle in the Defenses_Panel,
// paired with their defenseKey (mirrors the catalog in src/lib/snippets.js).
// A03 is intentionally excluded: it has no toggle (R7.6 "WHERE a defense exists").
const VULNS_WITH_DEFENSE = [
  { vuln: "A01", defenseKey: "A01_access_control" },
  { vuln: "A02", defenseKey: "A02_misconfiguration" },
  { vuln: "A05", defenseKey: "A05_injection" },
  { vuln: "A09", defenseKey: "A09_logging" },
];

// Extract the <section ...> opening tag's data-highlight attribute.
function readSectionHighlight(html) {
  const m = html.match(/<section\b[^>]*\bdata-highlight="([^"]*)"/);
  return m ? m[1] : null;
}

// Return the data-state values of all blocks carrying the code-active class.
// The code-section spans look like:
//   <span class="code-section code-active" data-state="secure" ...>
//   <span class="code-section" data-state="context" ...>
function readActiveStates(html) {
  const states = [];
  const re = /<span class="code-section([^"]*)" data-state="([^"]*)"/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const classSuffix = m[1];
    const state = m[2];
    if (/\bcode-active\b/.test(classSuffix)) {
      states.push(state);
    }
  }
  return states;
}

afterEach(() => {
  // Clear any in-memory toggle stub so state never leaks across runs/tests.
  resetToggles();
});

test("Property 14: highlight tracks the defense toggle (secure iff ON, else vulnerable)", async () => {
  // Build the app once and reuse it across every run (performance). The toggle
  // override is in-memory and swapped per run via setToggle.
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(...VULNS_WITH_DEFENSE),
      fc.boolean(),
      async ({ vuln, defenseKey }, toggleOn) => {
        // Drive the authoritative source of truth: the defense state.
        setToggle(defenseKey, toggleOn);

        const res = await agent(app).get(`/code/${vuln}`);

        assert.equal(
          res.status,
          200,
          `expected 200 for GET /code/${vuln}, got ${res.status}`
        );

        const html = res.text || "";
        const expected = toggleOn ? "secure" : "vulnerable";

        // The route must resolve the highlight from the defense state (R7.3/7.4/7.6).
        const sectionHighlight = readSectionHighlight(html);
        assert.equal(
          sectionHighlight,
          expected,
          `${vuln} toggle=${toggleOn}: section data-highlight should be "${expected}", got "${sectionHighlight}"`
        );

        // Exactly one block is emphasized, and it is the expected-state block
        // (secure when ON, vulnerable when OFF), never the opposite one.
        const activeStates = readActiveStates(html);
        assert.deepEqual(
          activeStates,
          [expected],
          `${vuln} toggle=${toggleOn}: exactly the "${expected}" block must be active (code-active), got ${JSON.stringify(
            activeStates
          )}`
        );
      }
    ),
    { numRuns: RUNS }
  );
});
