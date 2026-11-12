// attack-simulation/test/steplog.property.test.js
// Feature: aulas-24-25-resposta-incidentes-nuvem
// Property 10: Invariantes do log de etapas
// **Validates: Requirements 13.1, 13.6, 13.11**
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { formatStep, summarize } = require("../lib/steplog");

const RUNS = 100;

// Arbitrary strings, including newlines, quotes and unicode separators.
const textArb = fc.oneof(fc.string({ minLength: 1, maxLength: 20 }), fc.constantFrom("a\nb", 'x"y', "l\u2028s", "tab\there"));
const tsArb = fc
  .date({ min: new Date("2026-01-01T00:00:00Z"), max: new Date("2030-01-01T00:00:00Z"), noInvalidDate: true })
  .map((d) => d.toISOString());
const outcomeArb = fc.constantFrom("ok", "limit-reached", "error");

// A full run: N steps (numbered 1..N), each with a start and an end line.
const lifecycleArb = fc
  .array(
    fc.record({
      name: textArb,
      target: fc.webUrl(),
      outcome: outcomeArb,
      requestCount: fc.integer({ min: 0, max: 60 }),
      errorCount: fc.integer({ min: 0, max: 60 }),
      startTs: tsArb,
      endTs: tsArb,
    }),
    { minLength: 1, maxLength: 8 }
  )
  .map((specs) => {
    const lines = [];
    specs.forEach((s, i) => {
      const step = i + 1;
      lines.push(formatStep({ step, name: s.name, target: s.target, phase: "start", ts: s.startTs }));
      lines.push(
        formatStep({
          step,
          name: s.name,
          target: s.target,
          phase: "end",
          outcome: s.outcome,
          requestCount: s.requestCount,
          errorCount: s.errorCount,
          ts: s.endTs,
        })
      );
    });
    return { specs, lines };
  });

test("Property 10a: every formatStep line is a single-line valid JSON object", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 1000 }),
      textArb,
      fc.string({ maxLength: 30 }),
      fc.constantFrom("start", "end"),
      outcomeArb,
      fc.nat({ max: 300 }),
      fc.nat({ max: 300 }),
      (step, name, target, phase, outcome, requestCount, errorCount) => {
        const line = formatStep({ step, name, target, phase, outcome, requestCount, errorCount });
        assert.equal(typeof line, "string");
        assert.ok(!/[\r\n]/.test(line), "no embedded newline");
        const obj = JSON.parse(line);
        assert.equal(typeof obj, "object");
        assert.ok(obj !== null && !Array.isArray(obj));
        assert.equal(obj.step, step);
        assert.equal(obj.name, name);
        assert.equal(obj.phase, phase);
        assert.equal(obj.requestCount, requestCount);
        assert.equal(obj.errorCount, errorCount);
        // outcome is only meaningful on "end"
        assert.equal(obj.outcome, phase === "end" ? outcome : null);
        assert.ok(!Number.isNaN(Date.parse(obj.ts)));
      }
    ),
    { numRuns: RUNS }
  );
});

test("Property 10b: step numbers are sequential from 1 and non-decreasing across lines", () => {
  fc.assert(
    fc.property(lifecycleArb, ({ specs, lines }) => {
      const records = lines.map((l) => JSON.parse(l));
      for (let i = 1; i < records.length; i++) {
        assert.ok(records[i].step >= records[i - 1].step, "non-decreasing");
      }
      const distinct = [...new Set(records.map((r) => r.step))];
      assert.deepEqual(
        distinct,
        specs.map((_, i) => i + 1)
      );
    }),
    { numRuns: RUNS }
  );
});

test("Property 10c: summarize totals equal the sum of the generated inputs", () => {
  fc.assert(
    fc.property(lifecycleArb, ({ specs, lines }) => {
      const sum = (key) => specs.reduce((acc, s) => acc + s[key], 0);
      // Same result from raw strings and from parsed records.
      for (const input of [lines, lines.map((l) => JSON.parse(l))]) {
        const result = summarize(input);
        assert.equal(result.totalSteps, specs.length);
        assert.equal(result.totalRequests, sum("requestCount"));
        assert.equal(result.totalErrors, sum("errorCount"));
        assert.equal(result.steps.length, specs.length);
      }
    }),
    { numRuns: RUNS }
  );
});

test("Property 10d: every step has exactly one start and one end line, start before end", () => {
  fc.assert(
    fc.property(lifecycleArb, ({ specs, lines }) => {
      const records = lines.map((l) => JSON.parse(l));
      specs.forEach((_, i) => {
        const step = i + 1;
        const own = records.filter((r) => r.step === step);
        assert.deepEqual(
          own.map((r) => r.phase),
          ["start", "end"]
        );
        assert.equal(own[0].outcome, null);
        assert.ok(["ok", "limit-reached", "error"].includes(own[1].outcome));
      });
      const result = summarize(lines);
      assert.deepEqual(
        result.steps.map((s) => s.step),
        specs.map((_, i) => i + 1)
      );
    }),
    { numRuns: RUNS }
  );
});

test("Property 10e: summarize startedAt/finishedAt are the min start ts and max end ts", () => {
  fc.assert(
    fc.property(lifecycleArb, ({ specs, lines }) => {
      const result = summarize(lines);
      const starts = specs.map((s) => s.startTs).sort();
      const ends = specs.map((s) => s.endTs).sort();
      assert.equal(result.startedAt, starts[0]);
      assert.equal(result.finishedAt, ends[ends.length - 1]);
    }),
    { numRuns: RUNS }
  );
});
