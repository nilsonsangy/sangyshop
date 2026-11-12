// attack-simulation/test/plan.property.test.js
// Property 9: Rate and volume ceilings.
// Validates: Requirements 13.5

"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const {
  planSteps,
  validateCeilings,
  RIGID_RATE_RPS,
  RIGID_TOTAL_REQUESTS,
  STEP_BUDGETS,
  STEP_ORDER,
} = require("../lib/plan");

const NUM_RUNS = 100;

test("Property 9: inputs within the rigid ceilings are always accepted", () => {
  fc.assert(
    fc.property(
      fc.float({ min: Math.fround(0.01), max: RIGID_RATE_RPS, noNaN: true }),
      fc.integer({ min: 1, max: RIGID_TOTAL_REQUESTS }),
      (rateRps, totalRequests) => {
        const result = validateCeilings({ rateRps, totalRequests });
        assert.equal(result.rateRps, rateRps);
        assert.equal(result.totalRequests, totalRequests);
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: exceeding the rate ceiling is always rejected regardless of totalRequests", () => {
  fc.assert(
    fc.property(
      fc.float({ min: Math.fround(RIGID_RATE_RPS + 0.01), max: 100000, noNaN: true }),
      fc.integer({ min: 1, max: RIGID_TOTAL_REQUESTS * 10 }),
      (rateRps, totalRequests) => {
        assert.throws(
          () => validateCeilings({ rateRps, totalRequests }),
          RangeError
        );
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: exceeding the total requests ceiling is always rejected regardless of rateRps", () => {
  fc.assert(
    fc.property(
      fc.float({ min: Math.fround(0.01), max: RIGID_RATE_RPS, noNaN: true }),
      fc.integer({ min: RIGID_TOTAL_REQUESTS + 1, max: RIGID_TOTAL_REQUESTS * 10 }),
      (rateRps, totalRequests) => {
        assert.throws(
          () => validateCeilings({ rateRps, totalRequests }),
          RangeError
        );
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: exceeding either ceiling is always rejected, no matter how the other value is set", () => {
  fc.assert(
    fc.property(
      fc.float({ min: Math.fround(0.01), max: 100000, noNaN: true }),
      fc.integer({ min: 1, max: RIGID_TOTAL_REQUESTS * 10 }),
      (rateRps, totalRequests) => {
        const exceedsRate = rateRps > RIGID_RATE_RPS;
        const exceedsTotal = totalRequests > RIGID_TOTAL_REQUESTS;

        if (exceedsRate || exceedsTotal) {
          assert.throws(
            () => validateCeilings({ rateRps, totalRequests }),
            RangeError
          );
        } else {
          assert.doesNotThrow(() => validateCeilings({ rateRps, totalRequests }));
        }
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: per-step budgets in the returned plan never exceed their fixed maximums", () => {
  // The sum of all fixed per-step budgets is 6 + 60 + 12 + 30 + 4 = 112,
  // which is comfortably below the rigid total ceiling of 300. Using the
  // full STEP_ORDER on every run keeps totalRequests large enough to avoid
  // tripping the "sum exceeds totalRequests" guard while still exercising
  // the ceiling validation across a range of totals.
  const sumOfAllBudgets = STEP_ORDER.reduce((sum, name) => sum + STEP_BUDGETS[name], 0);

  fc.assert(
    fc.property(
      fc.integer({ min: sumOfAllBudgets, max: RIGID_TOTAL_REQUESTS }),
      (totalRequests) => {
        const plan = planSteps({ totalRequests });

        for (const step of plan.steps) {
          assert.ok(
            step.maxRequests <= STEP_BUDGETS[step.name],
            `step ${step.name} budget ${step.maxRequests} exceeds fixed maximum ${STEP_BUDGETS[step.name]}`
          );
          assert.equal(step.maxRequests, STEP_BUDGETS[step.name]);
        }
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: the sum of per-step budgets in a returned plan never exceeds the requested total", () => {
  const sumOfAllBudgets = STEP_ORDER.reduce((sum, name) => sum + STEP_BUDGETS[name], 0);

  fc.assert(
    fc.property(
      fc.integer({ min: sumOfAllBudgets, max: RIGID_TOTAL_REQUESTS }),
      (totalRequests) => {
        const plan = planSteps({ totalRequests });
        const sumOfStepBudgets = plan.steps.reduce((sum, step) => sum + step.maxRequests, 0);

        assert.ok(
          sumOfStepBudgets <= totalRequests,
          `sum of step budgets ${sumOfStepBudgets} exceeds requested total ${totalRequests}`
        );
        assert.equal(plan.totalRequests, totalRequests);
      }
    ),
    { numRuns: NUM_RUNS }
  );
});

test("Property 9: a requested total below the sum of per-step budgets is always rejected", () => {
  const sumOfAllBudgets = STEP_ORDER.reduce((sum, name) => sum + STEP_BUDGETS[name], 0);

  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: sumOfAllBudgets - 1 }),
      (totalRequests) => {
        assert.throws(() => planSteps({ totalRequests }), RangeError);
      }
    ),
    { numRuns: NUM_RUNS }
  );
});
