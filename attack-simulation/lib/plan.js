// attack-simulation/lib/plan.js
// Pure planning module: validates rate/volume options against fixed ceilings
// and builds an ordered, numbered step plan for the Script_Ataque.
//
// No I/O here. See lib/http.js for the side-effecting request execution that
// is expected to respect the budgets this module computes.

// Default ceilings (used when the caller does not override rate/volume).
const DEFAULT_RATE_RPS = 5;
const DEFAULT_TOTAL_REQUESTS = 150;

// Rigid (hard) ceilings. Requests to exceed these are always rejected,
// regardless of what the caller asks for (Requirement 13.5).
const RIGID_RATE_RPS = 10;
const RIGID_TOTAL_REQUESTS = 300;

// Per-step request budgets (max number of requests a single step may send).
// These are fixed; they are not configurable via opts.
const STEP_BUDGETS = Object.freeze({
  recon: 6,
  bruteforce: 60,
  sqli: 12,
  idor: 30,
  "credential-discovery": 4,
});

// Canonical step order. Index + 1 is the step number (1..N, no gaps/repeats).
const STEP_ORDER = Object.freeze(["recon", "bruteforce", "sqli", "idor", "credential-discovery"]);

function isPositiveNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

// Pure validation: throws a TypeError with an English message when opts
// request a rate or total volume above the rigid ceilings. Does not perform
// any I/O and does not mutate opts.
function validateCeilings(opts = {}) {
  const rateRps = opts.rateRps === undefined ? DEFAULT_RATE_RPS : opts.rateRps;
  const totalRequests = opts.totalRequests === undefined ? DEFAULT_TOTAL_REQUESTS : opts.totalRequests;

  if (!isPositiveNumber(rateRps)) {
    throw new TypeError("rateRps must be a positive number");
  }
  if (!isPositiveNumber(totalRequests)) {
    throw new TypeError("totalRequests must be a positive number");
  }
  if (rateRps > RIGID_RATE_RPS) {
    throw new RangeError(
      `rateRps (${rateRps}) exceeds the rigid ceiling of ${RIGID_RATE_RPS} requests per second`
    );
  }
  if (totalRequests > RIGID_TOTAL_REQUESTS) {
    throw new RangeError(
      `totalRequests (${totalRequests}) exceeds the rigid ceiling of ${RIGID_TOTAL_REQUESTS} total requests`
    );
  }
  return { rateRps, totalRequests };
}

// Builds the ordered, numbered plan. Throws if opts exceed the rigid
// ceilings (validateCeilings does the throwing). Returns a plain object:
// {
//   rateRps, totalRequests,          // effective, validated budgets
//   steps: [
//     { number, name, maxRequests },  // per-step budget, number starts at 1
//     ...
//   ],
// }
function planSteps(opts = {}) {
  const { rateRps, totalRequests } = validateCeilings(opts);

  const requestedSteps =
    Array.isArray(opts.steps) && opts.steps.length > 0 ? opts.steps : STEP_ORDER;

  const steps = requestedSteps.map((name, index) => {
    if (!Object.prototype.hasOwnProperty.call(STEP_BUDGETS, name)) {
      throw new RangeError(`unknown attack step: ${name}`);
    }
    return {
      number: index + 1,
      name,
      maxRequests: STEP_BUDGETS[name],
    };
  });

  const sumOfStepBudgets = steps.reduce((sum, step) => sum + step.maxRequests, 0);
  if (sumOfStepBudgets > totalRequests) {
    throw new RangeError(
      `sum of per-step budgets (${sumOfStepBudgets}) exceeds totalRequests (${totalRequests})`
    );
  }

  return { rateRps, totalRequests, steps };
}

module.exports = {
  planSteps,
  validateCeilings,
  DEFAULT_RATE_RPS,
  DEFAULT_TOTAL_REQUESTS,
  RIGID_RATE_RPS,
  RIGID_TOTAL_REQUESTS,
  STEP_BUDGETS,
  STEP_ORDER,
};
