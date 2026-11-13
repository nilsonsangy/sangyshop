// attack-simulation/lib/steplog.js
// Pure module: defines the JSON-line schema written to attack-steps.jsonl
// and aggregates it into a final summary.
//
// One line per step/event. formatStep() only builds and serializes the
// record; it never touches the filesystem (see lib/http.js / attack.js for
// the actual file append, kept out of this pure module).
//
// Record shape (one JSON object per line):
// {
//   ts: "2026-11-11T12:00:00.000Z",  // ISO 8601 UTC timestamp of this event
//   step: 2,                         // step number, 1..N
//   name: "bruteforce",              // step name
//   target: "http://10.0.1.5:3000",  // base target URL
//   phase: "start" | "end",          // one "start" and one "end" line per step
//   outcome: "ok" | "limit-reached" | "error" | null, // only set on "end"
//   requestCount: 12,                 // requests sent so far in this step
//   errorCount: 0,                    // failed requests so far in this step
// }

function isoNow() {
  return new Date().toISOString();
}

// Builds and serializes one JSONL line (string, WITHOUT trailing newline).
// phase: "start" | "end". On "end", outcome/requestCount/errorCount describe
// the step's result; on "start" they default to null/0.
function formatStep({
  step,
  name,
  target,
  phase,
  outcome = null,
  requestCount = 0,
  errorCount = 0,
  ts = isoNow(),
} = {}) {
  if (!Number.isInteger(step) || step < 1) {
    throw new RangeError("step must be a positive integer");
  }
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("name must be a non-empty string");
  }
  if (phase !== "start" && phase !== "end") {
    throw new TypeError('phase must be "start" or "end"');
  }

  const record = {
    ts,
    step,
    name,
    target: target === undefined || target === null ? "" : String(target),
    phase,
    outcome: phase === "end" ? outcome : null,
    requestCount,
    errorCount,
  };

  return JSON.stringify(record);
}

// Parses an array of raw JSONL lines (strings) into records, skipping
// blank lines. Malformed lines are skipped rather than throwing, so a
// partially-written log file can still be summarized.
function parseLines(lines) {
  const records = [];
  for (const line of lines) {
    const trimmed = typeof line === "string" ? line.trim() : "";
    if (!trimmed) continue;
    try {
      records.push(JSON.parse(trimmed));
    } catch {
      // skip malformed line
    }
  }
  return records;
}

// Aggregates parsed (or raw string) log lines into a final summary object:
// {
//   totalSteps,       // number of distinct step numbers seen
//   startedAt,        // ISO timestamp of the earliest "start" line, or null
//   finishedAt,       // ISO timestamp of the latest "end" line, or null
//   totalRequests,    // sum of requestCount across "end" lines
//   totalErrors,      // sum of errorCount across "end" lines
//   steps,            // [{ step, name, outcome, requestCount, errorCount }]
// }
function summarize(lines) {
  const records = Array.isArray(lines) && typeof lines[0] === "object" ? lines : parseLines(lines || []);

  const byStep = new Map();
  let startedAt = null;
  let finishedAt = null;

  for (const record of records) {
    if (!record || typeof record !== "object") continue;

    if (record.phase === "start") {
      if (startedAt === null || record.ts < startedAt) startedAt = record.ts;
    }
    if (record.phase === "end") {
      if (finishedAt === null || record.ts > finishedAt) finishedAt = record.ts;
      byStep.set(record.step, {
        step: record.step,
        name: record.name,
        outcome: record.outcome,
        requestCount: record.requestCount || 0,
        errorCount: record.errorCount || 0,
      });
    }
  }

  const steps = Array.from(byStep.values()).sort((a, b) => a.step - b.step);
  const totalRequests = steps.reduce((sum, s) => sum + s.requestCount, 0);
  const totalErrors = steps.reduce((sum, s) => sum + s.errorCount, 0);

  return {
    totalSteps: steps.length,
    startedAt,
    finishedAt,
    totalRequests,
    totalErrors,
    steps,
  };
}

module.exports = { formatStep, parseLines, summarize };
