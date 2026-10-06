// src/lib/logger.js
// Authentication event logging and brute-force detection (exercise A09).
// With defense A09 OFF: nothing is recorded (the attack goes unnoticed).
// With defense A09 ON: every attempt is recorded and an alert fires on brute force.
const fs = require("fs");
const path = require("path");
const { isOn } = require("./defenses");

const LOG_DIR = path.join(__dirname, "..", "..", "logs");
const AUTH_LOG = path.join(LOG_DIR, "auth.log");

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// Simple in-memory window counting failures per user/IP for the alert.
const failures = new Map();
const WINDOW_MS = 60 * 1000;
const THRESHOLD = 5;

function write(line) {
  fs.appendFileSync(AUTH_LOG, line + "\n", "utf8");
}

function recordLogin({ username, ip, success }) {
  // If the logging defense is OFF, record nothing: the attack stays invisible.
  if (!isOn("A09_logging")) return { logged: false, alert: false };

  const ts = new Date().toISOString();
  const status = success ? "SUCCESS" : "FAILURE";
  write(`${ts} auth ${status} user=${username} ip=${ip}`);

  let alert = false;
  if (!success) {
    const key = `${username}|${ip}`;
    const now = Date.now();
    const arr = (failures.get(key) || []).filter((t) => now - t < WINDOW_MS);
    arr.push(now);
    failures.set(key, arr);
    if (arr.length >= THRESHOLD) {
      write(`${ts} ALERT brute_force_suspected user=${username} ip=${ip} failures=${arr.length} window=60s`);
      alert = true;
    }
  } else {
    failures.delete(`${username}|${ip}`);
  }
  return { logged: true, alert };
}

function tail(n = 50) {
  try {
    const lines = fs.readFileSync(AUTH_LOG, "utf8").trim().split("\n");
    return lines.slice(-n);
  } catch (e) {
    return [];
  }
}

module.exports = { recordLogin, tail, AUTH_LOG };
