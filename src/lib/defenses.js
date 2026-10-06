// src/lib/defenses.js
// Central defense toggle panel. Reads and writes config/defenses.json.
// This is the pedagogical core: the student turns each defense on/off and reproduces the attack.
const fs = require("fs");
const path = require("path");

const CONFIG_PATH = path.join(__dirname, "..", "..", "config", "defenses.json");

function readAll() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch (e) {
    return {
      A05_injection: false,
      A01_access_control: false,
      A02_misconfiguration: false,
      A09_logging: false,
    };
  }
}

function isOn(key) {
  return readAll()[key] === true;
}

function setDefense(key, value) {
  const all = readAll();
  if (!(key in all)) throw new Error("Unknown defense: " + key);
  all[key] = value === true || value === "true" || value === "on";
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(all, null, 2) + "\n", "utf8");
  return all;
}

module.exports = { readAll, isOn, setDefense, CONFIG_PATH };
