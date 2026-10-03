// src/lib/defenses.js
// Painel central de toggles de defesa. Le e escreve config/defenses.json.
// E o coracao pedagogico: o aluno liga/desliga cada defesa e reproduz o ataque.
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
  if (!(key in all)) throw new Error("Defesa desconhecida: " + key);
  all[key] = value === true || value === "true" || value === "on";
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(all, null, 2) + "\n", "utf8");
  return all;
}

module.exports = { readAll, isOn, setDefense, CONFIG_PATH };
