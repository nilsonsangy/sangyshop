// src/lib/objectstore/none.js
// Null provider (default). No SDK, no network, no credentials.
const { fail } = require("./common");

function disabled() {
  return fail("STORE_DISABLED", "Object store is disabled (OBJECT_STORE=none).");
}

function create() {
  return {
    provider: "none",
    async put() { return disabled(); },
    async get() { return disabled(); },
    async list() { return disabled(); },
    async health() { return { ok: true, provider: "none", enabled: false }; },
  };
}

module.exports = { create };
