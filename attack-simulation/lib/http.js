// attack-simulation/lib/http.js
// Side-effecting I/O wrapper, kept deliberately isolated so lib/plan.js,
// lib/marker.js and lib/steplog.js stay pure and easy to test.
//
// Uses Node 20's built-in global fetch (no extra runtime dependency, as a deliberate design choice). Provides:
//   - request(): a single HTTP call normalized into { status, headers, body }
//     for lib/marker.js to inspect.
//   - RateLimiter: a tiny token-bucket limiter that enforces a max requests
//     per second, used to respect the budgets computed by lib/plan.js.

// Normalizes a fetch Response + parsed body into the shape lib/marker.js
// expects: { status, headers, body }.
async function toNormalizedResponse(fetchResponse) {
  const headers = {};
  for (const [key, value] of fetchResponse.headers.entries()) {
    headers[key] = value;
  }

  let body = null;
  const contentType = fetchResponse.headers.get("content-type") || "";
  const text = await fetchResponse.text();
  if (contentType.includes("application/json") && text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  } else {
    body = text;
  }

  return { status: fetchResponse.status, headers, body };
}

// Performs a single HTTP request and returns the normalized response.
// options: { method, headers, body, timeoutMs }
async function request(url, options = {}) {
  const { method = "GET", headers, body, timeoutMs = 10000 } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const fetchResponse = await fetch(url, {
      method,
      headers,
      body,
      signal: controller.signal,
    });
    return await toNormalizedResponse(fetchResponse);
  } finally {
    clearTimeout(timer);
  }
}

// Simple token-bucket rate limiter: at most `ratePerSecond` permits are
// granted per rolling second. Call acquire() before each request and await
// it; it resolves once a slot is available.
class RateLimiter {
  constructor(ratePerSecond) {
    if (typeof ratePerSecond !== "number" || ratePerSecond <= 0) {
      throw new RangeError("ratePerSecond must be a positive number");
    }
    this.ratePerSecond = ratePerSecond;
    this.timestamps = []; // timestamps (ms) of requests granted in the last second
  }

  async acquire() {
    for (;;) {
      const now = Date.now();
      this.timestamps = this.timestamps.filter((t) => now - t < 1000);
      if (this.timestamps.length < this.ratePerSecond) {
        this.timestamps.push(now);
        return;
      }
      const oldest = this.timestamps[0];
      const waitMs = 1000 - (now - oldest) + 1;
      await sleep(waitMs);
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

module.exports = { request, RateLimiter, sleep, toNormalizedResponse };
