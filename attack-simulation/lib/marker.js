// attack-simulation/lib/marker.js
// Pure module: decides whether a normalized HTTP response identifies the
// SangyShop laboratory marker (GET /.well-known/sangyshop-lab, see
// src/routes/lab.js in the sangyshop repo).
//
// Deliberately NOT coupled to any HTTP client. Callers normalize whatever
// client they use (fetch Response, http.IncomingMessage, etc.) into the
// shape below before calling isLabMarker.

const EXPECTED_HEADER_NAME = "x-sangyshop-lab";
const EXPECTED_HEADER_VALUE = "vulnerable-lab";
const EXPECTED_APP = "sangyshop";
const EXPECTED_MODE = "vulnerable";

// Case-insensitive header lookup. Accepts a plain object map of header
// name -> value (strings), as produced by most HTTP clients once headers
// are normalized to a plain object.
function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return undefined;
  const wanted = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === wanted) return headers[key];
  }
  return undefined;
}

// response: { status: number, headers: object, body: object }
// Returns true only if ALL of the following hold:
//   - status === 200
//   - body.app === "sangyshop"
//   - body.mode === "vulnerable"
//   - the X-SangyShop-Lab header is present with the expected value
function isLabMarker(response) {
  if (!response || typeof response !== "object") return false;

  if (response.status !== 200) return false;

  const body = response.body;
  if (!body || typeof body !== "object") return false;
  if (body.app !== EXPECTED_APP) return false;
  if (body.mode !== EXPECTED_MODE) return false;

  const headerValue = getHeader(response.headers, EXPECTED_HEADER_NAME);
  if (headerValue !== EXPECTED_HEADER_VALUE) return false;

  return true;
}

module.exports = {
  isLabMarker,
  EXPECTED_HEADER_NAME,
  EXPECTED_HEADER_VALUE,
  EXPECTED_APP,
  EXPECTED_MODE,
};
