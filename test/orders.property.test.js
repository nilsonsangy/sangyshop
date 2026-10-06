// test/orders.property.test.js
// Property-based tests for the "My Orders" page (feature:
// sangyshop-sessao-navegacao-ingles, tasks 4.4, 4.5, 4.6).
//
// Three properties live in this single file:
//   - Property 4: orders are filtered by the session user (via supertest).
//   - Property 5: every rendered order row shows id, product, quantity, total.
//   - Property 6: every rendered order row links to /api/orders/<id> (IDOR seed).
//
// Properties 5 and 6 render src/views/orders.ejs directly with ejs.renderFile,
// which resolves the navbar partial include by filename. Property 4 drives the
// real route through a supertest cookie jar so the full session + DB path runs.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const ejs = require("ejs");
const fc = require("fast-check");
const { createTestApp, agent, login, SEED } = require("./helpers");

const ORDERS_VIEW = path.join(__dirname, "..", "src", "views", "orders.ejs");
const RUNS = 100;

// Expected order ids per seeded user (mirrors SEED.orders ownership).
//   alice (id 2) -> {1, 2}; bob (id 3) -> {3}; carol (id 4) -> {4}; admin -> {}.
function expectedOrderIds(username) {
  const userId = SEED.users[username].id;
  return SEED.orders
    .filter((o) => o.user_id === userId)
    .map((o) => o.id)
    .sort((a, b) => a - b);
}

// Extract the set of order ids rendered on the My Orders page. The page renders
// one "View (API)" link per order pointing at /api/orders/<id>, so the hrefs are
// the authoritative, unambiguous source of the ids shown.
function renderedOrderIds(html) {
  const ids = [];
  const re = /href="\/api\/orders\/(\d+)"/g;
  let m;
  while ((m = re.exec(html)) !== null) ids.push(Number(m[1]));
  return ids.sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// Property 4 — filtering orders by user.
// Feature: sangyshop-sessao-navegacao-ingles, Property 4: Filtragem de pedidos por usuário
// Validates: Requirements 3.1
// ---------------------------------------------------------------------------
test("Property 4: GET /orders lists exactly the session user's orders", async () => {
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom("alice", "bob", "carol", "admin"),
      async (username) => {
        const a = agent(app);
        const loginRes = await login(a, username, SEED.credentials[username]);
        assert.equal(loginRes.status, 302);

        const res = await a.get("/orders");
        assert.equal(res.status, 200);

        const expected = expectedOrderIds(username);
        assert.deepEqual(renderedOrderIds(res.text), expected);

        if (expected.length === 0) {
          // Admin has no orders: empty-state message, no table rows.
          assert.match(res.text, /You have no orders yet\./);
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// ---------------------------------------------------------------------------
// Generators for the render-only properties.
// ---------------------------------------------------------------------------

// A "safe" non-empty product name: no HTML-special characters so the EJS
// `<%= %>` (HTML-escaping) output equals the raw string we assert against, and
// no leading/trailing whitespace collapse surprises. Letters, digits, spaces,
// and a few harmless punctuation marks only.
const safeProductName = fc
  .stringMatching(/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/)
  .filter((s) => s.trim().length > 0);

// A single arbitrary order record as the view consumes it.
const orderArb = fc.record({
  id: fc.integer({ min: 1, max: 1_000_000 }),
  product_name: safeProductName,
  quantity: fc.integer({ min: 0, max: 1000 }),
  total: fc.double({ min: 0, max: 1_000_000, noNaN: true, noDefaultInfinity: true }),
});

// A list of orders with DISTINCT positive integer ids (Property 6 needs the
// per-order href to be unambiguous; Property 5 is fine with distinct ids too).
const distinctOrdersArb = fc
  .uniqueArray(
    fc.record({
      id: fc.integer({ min: 1, max: 1_000_000 }),
      product_name: safeProductName,
      quantity: fc.integer({ min: 0, max: 1000 }),
      total: fc.double({ min: 0, max: 1_000_000, noNaN: true, noDefaultInfinity: true }),
    }),
    { selector: (o) => o.id, minLength: 1, maxLength: 12 }
  );

const RENDER_USER = { username: "x", role: "customer" };

function renderOrders(orders) {
  return ejs.renderFile(ORDERS_VIEW, { orders, user: RENDER_USER });
}

// Escape a raw string the way EJS `<%= %>` does, so assertions compare against
// the exact bytes the template emits.
function ejsEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&#34;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Property 5 — required fields per order row.
// Feature: sangyshop-sessao-navegacao-ingles, Property 5: Campos obrigatórios por pedido na página
// Validates: Requirements 3.2
// ---------------------------------------------------------------------------
test("Property 5: each order row renders id, product, quantity and total", async () => {
  await fc.assert(
    fc.asyncProperty(fc.array(orderArb, { minLength: 1, maxLength: 12 }), async (orders) => {
      const html = await renderOrders(orders);

      for (const o of orders) {
        // The row renders: <td>id</td><td>product</td><td>quantity</td><td>$ total</td>
        assert.ok(
          html.includes(`<td>${o.id}</td>`),
          `missing id cell for order ${o.id}`
        );
        assert.ok(
          html.includes(`<td>${ejsEscape(o.product_name)}</td>`),
          `missing product cell for order ${o.id} (${o.product_name})`
        );
        assert.ok(
          html.includes(`<td>${o.quantity}</td>`),
          `missing quantity cell for order ${o.id}`
        );
        assert.ok(
          html.includes(`$ ${Number(o.total).toFixed(2)}`),
          `missing total cell for order ${o.id} (total ${o.total})`
        );
      }
    }),
    { numRuns: RUNS }
  );
});

// ---------------------------------------------------------------------------
// Property 6 — IDOR link per order.
// Feature: sangyshop-sessao-navegacao-ingles, Property 6: Link de IDOR por pedido
// Validates: Requirements 3.5
// ---------------------------------------------------------------------------
test("Property 6: each order row links to exactly /api/orders/<id>", async () => {
  await fc.assert(
    fc.asyncProperty(distinctOrdersArb, async (orders) => {
      const html = await renderOrders(orders);

      for (const o of orders) {
        assert.ok(
          html.includes(`href="/api/orders/${o.id}"`),
          `missing IDOR link /api/orders/${o.id}`
        );
      }

      // The rendered hrefs are exactly the generated ids (no extra, no missing).
      assert.deepEqual(
        renderedOrderIds(html),
        orders.map((o) => o.id).sort((a, b) => a - b)
      );
    }),
    { numRuns: RUNS }
  );
});
