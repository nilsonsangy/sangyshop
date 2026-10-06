// test/navbar.property.test.js
//
// Property-based tests for the unified SangyShop navbar.
//
// These three properties all live in THIS single file (tasks 2.5, 2.6, 7.2 of
// the sangyshop-sessao-navegacao-ingles feature). They render the shared
// partial src/views/partials/navbar.ejs in isolation (Properties 1 and 2) and
// the five full views that include it (Property 3), using the ejs API directly
// — no HTTP server needed.
//
// Runner: node:test (native). PBT library: fast-check (>= 100 iterations each).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const ejs = require("ejs");
const fc = require("fast-check");

const VIEWS_DIR = path.join(__dirname, "..", "src", "views");
const PARTIAL_PATH = path.join(VIEWS_DIR, "partials", "navbar.ejs");
const PARTIAL_SRC = fs.readFileSync(PARTIAL_PATH, "utf8");

const NUM_RUNS = 100;

// --- Generators ------------------------------------------------------------
//
// Safe, non-empty identifiers for username/role. We constrain the alphabet to
// letters, digits, space, underscore and hyphen so the generated values are
// predictable to search for in the rendered HTML and never collide with HTML
// markup (no "<", ">", "&", quotes). EJS escapes <%= %> output anyway, but a
// clean alphabet keeps the "contains" assertions unambiguous.
const SAFE_CHARS =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- ";

const safeNonEmpty = fc
  .string({ unit: fc.constantFrom(...SAFE_CHARS.split("")), minLength: 1, maxLength: 24 })
  // Avoid values that are only spaces: trim-empty strings would be invisible in
  // the output and make "contains" checks meaningless.
  .filter((s) => s.trim().length > 0);

const authedUser = fc.record({
  username: safeNonEmpty,
  role: safeNonEmpty,
});

/** Render the navbar partial in isolation for a given `user` local. */
function renderNavbar(user) {
  return ejs.render(PARTIAL_SRC, { user });
}

/** Extract the text content of every <a> inside the first <nav> of some HTML. */
function navLinkTexts(html) {
  const navMatch = html.match(/<nav[\s\S]*?<\/nav>/i);
  assert.ok(navMatch, "expected a <nav> element in the rendered HTML");
  const nav = navMatch[0];
  const texts = [];
  const re = /<a\b[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(nav)) !== null) {
    texts.push(m[1].replace(/\s+/g, " ").trim());
  }
  return texts;
}

// ===========================================================================
// Feature: sangyshop-sessao-navegacao-ingles, Property 1: Seleção de variante
// da navbar pelo estado de sessão
//
// Validates: Requirements 1.3, 1.4, 2.2, 2.4
//
// For any session input — an authenticated user object {username, role}, null,
// or undefined/absent — rendering navbar.ejs NEVER throws and produces exactly
// one variant: authenticated (has /logout and /orders) when the user object is
// non-null, anonymous (has /login, no /orders, no /logout) when the value is
// null, undefined or absent.
// ===========================================================================
test("Property 1: navbar variant is selected by session state", () => {
  // sessionInput covers: authenticated object | null | undefined.
  const sessionInput = fc.oneof(
    authedUser,
    fc.constant(null),
    fc.constant(undefined)
  );

  fc.assert(
    fc.property(sessionInput, (user) => {
      let html;
      // Must never throw, including when user is undefined/absent.
      assert.doesNotThrow(() => {
        html = renderNavbar(user);
      });

      const authenticated = user != null; // non-null object
      if (authenticated) {
        assert.match(html, /href="\/logout"/, "authenticated navbar must link to /logout");
        assert.match(html, /href="\/orders"/, "authenticated navbar must link to /orders");
      } else {
        assert.match(html, /href="\/login"/, "anonymous navbar must link to /login");
        assert.doesNotMatch(html, /href="\/orders"/, "anonymous navbar must not link to /orders");
        assert.doesNotMatch(html, /href="\/logout"/, "anonymous navbar must not link to /logout");
      }
    }),
    { numRuns: NUM_RUNS }
  );
});

// Also exercise the "absent" case explicitly: rendering with NO `user` local in
// scope at all. The partial normalizes `typeof user !== 'undefined'`, so this
// must fall back to the anonymous variant without throwing.
test("Property 1 (addendum): navbar with no user local renders anonymous variant", () => {
  let html;
  assert.doesNotThrow(() => {
    html = ejs.render(PARTIAL_SRC, {});
  });
  assert.match(html, /href="\/login"/);
  assert.doesNotMatch(html, /href="\/orders"/);
  assert.doesNotMatch(html, /href="\/logout"/);
});

// ===========================================================================
// Feature: sangyshop-sessao-navegacao-ingles, Property 2: Conteúdo da navbar
// autenticada
//
// Validates: Requirements 2.1, 2.3
//
// For any authenticated user (any username and role), the rendered navbar
// contains the username, the role, href="/logout" and the /orders (My Orders)
// link.
// ===========================================================================
test("Property 2: authenticated navbar shows username, role, logout and My Orders", () => {
  fc.assert(
    fc.property(authedUser, (user) => {
      const html = renderNavbar(user);

      // EJS escapes <%= %>; the safe alphabet contains no HTML-special chars,
      // so the raw values appear verbatim in the output.
      assert.ok(
        html.includes(user.username),
        `navbar must contain the username (${JSON.stringify(user.username)})`
      );
      assert.ok(
        html.includes(user.role),
        `navbar must contain the role (${JSON.stringify(user.role)})`
      );
      assert.match(html, /href="\/logout"/, "navbar must contain a logout control");
      assert.match(html, /href="\/orders"/, "navbar must contain the My Orders link");
      // The visible label for the orders link is "My Orders".
      assert.ok(/>\s*My Orders\s*</.test(html), "orders link label must be 'My Orders'");
    }),
    { numRuns: NUM_RUNS }
  );
});

// ===========================================================================
// Feature: sangyshop-sessao-navegacao-ingles, Property 3: Consistência da
// navbar entre páginas
//
// Validates: Requirements 1.1, 1.2, 2.5
//
// For any session state ({username, role} object or null), rendering the five
// full views and extracting the set of <a> texts inside <nav> yields an
// IDENTICAL set across all five views for the same state.
// ===========================================================================

// Locals needed by each view, beyond `user`, so ejs.renderFile succeeds.
function viewMatrix(user) {
  return [
    { file: "products.ejs", locals: { products: [], q: "", sqlShown: null, error: null, user } },
    { file: "defenses.ejs", locals: { defenses: {}, labels: {}, user } },
    { file: "logs.ejs", locals: { lines: [], user } },
    { file: "login.ejs", locals: { error: null, user } },
    { file: "orders.ejs", locals: { orders: [], user } },
  ];
}

test("Property 3: navbar nav links are identical across the five views", async () => {
  const sessionInput = fc.oneof(authedUser, fc.constant(null));

  await fc.assert(
    fc.asyncProperty(sessionInput, async (user) => {
      const views = viewMatrix(user);
      const perView = [];
      for (const v of views) {
        const html = await ejs.renderFile(path.join(VIEWS_DIR, v.file), v.locals);
        perView.push({ file: v.file, links: navLinkTexts(html) });
      }

      const reference = perView[0];
      for (const current of perView.slice(1)) {
        assert.deepEqual(
          current.links,
          reference.links,
          `nav links differ between ${reference.file} and ${current.file} ` +
            `for session=${JSON.stringify(user)}`
        );
      }
    }),
    { numRuns: NUM_RUNS }
  );
});
