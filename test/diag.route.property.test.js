// test/diag.route.property.test.js
// Property-based tests for the SangyShop /_diag route (src/routes/diag.js),
// the HTTP surface of the posture diagnostic endpoint (Aula 17).
//
// Unlike test/posture.property.test.js (which drives the PURE collectors with a
// mocked `deps` layer), these tests exercise the ROUTE end to end via supertest.
// The route calls buildPostureReport() with no deps, so it reads the REAL
// process.env. To simulate "inside vs outside Kubernetes" we vary the env
// entries the collectors read (POD_NAME, POD_NAMESPACE, NODE_NAME, DB_PASSWORD)
// around each run, always saving and restoring the originals so the real
// environment is never permanently polluted. We also vary the negotiated
// representation (Accept header + ?format query).
//
// The Express app is built ONCE and reused across all runs for performance; the
// per-run variation is entirely in process.env and the request shape.
//
// This file is established by task 6.2 (Property 2). Later tasks (6.3, 6.4)
// append Properties 3 and 4 below.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { createTestApp, request } = require("./helpers");

const RUNS = 100;

// Env keys the posture collectors read. We snapshot/restore exactly these around
// every run so the predicate leaves process.env as it found it, even on failure.
const ENV_KEYS = ["POD_NAME", "POD_NAMESPACE", "NODE_NAME", "DB_PASSWORD"];

/** Capture the current values (or absence) of the env keys we will mutate. */
function snapshotEnv(keys) {
  const snap = {};
  for (const k of keys) {
    snap[k] = Object.prototype.hasOwnProperty.call(process.env, k)
      ? process.env[k]
      : undefined;
  }
  return snap;
}

/** Restore env keys to a previously captured snapshot (delete if was absent). */
function restoreEnv(snap) {
  for (const k of Object.keys(snap)) {
    if (snap[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = snap[k];
    }
  }
}

/**
 * Apply a simulated environment: for each key, either set it to the provided
 * value (present) or delete it (absent). Mutates process.env in place.
 */
function applyEnv(simulado) {
  for (const k of ENV_KEYS) {
    const v = simulado[k];
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
}

// An arbitrary env signal: present with an arbitrary string value, or absent
// (undefined). Covers both "inside the cluster" (Downward API injected) and
// "outside Kubernetes" (vars missing) across runs.
const envSignal = fc.option(fc.string(), { nil: undefined });

// Feature: sangyshop-diagnostico-postura, Property 2: Endpoint sempre responde 200 e nunca lança
// Validates: Requirements 1.3, 10.1, 10.2
//
// Para toda combinação de ambiente simulado (dentro ou fora do Kubernetes), uma
// requisição GET /_diag responde com HTTP 200 e não propaga exceção,
// independentemente de quais sinais puderam ser coletados nem de qual
// representação (json/html) é negociada.
test("Property 2: GET /_diag always responds 200 and never throws", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      // Simulated environment: each signal present (arbitrary value) or absent.
      fc.record({
        POD_NAME: envSignal,
        POD_NAMESPACE: envSignal,
        NODE_NAME: envSignal,
        DB_PASSWORD: envSignal,
      }),
      // Representation negotiation: vary both the ?format query and the Accept
      // header so JSON and HTML paths are both exercised.
      fc.constantFrom("json", "html", "none"),
      fc.constantFrom(
        "application/json",
        "text/html",
        "*/*",
        "application/xml",
        ""
      ),
      async (envSimulado, formatQuery, acceptHeader) => {
        // Snapshot BEFORE mutating so we can always roll back, even if the
        // assertion below throws (try/finally). Never pollute the real env.
        const snap = snapshotEnv(ENV_KEYS);
        try {
          applyEnv(envSimulado);

          let req = request(app).get("/_diag");
          if (formatQuery !== "none") {
            req = req.query({ format: formatQuery });
          }
          if (acceptHeader !== "") {
            req = req.set("Accept", acceptHeader);
          }

          // supertest resolves on any HTTP response; it only rejects on a
          // transport-level error or if the handler lets an exception escape
          // without a response. Awaiting here therefore also asserts "never
          // throws": an uncaught handler error would reject this promise.
          const res = await req;

          assert.equal(
            res.status,
            200,
            `expected 200 for /_diag (format=${formatQuery}, accept=${acceptHeader}), got ${res.status}`
          );
        } finally {
          restoreEnv(snap);
        }
      }
    ),
    { numRuns: RUNS }
  );
});
// Feature: sangyshop-diagnostico-postura, Property 3: Não-exfiltração
// Validates: Requirements 5.2, 8.2, 12.1, 12.3
//
// Os coletores de variáveis sensíveis e de token reportam apenas PRESENÇA
// (booleanos), nunca o VALOR. Esta propriedade exercita a rota GET /_diag ponta
// a ponta, injetando em process.env um segredo DB_PASSWORD aleatório (com um
// prefixo sentinela distinto para não coincidir com chaves do schema) e um
// valor de token sintético, e verifica que NENHUM desses valores secretos
// aparece — nem na resposta JSON (?format=json) nem no HTML renderizado
// (?format=html). O coletor de token só checa existência de um caminho e nunca
// lê conteúdo, então a superfície real de exfiltração é o valor de DB_PASSWORD;
// ainda assim asserimos também o token sintético para cobrir qualquer
// reflexão acidental de env no corpo da resposta.

// Env keys injetadas por esta propriedade. Snapshot/restore exatamente destas
// chaves para nunca poluir o ambiente real, mesmo em falha.
const SECRET_ENV_KEYS = ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"];

/** Gerador de segredo com prefixo sentinela distinto + sufixo aleatório. */
const dbPasswordSecret = fc
  .string({ minLength: 8, maxLength: 24 })
  .map((suffix) => `SENHA-SECRETA-${suffix}`);

/** Valor de token sintético (não lido pela app, mas asserido mesmo assim). */
const tokenSintetico = fc
  .string({ minLength: 8, maxLength: 24 })
  .map((suffix) => `TOKEN-SINTETICO-${suffix}`);

test("Property 3: /_diag never exfiltrates secret values (DB_PASSWORD/token)", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  await fc.assert(
    fc.asyncProperty(
      dbPasswordSecret,
      tokenSintetico,
      async (dbPassword, token) => {
        // Snapshot BEFORE mutating so we can always roll back, even if the
        // assertion below throws (try/finally). Never pollute the real env.
        const snap = snapshotEnv(SECRET_ENV_KEYS);
        try {
          process.env.DB_PASSWORD = dbPassword;
          process.env.AWS_SECRET_ACCESS_KEY = token;

          // Request BOTH representations.
          const jsonRes = await request(app).get("/_diag").query({ format: "json" });
          const htmlRes = await request(app).get("/_diag").query({ format: "html" });

          // Reunir todo o texto observável de ambas as representações.
          const jsonBody = JSON.stringify(jsonRes.body) + (jsonRes.text || "");
          const htmlBody = htmlRes.text || "";

          for (const [repr, body] of [
            ["json", jsonBody],
            ["html", htmlBody],
          ]) {
            assert.ok(
              !body.includes(dbPassword),
              `DB_PASSWORD secret value leaked into ${repr} response`
            );
            assert.ok(
              !body.includes(token),
              `synthetic token value leaked into ${repr} response`
            );
          }
        } finally {
          restoreEnv(snap);
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// Feature: sangyshop-diagnostico-postura, Property 4: Parâmetros arbitrários não leem caminhos
// Validates: Requirements 12.2
//
// O endpoint GET /_diag reporta um conjunto FIXO de sinais de postura: nenhuma
// querystring pode alterar esse conjunto nem fazer a rota ler/refletir caminhos
// fornecidos pelo cliente. Esta propriedade gera, a cada run, uma querystring
// arbitrária que pode conter chaves como `path`, `file`, `dir` (além de chaves
// aleatórias) com valores de caminho sensível (`/etc/shadow`, `/etc/passwd`,
// strings arbitrárias), sempre carregando um SENTINELA distinto para que a
// asserção de reflexão seja precisa e não um falso positivo por substring comum.
//
// Asserções:
//   1. As chaves de topo do JSON (com params arbitrários) são EXATAMENTE as
//      mesmas de uma requisição baseline sem params — só `format` muda a
//      representação, nunca o conjunto de sinais.
//   2. O valor-sentinela do caminho injetado NÃO aparece no corpo JSON nem no
//      HTML renderizado — o endpoint nunca lê nem reflete o caminho do cliente.

/**
 * Gerador de um valor de caminho "sensível" carregando um sentinela único, para
 * que a asserção de não-reflexão seja precisa. Ex.: "/etc/SENTINELA-abc123".
 * Alguns valores imitam caminhos reais clássicos mas sempre com o sentinela
 * embutido, de modo que qualquer eco do valor no corpo seja detectável sem
 * colidir com substrings comuns ("/etc", "passwd", etc.) que a app possa usar.
 */
const caminhoSentinela = fc
  .string({ minLength: 6, maxLength: 16 })
  .filter((s) => /^[A-Za-z0-9]+$/.test(s))
  .map((id) => {
    const marca = `SENTINELA-${id}`;
    return fc.sample(
      fc.constantFrom(
        `/etc/${marca}/shadow`,
        `/etc/${marca}/passwd`,
        `../../${marca}/secret`,
        `/proc/self/${marca}`,
        `${marca}-valor-arbitrario`
      ),
      1
    )[0];
  });

/**
 * Gerador de uma querystring arbitrária (objeto chave→valor string). Garante a
 * presença de pelo menos uma chave "de caminho" (`path`/`file`/`dir`) com um
 * valor-sentinela, e adiciona pares aleatórios extras. Retorna
 * `{ query, sentinelas }`, onde `sentinelas` é a lista de valores-sentinela que
 * NÃO podem aparecer na resposta.
 */
const querySentinela = fc
  .record({
    chaveCaminho: fc.constantFrom("path", "file", "dir"),
    valorCaminho: caminhoSentinela,
    extras: fc.dictionary(
      fc.string({ minLength: 1, maxLength: 12 }).filter((k) => k !== "format"),
      fc.oneof(fc.string({ maxLength: 20 }), caminhoSentinela),
      { maxKeys: 4 }
    ),
  })
  .map(({ chaveCaminho, valorCaminho, extras }) => {
    const query = { ...extras, [chaveCaminho]: valorCaminho };
    // Coletar todos os valores-sentinela presentes (chave de caminho + extras).
    const sentinelas = Object.values(query).filter(
      (v) => typeof v === "string" && v.includes("SENTINELA-")
    );
    return { query, sentinelas };
  });

test("Property 4: /_diag ignores arbitrary params — fixed signal set, never reads/reflects paths", async () => {
  // Build the app once and reuse it across every run (performance).
  const app = await createTestApp();

  // Baseline: the fixed set of top-level keys with NO query params at all.
  // Derived at runtime so the expectation tracks the real report shape
  // (meta + the 7 posture signals) without hardcoding.
  const baselineRes = await request(app).get("/_diag").query({ format: "json" });
  const expectedKeys = Object.keys(baselineRes.body).sort();

  await fc.assert(
    fc.asyncProperty(querySentinela, async ({ query, sentinelas }) => {
      // JSON representation with arbitrary params (plus format=json).
      const jsonRes = await request(app)
        .get("/_diag")
        .query({ ...query, format: "json" });

      assert.equal(
        jsonRes.status,
        200,
        `expected 200 for /_diag with arbitrary params, got ${jsonRes.status}`
      );

      // 1. The top-level signal set is EXACTLY the baseline set — no arbitrary
      //    param can add, drop, or alter which signals are reported.
      assert.deepEqual(
        Object.keys(jsonRes.body).sort(),
        expectedKeys,
        "arbitrary query params changed the fixed set of posture signals"
      );

      // HTML representation with the same arbitrary params (plus format=html).
      const htmlRes = await request(app)
        .get("/_diag")
        .query({ ...query, format: "html" });

      const jsonText = JSON.stringify(jsonRes.body) + (jsonRes.text || "");
      const htmlText = htmlRes.text || "";

      // 2. No injected sentinel path value is ever read into or reflected by the
      //    response — neither in the JSON body nor in the rendered HTML.
      for (const sentinela of sentinelas) {
        assert.ok(
          !jsonText.includes(sentinela),
          `injected path value was reflected in the JSON response: ${sentinela}`
        );
        assert.ok(
          !htmlText.includes(sentinela),
          `injected path value was reflected in the HTML response: ${sentinela}`
        );
      }
    }),
    { numRuns: RUNS }
  );
});
