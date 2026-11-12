// test/posture.property.test.js
// Property-based tests for the SangyShop posture collectors (src/lib/posture.js),
// the module behind the /_diag diagnostic endpoint (Aula 17).
//
// These tests exercise the PURE collectors with an injectable dependency layer
// (`deps` = { fs, os, process }). Every collector is deterministic given its deps,
// so we mock process/fs/os and NEVER touch the real ones. fast-check drives each
// property with >= 100 runs.
//
// This file is established by task 2.2 (Property 5). Later tasks append the
// remaining properties (6..10, 1) below.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");

const { coletarIdentidadeExecucao } = require("../src/lib/posture");

const RUNS = 100;

/**
 * Build a mock `process` whose getuid/getgid return the given values.
 * uid/gid are supplied as closures so each iteration gets its own numbers.
 */
function mockProcess({ uid, gid }) {
  return {
    getuid: () => uid,
    getgid: () => gid,
    env: {},
  };
}

// Feature: sangyshop-diagnostico-postura, Property 5: Execution identity is coherent with the uid
// Validates: Requirements 2.1, 2.2, 2.3, 2.4
//
// For every integer uid reported by process.getuid(), the signal has
// isRoot === (uid === 0) and papel "root"/"non-root" according to isRoot; when
// getuid/getgid do not exist on the platform, the signal is disponivel:false with a motivo.
test("Property 5: execution identity is coherent with the reported uid", async () => {
  await fc.assert(
    fc.property(
      // uid/gid as arbitrary non-negative integers; 0 (root) is well within range
      // and fast-check will cover the boundary across runs.
      fc.nat({ max: 4294967295 }),
      fc.nat({ max: 4294967295 }),
      (uid, gid) => {
        const deps = { process: mockProcess({ uid, gid }) };
        const sinal = coletarIdentidadeExecucao(deps);

        // Available signal: uid/gid echoed, isRoot/papel coherent with uid. (R2.1, R2.2, R2.3)
        assert.equal(sinal.disponivel, true);
        assert.equal(sinal.uid, uid);
        assert.equal(sinal.gid, gid);
        assert.equal(sinal.isRoot, uid === 0);
        assert.equal(sinal.papel, uid === 0 ? "root" : "non-root");
        // An available signal carries no "motivo".
        assert.equal(sinal.motivo, undefined);
      }
    ),
    { numRuns: RUNS }
  );
});

// Feature: sangyshop-diagnostico-postura, Property 5: Execution identity is coherent with the uid
// Validates: Requirements 2.4
//
// When getuid and/or getgid do not exist on the platform (e.g. Windows), the collector
// does not throw and reports the signal as unavailable with a motivo, with no value fields.
test("Property 5: missing getuid/getgid yields an unavailable signal with motivo", async () => {
  // Arbitrary subset of {getuid, getgid} present; at least one absent.
  const absenceArb = fc
    .record({ hasGetuid: fc.boolean(), hasGetgid: fc.boolean() })
    .filter(({ hasGetuid, hasGetgid }) => !(hasGetuid && hasGetgid));

  await fc.assert(
    fc.property(
      absenceArb,
      fc.nat({ max: 4294967295 }),
      fc.nat({ max: 4294967295 }),
      ({ hasGetuid, hasGetgid }, uid, gid) => {
        const proc = { env: {} };
        if (hasGetuid) proc.getuid = () => uid;
        if (hasGetgid) proc.getgid = () => gid;

        const sinal = coletarIdentidadeExecucao({ process: proc });

        // Unavailable contract: disponivel:false + motivo, no value fields. (R2.4)
        assert.equal(sinal.disponivel, false);
        assert.equal(typeof sinal.motivo, "string");
        assert.ok(sinal.motivo.length > 0);
        assert.equal(sinal.uid, undefined);
        assert.equal(sinal.gid, undefined);
        assert.equal(sinal.isRoot, undefined);
        assert.equal(sinal.papel, undefined);
      }
    ),
    { numRuns: RUNS }
  );
});

// --- Property 9 (task 2.4) --------------------------------------------------
// Collectors added below: ServiceAccount token (presence only) and sensitive
// env vars (DB_PASSWORD by presence only).
const {
  coletarTokenServiceAccount,
  coletarVariaveisSensiveis,
} = require("../src/lib/posture");

/**
 * Mock `fs` exposing only `existsSync`, returning the given boolean. Optionally
 * throws to simulate a failure while checking the token path (R5.3).
 */
function mockFsExists({ exists, throwErr }) {
  return {
    existsSync: () => {
      if (throwErr) {
        const e = new Error("mock existsSync failure");
        throw e;
      }
      return exists;
    },
  };
}

// Feature: sangyshop-diagnostico-postura, Property 9: Token and sensitive variables are reported by presence only
// Validates: Requirements 5.1, 8.1
//
// For every simulated token presence (via fs.existsSync) and DB_PASSWORD (via
// process.env with a random secret value), the token signal reflects fs.existsSync
// in `tokenMontado`, the sensitive variables signal reflects presence in
// `dbPasswordPresente`, and the secret VALUE NEVER appears in JSON.stringify of the signal.
test("Property 9: token and sensitive vars are reported by presence only, never by value", async () => {
  await fc.assert(
    fc.property(
      // token present/absent via fs.existsSync
      fc.boolean(),
      // DB_PASSWORD present or absent; when present, a random secret value
      // prefixed with a distinctive sentinel ("PASSWORD-"). The sentinel
      // guarantees the secret does not collide by chance with substrings of the
      // fixed schema keys (e.g. "tokenMontado" contains "M"); this way the
      // non-exfiltration assertion measures leakage of the VALUE, not schema coincidence.
      fc.option(
        fc.string({ minLength: 1 }).map((s) => "PASSWORD-" + s),
        { nil: undefined }
      ),
      (tokenExiste, segredo) => {
        // --- ServiceAccount token: presence only (R5.1) ---
        const depsToken = { fs: mockFsExists({ exists: tokenExiste }) };
        const sinalToken = coletarTokenServiceAccount(depsToken);

        assert.equal(sinalToken.disponivel, true);
        // tokenMontado reflects fs.existsSync exactly.
        assert.equal(sinalToken.tokenMontado, tokenExiste);

        // --- Sensitive variables: DB_PASSWORD by presence only (R8.1) ---
        const env = {};
        const temSegredo = typeof segredo === "string";
        if (temSegredo) env.DB_PASSWORD = segredo;
        const depsVars = { process: { env } };
        const sinalVars = coletarVariaveisSensiveis(depsVars);

        assert.equal(sinalVars.disponivel, true);
        // dbPasswordPresente reflects the presence of the name, not the value.
        assert.equal(sinalVars.dbPasswordPresente, temSegredo);

        // --- Non-exfiltration: the secret value never enters the report ---
        // (R8.2 / R12.1) We serialize both signals and ensure the generated
        // secret (when it exists and is non-trivial) appears nowhere.
        if (temSegredo && segredo.length > 0) {
          const serializado =
            JSON.stringify(sinalToken) + JSON.stringify(sinalVars);
          assert.ok(
            !serializado.includes(segredo),
            "the DB_PASSWORD value must never appear in the serialized signal"
          );
        }
      }
    ),
    { numRuns: RUNS }
  );
});

// Feature: sangyshop-diagnostico-postura, Property 9: Token and sensitive variables are reported by presence only
// Validates: Requirements 5.3
//
// When the token existence check throws (fs.existsSync fails), the
// collector does not rethrow: it reports the signal as unavailable with a motivo,
// without `tokenMontado`.
test("Property 9: a failing token existence check yields an unavailable signal", async () => {
  await fc.assert(
    fc.property(fc.boolean(), (_any) => {
      const deps = { fs: mockFsExists({ throwErr: true }) };
      const sinal = coletarTokenServiceAccount(deps);

      // Unavailability contract: disponivel:false + motivo, no value. (R5.3)
      assert.equal(sinal.disponivel, false);
      assert.equal(typeof sinal.motivo, "string");
      assert.ok(sinal.motivo.length > 0);
      assert.equal(sinal.tokenMontado, undefined);
    }),
    { numRuns: RUNS }
  );
});

// --- Property 6 (task 3.2) --------------------------------------------------
// Collector under test: coletarPrivilegio, specifically the resilient extraction
// of CapEff/CapPrm from /proc/self/status. We mock the whole fs surface the
// collector touches (readFileSync for the status file, readdirSync for /proc, and
// existsSync for /host) so the collector never throws regardless of what the
// status file looks like.
const { coletarPrivilegio } = require("../src/lib/posture");

/**
 * Build a mock `fs` for coletarPrivilegio. `statusContent` is what readFileSync
 * returns for /proc/self/status; when `statusThrows` is true, readFileSync throws
 * (simulating an absent status file, e.g. off-Linux). readdirSync/existsSync are
 * stubbed with harmless defaults so the node-mount and hostPID branches never
 * blow up and never interfere with the capability assertions.
 */
function mockFsPrivilegio({ statusContent, statusThrows }) {
  return {
    readFileSync: (filePath) => {
      if (statusThrows) {
        const e = new Error("mock readFileSync ENOENT");
        e.code = "ENOENT";
        throw e;
      }
      return statusContent;
    },
    // /proc listing: empty so hostPidProvavel stays false and never throws.
    readdirSync: () => [],
    // /host presence: false so montagemNoPresente stays false and never throws.
    existsSync: () => false,
  };
}

// Feature: sangyshop-diagnostico-postura, Property 6: Resilient capability extraction
// Validates: Requirements 3.1, 3.4
//
// For every simulated /proc/self/status content, the CapEff/CapPrm extraction is
// resilient: when CapEff/CapPrm lines with valid hex are present, the
// collector extracts exactly those values (lowercased, as the collector
// normalizes); when the file is absent (readFileSync throws) or the lines
// are malformed/missing, the cap fields are unavailable (empty string)
// WITHOUT throwing. (R3.1, R3.4)
test("Property 6: capability extraction from /proc/self/status is resilient", async () => {
  // A valid cap line value: 1..16 hex digits (kernels use up to 16). We keep the
  // raw (possibly mixed-case) form to feed the file and compare against the
  // lowercased form the collector is documented to produce.
  const hexArb = fc
    .string({
      unit: fc.constantFrom(..."0123456789abcdefABCDEF".split("")),
      minLength: 1,
      maxLength: 16,
    })
    .filter((s) => s.length > 0);

  // Arbitrary "other" status lines that must never be mistaken for CapEff/CapPrm.
  // We forbid them from starting with the exact "CapEff:"/"CapPrm:" prefixes so a
  // random line can't accidentally supply a value and defeat the oracle.
  const otherLineArb = fc
    .string({ maxLength: 40 })
    .map((s) => s.replace(/[\r\n]/g, " "))
    .filter((s) => !/^Cap(Eff|Prm):/.test(s));

  await fc.assert(
    fc.property(
      // Whether each valid cap line is present, and its hex value.
      fc.boolean(),
      fc.boolean(),
      hexArb,
      hexArb,
      // Surrounding noise lines and where to interleave the cap lines.
      fc.array(otherLineArb, { maxLength: 8 }),
      fc.nat({ max: 8 }),
      fc.nat({ max: 8 }),
      (
        hasEff,
        hasPrm,
        hexEff,
        hexPrm,
        otherLines,
        posEff,
        posPrm
      ) => {
        // Build the status content by interleaving the valid cap lines (when
        // present) among arbitrary other lines at bounded positions.
        const lines = otherLines.slice();
        if (hasEff) {
          const i = Math.min(posEff, lines.length);
          lines.splice(i, 0, "CapEff:\t" + hexEff);
        }
        if (hasPrm) {
          const j = Math.min(posPrm, lines.length);
          lines.splice(j, 0, "CapPrm:\t" + hexPrm);
        }
        const content = lines.join("\n");

        const deps = { fs: mockFsPrivilegio({ statusContent: content }) };

        // Must never throw. (R3.4)
        const sinal = coletarPrivilegio(deps);

        // The privilege signal itself is always available (degrades field-wise).
        assert.equal(sinal.disponivel, true);
        assert.equal(typeof sinal.capEff, "string");
        assert.equal(typeof sinal.capPrm, "string");

        // When a valid hex cap line is present, the collector extracts exactly
        // that value, lowercased. When absent, the field is empty. (R3.1)
        assert.equal(sinal.capEff, hasEff ? hexEff.toLowerCase() : "");
        assert.equal(sinal.capPrm, hasPrm ? hexPrm.toLowerCase() : "");
      }
    ),
    { numRuns: RUNS }
  );
});

// Feature: sangyshop-diagnostico-postura, Property 6: Resilient capability extraction
// Validates: Requirements 3.4
//
// When /proc/self/status is absent (readFileSync throws) OR all lines
// are malformed (invalid hex, no value, different prefix), the cap fields
// stay empty and the collector does not throw. (R3.4)
test("Property 6: an absent or malformed status file yields empty cap fields without throwing", async () => {
  // Malformed CapEff/CapPrm lines: right prefix but a value that the strict hex
  // regex must reject (non-hex chars, or trailing garbage after the hex).
  const malformedCapArb = fc.oneof(
    fc.constant("CapEff:"), // no value at all
    fc.constant("CapEff: \txyz"), // non-hex value
    fc.constant("CapEff: 00000000 extra"), // trailing garbage breaks the $ anchor
    fc.constant("CapPrm:"),
    fc.constant("CapPrm: zzzz"),
    fc.constant("CapPrm: 1g2h"),
    fc.constant("capeff: 0000003fffffffff"), // wrong case on the key -> not matched
    fc.constant("XCapEff: 0000003fffffffff") // prefixed key -> not matched
  );

  await fc.assert(
    fc.property(
      // absent file, or a body made solely of malformed cap lines + noise
      fc.boolean(),
      fc.array(malformedCapArb, { maxLength: 6 }),
      fc.array(fc.string({ maxLength: 30 }).map((s) => s.replace(/[\r\n]/g, " ")), {
        maxLength: 6,
      }),
      (absent, malformedCaps, noise) => {
        const body = malformedCaps.concat(noise).join("\n");
        const deps = {
          fs: mockFsPrivilegio(
            absent
              ? { statusThrows: true }
              : { statusContent: body }
          ),
        };

        // Must never throw. (R3.4)
        const sinal = coletarPrivilegio(deps);

        assert.equal(sinal.disponivel, true);
        // No well-formed cap line present -> both fields stay empty. (R3.4)
        assert.equal(sinal.capEff, "");
        assert.equal(sinal.capPrm, "");
      }
    ),
    { numRuns: RUNS }
  );
});
// --- Property 7 (task 3.3) --------------------------------------------------
// Collectors under test: the environment-sensing heuristics of coletarPrivilegio
// (node-mount presence + hostPID count threshold) and coletarRedeHost (hostname,
// node-mount presence + hostNetwork divergence rule). We mock the fs/os/process
// surface so the simulated environment (presence of /host, number of numeric
// entries under /proc, hostname vs POD_NAME) fully determines the signals.
const { coletarRedeHost } = require("../src/lib/posture");

const LIMIAR_HOST_PID = 50; // mirror of the collector's internal threshold (> 50)

/**
 * Build a mock `fs` for the coletarPrivilegio heuristics. `hostExists` drives
 * existsSync("/host"); `procEntries` is the array readdirSync("/proc") returns.
 * readFileSync returns an empty status body so the capability branch is inert and
 * never interferes with the heuristic assertions.
 */
function mockFsPrivilegeHeuristic({ hostExists, procEntries }) {
  return {
    readFileSync: () => "",
    readdirSync: () => procEntries,
    existsSync: () => hostExists,
  };
}

/**
 * Build a set of /proc entries containing exactly `numPids` numeric-named
 * entries, plus a handful of non-numeric names that the collector must ignore
 * (it only counts entries matching /^\d+$/).
 */
function buildProcEntries(numPids) {
  const entries = [];
  for (let i = 0; i < numPids; i++) {
    // Offset by 1 so we never emit "0" alone, but every entry is purely numeric.
    entries.push(String(i + 1));
  }
  // Non-numeric names that must be ignored by the counter.
  entries.push("self", "net", "cpuinfo", "1abc", "abc", "12x3");
  return entries;
}

// Feature: sangyshop-diagnostico-postura, Property 7: Privilege and network heuristics reflect the simulated environment
// Validates: Requirements 3.2, 3.3
//
// For every simulated /host presence (via fs.existsSync) and count of numeric
// entries in /proc (visible PIDs), the privilege collector reflects exactly
// existsSync("/host") in `montagemNoPresente` and sets `hostPidProvavel`
// by the threshold rule (> 50), ignoring non-numeric entries. The `metodo` field
// (string) is always present, declaring the inference.
test("Property 7: privilege heuristics reflect /host presence and the /proc PID threshold", async () => {
  await fc.assert(
    fc.property(
      // /host present or not.
      fc.boolean(),
      // Number of numeric PID entries under /proc, spanning both sides of the
      // > 50 threshold (0..120 covers below, at, just above, and well above).
      fc.nat({ max: 120 }),
      (hostExists, numPids) => {
        const procEntries = buildProcEntries(numPids);
        const deps = {
          fs: mockFsPrivilegeHeuristic({ hostExists, procEntries }),
        };

        const sinal = coletarPrivilegio(deps);

        assert.equal(sinal.disponivel, true);

        // montagemNoPresente reflects existsSync("/host") exactly. (R3.2)
        assert.equal(sinal.montagemNoPresente, hostExists);

        // hostPidProvavel follows the strict > 50 threshold; non-numeric entries
        // are ignored, so the count is exactly numPids. (R3.3)
        assert.equal(sinal.hostPidProvavel, numPids > LIMIAR_HOST_PID);

        // The heuristic always declares its method as a string (inference). (R3.3)
        assert.equal(typeof sinal.metodo, "string");
        assert.ok(sinal.metodo.length > 0);
      }
    ),
    { numRuns: RUNS }
  );
});

/**
 * Build a mock dependency layer for coletarRedeHost. `hostname` is what
 * os.hostname() returns; `hostExists` drives existsSync("/host"); `podName` is
 * injected via process.env.POD_NAME (omitted when undefined).
 */
function mockDepsNetworkHost({ hostname, hostExists, podName }) {
  const env = {};
  if (typeof podName === "string") env.POD_NAME = podName;
  return {
    os: { hostname: () => hostname },
    fs: { existsSync: () => hostExists },
    process: { env },
  };
}

// Mirror of the collector's pod-name suffix heuristic so assertions are precise.
function looksLikePodName(hostname) {
  return /-[0-9a-f]{5,}$/i.test(String(hostname));
}

// Feature: sangyshop-diagnostico-postura, Property 7: Privilege and network heuristics reflect the simulated environment
// Validates: Requirements 6.1, 6.2, 6.3, 6.4
//
// For every simulated hostname (via os.hostname()), /host presence and POD_NAME
// value, the network/host collector echoes `hostname`, reflects `montagemNoPresente`
// via existsSync("/host") and sets `hostNetworkProvavel` by the divergence rule:
// hostname differs from POD_NAME (present and non-empty) AND does not look like a
// generated Pod name (no hash suffix /-[0-9a-f]{5,}$/i). The `metodo` field (string)
// is always present.
test("Property 7: network heuristics reflect hostname, /host presence and the POD_NAME divergence rule", async () => {
  // A base name segment made of safe hostname characters.
  const nomeBaseArb = fc
    .string({
      unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-".split("")),
      minLength: 1,
      maxLength: 20,
    })
    .filter((s) => s.length > 0);

  // A pod-style hash suffix (5+ hex chars) to append, exercising the
  // looksLikePodName branch on purpose.
  const hashArb = fc.string({
    unit: fc.constantFrom(..."0123456789abcdef".split("")),
    minLength: 5,
    maxLength: 10,
  });

  await fc.assert(
    fc.property(
      nomeBaseArb,
      // Optionally append a pod-style hash suffix to make it look like a pod.
      fc.option(hashArb, { nil: undefined }),
      // /host present or not.
      fc.boolean(),
      // POD_NAME: absent, empty, equal to hostname, or an arbitrary other name.
      fc.oneof(
        fc.constant(undefined),
        fc.constant(""),
        fc.constant("__EQUAL__"), // sentinel: use the hostname itself
        nomeBaseArb
      ),
      (base, hashSuffix, hostExists, podNameRaw) => {
        const hostname =
          typeof hashSuffix === "string" ? base + "-" + hashSuffix : base;

        // Resolve the POD_NAME sentinel into the actual hostname when requested.
        const podName =
          podNameRaw === "__EQUAL__" ? hostname : podNameRaw;

        const deps = mockDepsNetworkHost({ hostname, hostExists, podName });
        const sinal = coletarRedeHost(deps);

        assert.equal(sinal.disponivel, true);

        // hostname echoed from os.hostname(). (R6.1)
        assert.equal(sinal.hostname, hostname);

        // montagemNoPresente reflects existsSync("/host") exactly. (R6.3)
        assert.equal(sinal.montagemNoPresente, hostExists);

        // hostNetworkProvavel = diverges from a present/non-empty POD_NAME AND
        // does not look like a generated pod name. (R6.2, R6.4)
        const divergesFromPodName =
          typeof podName === "string" &&
          podName.length > 0 &&
          podName !== hostname;
        const expected = divergesFromPodName && !looksLikePodName(hostname);
        assert.equal(sinal.hostNetworkProvavel, expected);

        // The heuristic always declares its method as a string (inference). (R6.2)
        assert.equal(typeof sinal.metodo, "string");
        assert.ok(sinal.metodo.length > 0);
      }
    ),
    { numRuns: RUNS }
  );
});

// --- Property 8 (task 3.5) --------------------------------------------------
// Collector under test: coletarSistemaArquivos, the controlled rootfs write probe.
// The collector derives a fixed probe path from process.cwd()/process.pid, tries a
// `wx` write there, classifies the result (writable / read-only / unavailable) and
// ALWAYS removes the file it created. We mock process (cwd + pid) to fully pin the
// probe path, and mock fs.writeFileSync/unlinkSync so the three outcomes are
// simulated and every creation/removal is recorded in closures, proving no residue.
const path = require("node:path");
const { coletarSistemaArquivos } = require("../src/lib/posture");

// Mirror of the collector's own path derivation so the oracle knows exactly which
// file the probe targets: cwd/.diag-rootfs-probe-<pid>, falling back to /etc when
// cwd is empty/absent. Kept in lock-step with src/lib/posture.js.
function caminhoSondaEsperado(cwd, pid) {
  const nomeArquivo = ".diag-rootfs-probe-" + pid;
  return typeof cwd === "string" && cwd.length > 0
    ? path.join(cwd, nomeArquivo)
    : path.join("/etc", nomeArquivo);
}

// The three write outcomes the probe must classify.
//   "ok"    -> writeFileSync succeeds (a file IS created)   -> rootfs writable
//   "erofs" -> writeFileSync throws { code: "EROFS" }         -> rootfs read-only
//   "outro" -> writeFileSync throws some other error          -> signal unavailable
const RESULTADOS_ESCRITA = ["ok", "erofs", "outro"];

/**
 * Build a mock dependency layer for coletarSistemaArquivos.
 *
 * `resultado` selects the writeFileSync behaviour. `criados`/`removidos` are the
 * shared closure arrays that record, respectively, every path a file was actually
 * created at (write succeeded) and every path unlinkSync was called with. Comparing
 * them lets the property prove: every created file is removed, and nothing is removed
 * that was not created.
 *
 * `cwd`/`pid` drive the probe path via the mock process; `cwd === undefined` exercises
 * the /etc fallback. `codigoOutro` is the error code used for the "outro" case.
 */
function mockDepsSistemaArquivos({
  resultado,
  cwd,
  pid,
  codigoOutro,
  criados,
  removidos,
}) {
  const fs = {
    writeFileSync: (caminho) => {
      if (resultado === "erofs") {
        const e = new Error("read-only file system, open '" + caminho + "'");
        e.code = "EROFS";
        throw e;
      }
      if (resultado === "outro") {
        const e = new Error("mock write failure");
        e.code = codigoOutro;
        throw e;
      }
      // "ok": the file was actually created, record it so cleanup can be checked.
      criados.push(caminho);
    },
    unlinkSync: (caminho) => {
      // Record every removal attempt the collector makes.
      removidos.push(caminho);
    },
  };

  const proc = { pid };
  // Only expose cwd() when a cwd is provided, so `cwd === undefined` exercises the
  // collector's missing-cwd fallback to /etc.
  if (cwd !== undefined) proc.cwd = () => cwd;

  return { fs, process: proc };
}

// Feature: sangyshop-diagnostico-postura, Property 8: The rootfs probe classifies and always cleans up
// Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5
//
// For every simulated rootfs write result (success, EROFS, other error) and
// for every probe path derived from process.cwd()/process.pid (with /etc fallback
// when cwd is absent), the collector:
//   - classifies correctly: success -> {disponivel:true, rootfsSomenteLeitura:false,
//     caminhoTestado}; EROFS -> {disponivel:true, rootfsSomenteLeitura:true,
//     caminhoTestado}; other error -> {disponivel:false, motivo}; (R4.1, R4.2, R4.3, R4.5)
//   - and ALWAYS cleans up: when the write created the file (success), unlinkSync is
//     called exactly for that path and no residue remains; when the write
//     threw (EROFS/other), no file was created, so there is nothing left to
//     remove. (R4.4)
test("Property 8: the rootfs probe classifies correctly and always cleans up", async () => {
  // Arbitrary cwd segment made of safe path characters; may also be absent/empty to
  // exercise the /etc fallback. pid is an arbitrary non-negative integer.
  const cwdSegmentoArb = fc.stringMatching(/^[A-Za-z0-9_./-]{1,20}$/);
  const cwdArb = fc.oneof(
    fc.constant(undefined), // no cwd() -> fallback to /etc
    fc.constant(""), // empty cwd -> fallback to /etc
    cwdSegmentoArb.map((s) => "/app/" + s)
  );

  await fc.assert(
    fc.property(
      fc.constantFrom(...RESULTADOS_ESCRITA),
      cwdArb,
      fc.nat({ max: 4294967295 }),
      // A non-EROFS error code for the "outro" case (never "EROFS").
      fc.constantFrom("EACCES", "ENOENT", "EEXIST", "EPERM", "EISDIR"),
      (resultado, cwd, pid, codigoOutro) => {
        // Fresh closure ledgers per iteration: paths created vs paths removed.
        const criados = [];
        const removidos = [];

        const deps = mockDepsSistemaArquivos({
          resultado,
          cwd,
          pid,
          codigoOutro,
          criados,
          removidos,
        });

        const caminhoEsperado = caminhoSondaEsperado(cwd, pid);

        // Must never throw regardless of the write outcome. (R4.4, R4.5)
        const sinal = coletarSistemaArquivos(deps);

        if (resultado === "ok") {
          // Write succeeded -> rootfs writable, path echoed. (R4.1, R4.2)
          assert.equal(sinal.disponivel, true);
          assert.equal(sinal.rootfsSomenteLeitura, false);
          assert.equal(sinal.caminhoTestado, caminhoEsperado);
          assert.equal(sinal.motivo, undefined);

          // A file WAS created exactly at the probe path...
          assert.deepEqual(criados, [caminhoEsperado]);
          // ...and it was removed exactly once, at that same path: no residue. (R4.4)
          assert.deepEqual(removidos, [caminhoEsperado]);
        } else if (resultado === "erofs") {
          // EROFS -> rootfs read-only (the hardened signal), path echoed. (R4.3)
          assert.equal(sinal.disponivel, true);
          assert.equal(sinal.rootfsSomenteLeitura, true);
          assert.equal(sinal.caminhoTestado, caminhoEsperado);
          assert.equal(sinal.motivo, undefined);

          // Write threw -> no file was created, so nothing must be removed. (R4.4)
          assert.deepEqual(criados, []);
          assert.deepEqual(removidos, []);
        } else {
          // Any other error -> unavailable with a motivo, no value fields. (R4.5)
          assert.equal(sinal.disponivel, false);
          assert.equal(typeof sinal.motivo, "string");
          assert.ok(sinal.motivo.length > 0);
          assert.equal(sinal.rootfsSomenteLeitura, undefined);
          assert.equal(sinal.caminhoTestado, undefined);

          // Write threw -> no file created, nothing removed. (R4.4)
          assert.deepEqual(criados, []);
          assert.deepEqual(removidos, []);
        }

        // Invariant across every outcome: nothing is ever removed that was not
        // created (no stray unlink), and every created file is removed (no residue).
        assert.deepEqual(removidos, criados);
      }
    ),
    { numRuns: RUNS }
  );
});

// --- Property 10 (task 3.7) -------------------------------------------------
// Collector under test: coletarIdentidadePod, the read-only projection of the
// three Downward API env vars (POD_NAME, POD_NAMESPACE, NODE_NAME) into the three
// signal sub-fields (nome, namespace, no). Each sub-field honours the uniform
// contract: present string -> {disponivel:true, valor}; absent -> {disponivel:false,
// motivo}. We mock process.env with an arbitrary subset of the three vars present
// (with arbitrary values) so the whole mapping is pinned by the simulated env, and
// NEVER touch the real process.env.
const { coletarIdentidadePod } = require("../src/lib/posture");

// Mapping from each signal sub-field to the env var that feeds it, mirroring the
// collector (nome<-POD_NAME, namespace<-POD_NAMESPACE, no<-NODE_NAME).
const MAPA_IDENTIDADE_POD = {
  nome: "POD_NAME",
  namespace: "POD_NAMESPACE",
  no: "NODE_NAME",
};

// Feature: sangyshop-diagnostico-postura, Property 10: Pod identity by env availability
// Validates: Requirements 7.1, 7.2, 7.3
//
// For every simulated subset of {POD_NAME, POD_NAMESPACE, NODE_NAME} present
// (with arbitrary values) or absent in process.env, the Pod identity collector
// projects each field by the availability of its env var: present (string) ->
// {disponivel:true, valor:<the env value>}; absent -> {disponivel:false} with a
// string `motivo`. The collector never throws and is read-only (does not mutate process.env).
test("Property 10: Pod identity is projected per env var availability, read-only", async () => {
  // For each of the three vars: absent (undefined) or present with an arbitrary
  // string value. fast-check covers every present/absent subset across runs.
  const valorArb = fc.option(fc.string(), { nil: undefined });

  await fc.assert(
    fc.property(valorArb, valorArb, valorArb, (podName, podNamespace, nodeName) => {
      // Build a mock env containing only the vars that are "present" (string),
      // leaving the rest truly absent so typeof env[x] !== "string".
      const env = {};
      if (typeof podName === "string") env.POD_NAME = podName;
      if (typeof podNamespace === "string") env.POD_NAMESPACE = podNamespace;
      if (typeof nodeName === "string") env.NODE_NAME = nodeName;

      // Snapshot the env to later assert the collector never mutated it. (R13-style
      // read-only guarantee for this signal.)
      const envAntes = { ...env };
      const deps = { process: { env } };

      // Must never throw regardless of which vars are present. (R7.1)
      const sinal = coletarIdentidadePod(deps);

      // The signal always exposes exactly the three fixed sub-fields.
      assert.deepEqual(
        Object.keys(sinal).sort(),
        ["namespace", "no", "nome"]
      );

      const esperados = {
        nome: podName,
        namespace: podNamespace,
        no: nodeName,
      };

      for (const campo of Object.keys(MAPA_IDENTIDADE_POD)) {
        const sub = sinal[campo];
        const valorEnv = esperados[campo];

        if (typeof valorEnv === "string") {
          // Present env var -> available sub-field echoing the exact value. (R7.1, R7.2)
          assert.equal(sub.disponivel, true);
          assert.equal(sub.valor, valorEnv);
          // An available sub-field carries no "motivo".
          assert.equal(sub.motivo, undefined);
        } else {
          // Absent env var -> unavailable sub-field with a string motivo, no value. (R7.3)
          assert.equal(sub.disponivel, false);
          assert.equal(typeof sub.motivo, "string");
          assert.ok(sub.motivo.length > 0);
          assert.equal(sub.valor, undefined);
        }
      }

      // Read-only: the collector must not mutate the injected env. (R13.1, R13.2)
      assert.deepEqual(env, envAntes);
    }),
    { numRuns: RUNS }
  );
});

// --- Property 1 (task 4.2) --------------------------------------------------
// Aggregator under test: buildPostureReport(deps). It runs every collector inside
// an isolated try/catch, so a throwing (or degrading) collector becomes a well
// formed signal and the aggregator NEVER rethrows. The report always carries the
// fixed top-level shape: `meta` plus exactly the 7 keys in CHAVES_SINAIS.
//
// This property drives an ARBITRARY SUBSET of the 7 collectors into failure and
// asserts the aggregator stays complete and robust. We force failures by injecting
// a `deps` ({ fs, os, process }) whose operations throw for the chosen signals:
//   - identidadeExecucao  -> process.getuid() throws (unguarded in the collector)
//   - sistemaArquivos     -> reading process.pid throws (unguarded property access)
//   - identidadePod       -> reading process.env[...] throws (unguarded access)
//   - tokenServiceAccount -> fs.existsSync(token) throws -> collector returns
//                            {disponivel:false, motivo} by its own guard
//   - redeHost            -> os.hostname() throws -> collector returns
//                            {disponivel:false, motivo} by its own guard
//   - variaveisSensiveis  -> reading process.env.DB_PASSWORD throws -> guarded
//                            {disponivel:false, motivo}
// `privilegio` is robust by design (every fs call is guarded) and always reports
// disponivel:true, so it is never asked to fail here.
const {
  buildPostureReport,
  CHAVES_SINAIS,
} = require("../src/lib/posture");

// Signals that can be driven to disponivel:false (either by throwing out to the
// aggregator's catch, or by the collector's own internal guard). `privilegio` is
// excluded on purpose: it degrades field-wise but never reports disponivel:false.
const SINAIS_FALHAVEIS = [
  "identidadeExecucao",
  "sistemaArquivos",
  "tokenServiceAccount",
  "redeHost",
  "identidadePod",
  "variaveisSensiveis",
];

// Sentinel errors so the aggregator's `motivo` is a real, non-empty string.
function simulatedError(msg) {
  return new Error(msg);
}

/**
 * Build a `deps` layer that forces exactly the signals in `falhar` (a Set of keys)
 * to end up disponivel:false, while the remaining collectors run normally against
 * harmless, non-throwing stubs.
 *
 * The failure levers are chosen per collector so that each targeted signal reliably
 * becomes disponivel:false, some by throwing out to the aggregator's try/catch,
 * others by throwing a guarded dependency the collector itself turns into a motivo.
 */
function mockDepsFalhas(falhar) {
  // --- process -------------------------------------------------------------
  // getuid/getgid: throw when identidadeExecucao must fail; otherwise return a
  // benign uid/gid so the collector succeeds.
  const proc = {
    getuid: () => {
      if (falhar.has("identidadeExecucao")) throw simulatedError("getuid boom");
      return 1000;
    },
    getgid: () => 1000,
    // cwd used by sistemaArquivos; benign when that signal is not failing.
    cwd: () => "/app",
  };

  // pid is read (unguarded) by sistemaArquivos. A throwing getter forces that
  // collector to throw out to the aggregator's catch.
  Object.defineProperty(proc, "pid", {
    get() {
      if (falhar.has("sistemaArquivos")) throw simulatedError("pid boom");
      return 4242;
    },
  });

  // env is read (unguarded) by identidadePod and (guarded) by variaveisSensiveis.
  // A throwing getter on the env OBJECT forces identidadePod to throw out to the
  // aggregator and makes variaveisSensiveis hit its own guard -> disponivel:false.
  // When neither must fail, env is a plain object so both collectors succeed.
  const envAlvo =
    falhar.has("identidadePod") || falhar.has("variaveisSensiveis");
  if (envAlvo) {
    Object.defineProperty(proc, "env", {
      get() {
        throw simulatedError("env boom");
      },
    });
  } else {
    proc.env = { POD_NAME: "sangyshop", DB_PASSWORD: "x" };
  }

  // --- fs ------------------------------------------------------------------
  // tokenServiceAccount calls fs.existsSync(tokenPath) inside a guard; throwing
  // there yields disponivel:false. privilegio also calls existsSync("/host") but
  // guards it, so a throw there is harmless (stays disponivel:true). We only throw
  // for the token path to avoid coupling the two signals.
  const CAMINHO_TOKEN =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";
  const fs = {
    existsSync: (caminho) => {
      if (caminho === CAMINHO_TOKEN && falhar.has("tokenServiceAccount")) {
        throw simulatedError("existsSync token boom");
      }
      return false;
    },
    // privilegio reads these (guarded); benign defaults keep it disponivel:true.
    readFileSync: () => "",
    readdirSync: () => [],
    // sistemaArquivos: writeFileSync throws EROFS so, when NOT failing, it still
    // classifies cleanly as read-only (disponivel:true) without leaving residue.
    writeFileSync: () => {
      const e = simulatedError("read-only file system");
      e.code = "EROFS";
      throw e;
    },
    unlinkSync: () => {},
  };

  // --- os ------------------------------------------------------------------
  // redeHost calls os.hostname() inside a guard; throwing there yields
  // disponivel:false. Otherwise return a benign hostname.
  const os = {
    hostname: () => {
      if (falhar.has("redeHost")) throw simulatedError("hostname boom");
      return "sangyshop";
    },
  };

  return { fs, os, process: proc };
}

// Feature: sangyshop-diagnostico-postura, Property 1: Complete and robust report
// Validates: Requirements 1.2, 9.1, 9.2, 9.3
//
// For EVERY subset of collectors forced to fail (by throwing to the aggregator's
// catch or by falling into the collector's own guard), buildPostureReport:
//   - NEVER throws; (R9.1, R9.2)
//   - returns an object with EXACTLY the fixed top-level keys: `meta` + the 7
//     signals of CHAVES_SINAIS; no signal is omitted and no extra appears; (R1.2, R9.3)
//   - `meta` carries `geradoEm` and `versaoRelatorio`;
//   - every signal whose collector failed has `disponivel:false` and a string `motivo`; (R9.3)
//   - every signal whose collector did NOT fail is present and well-formed.
test("Property 1: the report is always complete and robust under arbitrary collector failures", async () => {
  // Arbitrary subset of the failable signals (0..all of them). Represented as a
  // record of booleans so fast-check explores every combination across runs.
  const subsetArb = fc.record(
    Object.fromEntries(SINAIS_FALHAVEIS.map((k) => [k, fc.boolean()]))
  );

  await fc.assert(
    fc.property(subsetArb, (flags) => {
      const falhar = new Set(
        SINAIS_FALHAVEIS.filter((k) => flags[k])
      );

      const deps = mockDepsFalhas(falhar);

      // The aggregator must NEVER throw, whatever the failing subset. (R9.1, R9.2)
      let report;
      assert.doesNotThrow(() => {
        report = buildPostureReport(deps);
      });

      // Exactly the fixed top-level keys: meta + the 7 signals, nothing more,
      // nothing missing. (R1.2, R9.3)
      const expectedKeys = ["meta", ...CHAVES_SINAIS].sort();
      assert.deepEqual(Object.keys(report).sort(), expectedKeys);

      // meta carries the timestamp and the schema version.
      assert.equal(typeof report.meta.geradoEm, "string");
      assert.ok(report.meta.geradoEm.length > 0);
      assert.equal(typeof report.meta.versaoRelatorio, "number");

      // Every one of the 7 signals is present (never omitted). (R9.3)
      for (const chave of CHAVES_SINAIS) {
        assert.ok(
          Object.prototype.hasOwnProperty.call(report, chave),
          "missing signal: " + chave
        );
        assert.equal(typeof report[chave], "object");
        assert.notEqual(report[chave], null);
      }

      // Every FAILED signal degrades to the uniform unavailable contract:
      // disponivel:false + a non-empty string motivo. (R9.3)
      for (const chave of falhar) {
        const sinal = report[chave];
        assert.equal(
          sinal.disponivel,
          false,
          "expected disponivel:false in " + chave
        );
        assert.equal(typeof sinal.motivo, "string");
        assert.ok(sinal.motivo.length > 0);
      }

      // privilegio is never asked to fail and stays available. (field-level robustness)
      assert.equal(report.privilegio.disponivel, true);
    }),
    { numRuns: RUNS }
  );
});
