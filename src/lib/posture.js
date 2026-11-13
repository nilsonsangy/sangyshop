// src/lib/posture.js
// Feature: sangyshop-diagnostico-postura
// Posture diagnostic collectors for the /_diag endpoint.
//
// Each collector observes a single posture signal from inside the container
// (execution identity, privilege, filesystem, ServiceAccount token, network/host,
// Pod identity, sensitive env vars) and returns a UNIFORM contract:
//
//   { disponivel: true, ...value fields }          // signal collected
//   { disponivel: false, motivo: "<text>" }          // signal unavailable (no value fields)
//
// buildPostureReport() aggregates every collector with a try/catch per signal so
// that a single failing collector never throws and never omits a signal (R9).
//
// SECURITY / SCOPE:
// - Uses ONLY process, os and fs. It MUST NOT import any database driver (R14):
//   DB_PASSWORD is reported by presence of the name only, never by value, and no
//   DB connection is ever opened (R8, R14).
// - Token and node-mount signals report presence only, never content (R5.2, R6.3, R12).
//
// Collectors accept an optional injectable `deps` object ({ fs, os, process }) that
// defaults to the real modules in production and receives mocks in tests, keeping the
// real fs/os/process untouched during property-based testing.

const realFs = require("fs");
const realOs = require("os");
const path = require("path");

// Version of the report schema. Bump when the top-level shape changes.
const REPORT_VERSION = 1;

// Fixed set of top-level signal keys, in a stable order (R1.2, R12.2).
const SIGNAL_KEYS = [
  "executionIdentity",
  "privilegio",
  "sistemaArquivos",
  "tokenServiceAccount",
  "redeHost",
  "podIdentity",
  "variaveisSensiveis",
];

/**
 * Normalize the injectable dependency layer. In production the collectors use the
 * real fs/os/process modules; tests pass mocks. Any subset may be overridden.
 *
 * @param {{ fs?: object, os?: object, process?: object }} [deps]
 * @returns {{ fs: object, os: object, process: object }}
 */
function resolveDeps(deps) {
  const d = deps || {};
  return {
    fs: d.fs || realFs,
    os: d.os || realOs,
    process: d.process || process,
  };
}

/**
 * Build an "unavailable" signal following the uniform contract: `disponivel:false`
 * plus a `motivo` string, with no value fields (R9.3).
 *
 * @param {string} motivo
 * @returns {{ disponivel: false, motivo: string }}
 */
function unavailable(motivo) {
  return { disponivel: false, motivo: String(motivo) };
}

// --- Collectors (skeleton) --------------------------------------------------
// Each collector is implemented in a later task. For now they honour the uniform
// contract by reporting themselves as unavailable so the aggregator already yields
// a complete, well-formed report.

/**
 * Execution identity signal: uid/gid, isRoot, papel. (R2)
 * @param {object} [deps]
 */
function collectExecutionIdentity(deps) {
  const { process: proc } = resolveDeps(deps);

  // getuid/getgid only exist on POSIX platforms. On Windows (e.g. the instructor's
  // npm start) they are absent and the signal is unavailable. (R2.4)
  if (typeof proc.getuid !== "function" || typeof proc.getgid !== "function") {
    return unavailable("getuid unavailable on this platform");
  }

  const uid = proc.getuid();
  const gid = proc.getgid();
  const isRoot = uid === 0; // (R2.2)
  const papel = isRoot ? "root" : "non-root"; // (R2.3)

  return { disponivel: true, uid, gid, isRoot, papel };
}

/**
 * Privilege signal: capabilities (CapEff/CapPrm), node mount, hostPID heuristic. (R3)
 *
 * - Reads `/proc/self/status` and extracts `CapEff`/`CapPrm` with a per-line regex,
 *   resiliently: a missing file or malformed lines leave the cap fields
 *   unavailable (empty string) without throwing. (R3.1, R3.4)
 * - `montagemNoPresente = fs.existsSync("/host")`: presence only, no content listing.
 *   (R3.2, R12.3)
 * - `likelyHostPid` is a HEURISTIC: it counts numeric entries in `/proc` (visible PIDs)
 *   and sets `true` above a threshold (> 50). The `metodo` field states that this is an
 *   inference, not proof. (R3.3)
 *
 * @param {object} [deps]
 */
function coletarPrivilegio(deps) {
  const { fs } = resolveDeps(deps);

  const STATUS_PATH = "/proc/self/status";
  const PROC_PATH = "/proc";
  const HOST_PATH = "/host";
  const HOST_PID_THRESHOLD = 50;

  // --- Capabilities (CapEff / CapPrm) ---------------------------------------
  // Resilient extraction: per-line regex. A missing file or malformed lines
  // => unavailable field (empty string), without throwing. (R3.1, R3.4)
  let capEff = "";
  let capPrm = "";
  try {
    const conteudo = fs.readFileSync(STATUS_PATH, "utf8");
    if (typeof conteudo === "string") {
      for (const linha of conteudo.split(/\r?\n/)) {
        const mEff = /^CapEff:\s*([0-9a-fA-F]+)\s*$/.exec(linha);
        if (mEff) {
          capEff = mEff[1].toLowerCase();
          continue;
        }
        const mPrm = /^CapPrm:\s*([0-9a-fA-F]+)\s*$/.exec(linha);
        if (mPrm) {
          capPrm = mPrm[1].toLowerCase();
        }
      }
    }
  } catch (_err) {
    // /proc/self/status missing (e.g. outside Linux) => caps unavailable. (R3.4)
    capEff = "";
    capPrm = "";
  }

  // --- Node mount (hostPath /host) ------------------------------------------
  // Presence only, never lists content. (R3.2, R12.3)
  let montagemNoPresente = false;
  try {
    montagemNoPresente = Boolean(fs.existsSync(HOST_PATH));
  } catch (_err) {
    montagemNoPresente = false;
  }

  // --- hostPID heuristic ----------------------------------------------------
  // Counts numeric entries (PIDs) in /proc. With hostPID:true the container sees
  // many node processes; without it, few. Inference, not proof. (R3.3)
  let likelyHostPid = false;
  try {
    const entradas = fs.readdirSync(PROC_PATH);
    const pids = (Array.isArray(entradas) ? entradas : []).filter((nome) =>
      /^\d+$/.test(String(nome))
    );
    likelyHostPid = pids.length > HOST_PID_THRESHOLD;
  } catch (_err) {
    // /proc unreadable/missing => cannot infer; keep false.
    likelyHostPid = false;
  }

  return {
    disponivel: true,
    capEff,
    capPrm,
    montagemNoPresente,
    likelyHostPid,
    metodo:
      "heuristic: CapEff/CapPrm from /proc/self/status; likelyHostPid by " +
      "counting PIDs in /proc (threshold > 50); inference, not proof",
  };
}

/**
 * Filesystem signal: controlled rootfs write probe (read-only vs writable). (R4)
 * @param {object} [deps]
 */
function coletarSistemaArquivos(deps) {
  const { fs, process: proc } = resolveDeps(deps);

  // Fixed name derived from the PID, avoiding collisions and involving no user
  // data. (R12.3) We try the app rootfs (process.cwd()); if `cwd` is not
  // available, we fall back to `/etc`, also part of the rootfs. (R4.1)
  const pid =
    typeof proc.pid === "number" || typeof proc.pid === "string"
      ? proc.pid
      : "x";
  const nomeArquivo = ".diag-rootfs-probe-" + pid;

  let diretorioBase;
  try {
    diretorioBase =
      typeof proc.cwd === "function" ? proc.cwd() : undefined;
  } catch (_err) {
    diretorioBase = undefined;
  }
  const testedPath =
    typeof diretorioBase === "string" && diretorioBase.length > 0
      ? path.join(diretorioBase, nomeArquivo)
      : path.join("/etc", nomeArquivo);

  // Flags whether the file was actually created, so the cleanup in `finally`
  // only removes something when there is something to remove (success or error
  // after creation).
  let arquivoCriado = false;

  try {
    // Attempt to write to the rootfs. `wx` fails if the file already exists and,
    // crucially, throws `EROFS` when the filesystem is read-only
    // (readOnlyRootFilesystem:true in hardened). (R4.1, R4.3)
    fs.writeFileSync(testedPath, "", { flag: "wx" });
    arquivoCriado = true;

    // Successful write => writable rootfs. (R4.2)
    return { disponivel: true, rootfsSomenteLeitura: false, testedPath };
  } catch (err) {
    // EROFS => read-only rootfs: this is the "hardened" signal. (R4.3)
    if (err && err.code === "EROFS") {
      return { disponivel: true, rootfsSomenteLeitura: true, testedPath };
    }

    // Any other error (e.g. EACCES, ENOENT) => cannot classify; report the
    // signal as unavailable with the reason. (R4.5)
    return unavailable(
      err && err.message ? err.message : "failed to probe rootfs"
    );
  } finally {
    // Guaranteed cleanup: if the file was created, remove it, always, on both the
    // success path and on an error after creation. Removal must never bring
    // the collector down, so it is protected by its own try/catch. (R4.4)
    if (arquivoCriado) {
      try {
        fs.unlinkSync(testedPath);
      } catch (_cleanupErr) {
        // A removal failure does not change the classification already decided; we
        // ignore it so as not to mask the result or throw from `finally`.
      }
    }
  }
}

/**
 * ServiceAccount token signal: presence only, never content. (R5, R12)
 * @param {object} [deps]
 */
function coletarTokenServiceAccount(deps) {
  const { fs } = resolveDeps(deps);

  // Default path where the kubelet mounts the ServiceAccount token when
  // automountServiceAccountToken is not disabled. (R5.1)
  const TOKEN_PATH =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

  // Presence only: we never read the token content. (R5.2, R12.1)
  let tokenMontado;
  try {
    tokenMontado = fs.existsSync(TOKEN_PATH);
  } catch (err) {
    // A failure to check existence becomes an unavailable signal. (R5.3)
    return unavailable(
      err && err.message ? err.message : "failed to check token"
    );
  }

  return { disponivel: true, tokenMontado: Boolean(tokenMontado) };
}

/**
 * Network/host signal: hostname, node mount presence, hostNetwork heuristic. (R6)
 *
 * - `hostname` via `os.hostname()`. (R6.1)
 * - `likelyHostNetwork` is a HEURISTIC: with `hostNetwork:true` the Pod hostname tends
 *   to be the NODE name (e.g. `desktop-worker`) instead of the Pod name. The collector sets
 *   `true` when `hostname` differs from `POD_NAME` and looks like a node name (does not match
 *   the random Pod suffix pattern). The `metodo` field states the inference. (R6.2)
 * - `montagemNoPresente` reuses `/host` by existence, without listing content. (R6.3, R12.3)
 *
 * @param {object} [deps]
 */
function coletarRedeHost(deps) {
  const { fs, os, process: proc } = resolveDeps(deps);

  const HOST_PATH = "/host";

  // --- Hostname -------------------------------------------------------------
  let hostname;
  try {
    hostname = os.hostname();
  } catch (err) {
    return unavailable(
      err && err.message ? err.message : "failed to get hostname"
    );
  }

  // --- Node mount (reuses /host, presence only) -----------------------------
  let montagemNoPresente = false;
  try {
    montagemNoPresente = Boolean(fs.existsSync(HOST_PATH));
  } catch (_err) {
    montagemNoPresente = false;
  }

  // --- hostNetwork heuristic ------------------------------------------------
  // Without hostNetwork, the Pod hostname is the Pod name itself (== POD_NAME).
  // With hostNetwork:true, the hostname becomes the NODE name, differing from
  // POD_NAME. We set `true` when they differ and the hostname looks like a node
  // name (no typical Pod hash suffix). Inference, not proof. (R6.2, R6.4)
  let podName;
  try {
    podName = proc.env.POD_NAME;
  } catch (_err) {
    podName = undefined;
  }

  // Generated Pod name pattern: ends in lowercase hash/digit segment(s)
  // (e.g. "sangyshop-7d9c-abcde"). A node name (e.g. "desktop-worker") does not.
  const pareceNomeDePod = /-[0-9a-f]{5,}$/i.test(String(hostname));
  const divergeDoPodName =
    typeof podName === "string" && podName.length > 0 && podName !== hostname;

  const likelyHostNetwork = divergeDoPodName && !pareceNomeDePod;

  return {
    disponivel: true,
    hostname,
    montagemNoPresente,
    likelyHostNetwork,
    metodo:
      "heuristic: hostname differs from POD_NAME and looks like a node name; " +
      "inference, not proof",
  };
}

/**
 * Pod identity signal: POD_NAME / POD_NAMESPACE / NODE_NAME, read-only. (R7, R13)
 *
 * Projects three Downward API fields: `nome` (POD_NAME), `namespace`
 * (POD_NAMESPACE) and `no` (NODE_NAME), from `process.env`. Each field follows
 * the uniform contract: present (string) => `{disponivel:true, valor}`; absent =>
 * `{disponivel:false, motivo:"not injected via Downward API"}`. (R7.1, R7.2, R7.3)
 *
 * Reading is READ-ONLY: it only queries `process.env`, without mutating the
 * environment or `app.locals`. (R13.1, R13.2)
 * @param {object} [deps]
 */
function collectPodIdentity(deps) {
  const { process: proc } = resolveDeps(deps);

  const MISSING_REASON = "not injected via Downward API";

  // Reads an env field defensively: present (string) => available with a
  // value; absent or unexpected type => unavailable with the default reason.
  const lerCampo = (nomeVar) => {
    const valor = proc.env[nomeVar];
    if (typeof valor === "string") {
      return { disponivel: true, valor };
    }
    return unavailable(MISSING_REASON);
  };

  return {
    nome: lerCampo("POD_NAME"),
    namespace: lerCampo("POD_NAMESPACE"),
    no: lerCampo("NODE_NAME"),
  };
}

/**
 * Sensitive env vars signal: presence of DB_PASSWORD by name only, never value. (R8, R14)
 * @param {object} [deps]
 */
function coletarVariaveisSensiveis(deps) {
  const { process: proc } = resolveDeps(deps);

  // Reports only the PRESENCE of the DB_PASSWORD name; the value never enters
  // the report and no database connection is opened. (R8.1, R8.2, R12.1, R14.2)
  let dbPasswordPresente;
  try {
    dbPasswordPresente = typeof proc.env.DB_PASSWORD === "string";
  } catch (err) {
    // A failure to inspect the environment becomes an unavailable signal.
    return unavailable(
      err && err.message ? err.message : "failed to check DB_PASSWORD"
    );
  }

  return { disponivel: true, dbPasswordPresente };
}

// Ordered map of top-level key -> collector, used by the aggregator.
const COLETORES = {
  executionIdentity: collectExecutionIdentity,
  privilegio: coletarPrivilegio,
  sistemaArquivos: coletarSistemaArquivos,
  tokenServiceAccount: coletarTokenServiceAccount,
  redeHost: coletarRedeHost,
  podIdentity: collectPodIdentity,
  variaveisSensiveis: coletarVariaveisSensiveis,
};

/**
 * Aggregate every collector into a PostureReport. Each collector runs inside an
 * isolated try/catch: a collector that throws becomes `{disponivel:false, motivo}`
 * for its signal and the others still run. This function NEVER throws (R9).
 *
 * The returned object always carries the fixed set of top-level signal keys plus a
 * `meta` block ({ geradoEm, reportVersion }).
 *
 * @param {{ fs?: object, os?: object, process?: object }} [deps]
 * @returns {object} PostureReport
 */
function buildPostureReport(deps) {
  const resolvidas = resolveDeps(deps);

  const report = {
    meta: {
      geradoEm: new Date().toISOString(),
      reportVersion: REPORT_VERSION,
    },
  };

  for (const chave of SIGNAL_KEYS) {
    const coletor = COLETORES[chave];
    try {
      report[chave] = coletor(resolvidas);
    } catch (err) {
      report[chave] = unavailable(err && err.message ? err.message : err);
    }
  }

  return report;
}

module.exports = {
  // Aggregator
  buildPostureReport,
  // Collectors
  collectExecutionIdentity,
  coletarPrivilegio,
  coletarSistemaArquivos,
  coletarTokenServiceAccount,
  coletarRedeHost,
  collectPodIdentity,
  coletarVariaveisSensiveis,
  // Helpers / constants (exported for reuse and testing)
  resolveDeps,
  unavailable,
  SIGNAL_KEYS,
  REPORT_VERSION,
};
