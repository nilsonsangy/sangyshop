// src/lib/posture.js
// Feature: sangyshop-diagnostico-postura
// Posture diagnostic collectors for the /_diag endpoint (Aula 17).
//
// Each collector observes a single posture signal from inside the container
// (execution identity, privilege, filesystem, ServiceAccount token, network/host,
// Pod identity, sensitive env vars) and returns a UNIFORM contract:
//
//   { disponivel: true, ...campos de valor }        // signal collected
//   { disponivel: false, motivo: "<texto>" }        // signal unavailable (no value fields)
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
const VERSAO_RELATORIO = 1;

// Fixed set of top-level signal keys, in a stable order (R1.2, R12.2).
const CHAVES_SINAIS = [
  "identidadeExecucao",
  "privilegio",
  "sistemaArquivos",
  "tokenServiceAccount",
  "redeHost",
  "identidadePod",
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
function indisponivel(motivo) {
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
function coletarIdentidadeExecucao(deps) {
  const { process: proc } = resolveDeps(deps);

  // getuid/getgid só existem em plataformas POSIX. Em Windows (ex.: npm start do
  // instrutor) elas não estão presentes e o sinal fica indisponível. (R2.4)
  if (typeof proc.getuid !== "function" || typeof proc.getgid !== "function") {
    return indisponivel("getuid indisponivel na plataforma");
  }

  const uid = proc.getuid();
  const gid = proc.getgid();
  const isRoot = uid === 0; // (R2.2)
  const papel = isRoot ? "root" : "nao-root"; // (R2.3)

  return { disponivel: true, uid, gid, isRoot, papel };
}

/**
 * Privilege signal: capabilities (CapEff/CapPrm), node mount, hostPID heuristic. (R3)
 *
 * - Lê `/proc/self/status` e extrai `CapEff`/`CapPrm` com regex por linha, de forma
 *   resiliente: arquivo ausente ou linhas malformadas deixam os campos de cap
 *   indisponíveis (string vazia) sem lançar. (R3.1, R3.4)
 * - `montagemNoPresente = fs.existsSync("/host")` — só presença, sem listar conteúdo.
 *   (R3.2, R12.3)
 * - `hostPidProvavel` é HEURÍSTICO: conta entradas numéricas em `/proc` (PIDs visíveis)
 *   e marca `true` acima de um limiar (> 50). O campo `metodo` declara que é inferência,
 *   não prova. (R3.3)
 *
 * @param {object} [deps]
 */
function coletarPrivilegio(deps) {
  const { fs } = resolveDeps(deps);

  const CAMINHO_STATUS = "/proc/self/status";
  const CAMINHO_PROC = "/proc";
  const CAMINHO_HOST = "/host";
  const LIMIAR_HOST_PID = 50;

  // --- Capabilities (CapEff / CapPrm) ---------------------------------------
  // Extração resiliente: regex por linha. Ausência do arquivo ou linhas
  // malformadas => campo indisponível (string vazia), sem lançar. (R3.1, R3.4)
  let capEff = "";
  let capPrm = "";
  try {
    const conteudo = fs.readFileSync(CAMINHO_STATUS, "utf8");
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
  } catch (_erro) {
    // /proc/self/status ausente (ex.: fora do Linux) => caps indisponíveis. (R3.4)
    capEff = "";
    capPrm = "";
  }

  // --- Montagem do nó (hostPath /host) --------------------------------------
  // Só presença, nunca lista conteúdo. (R3.2, R12.3)
  let montagemNoPresente = false;
  try {
    montagemNoPresente = Boolean(fs.existsSync(CAMINHO_HOST));
  } catch (_erro) {
    montagemNoPresente = false;
  }

  // --- Heurística de hostPID ------------------------------------------------
  // Conta entradas numéricas (PIDs) em /proc. Com hostPID:true o container vê
  // muitos processos do nó; sem ele, poucos. Inferência, não prova. (R3.3)
  let hostPidProvavel = false;
  try {
    const entradas = fs.readdirSync(CAMINHO_PROC);
    const pids = (Array.isArray(entradas) ? entradas : []).filter((nome) =>
      /^\d+$/.test(String(nome))
    );
    hostPidProvavel = pids.length > LIMIAR_HOST_PID;
  } catch (_erro) {
    // /proc ilegível/ausente => não dá para inferir; mantém false.
    hostPidProvavel = false;
  }

  return {
    disponivel: true,
    capEff,
    capPrm,
    montagemNoPresente,
    hostPidProvavel,
    metodo:
      "heuristica: CapEff/CapPrm de /proc/self/status; hostPidProvavel por " +
      "contagem de PIDs em /proc (limiar > 50); inferencia, nao prova",
  };
}

/**
 * Filesystem signal: controlled rootfs write probe (read-only vs writable). (R4)
 * @param {object} [deps]
 */
function coletarSistemaArquivos(deps) {
  const { fs, process: proc } = resolveDeps(deps);

  // Nome fixo derivado do PID, evitando colisão e sem envolver dado de usuário.
  // (R12.3) Tentamos no rootfs do app (process.cwd()); se `cwd` não estiver
  // disponível, caímos para `/etc`, também parte do rootfs. (R4.1)
  const pid =
    typeof proc.pid === "number" || typeof proc.pid === "string"
      ? proc.pid
      : "x";
  const nomeArquivo = ".diag-rootfs-probe-" + pid;

  let diretorioBase;
  try {
    diretorioBase =
      typeof proc.cwd === "function" ? proc.cwd() : undefined;
  } catch (_erro) {
    diretorioBase = undefined;
  }
  const caminhoTestado =
    typeof diretorioBase === "string" && diretorioBase.length > 0
      ? path.join(diretorioBase, nomeArquivo)
      : path.join("/etc", nomeArquivo);

  // Sinaliza se o arquivo chegou a ser criado, para a limpeza no `finally`
  // só remover quando houver algo a remover (sucesso ou erro após criação).
  let arquivoCriado = false;

  try {
    // Tentativa de escrita no rootfs. `wx` falha se já existir e,
    // crucialmente, lança `EROFS` quando o sistema de arquivos é somente
    // leitura (readOnlyRootFilesystem:true no hardened). (R4.1, R4.3)
    fs.writeFileSync(caminhoTestado, "", { flag: "wx" });
    arquivoCriado = true;

    // Escrita bem-sucedida => rootfs gravável. (R4.2)
    return { disponivel: true, rootfsSomenteLeitura: false, caminhoTestado };
  } catch (erro) {
    // EROFS => rootfs somente leitura: este é o sinal "robustecido". (R4.3)
    if (erro && erro.code === "EROFS") {
      return { disponivel: true, rootfsSomenteLeitura: true, caminhoTestado };
    }

    // Qualquer outro erro (ex.: EACCES, ENOENT) => não dá para classificar;
    // reporta o sinal como indisponível com o motivo. (R4.5)
    return indisponivel(
      erro && erro.message ? erro.message : "falha ao sondar rootfs"
    );
  } finally {
    // Limpeza garantida: se o arquivo foi criado, remove-o — sempre, tanto no
    // caminho de sucesso quanto em erro após a criação. A remoção nunca pode
    // derrubar o coletor, então é protegida por try/catch próprio. (R4.4)
    if (arquivoCriado) {
      try {
        fs.unlinkSync(caminhoTestado);
      } catch (_erroLimpeza) {
        // Falha ao remover não altera a classificação já decidida; ignoramos
        // para não mascarar o resultado nem lançar a partir do `finally`.
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

  // Caminho padrão onde o kubelet monta o token da ServiceAccount quando
  // automountServiceAccountToken não está desabilitado. (R5.1)
  const CAMINHO_TOKEN =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

  // Somente presença: nunca lemos o conteúdo do token. (R5.2, R12.1)
  let tokenMontado;
  try {
    tokenMontado = fs.existsSync(CAMINHO_TOKEN);
  } catch (erro) {
    // Falha ao verificar a existência vira sinal indisponível. (R5.3)
    return indisponivel(
      erro && erro.message ? erro.message : "falha ao verificar token"
    );
  }

  return { disponivel: true, tokenMontado: Boolean(tokenMontado) };
}

/**
 * Network/host signal: hostname, node mount presence, hostNetwork heuristic. (R6)
 *
 * - `hostname` via `os.hostname()`. (R6.1)
 * - `hostNetworkProvavel` é HEURÍSTICO: com `hostNetwork:true` o hostname do Pod tende a
 *   ser o nome do NÓ (ex.: `desktop-worker`) em vez do nome do Pod. O coletor marca
 *   `true` quando o `hostname` diverge de `POD_NAME` e parece nome de nó (não corresponde
 *   ao padrão de sufixo aleatório de Pod). O campo `metodo` declara a inferência. (R6.2)
 * - `montagemNoPresente` reusa `/host` por existência, sem listar conteúdo. (R6.3, R12.3)
 *
 * @param {object} [deps]
 */
function coletarRedeHost(deps) {
  const { fs, os, process: proc } = resolveDeps(deps);

  const CAMINHO_HOST = "/host";

  // --- Hostname -------------------------------------------------------------
  let hostname;
  try {
    hostname = os.hostname();
  } catch (erro) {
    return indisponivel(
      erro && erro.message ? erro.message : "falha ao obter hostname"
    );
  }

  // --- Montagem do nó (reusa /host, só presença) ----------------------------
  let montagemNoPresente = false;
  try {
    montagemNoPresente = Boolean(fs.existsSync(CAMINHO_HOST));
  } catch (_erro) {
    montagemNoPresente = false;
  }

  // --- Heurística de hostNetwork --------------------------------------------
  // Sem hostNetwork, o hostname do Pod é o próprio nome do Pod (== POD_NAME).
  // Com hostNetwork:true, o hostname passa a ser o nome do NÓ, divergindo de
  // POD_NAME. Marcamos `true` quando divergem e o hostname parece nome de nó
  // (ausência do sufixo hash típico de Pods). Inferência, não prova. (R6.2, R6.4)
  let podName;
  try {
    podName = proc.env.POD_NAME;
  } catch (_erro) {
    podName = undefined;
  }

  // Padrão de nome de Pod gerado: termina em segmento(s) de hash minúsculo/dígito
  // (ex.: "sangyshop-7d9c-abcde"). Um nome de nó (ex.: "desktop-worker") não.
  const pareceNomeDePod = /-[0-9a-f]{5,}$/i.test(String(hostname));
  const divergeDoPodName =
    typeof podName === "string" && podName.length > 0 && podName !== hostname;

  const hostNetworkProvavel = divergeDoPodName && !pareceNomeDePod;

  return {
    disponivel: true,
    hostname,
    montagemNoPresente,
    hostNetworkProvavel,
    metodo:
      "heuristica: hostname diverge de POD_NAME e parece nome de no; " +
      "inferencia, nao prova",
  };
}

/**
 * Pod identity signal: POD_NAME / POD_NAMESPACE / NODE_NAME, read-only. (R7, R13)
 *
 * Projeta três campos da Downward API — `nome` (POD_NAME), `namespace`
 * (POD_NAMESPACE) e `no` (NODE_NAME) — a partir de `process.env`. Cada campo segue
 * o contrato uniforme: presente (string) => `{disponivel:true, valor}`; ausente =>
 * `{disponivel:false, motivo:"nao injetado via Downward API"}`. (R7.1, R7.2, R7.3)
 *
 * A leitura é SOMENTE-LEITURA: apenas consulta `process.env`, sem mutar o ambiente
 * nem `app.locals`. (R13.1, R13.2)
 *
 * @param {object} [deps]
 */
function coletarIdentidadePod(deps) {
  const { process: proc } = resolveDeps(deps);

  const MOTIVO_AUSENTE = "nao injetado via Downward API";

  // Lê um campo de env de forma defensiva: presente (string) => disponível com
  // valor; ausente ou tipo inesperado => indisponível com o motivo padrão.
  const lerCampo = (nomeVar) => {
    const valor = proc.env[nomeVar];
    if (typeof valor === "string") {
      return { disponivel: true, valor };
    }
    return indisponivel(MOTIVO_AUSENTE);
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

  // Reporta apenas a PRESENÇA do nome DB_PASSWORD; o valor nunca entra no
  // relatório e nenhuma conexão de banco é aberta. (R8.1, R8.2, R12.1, R14.2)
  let dbPasswordPresente;
  try {
    dbPasswordPresente = typeof proc.env.DB_PASSWORD === "string";
  } catch (erro) {
    // Falha ao inspecionar o ambiente vira sinal indisponível.
    return indisponivel(
      erro && erro.message ? erro.message : "falha ao verificar DB_PASSWORD"
    );
  }

  return { disponivel: true, dbPasswordPresente };
}

// Ordered map of top-level key -> collector, used by the aggregator.
const COLETORES = {
  identidadeExecucao: coletarIdentidadeExecucao,
  privilegio: coletarPrivilegio,
  sistemaArquivos: coletarSistemaArquivos,
  tokenServiceAccount: coletarTokenServiceAccount,
  redeHost: coletarRedeHost,
  identidadePod: coletarIdentidadePod,
  variaveisSensiveis: coletarVariaveisSensiveis,
};

/**
 * Aggregate every collector into a PostureReport. Each collector runs inside an
 * isolated try/catch: a collector that throws becomes `{disponivel:false, motivo}`
 * for its signal and the others still run. This function NEVER throws (R9).
 *
 * The returned object always carries the fixed set of top-level signal keys plus a
 * `meta` block ({ geradoEm, versaoRelatorio }).
 *
 * @param {{ fs?: object, os?: object, process?: object }} [deps]
 * @returns {object} PostureReport
 */
function buildPostureReport(deps) {
  const resolvidas = resolveDeps(deps);

  const report = {
    meta: {
      geradoEm: new Date().toISOString(),
      versaoRelatorio: VERSAO_RELATORIO,
    },
  };

  for (const chave of CHAVES_SINAIS) {
    const coletor = COLETORES[chave];
    try {
      report[chave] = coletor(resolvidas);
    } catch (erro) {
      report[chave] = indisponivel(erro && erro.message ? erro.message : erro);
    }
  }

  return report;
}

module.exports = {
  // Aggregator
  buildPostureReport,
  // Collectors
  coletarIdentidadeExecucao,
  coletarPrivilegio,
  coletarSistemaArquivos,
  coletarTokenServiceAccount,
  coletarRedeHost,
  coletarIdentidadePod,
  coletarVariaveisSensiveis,
  // Helpers / constants (exported for reuse and testing)
  resolveDeps,
  indisponivel,
  CHAVES_SINAIS,
  VERSAO_RELATORIO,
};
