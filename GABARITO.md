# GABARITO - SangyShop (OWASP Top 10:2025 na visao de defesa)

Documento do professor. Cada secao e um exercicio: primeiro o **ataque** (defesa OFF),
depois a **defesa** (toggle ON) e a **comprovacao** de que o mesmo ataque falha. Todos os
comandos foram validados. Base URL: `http://localhost:3000`.

Resetar todas as defesas para OFF (estado inicial de ataque): reinicie o container, ou
poste `value:false` em cada chave em `/api/defenses/<chave>`.

---

## Exercicio 1 - A05:2025 Injection (SQL Injection)

**Alvo:** login (`/login`) e busca de produtos (`/products?q=`).

### Ataque (defesa OFF)
- **Bypass de login:** usuario `admin'--` com qualquer senha. A query vira
  `... WHERE username = 'admin'--' AND password = '...'`; o `--` comenta o resto e
  autentica como admin.
- **Extracao via UNION na busca:**
  `/products?q=' UNION SELECT id,username,password,role FROM users --`
  As senhas de todos os usuarios aparecem como se fossem produtos.

### Defesa
Ligar `A05_injection`. O codigo passa a usar **prepared statement**
(`db.prepare("... WHERE username = ? AND password = ?").get(username, password)`): a
entrada nunca e interpretada como SQL.

```
curl -X POST http://localhost:3000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Comprovacao
- Login com `admin'--` retorna **401**.
- A busca com UNION nao retorna senha nenhuma.
- **Criterio:** explicar por que a parametrizacao separa codigo de dado e neutraliza o vetor.

---

## Exercicio 2 - A01:2025 Broken Access Control (IDOR)

**Alvo:** `/api/orders/:id` (e `/api/users/:id`).

### Ataque (defesa OFF)
1. Login como `alice` (que so tem os pedidos 1 e 2).
2. `GET /api/orders/3` - a alice ve o pedido do **bob**. Trocar o id navega pelos recursos
   de outros usuarios (IDOR). Em `/api/users/3` vaza email e cartao de outro usuario.

### Defesa
Ligar `A01_access_control`. O backend passa a **verificar a propriedade**: compara
`order.user_id` com o id do usuario autenticado da sessao; so o dono (ou admin) acessa.

```
curl -X POST http://localhost:3000/api/defenses/A01_access_control -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Comprovacao
- `GET /api/orders/3` como alice retorna **403**.
- `GET /api/orders/1` (proprio da alice) continua **200**: a defesa nao quebra a funcao legitima.
- **Criterio:** a autorizacao deve ser do lado do servidor, amarrando recurso ao dono; o id
  vindo do cliente nunca e confiavel sozinho.

---

## Exercicio 3 - A03:2025 Software Supply Chain Failures

**Alvo:** as dependencias do `package.json` (lodash 4.17.11, minimist 1.2.0, marked 0.3.6).

### Ataque / diagnostico
```
npm install          # ja exibe o aviso de vulnerabilidades
npm audit            # relatorio detalhado: severidade, CWE, caminho da dependencia
```
Identificar as vulnerabilidades (ex.: prototype pollution em lodash/minimist, ReDoS em
marked) e entender o risco de dependencias desatualizadas e transitivas.

### Defesa
- `npm audit fix` (ou atualizar manualmente para versoes corrigidas e fixar no lockfile).
- Discutir pinning de versoes, commit do `package-lock.json`, geracao de SBOM e checagem
  automatica no CI.

### Comprovacao
```
npm audit            # apos o fix, o numero de vulnerabilidades cai (idealmente a zero)
```
- **Criterio:** mostrar o antes/depois do `npm audit` e explicar a politica de atualizacao
  e pinning que impede regressao.

---

## Exercicio 4 - A02:2025 Security Misconfiguration

**Alvo:** headers HTTP e pagina de erro.

### Ataque (defesa OFF)
```
curl -I http://localhost:3000/products
```
- Header `X-Powered-By: Express 4.18 / SangyShop 1.0` revela o stack.
- Ausencia de `Content-Security-Policy`, `X-Content-Type-Options`, etc.
- `GET /debug/boom` devolve **stack trace completo** (vazamento de informacao).

### Defesa
Ligar `A02_misconfiguration`: aplica os security headers (CSP, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy), remove o `X-Powered-By` e troca o erro detalhado por uma
mensagem generica.

```
curl -X POST http://localhost:3000/api/defenses/A02_misconfiguration -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Comprovacao
```
curl -I http://localhost:3000/products   # X-Powered-By sumiu; CSP e nosniff presentes
curl http://localhost:3000/debug/boom    # "Erro interno. Tente novamente mais tarde."
```
- **Criterio:** comparar os headers antes/depois e o erro silenciado.

---

## Exercicio 5 - A09:2025 Security Logging & Alerting Failures

**Alvo:** login sob brute force. (Amarra com a aula 12 - Wazuh/SIEM.)

### Ataque (defesa OFF)
Repetir varias tentativas de login com senha errada para a `alice`:
```
for /l %i in (1,1,6) do curl -s -X POST http://localhost:3000/login -d "username=alice&password=errada%i" -o nul
```
Abrir `/logs`: **nada aparece**. Sem registro, o ataque passa despercebido (tempo de
deteccao infinito).

### Defesa
Ligar `A09_logging`: cada tentativa passa a ser registrada em `logs/auth.log` e, ao
ultrapassar 5 falhas em 60s para o mesmo usuario/IP, dispara `ALERT brute_force_suspeito`.

```
curl -X POST http://localhost:3000/api/defenses/A09_logging -H "Content-Type: application/json" -d "{\"value\":true}"
```

### Comprovacao
Repetir o brute force e abrir `/logs`: aparecem as linhas `FAILURE` e a linha
`ALERT brute_force_suspeito`. O ataque agora e **visivel e detectavel**.
- **Criterio:** sem log nao ha deteccao; com log + alerta, fecha-se o ciclo detectar ->
  responder. Discutir o envio desses logs para um SIEM (Wazuh) como continuacao.

---

## Observacoes

- As senhas estao em texto puro no seed de proposito (facilita a leitura do impacto da SQLi
  e do IDOR). Em producao, discutir hashing com bcrypt/argon2 (relacionado a A07).
- O SSRF, que era categoria propria ate 2021, foi consolidado em A01 na versao 2025.
- As duas categorias novas de 2025 sao A03 (Software Supply Chain Failures) e A10
  (Mishandling of Exceptional Conditions). O lab cobre A03; A10 e discutido na teoria.
