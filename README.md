# SangyShop

Aplicacao web **propositalmente vulneravel** para o ensino do **OWASP Top 10:2025** na
**visao de defesa (Blue Team)**. Diferente de um alvo so para atacar, a SangyShop traz um
**Painel de Defesas**: cada vulnerabilidade tem um *toggle*. O fluxo pedagogico e sempre o
mesmo: **ataca com a defesa desligada, liga a defesa e reproduz o mesmo ataque para ver o
bloqueio**, comparando o comportamento e inspecionando o codigo dos dois lados.

> **Aviso.** Esta aplicacao contem vulnerabilidades reais de proposito. Use **somente em
> ambiente isolado** (seu notebook / VM / WSL), **nunca** exposta na internet. E material
> didatico do curso de Blue Team da Strong Security Brasil.

## Vulnerabilidades cobertas (5 das 10 categorias)

| Categoria OWASP 2025 | Onde | Defesa (toggle) |
|---|---|---|
| **A01** Broken Access Control (IDOR) | `/api/orders/:id`, `/api/users/:id` | verificacao de propriedade do recurso |
| **A02** Security Misconfiguration | headers HTTP, pagina de erro | security headers + erro generico |
| **A03** Software Supply Chain Failures | `package.json` | `npm audit` + pinning de versoes |
| **A05** Injection (SQL) | login e busca de produtos | consulta parametrizada (prepared statement) |
| **A09** Security Logging & Alerting Failures | login / brute force | log de autenticacao + alerta |

## Como subir

### Opcao 1 - Docker (recomendado, mais leve)

```
git clone https://github.com/nilsonsangy/sangyshop
cd sangyshop
docker compose up -d --build
```

Acesse **http://localhost:3000**.

### Opcao 2 - Node local

```
git clone https://github.com/nilsonsangy/sangyshop
cd sangyshop
npm install        # repare no aviso de vulnerabilidades: e o exercicio A03
npm start
```

## Mapa da aplicacao

- `/` e `/products` - catalogo (e a busca vulneravel a SQLi).
- `/login` - autenticacao (SQLi + brute force). Contas: `alice/alice123`, `bob/bob123`, `admin/SangyAdmin!2025`.
- `/api/orders/:id`, `/api/users/:id` - API com IDOR.
- `/defenses` - **Painel de Defesas**: liga/desliga cada mitigacao.
- `/logs` - eventos de autenticacao (so aparecem com a defesa A09 ligada).
- `/debug/boom` - rota que gera erro, para demonstrar o A02.

Tambem da para alternar as defesas por linha de comando:

```
curl -X POST http://localhost:3000/api/defenses/A05_injection -H "Content-Type: application/json" -d "{\"value\":true}"
```

## Para o professor

O passo a passo completo de ataque e defesa de cada vulnerabilidade esta em
[`GABARITO.md`](GABARITO.md).

## Licenca

MIT. Autor: Prof. Nilson Sangy. Material do curso de Blue Team.
