# PR #56 — auditoria estática Semgrep OSS (22/10/2026)

Base publicada: `e5053835c0ca74807419d2304173cf82dedc269a`.
Executor: Semgrep OSS `1.182.1` no Ubuntu WSL, em ambiente virtual privado.
O código analisado permaneceu na worktree isolada `E:/Virki/.worktrees/virki-semgrep-offline-worker13-20261022`.
Semgrep foi executado com métricas desabilitadas; o download do pacote comunitário trouxe apenas regras e não exigiu carregar fontes do projeto. Esta auditoria **não** substitui CodeQL, CI hospedado, análise interprocedural completa ou prova de implantação.

## Execução e escopo

| Execução | Regras | Arquivos | Achados | Erros |
| --- | ---: | ---: | ---: | ---: |
| `p/security-audit` (Semgrep Community) | 225 carregadas; 33 executadas | 433 | 9 | 0 |
| Reprodução offline do snapshot local das mesmas regras | 225 carregadas; 33 executadas | 433 | 9 | 0 |
| `scripts/security/semgrep-pr56-offline.yml` (JS/TS, C, Bash, PowerShell) | 6 executadas | 326 | 0 | 0 |
| Canários inseguros locais em 4 arquivos ignorados | 6 executadas | 4 | 6/6 detectados | 0 |

Os resultados incluem arquivos TS/TSX, JS/MJS, C, Dockerfile, Bash e PowerShell. As regras PowerShell usam o mecanismo `generic` do Semgrep para analisar os dois arquivos `.ps1`, sem afirmar cobertura sintática completa do PowerShell. O snapshot de regras comunitárias contém 492.566 bytes e permite repetir o mesmo conjunto sem dependência de conteúdo mutável do Registry.

### Classificação individual dos nove findings comunitários

| Local | Regra | Decisão e evidência |
| --- | --- | --- |
| `e2e/jwks-service.spec.ts:20` | `react-insecure-request` | Falso positivo no contexto: POST de teste para `http://127.0.0.1:3010/__test__/keys`, sem token; verifica 403. |
| `e2e/jwks-service.spec.ts:28` | `react-insecure-request` | Falso positivo no contexto: mesma origem loopback de teste, token deliberadamente incorreto; verifica 403. |
| `e2e/jwks-service.spec.ts:38` | `react-insecure-request` | Falso positivo no contexto: endpoint local de registro de chave pública de teste, token restrito ao ensaio; verifica 204. |
| `e2e/jwks-service.spec.ts:53` | `react-insecure-request` | Falso positivo no contexto: caso negativo local que envia chave privada de teste e exige 400. |
| `e2e/jwks-service.spec.ts:63` | `react-insecure-request` | Falso positivo no contexto: GET do JWKS de teste no mesmo endereço loopback; verifica resposta 200 e ausência de componente privado. |
| `infra/offline/native-peer/native-peer-probe.c:190` | `insecure-use-string-copy-fn` | Falso positivo por tamanho: `strlen(requested) >= sizeof(addr.sun_path)` bloqueia antes do `strcpy` (linhas 185–190). |
| `infra/offline/native-supervisor/fd-lifecycle-fixture.c:380` | `insecure-use-string-copy-fn` | Falso positivo por tamanho: `endpoint[108]` só é inicializado após `snprintf(..., sizeof(endpoint), ...) < sizeof(endpoint)`, linhas 455–456; `main` exige `fixture_directory()` antes do fork, linhas 489–505. |
| `infra/offline/native-supervisor/fd-lifecycle-fixture.c:445` | `insecure-use-string-copy-fn` | Falso positivo por tamanho: `ROOT "XXXXXXXX"` é constante compilada de 31 bytes aproximadamente, compatível com `rootdir[80]` (linhas 42 e 56). |
| `infra/offline/native-supervisor/fd-lifecycle-fixture.c:531` | `insecure-use-string-copy-fn` | Falso positivo por tamanho: `endpoint` está limitado por `snprintf` em 455–456 antes do uso no processo pai. |

**P1/P2 confirmados nesses nove findings: zero.** Isso não é garantia de ausência de vulnerabilidades fora das regras, arquivos e modelos de execução usados.

### Correção do erro de parsing

Na primeira execução, havia um aviso `PartialParsing` em `packages/auth/src/csrf.ts:112`; o arquivo continha **três bytes NUL literais** nas strings de separação de domínio criptográfico. O parser Semgrep perdia cobertura nesse arquivo. Os três bytes foram representados no arquivo-fonte por escapes JavaScript `\0`, que preservam exatamente os bytes das strings em tempo de execução e as assinaturas HMAC existentes. Nova execução: **zero erros de parsing**; testes de CSRF: **5/5 PASS**.

### Evidências locais ignoradas

Diretório ignorado pelo Git: `.virki-mission-tmp/semgrep-oss-worker13/`. O relatório bruto não foi commitado.

| Arquivo | SHA-256 |
| --- | --- |
| `community-security-audit.yml` | `83D7CDE9157B3C79CC5CFAEA26E7BD2BA9C740F2BA07635AD475B2585556C32D` |
| `security-audit-final.json` | `72997B4927F04AD7A13753BFF1A24F06E1D8AA9C4FFEEB3A8B1757117536A39E` |
| `community-snapshot-replay.json` | `70B87CFA5C19EE533971DB3624B2729BB5CA61CAB19EB772B64911E13DB9829B` |
| `targeted-final.json` | `D994C5EDD79281B3CF65E687FAD70D381CE581FFADE6F7C2754227628031C6E2` |
| `canary-scan-final.json` | `ED00ED70A73E49C9A5C87FC0950CBAB54E32E5AAAE0F141259533105F6E0D68B` |
| `scripts/security/semgrep-pr56-offline.yml` (rastreado) | `27BDBDAE1E140DEECAEBA3D0B707548162F951BD6BC30D3147B5EAC08A414C47` |

Para reproduzir na raiz da worktree, com `semgrep` OSS no `PATH`, executar:

```bash
semgrep scan --config .virki-mission-tmp/semgrep-oss-worker13/community-security-audit.yml --metrics off --disable-version-check --json --output .virki-mission-tmp/semgrep-oss-worker13/community-snapshot-replay.json --exclude .virki-mission-tmp --exclude node_modules --max-target-bytes 500000 .
semgrep scan --config scripts/security/semgrep-pr56-offline.yml --metrics off --disable-version-check --json --output .virki-mission-tmp/semgrep-oss-worker13/targeted-final.json --exclude .virki-mission-tmp --exclude node_modules --max-target-bytes 500000 .
```

Os hashes do JSON comprovam os artefatos desta execução específica; campos de tempo, caminhos ou atualizações de ferramentas podem gerar hashes diferentes numa nova execução equivalente.

## Evidência complementar

- `node scripts/secret-scan.mjs`: PASS.
- `tsx --test packages/auth/src/csrf.test.ts`: 5 PASS / 0 FAIL.
- `npm run lint`: PASS.
- `npm run prisma:validate`: PASS.
- `git diff --check`: PASS.
- `npm ci --prefer-offline`: PASS em instalação isolada; 250 pacotes adicionados, 256 auditados, 0 vulnerabilidades reportadas pelo npm. O host fornecia Node 24.14.1/npm 11.11.0, fora da faixa declarada do projeto (Node 22/npm 10), portanto os resultados locais devem ser interpretados com essa ressalva.
- `npm run typecheck`: **PASS em todos os cinco workspaces após a instalação isolada**. Um primeiro ensaio com junction para `E:/Virki/node_modules` falhara devido a tipos Prisma e `oidc-provider` de outro checkout; a instalação própria gerou o Prisma Client correto e eliminou os erros. A junction foi removida antes da instalação local.
- `npm run build`: **PASS**, incluindo build otimizado do site público e do hub, após a instalação isolada.

O estado do CodeQL e CI hospedado permanece **não verificado / NO-GO para alegar publicação segura com base apenas nesta auditoria**. Não houve push, merge, deploy ou acesso a Docker de produção.
