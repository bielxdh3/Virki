# VIRKI — fechamento final dos gates locais de segurança

**Data:** 2026-10-19
**Decisão:** **BLOCKED_WITH_EVIDENCE**

Este fechamento consolida a validação final após a conclusão de LOW-05 e as lacunas que continuam abertas. A execução isolada mais recente `780a48000c` passou nos 17 estágios, com 307/307 testes unitários, 86 testes de integração aprovados e um skip identificado, E2E completo em Next dev (21/21) e E2E focado do Hub em modo de produção (1/1). O TAP completo da integração foi retido. LOW-05 está corrigido para o comportamento de conteúdo obsoleto após logout/histórico, com a lacuna P2 de atribuição documentada abaixo. Quatro outros achados seguem bloqueados; os gates externos, Linux nativo e topologia de produção não foram executados.

## Fonte e limites

- Worktree: `E:\Virki\.worktrees\virki-full-security-remediation-20261019`
- Branch: `cdx/virki-full-security-remediation-20261019`
- HEAD verificado: `a532560a3c2c32f05ed8ff3d415778be11d83581`
- Execução abrangente anterior: `9a74aaef2b`, 2026-10-19 17:42:50–17:48:16 UTC; 17/17 estágios passaram
- Execução abrangente anterior: `044d469937`, 2026-10-19 19:25:34–19:30:36 UTC; 17/17 estágios passaram, mas o TAP da integração não foi retido e suas contagens foram substituídas pela execução abaixo
- Execução abrangente final: `780a48000c`, 2026-10-19 19:43:38–19:48:42 UTC; 17/17 estágios passaram; manifesto e TAP completo retidos
- Teste de papéis PostgreSQL 17: `4f6a1e3de7`; fresh, interrupted-init e populated passaram com Node `v22.23.3`/npm `10.9.9`
- E2E focado LOW-05 com Hub de produção: `210cd37481`; build e 1/1 browser passaram
- Runtime: Node `v22.23.3`, npm `10.9.9`
- Manifesto e evidência TAP final: `.superpowers/sdd/2026-10-19-virki-final-gates/runs/780a48000c/` (inclui `unit-tests.tap.log`, `integration-tests.tap.log`, `browser-e2e-output.log` e `production-operations-tests.tap.log`)

O runner confirmou branch e SHA, terminou com `exitCode=0`, `failedStages=[]` e exit code 0 em todos os 17 estágios. Os testes de PostgreSQL e browser usaram fixtures e runners isolados. `test:database:roles` foi executado separadamente sob Node 22 portátil, conferido pelo SHA-256 da lista oficial do Node.js, e seus recursos próprios foram removidos pelo teste. Nenhum host/SSH de produção, banco real, Cloudflare/Tunnel, GHCR, estado do GitHub ou workflow remoto foi consultado. Nenhuma alteração de produção, release, push, merge, commit, reset, clean ou staging foi feita nesta continuação. A mistura preexistente de alterações staged, unstaged e untracked foi preservada; não foi adicionado staging.

## Resultado dos gates locais

| Estágio do runner | Exit | Resultado |
|---|---:|---|
| `tooling-policy-dependencies` | 0 | Passou |
| `tooling-policy-tests` | 0 | Passou |
| `runtime` | 0 | Passou |
| `secrets-scan` | 0 | Passou |
| `production-revision-tests` | 0 | Passou |
| `backup-inventory-tests` | 0 | Passou |
| `production-operations-tests` | 0 | 100 TAP: 98 passaram, 0 falharam, 2 ignorados |
| `public-site-tests` | 0 | Estágio passou; o runner não reteve a contagem TAP desta execução |
| `unit-tests` | 0 | 307/307 passaram; TAP completo retido |
| `integration-tests` | 0 | 86 passaram, 0 falharam, 1 ignorado; banco descartável migrado e TAP completo retido. O skip é `legitimate bootstrap survives real pre-account authentication, audit and limiter activity in an otherwise virgin DB`: `MISSING_FIXTURE`, pois o fixture virgin dedicado não estava configurado. |
| `browser-e2e` | 0 | Execução completa Next dev: 21/21 passaram, incluindo logout USER/TOTP e fluxo ADMIN de códigos de recuperação. E2E focado com Hub em modo de produção `210cd37481`: 1/1 passou. |
| `lint` | 0 | Passou |
| `typecheck` | 0 | Passou |
| `prisma-validate` | 0 | Passou |
| `build` | 0 | Passou |
| `windows-ca-helper-tests` | 0 | Passou |
| `worktree-diff-check` | 0 | Passou |

Os dois testes de operações ignorados foram `native shell probe emits the sanitized protected environment metadata category` e `Linux first-install shell guard accepts only a pristine Virki target before image or database work`. Ambos exigem Linux nativo e foram ignorados no WSL; isso não valida o host Linux de produção.

`npm run test:database:roles` passou em uma execução separada (`4f6a1e3de7`): fresh, interrupted-init e populated PostgreSQL 17; o cenário populated confirmou least privilege após uma falha determinística de provisionamento e convergência no rerun. O log completo está em `.superpowers/sdd/2026-10-19-virki-final-gates/role-tests/4f6a1e3de7/database-role-isolation.log`.

As invocações reproduzíveis relevantes, sob a configuração de `package.json`, são `node --test scripts/production-ops.test.mjs` (operações), `npm run test:unit`, `npm run test:public-site`, `npm run test:integration:local`, `npm run test:e2e`, `npm run test:database:roles`, `npm run test:production-revision`, `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate` e `npm run build`. O manifesto final registra exatamente os 17 rótulos de estágio, duração e exit code; não serializa o argv completo do wrapper para cada estágio. Não reconstruí argumentos do wrapper que não ficaram retidos.

O teste de bootstrap ignorado requer banco recém-migrado separado e `VIRKI_BOOTSTRAP_TEST_DATABASE_CONFIRM=virgin`. O script padrão de integração usa o nome fixo `virki-integration-postgres-local`, e seu comando `stop` remove esse container com `--volumes`; por isso, não deve ser invocado diretamente no workspace compartilhado sem confirmar posse ou adaptar o runner para um nome único. A validação final usou apenas o runner isolado, que criou e removeu os recursos descartáveis da própria execução.

Além da execução abrangente, a suíte focada de recuperação PostgreSQL 17 passou com barreiras determinísticas para concorrência por conta e quota compartilhada por origem. Os testes de isolamento de papéis PostgreSQL 17 passaram com injeção de falha determinística no limite de propriedade do schema, estado parcial menos privilegiado e convergência ao repetir a inicialização. Eles não injetaram encerramento arbitrário do processo em cada instrução nem falha do init-hook inicial do Docker.

### Encerramento das 23 falhas antigas de operações

A execução histórica `1790baebb5` tem TAP preservado com **120 testes agregados: 97 passaram, 23 falharam, 0 ignorados; estágio exit 1**. O cruzamento das 23 falhas é:

| Contagem | Teste/falha | Categoria | Causa e correção |
|---:|---|---|---|
| 1 | TAP #50 `standalone preflight binds host contact to the exact accepted source gate` | `TEST_BUG` | A fixture exigia que `repositoryRoot` contivesse o nome `virki`; o runner isolado usa a raiz `/workspace`. A fixture agora exige caminho absoluto e `package.json` na raiz isolada. |
| 1 | TAP #56 `native shell probe emits the sanitized protected environment metadata category` | `UNSUPPORTED_ENVIRONMENT` | O shell parou corretamente no guard WSL antes de chegar ao cenário de permissões de `.env.oidc-data`. O teste agora é ignorado quando o kernel é WSL. |
| 1 + 20 subtestes | TAP #73 `Linux first-install shell guard accepts only a pristine Virki target before image or database work` e seus 20 subtestes abaixo | `UNSUPPORTED_ENVIRONMENT` | Cada caso parou no guard WSL, como exige a proteção de produção. O teste pai agora é ignorado em WSL; não se afrouxou o guard. |

Os 20 subtestes foram: `recovery refuses a root without retained install source markers before Docker access`; `recovery refuses unverified backup files before inspecting or starting PostgreSQL`; `recovery accepts one current verified backup and rejects every other backup entry`; `recovery accepts the pinned PostgreSQL image reference and safely repeats a prepared checkpoint`; `recovery refuses project identity collisions before image or database work`; `recovery refuses consumer identity collisions before image or database work`; `recovery refuses volume-label identity collisions before image or database work`; `recovery refuses network-label identity collisions before image or database work`; `recovery refuses network-member identity collisions before image or database work`; `recovery refuses a checkpoint bound to a different accepted SHA before Docker access`; `recovery refuses a symlinked production root before Docker access`; `recovery refuses an unexpected release symlink before Docker access`; `pristine root passes all collision checks before missing-image failure`; `active source link blocks without Docker calls`; `any pre-existing release directory blocks as partial state`; `partial source metadata blocks without Docker calls`; `retained backup blocks before loading images`; `container collision blocks before loading images`; `volume collision blocks before loading images`; `network collision blocks before loading images`.

O ledger SDD anterior registra `96 passaram, 23 falharam`, mas não aponta run ID nem contém log que permita reconciliar esse total. Para o run `1790baebb5`, o log bruto prova 97/23; a discrepância legada 96-versus-97 permanece **não resolvida**, sem combinação ou suposição. Na execução abrangente `0f30a1566f`, `node --test scripts/production-ops.test.mjs` dentro do runner isolado terminou exit 0, com 100 TAP: 98 passaram, 0 falharam e 2 testes nativos explicitamente ignorados. As execuções `044d469937` e `780a48000c` repetiram o mesmo resultado. A execução nativa Linux continua sem evidência.

Também há execuções intermediárias com falha documentada: `492cbedc38` terminou com somente `browser-e2e=1` (duas falhas de caso; logs individuais não foram retidos no diretório da execução). O diagnóstico de navegação identificou que o teste esperava outra URL após `window.location.replace`; a correção espera o fragmento anterior e mantém asserções de segredo ausente. O diagnóstico de cache identificou que Next em modo de desenvolvimento substitui o header por `no-cache, must-revalidate`; a E2E agora registra essa limitação e um teste de Proxy verifica a política de produção. `e30cea92fd` passou 2/2 casos direcionados e o run final passou 21/21 E2E. A tentativa direcionada `9773af0c7f` também revelou que o recorder de page lifecycle estava no teste de convite em vez do teste TOTP; foi movido e a execução final passou.

## Estado dos achados

A matriz contém **50 achados distintos**: `33 FIXED_AND_REVIEWED`, `13 JUSTIFIED_NO_CHANGE` e `4 BLOCKED_UNVERIFIED`. `BLIND-01` é alias de `MED-03` e não aumenta a contagem.

### Disposição dos nove achados em foco

| ID | Disposição e evidência local | Prova ainda necessária |
|---|---|---|
| `HIGH-15` | `FIXED_AND_REVIEWED`. `npm run test:database:roles` passou no PostgreSQL 17 descartável. `scripts/database-role-isolation.test.mjs` injeta falha no limite de propriedade de `virki_security`, verifica estado parcial de privilégio mínimo e convergência no retry. | Não foram injetados SIGKILL em cada instrução nem falha do init-hook inicial do Docker. |
| `HIGH-16` | `BLOCKED_UNVERIFIED`. Testes PostgreSQL 17 agora rejeitam referência de sessão ausente, de outro usuário, revogada ou expirada; duplicatas permanecem limitadas por escopo, e limpeza deixa somente elevações obsoletas inertes. Full run `780a48000c` passou; o TAP de integração retido registra os casos. Nenhum dado real foi consultado. | Contagens agregadas de órfãos/divergências/duplicatas e política revisada de exclusão/retenção antes de FK ou unicidade. Ver `docs/legacy-data-closure-plan.md`. |
| `MED-01` | `FIXED_AND_REVIEWED`. `packages/auth/src/recovery.integration.test.ts`, caso `concurrent recovery completion changes the credential once and records one success`; barreiras PostgreSQL 17 provam uma mudança de credencial e um efeito de auditoria/outbox. A execução abrangente final `780a48000c` concluiu com exit 0 (86 pass/1 skip na integração). | Nenhuma lacuna de concorrência local conhecida; não é evidência de dados de produção. |
| `MED-02` | `FIXED_AND_REVIEWED`. Mesmo arquivo, casos `recovery source quota serializes competing accounts and separates sources` e `recovery source quota denies silently and resets at the exact window boundary`; PostgreSQL 17 prova serialização entre contas, separação de origens, negação silenciosa e reset no limite. `npm run test:integration:local`: exit 0. | Nenhuma lacuna local conhecida; não é prova de carga de produção. |
| `MED-19` | `FIXED_AND_REVIEWED`. `npm run test:database:roles`, PostgreSQL 17 descartável: rotina `SECURITY DEFINER` não revisada é rejeitada, novos grants de rotinas são verificados e `search_path=public, pg_temp` com tabelas sombreadas confirma leitura da policy protegida e escrita na tabela qualificada. | O caminho de falha do init-hook inicial do Docker não foi injetado. |
| `MED-20` | `BLOCKED_UNVERIFIED`. A UI exibe `accountStatus`; somente pares ACTIVE/INACTIVE consistentes permitem toggle, e a ação de servidor exige o par atual exato. Testes unitários/UI passaram em `780a48000c` (307/307). A validação de inventário agora rejeita privilégios além do contrato de leitura. Nenhuma contagem real foi consultada. | Contagens agregadas de normalização/collision e de pares de estado, resolução revisada de contas afetadas e regra canônica antes de backfill ou constraints. Ver `docs/legacy-data-closure-plan.md`. |
| `MED-22` | `BLOCKED_UNVERIFIED`. `PROCESSING` com lease NULL agora é recuperável pelo CAS de claim; cobertura unitária e integração PostgreSQL de finalizer obsoleto passaram em `780a48000c` (307/307 unit; 86 integração, 1 skip). O TAP retido também cobre as consultas de privilégio do inventário em PostgreSQL 17 descartável e rejeita o papel mais amplo da aplicação. Nenhuma linha real foi consultada. | Contagens agregadas de lease/timestamps e atribuição grantor/reviewer, política de estados/retention e compatibilidade de migration em restore descartável. Ver `docs/legacy-data-closure-plan.md`. |
| `LOW-05` | `FIXED_AND_REVIEWED`. O E2E focado de produção `210cd37481` passou: rota protegida, política `private, no-store, max-age=0, must-revalidate`, login, confirmação por e-mail, TOTP, códigos de recuperação, logout 303 `no-store`, cookie limpo, sessão revogada e Back até login sem conteúdo autenticado. O run completo mais recente `780a48000c` passou 21/21 browser E2E, 307/307 unit, 86 integração com 1 skip, e todos os 17 estágios. | O browser observou `pagehide.persisted=false` e `pageshow.persisted=false`; nenhuma restauração BFCache foi observada. E2E não prova diretamente que o detector de `PerformanceNavigationTiming.type` disparou na página USER protegida; os casos unitários cobrem essa lógica. `no-store` não é tratado como bloqueio de BFCache. |
| `LOW-08` | `BLOCKED_UNVERIFIED`. `docs/index-query-plan-evidence.md` separa os dois chamadores de elevação e explicita os limites dos planos sintéticos de elevação, auditoria e outbox. A pré-verificação do inventário faz cumprir o limite de privilégios; casos adversariais unitários e integração PostgreSQL 17 descartável passaram em `780a48000c`. | Planos representativos, skew, frequência de consultas, volume de escrita e custo de índices fornecidos/revisados pelo operador. Ver `docs/legacy-data-closure-plan.md`. |

### Consultas count-only para futura revisão

As consultas SQL abaixo são esboços históricos, não foram executados e **não devem ser usados para fechar MED-20**: `lower(btrim(email))` não reproduz integralmente a normalização JavaScript `trim().toLowerCase()`. Para coleta futura, use o comando protegido, agregado e fail-closed documentado em [`legacy-data-closure-plan.md`](legacy-data-closure-plan.md), que valida host, database, IP conectado, versão PostgreSQL, schema/migrations, transação read-only e papel dedicado antes de devolver apenas contagens. Nenhuma conexão real ou snapshot foi usado nesta tarefa.

```sql
BEGIN TRANSACTION READ ONLY;

-- HIGH-16: órfãos e sessões pertencentes a outra conta
SELECT
  count(*) FILTER (WHERE e."sessionId" IS NULL) AS null_session_id,
  count(*) FILTER (WHERE e."sessionId" IS NOT NULL AND s.id IS NULL) AS missing_session,
  count(*) FILTER (WHERE s.id IS NOT NULL AND s."userId" <> e."userId") AS owner_mismatch
FROM public."SecurityElevation" AS e
LEFT JOIN public."Session" AS s ON s.id = e."sessionId";
SELECT count(*) AS duplicate_effective_elevation_groups
FROM (
  SELECT e."userId", e."sessionId", e.scope
  FROM public."SecurityElevation" AS e
  JOIN public."Session" AS s ON s.id = e."sessionId"
  JOIN public."User" AS u ON u.id = e."userId"
  WHERE e.status = 'ACTIVE'
    AND (e."manualUntilRevoked" OR e."expiresAt" > now())
    AND s."revokedAt" IS NULL AND s."expiresAt" > now()
    AND u.role = 'ADMIN' AND u."isActive" AND u."accountStatus" = 'ACTIVE'
  GROUP BY e."userId", e."sessionId", e.scope
  HAVING count(*) > 1
) AS duplicates;

-- MED-20: nulls, divergência de normalização, grupos duplicados e pares de estado
SELECT
  count(*) FILTER (WHERE "emailNormalized" IS NULL) AS null_normalized,
  count(*) FILTER (WHERE "emailNormalized" IS NOT NULL AND "emailNormalized" <> lower(btrim(email))) AS normalization_mismatch
FROM public."User";
SELECT count(*) AS duplicate_normalized_email_groups
FROM (
  SELECT "emailNormalized"
  FROM public."User"
  WHERE "emailNormalized" IS NOT NULL
  GROUP BY "emailNormalized"
  HAVING count(*) > 1
) AS duplicates;
SELECT "isActive", "accountStatus"::text, count(*)
FROM public."User"
GROUP BY 1, 2
ORDER BY 1, 2;

-- MED-22: estados/leases e timestamps do outbox
SELECT
  status::text,
  count(*) FILTER (WHERE status::text = 'PROCESSING' AND "processingLeaseExpiresAt" IS NULL) AS processing_without_lease,
  count(*) FILTER (WHERE status::text = 'PROCESSING' AND "processingLeaseExpiresAt" <= now()) AS expired_processing_lease,
  count(*) FILTER (WHERE status::text <> 'PROCESSING' AND "processingLeaseExpiresAt" IS NOT NULL) AS stray_lease,
  count(*) FILTER (WHERE status::text = 'SENT' AND "sentAt" IS NULL) AS sent_without_timestamp,
  count(*) FILTER (WHERE status::text = 'TERMINAL_FAILURE' AND "terminalFailedAt" IS NULL) AS terminal_without_timestamp
FROM public."EmailOutboxMessage"
GROUP BY status;
SELECT count(*) AS orphaned_grantors
FROM public."UserProjectGrant" AS g
WHERE g."grantedByUserId" IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public."User" AS u WHERE u.id = g."grantedByUserId");
SELECT count(*) AS self_reviewed_recovery_requests
FROM public."AccountRecoveryRequest" AS r
WHERE r."reviewedByUserId" = r."userId";
ROLLBACK;
```

A comparação `lower(btrim(email))` é apenas um sinal diagnóstico; ela não define nem prova a regra Unicode de normalização que a operação deverá adotar.

| ID | Bloqueio que falta para concluir |
|---|---|
| `HIGH-16` | Inventário de dados com formato de produção para órfãos, unicidade e ciclo de vida de `SecurityElevation.sessionId`; rever o resultado antes de propor DDL. |
| `MED-20` | Inventário de nulos/brancos/divergências/colisões usando o helper de aplicação, pares de estado e resolução revisada por conta antes de backfill ou restrições. |
| `MED-22` | Inventário legado do estado/lease do outbox e grantor/reviewer, política de atribuição/retention e compatibilidade de migração em restore descartável. |
| `LOW-08` | Planos representativos, distribuição/skew, frequência de workload, volume de escrita e trade-off de índice fornecidos pelo operador. A evidência sintética em `docs/index-query-plan-evidence.md` não substitui isso. |

No E2E focado de produção `210cd37481`, a rota protegida respondeu com política `private, no-store, max-age=0, must-revalidate`; o fluxo USER percorreu login, confirmação por e-mail, TOTP, códigos de recuperação e logout 303 com `no-store`, cookie limpo e sessão revogada. Após Back, o browser exibiu login sem conteúdo autenticado ou controles de sessão. O run completo mais recente `780a48000c` também passou 21/21 E2E. Em ambos os runs, `pagehide.persisted=false` e `pageshow.persisted=false`; nenhuma restauração BFCache foi observada, portanto o resultado não prova que `no-store` bloqueie BFCache. O E2E não registra diretamente que o detector `PerformanceNavigationTiming.type` disparou no documento protegido USER; a lógica do detector é coberta por testes unitários, e o E2E confirma o estado final seguro após logout/Back. Essa lacuna de atribuição é P2 de evidência, sem defeito runtime reproduzido.

## Revisões independentes e proveniência

- `final_runtime_review`: não encontrou problema acionável no limite de limpeza/retenção de auditoria.
- `final_security_review`: levantou uma questão sobre reconciliação da retenção. A correção migra essa reconciliação para o papel migrador; o follow-up direcionado não encontrou risco residual acionável.
- `final_gate_review`: identificou a divergência da detecção de WSL; a correção alinhou a fonte do detector com o guard de produção. A revisão e o follow-up ocorreram antes do E2E focado final e não executaram testes; portanto, a classificação antiga de LOW-05 como bloqueado foi substituída pela evidência posterior descrita acima.
- `low05_lifecycle_review`: revisão somente de leitura do patch final; não encontrou defeito de conteúdo obsoleto, regressão ADMIN nem loop de reload. Registrou a lacuna P2: o browser E2E não afirma diretamente que o detector de histórico disparou no documento USER, e nenhuma restauração BFCache foi observada. Não executou testes.
- `review_final_four_code`: revisão somente de leitura das correções NEW-01 (cobertura do limite de privilégios do inventário) e NEW-02 (retenção do TAP de integração). Não encontrou achado acionável P1/P2; confirmou que o teste de integração usa as mesmas consultas de privilégio do inventário e que runner/manifesto preservam o TAP e falhas nomeadas. Não executou testes, acessou banco ou consultou sistemas externos. Modelo/esforço solicitados: GPT-6 Luna/High; metadados efetivos: `USER_CONFIGURED_NOT_API_ATTESTED`.
- `diagnose_admin_recovery_history` e `diagnose_security_cache_header`: localizaram, respectivamente, a expectativa incorreta de histórico do teste de recuperação e a sobrescrita do cache header pelo servidor Next de desenvolvimento. Foram diagnósticos somente de leitura; não alteraram código nem executaram testes.
- Evidência RED/GREEN: o run de operações `1790baebb5` reproduziu a fixture de caminho inválida e o mismatch WSL; depois da correção, o run abrangente `0f30a1566f` terminou 98/0/2 skip. O run E2E `492cbedc38` falhou em dois casos; os diagnósticos motivaram os ajustes de histórico/cache, o direcionado `e30cea92fd` passou 2/2 e o run abrangente `0f30a1566f` passou 21/21. Na continuação, o E2E focado de produção `210cd37481` passou 1/1; a execução intermediária `9a74aaef2b` e a anterior `044d469937` passaram nos 17 estágios, embora a última não tenha retido o TAP de integração. A execução final `780a48000c` reteve todos os logs TAP e passou 307/307 unit, 86 integration com 1 skip, 21/21 E2E e todos os 17 estágios. O teste de papéis separado `4f6a1e3de7` também passou fresh/interrupted/populated. A política `no-store` não foi relaxada para fabricar BFCache; nenhuma restauração foi observada.
- Modelo/esforço efetivos dos workers não são expostos pela aplicação. Onde a configuração de review foi registrada como GPT-6 Luna/High, isso representa a solicitação, não uma atestação independente da execução. A identidade técnica/versão de workers fica `USER_CONFIGURED_NOT_API_ATTESTED`.
- O objetivo do usuário especifica o agente principal como GPT-6 Luna/Extra High; isso é a configuração solicitada. Metadados efetivos do modelo/esforço do agente principal também não ficam expostos nesta execução, então não faço uma atestação de runtime.
- Ledger de delegação: o SDD anterior registra 9 tarefas solicitadas como GPT-6 Luna/High. Nesta continuação, `final_gate_review` e `post_review_gate_correction` também têm solicitação High registrada; as configurações solicitadas para `diagnose_admin_recovery_history`, `diagnose_security_cache_header`, `ingress_static_audit`, `legacy_fixture_audit`, `recovery_concurrency` e `role_fault_injection` não estão disponíveis neste registro. Contagem inferior verificável: pelo menos 11 de 17 tarefas (64,7%) pediram High; nenhuma solicitação Extra High está registrada, então não há justificativa Extra High a alegar. O limite de 40% Extra High não pode ser atestado para as seis tarefas sem configuração preservada.
- A distribuição dos 16 IDs de severidade HIGH é: 11 corrigidos e revisados (68,75%), 4 justificados sem alteração (25%) e 1 bloqueado (6,25%; `HIGH-16`). A rerevisão direcionada de NEW-01 e NEW-02 não encontrou P1/P2 restantes nessas correções; isso não fecha o achado `HIGH-16`, que segue bloqueado.

## Gates externos e disposição

Permanecem sem execução ou confirmação: CI remoto no SHA exato, CodeQL e armazenamento/reavaliação do artefato SARIF, estado de registry, execução em Linux nativo, topologia de produção e aceitação humana. Os três bloqueios de inventário exigem dados revisados pelo operador; esse relatório não contém consulta ao banco de produção.

### Ações mínimas futuras, após autorização específica

- `REQUIRES_REAL_DATA`: pedir ao operador contagens redigidas obtidas das consultas count-only acima em snapshot aprovado; revisar a regra canônica e a compatibilidade antes de qualquer migração.
- `REQUIRES_REMOTE_CI`: somente após autorização separada para publicar um candidato imutável, obter CI/CodeQL no SHA exato e armazenar, recuperar e reavaliar SARIF desse SHA.
- `REQUIRES_NATIVE_PRODUCTION`: executar os dois testes atualmente ignorados em Linux nativo suportado. Qualquer preflight, backup/restore ou validação no host de produção exige aprovação própria e os gates do guia operacional.
- `REQUIRES_EXTERNAL_CONFIGURATION`: o operador confirma registry/GHCR, Cloudflare Access/Tunnel, topologia e aprovação/release; obter aceitação humana dos fluxos afetados. Nenhuma dessas ações foi iniciada.

**Disposição final: `BLOCKED_WITH_EVIDENCE`.** A execução final `780a48000c` passou nos 17 estágios, incluindo 307/307 unit, 86 integration com 1 skip e TAP retido, e 21/21 browser E2E; o teste de papéis `4f6a1e3de7` passou nos três fixtures PostgreSQL 17. O E2E focado de produção `210cd37481` passou 1/1. As correções de acompanhamento NEW-01 e NEW-02 passaram pela revisão direcionada sem achados P1/P2. LOW-05 está corrigido, com a lacuna P2 de atribuição do detector descrita acima. Permanecem quatro achados bloqueados e gates externos sem evidência. O trabalho não está liberado para produção ou release. Nenhuma ação externa ou de produção foi tomada.

## Continuação LOW-05: Hub em modo de produção

Foi acrescentado um caminho de E2E local que compila o Hub com `NODE_ENV=production`, executa `next start` atrás do proxy HTTPS descartável e mantém o guard de banco de testes. O runner validou Node `v22.23.3`, npm `10.9.9`, Playwright `1.63.0`, revisão Chromium `1243` e `Google Chrome for Testing 153.0.8010.12`, usando a imagem local `mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27`. As nove migrações aplicaram e o build do Hub terminou com exit 0.

| Run | Resultado observado |
|---|---|
| `ddc29d7f99` | Abortou no preflight antes de qualquer stage: Windows PowerShell não resolveu `Get-FileHash`; o manifesto registra exit 1, sem recursos criados. O runner passou a usar SHA-256 via .NET e os runs seguintes completaram os stages. |
| `5c830b8f89` | Build e migrações passaram; a etapa de navegador selecionou quatro testes em vez do teste TOTP solicitado, por perda dos limites do argumento com espaços, e terminou com exit 1. A invocação foi corrigida para um argumento regex sem espaços. |
| `630c408035` | Filtro validado como exatamente um teste. Build exit 0; navegador exit 1 na checagem inicial, pois `/account/security` permaneceu na URL em vez de redirecionar para login. O teste não chegou à leitura de Cache-Control nem às verificações de histórico/BFCache. |
| `190719c666` | Repetiu o único teste após limpar cookies e confirmar ausência do cookie de sessão no contexto. Build exit 0; navegador exit 1 pela mesma checagem de redirecionamento. O log completo da saída Playwright e o manifesto estão em `.superpowers/sdd/2026-10-19-virki-final-gates/runs/190719c666/`. |
| `210cd37481` | Execução corrigida com Hub de produção: build e 1/1 browser passaram; observou status/header/request ID, política `no-store`, fluxo TOTP/recuperação, logout, cookie limpo, sessão revogada e Back até login sem conteúdo autenticado. `pagehide.persisted=false`, `pageshow.persisted=false`; não houve restauração BFCache. |
| `9a74aaef2b` | Execução abrangente anterior: todos os 17 estágios passaram, incluindo 21/21 browser E2E e os fluxos USER/ADMIN documentados. |
| `044d469937` | Execução abrangente anterior: 17/17 estágios passaram; seus logs informaram unit e browser, mas o TAP de integração não foi retido e a contagem reportada anteriormente foi substituída pela execução final. |
| `780a48000c` | Execução abrangente final: 17/17 estágios passaram; 307/307 unit e TAP retido, 86 integration + 1 skip com TAP retido, 21/21 browser E2E, 98/100 production-operations TAP (2 skips WSL), public-site stage exit 0 (contagem TAP não retida), lint, typecheck, Prisma validate, build, secrets scan e diff check. |

Os dois primeiros runs focados não capturaram status HTTP nem título/conteúdo da página e não sustentavam conclusão sobre autenticação, cache ou BFCache. A correção adicionou captura segura de status, destino categorizado, cache e presença de request ID; `210cd37481` executou essa captura em produção e passou. As asserções de histórico/reload verificam que os valores sensíveis permanecem ausentes; a execução abrangente final também passou. O limite restante é que o browser E2E não afirma diretamente que o detector `PerformanceNavigationTiming.type` disparou no documento protegido USER. Os testes unitários cobrem essa lógica; a revisão independente não encontrou defeito runtime ou loop. `no-store` não é apresentado como bloqueio de BFCache e nenhuma restauração foi observada.

O runner removeu os recursos descartáveis próprios em cada tentativa. Nenhum serviço, banco, host, segredo, Cloudflare, GitHub ou registry de produção foi acessado.
