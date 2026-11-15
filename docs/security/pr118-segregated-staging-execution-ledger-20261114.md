# PR #118 — segregated staging execution ledger (operator handoff)

> **NOT EXECUTED / EXTERNAL RELEASE NO-GO.** This is an unfilled operational ledger, not an authorization, staging observation, security approval, or proof of email delivery. Do not execute a production mutation from this document.

**Operator source-of-truth rule:** the commit IDs, CI results and proposed
changes in the provenance inventory below are **dated historical snapshots**,
not the currently approved staging image or authority to execute. Before any
operational gate, the operator must independently obtain the **actual PR #118
HEAD** from GitHub and compare it with the owner-signed exact source SHA and
immutable OCI digest. Each new commit, including a documentation correction,
requires fresh exact-SHA CI/CodeQL and independent review; a green CI cannot
turn any `NOT RUN` physical gate into `PASS`. The conditional architectural
consent recorded on 2026-11-10 is not permission to start staging or change the
production Cloudflare Access perimeter; the P1 trust-boundary thread stays open.

## Provenance and scope of the handoff

- Previously independently **CI-verified** PR source: `678d81af31fb6aa5f1ab4effcdee823a030c38ce` on `feat/virki-native-admin-perimeter-20261110`. Earlier runtime baseline `2cb74f576039cac8d83fd2d1cc52e47f36184ad1` includes the original `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c`. Descendant hardening includes operator-only `scripts/staging-pgpass-bootstrap-binding.mjs` and `scripts/staging-prisma-migration-ledger-binding.mjs`, bootstrap/HBA changes, and **runtime changes to passkey RP-ID selection and recovery validation**, with local regressions. Operator helpers are not imported into Hub/worker; passkey and recovery changes are. Publication of a new descendant commit is NOT an independently accepted SOURCE GO. Review and CI/CodeQL must cover the exact new PR head and immutable image digest, not just `2cb74f5`; changes invalidate prior exact-SHA gates.
- The originally requested authenticated SOURCE interval `678d81a..6feb2da` remains included, but insufficient: subsequent commits add staging preflight, resource/relay policy and role provisioning. Final SOURCE review must cover **all descendants through the actual final PR HEAD**, including runtime WebAuthn/recovery modifications, operator helpers/tests and runbook. The historical Claude Code OAuth issue is not a substitute for review; no authentication bypass was attempted.
- GitHub checks verified on the **previously published parent** at this local inspection: CI runs `43594678814` and `43594674461`, CodeQL `43594678827` — `SUCCESS`. Those checks **do not approve the descendant source**: re-evaluate hosted exact-final-SHA CI/CodeQL and required independent SOURCE GO after publication. The production-image publication jobs were skipped by branch policy. Hosted native Hub Chromium tests are CI fixtures, **not an external staging run**.
- Independent source reviews of the published code previously reported GO; this is **not** an independent operational-security sign-off, a GitHub `APPROVED` review, or permission to merge.
- GitHub PR #118 remains `OPEN/DRAFT`. The three P2 threads were reconciled against the reviewed application code in original candidate `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c` and resolved with evidence; local `2cb74f5` changes only the signed staging preflight/standalone worker contract and PostgreSQL bootstrap prompt behavior, not those reviewed application paths. The P1 native/Access trust-boundary thread remains open pending external edge/rollback acceptance. Resolving findings is not a GitHub APPROVED review.
- Parent contracts, which take precedence if this ledger is incomplete: [`native-hub-staging-otp-acceptance-20261110.md`](native-hub-staging-otp-acceptance-20261110.md), [`native-hub-perimeter-cutover-20261110.md`](native-hub-perimeter-cutover-20261110.md), and [`staging-email-worker-role-20261112.md`](staging-email-worker-role-20261112.md).

### 2026-11-15 operator-helper provenance inventory (local pre-publication inspection)

This inventory is **source scope, not proof of production or staging execution**.
The physical worktree was inspected at source HEAD
`60e05bffdc2f741417a93002f1e02157d9db133f` on branch
`fix/pr118-native-admin-perimeter-hardening-20261115-r2`. The operator-only
changes below were **uncommitted at the inspection point** and cannot
inherit older hosted approval. A later commit and push still require
their own exact-SHA CI/CodeQL and independent acceptance.
Independent final review must cover the exact resulting candidate including
all of these files, not merely the runtime interval ending at `2cb74f5`:

- `scripts/staging-prisma-migration-ledger-binding.mjs` and
  `scripts/staging-prisma-migration-ledger-binding.test.mjs`: raw Git object
  and migration-ledger binding, adversarial SHA-1/SHA-256 trees, commits,
  ODB layouts, Windows Git executable and lossless PostgreSQL row encoding.
- `scripts/staging-pgpass-bootstrap-binding.mjs`: protected libpq credentials
  and strict worker/Hub runtime URL-password binding.
- `scripts/staging-toolchain-preflight.mjs` and
  `scripts/staging-toolchain-preflight.test.mjs`: Node/npm version range,
  real npm CLI, hostile `PATH` and preload regression checks.
- `scripts/staging-otp-preflight.mjs` and
  `scripts/staging-otp-preflight.test.mjs`: already-committed offline
  signed-declaration gate used by this runbook (unchanged in this pass).
- `scripts/secret-scan.mjs` and `scripts/secret-scan.test.mjs`:
  exact three-file allowlist for non-export read-only HBA SQL verifiers;
  real credential and other database-dump detection remains enforced.
- `scripts/staging-remote-hba-active.sql`,
  `scripts/staging-remote-hba-rules.sql`,
  `scripts/staging-local-hba-peer.sql`, and
  `scripts/postgres-bootstrap-allowlist.test.mjs`: effective HBA, active
  reload, auth/role checks and PostgreSQL security regression contracts.
- `scripts/staging-email-worker-standalone.contract.test.mjs` and
  `scripts/staging-runbook-lifecycle.test.mjs`: immutable/synthetic standalone
  worker inventory and Hub/worker guarded shutdown/fault injection.
- `infra/postgres-init/10-virki-database-roles.sh`,
  `infra/postgres-init/11-virki-email-worker-role.sh`,
  `package.json`, this evidence ledger,
  `docs/security/native-hub-staging-otp-acceptance-20261110.md`, and
  `docs/security/pr118-staging-operator-runbook-20261114.md`.

Local observations on 2026-11-15: a compatible isolated Windows
Node 22.22.1/npm 10.9.4 passed 141/141 focused OTP-signed-declaration,
PostgreSQL, toolchain, secret-scanner regression and synthetic Docker
Compose contract tests; the standalone source secret scanner also PASSed;
the runbook's isolated Bash/mocked-Docker lifecycle tests passed 12/12
on WSL, including interrupted/failed worker stop and a Git
`assume-unchanged` attack. The migration ledger verifier passed 42/43
focused tests on the pinned Windows Node 22.22.1 (0 failures, 1 skipped
POSIX FIFO fixture not applicable on Windows), including the
hexadecimal-row-forgery regression for SHA-1 and SHA-256. Independent
read-only Git/HBA/runbook reviewers reconciled the integration.
Separate local TOTP, passkey, recovery and mocked-email suites passed
80/80 on the pinned Windows Node 22.22.1 using a transient dependency
overlay built from another worktree with an identical package-lock digest;
all workspace module junctions were explicitly linked back to the
current worktree, and all 202 temporary links were removed and
independently checked. A second, non-overlapping functional batch of
15 test files passed **74/74**, covering recovery origin/consent,
TOTP, session revocation, admin authorization, same-origin CSRF,
email worker privilege and native perimeter; the total focused local
TOTP/passkey/recovery/mock-email suite is now **154/154 PASS**. The
same lock-identical offline dependency overlay was verified, removed
and rechecked after the new run. Ten additional read-only SMTP-wire
and disposable-worker isolation contract tests passed **10/10**
without creating containers, connecting to a relay or delivering a
message. No external PostgreSQL,
SMTP, recipient mailbox, deployed native ingress/egress, CI/CodeQL on the
final source, or physical staging rollback was exercised. All operational
Gate 0-4 cells below remain `NOT RUN` / release **NO-GO**.
The npm cache remains incomplete (`nodemailer@10.2.1`), so a fresh clean
offline `npm ci` did not pass; the matching-lock temporary overlay is
limited to local verification, not a deployment dependency installation.
Open acceptance dependencies include the exact-final-SHA hosted CI/CodeQL,
independently verified deployed DB CA for the Hub and worker, staging-only
WebAuthn RP IDs, the signed external network boundary, and real staged
provider-to-inbox OTP evidence. The role bootstrap scripts deliberately
require a Unix socket on port 5432; other staging ports are unsupported
without separately reviewed bootstrap changes. Do not promote local or
historical E2E PASS to this source SHA.

**Precisely bounded staging blockers — passkeys and database trust:** this
source candidate adds an explicit production-mode native-only
staging USER/ADMIN RP resolver in `packages/auth/src/passkeys.ts`, reused
for passkey recovery liveness in `packages/auth/src/recovery-methods.ts`.
Default production RP IDs and flags remain unchanged; invalid staging
hostname pairs or opt-in contexts fail closed. A separate local source-only
regression batch on pinned Node 22.22.1 passed **60/60** tests, including
new malicious/partial staging RP configurations, cross-role credential
rejection, and the exact staging Host API route; the auth package TypeScript
typecheck also PASSed. No real RP hostnames were approved or exercised.
Staging RP separation still cannot be proven from test-only hostnames;
reusing production RP IDs, enabling local testing in production, or
counting TOTP as passkey coverage remains prohibited. For PostgreSQL, the
approved libpq CA alone does not establish the certificate trusted by
Prisma 6.19.3 inside either runtime image. This local revision adds a
separate `infra/Dockerfile.staging-db-trust` requiring an explicit signed
base digest, mandatory BuildKit CA secret, independently approved SHA256,
strict CA-only PEM/X.509 parsing and root-owned 0444 installation at
`/app/ca/staging-db-root.pem`. `infra/Dockerfile.prod` is byte-identical
to the source HEAD and its implicit CI build target is unchanged. The
runtime helper and both operator URL checks require **only**
`sslmode=require&sslaccept=strict&sslcert=<fixed in-image CA path>`, the
Prisma 6 parameter names described in its documentation, rejecting absent,
duplicate, unknown, invalid-mode or alternate-path TLS arguments. The
operator runbook additionally defines a bounded, **non-executing**
`docker create` + `docker cp` extraction of the final image CA directory
for each Hub and worker image; a separate pinned host-side Node 22 TAR
verifier rejects noncanonical paths, symlinks/hardlink entries, wrong CA
digest, non-root owner and wrong file/directory modes. The inspection
container is never started. Cleanup is attempted even after create errors
using a preassigned random name and ownership nonce; bounded repeated
inspection catches delayed creation. If the daemon's final create result
cannot be established, staging remains **BLOCK** pending independent
manual reconciliation of that named resource (an empty one-time query is
not accepted as proof of cleanup).
Docker daemon-supplied archive metadata is still not an independent image
signature or actual TLS proof; no OCI inspection was **run against an
actual image** here. The image verifier contract passed **2/2** offline
tests using a public unrelated X.509 CA fixture; worker/Hub URL and
Compose contracts passed **8/8**; runbook Bash/mock-lifecycle passed
**13/13**, including false-hash, volume, create, copy and cleanup faults.
Secret scan and diff checks PASS.
Production Dockerfile remained unchanged. The earlier Prisma 6.19.3
Windows native engine inspection found support markers for `sslcert` and
`sslaccept`, but not a reliable basis for libpq-specific `sslrootcert`
or the Linux engine's actual peer hostname validation. **Neither local
URL parsing nor an OCI image label proves trusted TLS.** Signed CA/base
images, exact Linux Prisma engine live CA/SAN positive and negative
connections, real edge isolation and external browser acceptance remain
**BLOCK**, as do hosted exact-final-SHA CI/CodeQL and physical rollback.
No source-only acceptance or simulated test was promoted to operational GO.

### Four existing GitHub review threads reconciled against source

| Location of thread | Current code and decision | Remaining gate |
| --- | --- | --- |
| `apps/hub/src/lib/cloudflare-access.ts:19` (P1, not outdated) | `native` deliberately bypasses **application** Access JWT while protected Hub pages/mutations still require Virki ADMIN session, role, CSRF/Origin and scoped elevation. The default production mode stays `access`. No automatic ADMIN action bypass was established by the thread. | Independently approve the changed trust boundary on the real external native edge and its tested rollback, reconcile the contributor guide's older Access outer-boundary requirement; **leave open**. |
| `apps/hub/src/app/account/security/page.tsx:35` (P2, outdated; resolved with reply) | UI checks `canOfferRecoveryEmailRebind` against consumed non-EMAIL recovery provenance, matching the mutation's strict recheck. PostgreSQL 18 integration: **5/5 PASS** including modern-origin denials, eligible legacy positive control, revoked/expired/foreign. |
| `apps/hub/src/app/recover/actions.ts:94` (P2, outdated; resolved with reply) | Proven browser-bound modern recovery preserves its original key/token; explicit restart consent, validated bearer pair and origin Web Lock prevent the documented cooperating-tab late-response clobber. Chromium recovery/passkey suite: **12/12 PASS**, including restart and USER/ADMIN races. |
| `packages/auth/src/security.ts:973` (P2, resolved with reply) | Legacy discovery remains restricted. Active GET/first POST only set a candidate; a separate CSRF/Origin/role/surface-validated POST performs an explicit switch. The previously cited `recovery-switch.ts` helper is unused and is not claimed as enforcement. Chromium proved the modern key/TTL survives legacy GET/POST until explicit switch. |

The three P2 threads were replied to with exact-candidate evidence and resolved. The P1 remains unresolved; no review was marked APPROVED.

### Local patch evidence — not external acceptance

- Reproduced the previous worker-only Compose environment inheritance from the published parent: ordinary `VIRKI_EMAIL_*` SMTP/outbox sources remained after overriding only `DATABASE_URL`. A new contract assertion failed on the parent (3 PASS, 1 FAIL), then passed with the staging-only source override (4 PASS).
- Additional post-`f50fc58` causal RED: the manual Compose worker still inherited `depends_on.postgres` from the base production manifest. A regression test failed against that exact local parent (**4 PASS, 1 FAIL**); after `depends_on: !reset []`, the parsed effective worker dependency graph is **absent/empty**. This proves the worker no longer selects PostgreSQL through its dependency graph, **not** that Compose cannot prepare the base project's named volumes. No external staging worker start or production/staging volume mutation was tested or authorized; the separate local disposable worker execution is recorded below.
- A new separately testable **standalone** manual worker manifest (`infra/docker-compose.staging-email-worker-only.yml`) avoids the production-style base entirely. Causal RED: its two contract tests both failed when the file was absent; after creation, its source and actual Docker Compose configuration both passed using **synthetic** inputs. The effective model has exactly one profiled worker service, only a pre-existing external network, no PostgreSQL services, no named volumes and no implicit dependencies. This still proves only the manifest's declared model, not the identity or behavior of any external host, project or existing Docker resources.
- Effective Docker Compose interpolation with **synthetic values only**: deliberately injected ordinary SMTP/outbox/database sentinels were overridden for staging Hub/worker; both share the same synthetic staging outbox key, `restart=no`, the manual profile remains, and a distinct explicit staging project name renders. Missing any of the staging Compose project, SMTP password, outbox key, or Hub database URL failed rendering: **4/4 denied**. `-p` and `COMPOSE_PROJECT_NAME` still require a separately witnessed effective-project check. No Docker service/daemon activity or real SMTP was involved.
- The actual stage guard previously accepted an exited worker despite an inherited auto-restart policy. Stubbed physical-Bash guard test reproduced the negative case before the fix; after inspecting `HostConfig.RestartPolicy.Name`, the focused test passed and denies `unless-stopped`, `always`, `on-failure`, absent/unknown policy, or active worker state.
- Full local `scripts/production-ops.test.mjs` against temporarily linked approved dependencies: **64 total, 51 PASS, 0 FAIL, 13 platform-conditional SKIP**. The updated worker role/SCRAM suite: **8 PASS, 0 FAIL, 0 SKIP**. `npm run lint`, `npm run secrets:scan`, Bash syntax and `git diff --check` passed. The temporary dependency junction was checked and removed.
- A descendant-worktree `npm run typecheck` using a temporary dependency junction failed resolving the unchanged issuer's `oidc-provider` declarations, with cascading implicit-any diagnostics; a direct issuer typecheck passed in the previously approved parent worktree at `678d81a`. This local setup is **not** a full descendant typecheck PASS; fresh exact-SHA CI is required after independent SOURCE GO and eventual publication.
- On the local Windows `desktop-linux` Docker engine, exact pinned Node 22.23.3, PostgreSQL 18.6 and Playwright images were already cached; no image pull was performed. Native Hub browser gate: **3/3 PASS** with no Access JWT or synthetic issuer/JWKS, but only against a disposable local database. Recovery/passkey browser selection: **12/12 PASS**, including USER/ADMIN TOTP_ADMIN, USER PASSKEY_ADMIN, USER/ADMIN passkey tests, same-browser partial-proof restart, delayed legacy GET, explicit legacy switch and two-tab races. These browser tests use local fixtures and are not external staging.
- Dedicated PostgreSQL 18.6 integration runner: `recovery-email-rebind.integration.test.ts` **5/5 PASS**; SMTP wire integration: **1/1 PASS** over verified loopback STARTTLS/AUTH using the actual worker and synthetic mailboxes, with zero external delivery. SMTP wire typecheck and lint both passed. The full-schema disposable worker rehearsal applied **19/19 migrations** and passed **5/5** tests with real scoped Prisma worker processes, SCRAM, STARTTLS/AUTH, two-worker CAS/reconciliation and ACL-drift fail-closed checks.
- Redacted local runner evidence is preserved under `.virki-mission-tmp/isolated-runs/`: native Hub Chromium `d6988c0c6f7e4b758a6b3b962b1d29fb`; recovery/passkey Chromium `6c6f808acf204cd89e4cd3cb7d10ec9b`; recovery-email-rebind PostgreSQL integration `74fb3b0c58084be5ad802ef4ddcb2692`; SMTP wire integration `ce36878e404d47b7bb0db72eca5329da`. Each manifest records exact source HEAD `6feb2da5ab9bd25ce1cc2f53c6a7c4fc4807bd1c`, exit 0 and `dockerCleanupVerified=true`. Logs remain local and are not committed.
- Local physical cleanup fault injection: failure after SMTP certificate creation returned the expected nonzero result and recorded runner/DB/network removal plus `CLEANUP_CONFIRMED`; simulated unacknowledged runner creation correctly withheld cleanup success and recorded `RECONCILIATION_REQUIRED`, while DB/network removal was confirmed. Private receipt journals are under the owner-private local HOL directory; do not copy them into Git. The E2E runner manifests report `dockerCleanupVerified=true` for all four runs. One unrelated empty Docker network labelled with prior run ID `06fc1622b8d7467bb8a3a1f5bd6ade40` was observed and left untouched.
- `scripts/staging-otp-preflight.test.mjs`: **105/105 PASS** after extending the Ed25519-signed approval/observation schema with separate worker/Hub OCI digests, distinct Compose project IDs, Hub Compose file SHA-256, staging/production Docker network IDs, worker resource limits, and non-secret SMTP tenant/endpoint/account IDs, exact host/port/TLS mode, username fingerprint and independent credential-authentication evidence. Signed negatives reject missing/invalid/reused identities, relay/runtime mismatches, unauthenticated or unproven relay observations, network/image mismatches, unbounded resources and stale/invalid declarations. This proves offline signature/declaration consistency only; no owner/observer signatures or live target were supplied.
- Compose inspection: the standalone worker manifest has one profiled service, no ports, bind mounts, persistent volumes or dependencies, and one pre-existing external network; read-only root, `node:node`, all capabilities dropped, `no-new-privileges`, `pull_policy: never`, `restart: no`, one bounded `/tmp` tmpfs and mandatory signed `mem_limit`, `cpus` and `pids_limit`. It has **no Docker HEALTHCHECK** and does not itself enforce network egress/recipient allowlisting; the host firewall, relay policy and external observation remain mandatory.
- The standalone Compose contract passes **2/2** using Docker Compose's actual JSON renderer and synthetic-only values. The effective model requires memory `512m` (rendered as 536870912 bytes), CPU `1.0` (1,000,000,000 nanocores), PID limit `128`, `node:node`, one external network, exactly 13 worker environment keys, no volumes and no healthcheck. These are test fixtures, not approved staging resource values. The missing-environment negative cases require a real Compose exit status and the exact missing-variable diagnostic; process launch errors/timeouts cannot count as a successful denial.
- Earlier focused local validation on the descendant of runtime-code baseline `2cb74f5`: **136/136 PASS** across OTP preflight, standalone Compose, worker-role/SCRAM, PostgreSQL bootstrap allowlist/auth (including the exact TLS bootstrap-service/PGPASSFILE/`POSTGRES_PASSWORD` binding) and production Compose contracts; `npm run lint`, `npm run secrets:scan`, all eight then-existing runbook POSIX blocks via `bash -n`, and `git diff --check` passed. Lint used a temporary dependency junction to an existing worktree with identical `package-lock.json` hash; the junction was removed. A synthetic Hub-only Compose fixture rendered and passed equivalent isolation assertions. The Windows environment had no `jq` binary; staging-host jq/Docker inspection remains unverified. Hosted CI/CodeQL for this subsequently hardened exact SHA was **not part of that local test pass** and must be checked independently after push.
- `scripts/database-role-isolation.test.mjs` was attempted separately but stopped **before Docker activity** with `DISPOSABLE_RUNNER_JOURNAL_UNAVAILABLE` because this Windows session lacks the required protected journal/ACL identity. A WSL retry could not start within the session and was stopped; no ACL or runner guard was bypassed. This is an environment-blocked disposable integration test, not a passing integration result.
- The operator runbook now binds signed worker/Hub projects, both OCI digests, Hub Compose hash, resource-policy identity/receipt and exact memory/CPU/PID/interval values; checks the OCI source/revision labels against the final approved source SHA (labels remain consistency checks, not provenance); compares the live SMTP tenant/endpoint/account, host/port/TLS mode and username fingerprint against the signed owner approval and independent authenticated-relay observation; and checks the effective Hub/worker command, restart policy, non-root user, read-only root, exact capability/security options, tmpfs-only mounts, absence of Docker/API socket, bind/persistent mounts, ports, devices, added groups, alternate runtime, host/shared namespaces, environment and external network. The worker runtime gate compares its effective environment against the immutable image baseline merged with the exact approved service keys, rejecting duplicate/unapproved keys and any baked worker secret. Separate Hub/worker egress-policy evidence is mandatory even for an internal Docker network: Hub is restricted to signed DB/identity/application endpoints and the approved DNS path, worker to staging DB/approved SMTP and the approved DNS path, and both deny all Docker Engine TCP API listeners (including 2375/2376 and custom ports), SSH/RDP and host-gateway management. It requires separate exact-SHA hosted CI/CodeQL and GHCR provenance evidence, clears ambient libpq overrides before remote connections, verifies PostgreSQL TLS endpoints and effective remote `hostssl` SCRAM authentication for the migrator/runtime/worker/bootstrap roles, binds `POSTGRES_PASSWORD` to exactly one bootstrap PGPASSFILE row for both `postgres` and the restore DB, and binds `VIRKI_EMAIL_WORKER_DB_PASSWORD` to worker rows for the approved and restore DBs (literal `*` remains valid in password fields; wildcard match fields are rejected), checks Hub/worker DB principals and virgin outbox, and requires a peer-authenticated staging-only superuser rollback path with exactly two local HBA rules: one exact direct `peer` match for `postgres` and one for the fresh restore DB, both restricted to the bootstrap role with no options; included HBA files are rejected and the canonical main HBA file must have been loaded after its exact modification time; the restored Prisma migration ledger must exactly match every committed migration name and SHA-256 checksum, with no extra, missing, duplicate, unfinished or rolled-back rows; script 10 independently clears ambient libpq overrides and pins local Unix-socket access before role provisioning. The native-mode staging Hub requires a separate default-deny edge IP allowlist because application Access JWT validation is bypassed in native mode; production remains on Access.
- **Passkey staging remains BLOCKED operationally, not for lack of a source resolver:** `packages/auth/src/passkeys.ts` now implements separate USER and ADMIN HTTPS RP IDs for explicit canonical staging hostnames with `VIRKI_STAGING_PASSKEY_RP_ENABLED=true`, `NODE_ENV=production` and `VIRKI_HUB_PERIMETER_MODE=native`; it rejects parent/child or equal RP scopes between stages or against production, invalid opt-ins and reused production hostnames. Production defaults stay `portal.biel.dev.br` and `hub.biel.dev.br`. The **current safe-closed Hub runbook deliberately forbids staging RP opt-in and keeps both passkey flags false** until a separately approved passkey-enabled staging procedure binds an owner-signed distinct Portal/Hub host pair, independent HTTPS/TLS/edge inventory, correctly isolated credentials, exact runtime env and genuine USER/ADMIN browser ceremonies. Do **not** use this closed-mode runbook as proof that Gate 2 passkey tests ran or can be marked PASS; TOTP is not a substitute. Do not enable local testing in production, silently relax the runbook guards or touch production Access to bypass this gate. No approved external staging RP hosts or physical staging WebAuthn ceremonies were exercised; earlier local disposable-browser fixtures do not count.
- Reconciled the older staging-worker advisory: the published parent `678d81a` already sets the layered override to `restart: "no"` and `depends_on: !reset []`; the effective synthetic merged Compose render confirms both. That layered project still declares the base PostgreSQL volume and unrelated services, so the worker-only standalone manifest remains the preferred isolated path.

**Evidence location:** an operator-controlled, access-restricted repository **outside this Git tree**. Use opaque receipt references here; never commit or upload `.env` values, personal data, recipient addresses, screenshots of OTPs, passkeys, private keys, tokens, URLs containing capabilities, SQL dumps, raw headers or unredacted logs.

The command-level staging and physical-rollback procedure is in
[`pr118-staging-operator-runbook-20261114.md`](pr118-staging-operator-runbook-20261114.md).

## Gate 0 — authorize and identify the independent staging target

All fields below must be completed by the actual owner/operator and independently verified before any external resource change. A blank or `NOT RUN` field is **BLOCK**, not implicit consent.

| Mandatory identity or approval | Operator receipt | State |
| --- | --- | --- |
| Owner-approved host and independent operator, exact maintenance window (UTC) | — | NOT RUN |
| Separate staging host, network boundary, TLS endpoint and routing; not production/deManage | — | NOT RUN |
| Separate PostgreSQL database, migrator/runtime/email-worker roles; no production credentials | — | NOT RUN |
| Designated USER and ADMIN test identities, independent elevated reviewer, authorized test inbox owners | — | NOT RUN |
| Staging-only SMTP tenant/relay, TLS/AUTH, hard receiver allowlist, rate and total-message budget | — | NOT RUN |
| Pre-approved staging-only immutable OCI digest and source SHA, verified independently on target | — | NOT RUN |
| Out-of-band pinned owner and observer Ed25519 identities, offline signed approvals | — | NOT RUN |
| Signed worker resource-policy ID and exact memory-byte, CPU-nanocore and PID limits, matched to independent observation | — | NOT RUN |
| Native Hub staging edge ingress: owner-approved default-deny policy, exact operator/test source IPs or private VPN, unknown-host denial; production DNS/Access/hostnames unchanged | — | NOT RUN |
| Hub host/firewall egress policy: signed policy ID and receipt, independently observed active; staging DB + signed identity/application endpoints + approved DNS only; SMTP and all other destinations denied | — | NOT RUN |
| Worker host/firewall egress policy: distinct signed policy ID and receipt, independently observed active; staging DB + approved SMTP relay + approved DNS only; all other destinations denied | — | NOT RUN |
| Hub/worker egress policy IDs differ and their receipts differ; receipts are opaque references, not proof of active enforcement | — | NOT RUN |
| Named rollback operator, baseline snapshot custody, restore rehearsal and stop conditions | — | NOT RUN |

**Stop immediately** if there is a target-identity mismatch, possible production/deManage crossover, untrusted signing key, unknown mailbox owner, unexpected inbound route, worker already running or unexplained queued email. Do not silently reconcile a discrepant environment.

## Gate 1 — establish provenance and start in a closed state

1. Operator independently compares approved source SHA, immutable OCI manifest digest, runtime image identifier and effective Compose configuration on the **staging host only**. Record opaque receipt IDs and UTC timestamps; no `docker compose config` dump containing secrets.
2. Verify host and database separation **against** production inventories held by the operator, with least-privilege accounts and committed migrations only. Record the actual PostgreSQL major/schema migration state, grants, TLS endpoint and fail-closed negative checks without identifiers or connection strings in this ledger.
3. Establish protected baseline backup, prove a restorable staging-only snapshot, and take redacted counts for users, sessions, pending recovery, outbox by kind/state, delivery attempts and audit events. Never restore a staging dump over production.
4. Prepare the approved application components, identities and environment for independent validation. **Do not start the Hub before step 6** has validated the signed inventory and fresh observation; the worker must remain **stopped** with zero replicas, no outbox drain and verified `HostConfig.RestartPolicy.Name=no` (for any existing staging worker container), not merely a corrected YAML file.
5. Use the preferred **standalone** worker-only manifest `infra/docker-compose.staging-email-worker-only.yml` with **no production or staging base Compose files combined**. Verify that the real parsed configuration has exactly one manual-profile email-worker, `restart=no`, signed positive memory/CPU/PID limits, the exact ephemeral `/tmp` tmpfs, only an approved pre-existing external staging network, no PostgreSQL service, no bind/persistent volume and no dependencies. Verify the exact immutable image digest and all staging-only environment sources. Independently witness `VIRKI_STAGING_COMPOSE_PROJECT` and actual final project/context, including overriding `-p` or `COMPOSE_PROJECT_NAME`, and verify pre-existing worker resources and network/volume identity. The operator must still refuse any unqualified `up`; only a distinct approved attended `up --no-deps email-worker` after all gates. If using the **legacy layered override** instead, an independently vetted staging-only base and a nonmutating command plan showing no production volume/resource impact are mandatory. Do not claim that `depends_on: !reset []` alone proves volume safety.
6. Independently observe the worker stopped, restart/autostart disabled, resource limits equal to the signed values, empty virgin outbox and zero attempts. Sign the separate observation. Execute the **full** `signed_staging_runtime_preflight` function from the [operator runbook](pr118-staging-operator-runbook-20261114.md) in the same protected shell, before Hub activation and again before worker activation with a fresh independent observation. It invokes `scripts/staging-otp-preflight.mjs` with signed approval/observation, both **public** verification keys, exact `--expected-source-sha`, SMTP identity, and all **13 mandatory `--runtime-*` bindings** for measured digests, projects, Compose hash, network, DB and resource policy/limits. A truncated standalone command must fail closed; neither matching signatures nor operator CLI arguments establish live state or authorize sending.
7. Only after the signed preflight has passed, activate **only the approved Hub** with the operator runbook's protected attended shell, bounded health wait, post-start state/network checks and cleanup trap. The email worker remains stopped for the browser-only Gate 2; a separate fresh preflight, stopped-worker reinspection and explicit owner-authorized attended send window are mandatory before Gate 3. This step is an **operator instruction**, not an authorization to execute it now.

| Gate-1 proof | Operator receipt | State |
| --- | --- | --- |
| Image / SHA / effective configuration matched | — | NOT RUN |
| Host, origin, TLS and PostgreSQL isolation proved | — | NOT RUN |
| Fresh backup and restoration plan independently validated | — | NOT RUN |
| Native Hub edge ingress allowlist physically active and independently observed; unknown hosts denied; no broad Access bypass | — | NOT RUN |
| Hub egress host/firewall policy physically active and independently observed; policy ID/receipt distinct from worker | — | NOT RUN |
| Worker egress host/firewall policy physically active and independently observed; policy ID/receipt distinct from Hub | — | NOT RUN |
| Hub/worker database sessions use TLS with exact hostssl SCRAM-SHA-256 HBA rules; no trust/cert/MD5 or broad/group fallback | — | NOT RUN |
| Worker physical stopped state, `no` restart, profile, no backlog, zero attempts | — | NOT RUN |
| Signed owner approval + independent observation, offline preflight consistent | — | NOT RUN |

## Gate 2 — browser, authorization, recovery and passkey acceptance

Use an **authorized external** staging deployment at the approved digest. Use clean real browsers on the correct HTTPS Portal/Hub origins. For native Hub, begin without a Cloudflare Access JWT/cookie and without a synthetic JWT issuer; this is not a production Access-policy modification. Log only redacted audit refs and aggregate database effects. Record exact test role, preconditions, positive result, negative result, whether a security state changed, UTC timestamp and opaque evidence receipt for each case.

| Required physical scenario on staging | PASS / FAIL / NOT RUN | Receipt |
| --- | --- | --- |
| Native Hub ADMIN login: valid password + live second factor; no Access JWT; no unauthorized ADMIN page/mutation | NOT RUN | — |
| Native perimeter: unauthenticated denial, forged Access/JWT/Origin/CSRF denial, valid USER Portal session refused by Hub, wrong host denied | NOT RUN | — |
| USER login and independent lost-original-mailbox recovery with verified replacement mailbox and exact Portal RP passkey/TOTP | NOT RUN | — |
| ADMIN lost-original-mailbox recovery with required independent factors and distinct active elevated ADMIN reviewer | NOT RUN | — |
| USER `TOTP_ADMIN` recovery and USER `PASSKEY_ADMIN` recovery as separate tests, with reviewer/role rejection | NOT RUN | — |
| ADMIN separate-credential rotation with original inbox OTP + current normal password + fresh session/CSRF | NOT RUN | — |
| ADMIN separate-credential rotation with unused recovery code + normal password, including concurrent same-code replay denial | NOT RUN | — |
| ADMIN separate-credential rotation with ACTIVE TOTP + normal password, preserving active TOTP and rotating codes | NOT RUN | — |
| ADMIN normal password unchanged; old admin password/codes denied; ten replacement recovery codes; new scoped elevation required | NOT RUN | — |
| USER and ADMIN passkey enrollment, assertion, revocation/replay, wrong role/origin/RP, forgotten device and expired challenge | NOT RUN | — |
| Post-recovery: revoke old sessions/devices/elevations, old credentials denied, new session and fresh MFA/new elevation allowed | NOT RUN | — |
| Recovery cross-tab restart/link races, explicit consent, expiry, one-winner, rate limit, revoked factors and audited denials | NOT RUN | — |

Any required scenario that is skipped, observed only in CI, backed solely by a database row, or lacks a browser and server-side audit correlation remains **NO-GO**. The Web Locks UI mitigates honest same-origin races but does not serialize malicious raw HTTP `Set-Cookie` responses; test the approved adversarial cases and record this residual availability risk for independent acceptance, not as an MFA bypass.

## Gate 3 — authenticated SMTP and one real OTP end-to-end

**Do not start a worker yet.** First the independent operator must prove the staging relay identity, certificate/TLS and AUTH, provider and worker quota, **provider-enforced** recipient allowlist including rejection of an unlisted address, empty backlog, dedicated SQL privileges and a bounded attended sending window. Recheck the physical worker state and sign a new observation immediately before the window. Do not use a production Brevo credential, mailbox or tenant.

Only after these gates and a distinct send authorization, the operator explicitly selects the manual Compose service/profile, supervises the approved number of OTP sends, and stops it before the window closes. A successful `docker compose config`, SMTP `250`, `SENT` database state, header `Message-ID`, or an earlier diagnostic email is **not** proof of recipient delivery.

| Distinct OTP chain observation | Operator receipt (non-secret) | State |
| --- | --- | --- |
| Virki action, authenticated USER/ADMIN role, ceremony isolation and redacted audit reference | — | NOT RUN |
| Real staging outbox kind, bounded age, recipient binding and HMAC-correlated opaque row reference | — | NOT RUN |
| Single worker claim/CAS winner, attempt record, verified STARTTLS/AUTH and bounded retry/lease state | — | NOT RUN |
| Relay/provider acceptance event and correctly matched provider message ID | — | NOT RUN |
| Authorized test inbox owner independently confirms actual Virki-generated OTP and matching safe message trace | — | NOT RUN |
| One-time OTP acceptance, expired/replayed/wrong-role denial, no second dispatch or secret in audit output | — | NOT RUN |
| Worker stopped after window, zero replicas, no restart/autostart; uncertain sends independently reconciled | — | NOT RUN |

If the provider-to-inbox join cannot be established without exposing sensitive headers or OTP data, record `OTP_CORRELATION_UNPROVEN`: **NO-GO**. Retry/relay acknowledgement ambiguities are not automatically successful or safe for resend.

## Gate 4 — physical rollback and final operator decision

1. Stop and physically verify the worker stopped and unable to restart before any restore. Reconcile every queued, processing, sent, retryable and uncertain message/attempt, including reserved Message-IDs and leases, without resending.
2. Restore only the approved independent staging database/snapshot to the staging target, with the named rollback owner present; exercise application rollback and verify the approved source/image and ingress configuration. Do not touch production or Cloudflare production policies.
3. Compare before/after sanitized counts across users, sessions, recoveries, outbox by kind, attempts, and audits. Confirm expired tokens, session revocation and negative replay behavior; retain immutable/redacted receipt IDs.
4. Review risks and evidence with an independent security reviewer, operator and owner; do not close GitHub threads, mark `APPROVED`, promote images, remove Draft or change the production perimeter based on this ledger.

| Final acceptance condition | State |
| --- | --- |
| Exact candidate SHA and staging immutable digest independently verified | NOT RUN |
| Every Gate-2 mandatory browser scenario PASS, no silent SKIP | NOT RUN |
| Real provider-to-recipient OTP matched for authorized test identities | NOT RUN |
| Physical staging rollback and post-restore invariant evidence PASS | NOT RUN |
| Independent operational-security approval, review-thread reconciliation and formal GitHub approval | NOT RUN |
| Separate explicit final owner approval for any production perimeter change | NOT RUN |

**Decision rule:** release remains **NO-GO** unless **all** applicable cells have external evidence and independent acceptance. Code/source review, green CI/CodeQL, a Compose dry run or a signed statement alone cannot substitute. Any blocker, unknown, missing receipt, secret spill, provider discrepancy or unverifiable restore forces **NO-GO** and a new reviewed window.

## Residual risks and follow-up ownership

- **Native outer boundary:** with `VIRKI_HUB_PERIMETER_MODE=native`, the application deliberately stops requiring the Access JWT. The documented production default remains Access. Independent operator must reconcile this design choice with `AGENTS.md` and approve an externally tested edge/rollback boundary; the open P1 thread is an acceptance gate, not evidence of a currently exploited bypass.
- **Browser response ordering:** Web Locks coordinate cooperating forms only; an adversarial direct HTTP client may induce availability races. Retain backend CSRF/role/proof/capability protections and record the residual limitation for reviewer acceptance.
- **Mail delivery:** an outbox receipt, SMTP acceptance or provider event alone does not prove inbox arrival; only the complete authorized chain does.
- **Worker restart:** staging `restart=no` and a profile do not prevent explicit starts or override a stale existing container. The stage guard now rejects any stopped-but-restartable worker it observes; the operator must still verify the physical container before **each** approved window.
- **Compose environment inheritance:** manual worker overrides merge, not replace, base service environment. Required staging-only variables prevent silent inheritance of ordinary SMTP/outbox sources, but **do not** independently prove a secret, host or account is different from production; the independent operator must inspect identity and segregation out of band.
- **Compose service dependencies and volumes:** the legacy layered override resets worker dependencies but still includes the base project's named PostgreSQL volume. The **preferred standalone worker-only manifest** declares no PostgreSQL service, persistent volume or implicit project network; it has one ephemeral `/tmp` tmpfs and requires signed CPU/memory/PID limits. It still cannot prove runtime host/project resource ownership or network egress without external observation. Require an independently approved context/project/external network/resource inventory. No unqualified stack-wide `up` or production project/volume is authorized.
- **Operational authority:** SOURCE GO and CI on a code SHA do not authorize staging, SMTP, closing review threads, merge or production cutover. Keep PR #118 `DRAFT`, production native cutover blocked and the evidence outside source control.

These source and test observations are **local/historical**, not external staging acceptance. Do not transfer earlier SOURCE GO or CI to a new descendant; obtain fresh exact-final-SHA CI/CodeQL and independent acceptance for the next candidate. Physical gates remain `NOT RUN` and staging itself still requires separately authorized owner/operator execution.
