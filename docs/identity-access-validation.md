# BielOS identity/access campaign validation

## Scope and status

The source implementation is complete for the current identity/access surfaces. The accepted remote deployment is `ba1c80a05b76d8fc7539dcd90a47f8fa187ffd76`; exact-SHA CI run `35630592690` passed. Authenticated human smoke remains external. Public registration and live Intake stay disabled. Historical smoke and CI claims below retain their original dates and SHAs.

Local patch validation for the earlier snapshot completed under Node `24.14.1`; that evidence is historical and unsupported for release.

The current direct campaign supersedes that opening snapshot locally: Next.js is `16.3.5`, sharp is `0.35.4`, Nodemailer is `10.0.10`, the production dependency tree is audit-clean, and Node `22.20.0` runtime-sensitive checks pass. Docker/PostgreSQL/backup/runtime checks, exact-SHA CI, Cloudflare, and authenticated human smoke remain open. Historical sections below retain their original SHA and runtime claims.

## Dependency order and task status

1. Baseline, threat model, dependency ledger, and reusable implementation skill — completed.
2. Identity/access schema, additive migrations, catalog, and helpers — completed.
3. Provider-neutral encrypted email outbox — completed.
4. Isolated public intake and feature gates — completed, production disabled.
5. Email verification, owner review, partial approval, and atomic activation — completed; disposable PostgreSQL integration and concurrency validation passed.
6. Module catalog, requests, feature permissions, grants, expiry, and owner review — completed; disposable PostgreSQL integration and concurrency validation passed.
7. Email/TOTP second factor, encrypted TOTP, recovery codes, device challenges, trusted devices, and ordinary recovery — completed; disposable PostgreSQL integration and concurrency validation passed.
8. Separate administrative credential and session-bound `SecurityElevation` — completed; disposable PostgreSQL integration and concurrency validation passed.
9. UI, audit, notifications, operations state, and opaque UI references — completed.
10. Adversarial validation and publication — source validation exists; final-SHA CI, durable rollout, and the authorized application smoke remain external gates.

## Surfaces and safety state

- Public intake is isolated in `apps/intake`, with a restricted Prisma client and no public-site database import. Private/unlisted modules do not enter public responses. Missing feature flags, abuse secret, restricted database URL, or email transport keep intake unavailable.
- `/apply` builds and renders an unavailable state unless `NEXT_PUBLIC_INTAKE_URL` is configured. Production Compose defaults `BIELOS_INTAKE_ENABLED=false`; enablement requires the private production environment value after all rollout gates pass.
- Applications move through pending email, verified, review, partial/approved/rejected, and one-time activation states. Activation creates the user and grants atomically; delivery failure does not authorize activation.
- The catalog distinguishes visibility, runtime availability, and entitlement. GymForge is available; AIP and root.ark are unavailable; L-vault and H-vault remain private/inert.
- Module and feature requests are independently rate-limited for 24 hours. Owner review uses opaque request keys and active scoped elevation. Temporary grants fail closed after expiry.
- Login creates no session before the email/device ceremony. TOTP secrets are encrypted under `BIELOS_TOTP_ENCRYPTION_KEY`; recovery codes are hashed and one-use; trusted devices are user-scoped and revocable.
- A fully verified trusted browser may create a new ordinary session with the password alone for one absolute seven-day server-side grant; ordinary logout preserves that grant, while expiry, revocation, recovery, password reset, TOTP changes, account state changes, and revoke-all security actions fail closed.
- Ordinary recovery uses generic responses, verified email, owner approval, password replacement, and session revocation. Administrative recovery is separate and uses an offline administrative recovery code.
- Administrative credentials are independent from the normal password. `SecurityElevation` protocol version is `1`, bound to owner, session, scope, and explicit timed/manual duration. Legacy `SecurityUnlock` rows grant nothing.
- Critical scopes include application review, activation reissue, module/feature access, account state/recovery approval, global roles, catalog changes, administrative credentials/recovery codes, project-owner access, and Core project archive.
- UI exposes PT-BR/English paths, safe statuses, and only opaque references. Audit metadata is bounded and hashed; no codes, secrets, passwords, raw bearer values, IPs, user agents, or provider errors are written.
- Operations reports only database probe state, email configured/unavailable, intake enabled/disabled, and worker not-checked. No queues, environment values, or provider identifiers are exposed.

## Historical Evidence

- Focused/core unit suite: 71 passing.
- Public-site discovery: 3 passing.
- GymForge scoring: 8 passing.
- Core project validation: 5 passing.
- Production revision/Compose source tests: 12 passing.
- `npm run lint`: passed.
- `npm run typecheck`: passed for hub, intake, public-site, auth, and database.
- `npm run prisma:validate`: passed.
- `npm run secrets:scan`: passed.
- `npm ci --ignore-scripts` with the committed lockfile: passed locally under Node `24.14.1`; the repository CI Node 22 runtime remains the remote gate.
- `npm audit --package-lock-only --audit-level=moderate`: passed with 0 vulnerabilities after pinning PostCSS `8.5.25` while retaining the existing Next.js `16.2.12` override.
- Fixed dependency versions are Next.js `16.2.12`, PostCSS `8.5.25`, sharp `0.35.0`, and brace-expansion `5.0.9`; both Next applications resolve the same Next.js version.
- `npm run build`: public site and hub passed, including login verification, recovery, account security, and administrative security routes.
- CI now runs dependency audit and application validation as independent jobs, so an audit failure cannot skip the remaining validation gates.
- `git diff --check`: passed before publication.
- Core database validation: disposable integration `53/53` and concurrency `12/12` passed locally after Docker Desktop restart restored Docker Engine `29.6.2`.
- Backup/restore evidence: passed locally using a custom-format dump and a separate disposable restore database; no production database was accessed or modified.
- Restricted intake database-role evidence: passed locally with direct access denied to private Core, outbox, administrative/security, audit, and GymForge data; public catalog, intake writes, activation, and the narrow verification enqueue capability passed.
- Production Compose config validation: passed locally. Production image build, image revision-label verification, and runtime smoke remain to be run against the final committed SHA.
- Exact pre-remediation remote CI for `b70b42400a6234483bd353d1bbdad8f964d679ba`: run `30733244283` failed at `Audit dependency lockfile`; the audit and validation jobs were previously coupled, so later steps were skipped.
- Exact post-remediation remote CI for validation commit `223528948a7732b9b1f5f6ea148759c0497439e6`: run `30736308059` passed both independent jobs, including 37 Core integration tests, concurrency tests, production image revision verification, and Compose validation.
- Historical CI runs are retained in the dated historical sections, and the current-SHA result is recorded in the 2026-08-13 final campaign status boundary.
- Codex Security diff scan: scan `68209414-195e-47e5-bd45-88bd257f1d48` reviewed `b70b42400a6234483bd353d1bbdad8f964d679ba...66908a4113f5bfa23e3c0b98a903067cd60193c2` with complete coverage. The sealed contract report contains one high-confidence Low/P3 information-disclosure finding (`CWE-200`) for the public intake catalog exposing an internal `ModuleCatalog.id`; two other candidates were validated and suppressed/ignored. The report was generated locally from the completed scan artifacts because the native workbench became terminal before indexing; no Critical, High, or Medium finding was reported.

## Migrations

`20260801090000_identity_access_foundation`, `20260801100000_add_intake_dedupe_controls`, `20260801110000_add_partial_application_state`, `20260801120000_account_security_verification`, `20260801130000_administrative_elevation`, `20260801140000_security_ui_keys`, `20260802090000_restrict_intake_database_access`, `20260802100000_fix_intake_security_functions`, and `20260805120000_add_remembered_browser_grant` are additive. The remembered-browser migration defaults existing rows to no active grant through nullable timestamps. Down-migrations and destructive rollback are not assumed safe; take and verify a backup before deployment.

Historical technical/runtime/CI/Cloudflare evidence is retained for its exact published SHA. Local implementation and validation are complete under the stated runtime limitation; the affected human smoke remains pending. No final enablement, current authenticated OWNER/MEMBER smoke, new deployment, or new remote CI result is claimed.

## Public catalog disclosure hotfix

- The Low/P3 `ModuleCatalog.id` disclosure (CWE-200) was fixed in implementation commit `d5e01c5e6f23538a32591dece35402142d9004e0` (`fix: remove internal module id from public catalog`).
- The public response now uses an explicit allowlisted projection containing only `key`, `name`, and `runtimeAvailability`; internal `id` remains available to repository logic for deduplication and module-decision persistence.
- The behavioral regression exercises the real handler-to-intake-repository catalog path, proves serialized `id` absence, preserves private-module exclusion and internal-ID submission/activation behavior in the database-role validation, and proves disabled or misconfigured intake remains fail-closed.
- Exact final CI for the fixing SHA: GitHub Actions run `30778813575` passed both `Validate` and `Audit dependency lockfile`.
- Intake remains disabled in the local production environment, and no durable production migration occurred.

## Local revalidation — 2026-08-11

- Supported runtime: Node `v22.20.0`, npm `11.11.0`; the earlier `uv_os_get_passwd returned ENOMEM` under Node `v24.14.1` is classified as an unsupported-runtime/environment failure.
- `npm ci` and `npm audit --package-lock-only --audit-level=moderate`: passed with 0 vulnerabilities after the narrow `nanoid` `3.3.16` → `3.3.17` override; no broad dependency upgrade was performed.
- Docker Desktop was recovered locally; Docker Engine `29.6.2` served only loopback-bound disposable PostgreSQL validation.
- `npm run secrets:scan`, `npm run lint`, `npm run typecheck`, `npm run prisma:validate`, `npm run test:production-revision` (13/13), `npm run test:public-site` (3/3), and `git diff --check`: passed.
- `npm run test:core:unit`: passed, 77/77 under Node 22.20.0.
- `npm run test:core:db:integration`: passed, 53/53 against a Docker-managed disposable PostgreSQL database.
- `npm run test:core:concurrency`: passed, 12/12 against a Docker-managed disposable PostgreSQL database.
- `npm run test:intake:db-role`: passed after applying the 14 additive migrations to a loopback-only disposable database; the restricted role remained unable to read or mutate private Core tables.
- `npm run test:backup:restore`: passed (`exit=0`) with a disposable PostgreSQL dump, restore, migration, and representative-data check.
- `npm run build`: passed for public-site and hub. A local production image built with synthetic revision `0123456789abcdef0123456789abcdef01234567`, its OCI revision label matched, production runtime smoke passed, and production Compose config validation passed with placeholders.
- Public Intake remains fail-closed; no runtime code, schema, migration, CI, production configuration, deployment, or production database was changed.
- Production migration and backup authorization, owner security ceremonies, Cloudflare routing, and authorized production application smoke remain external gates.

## Historical local revalidation — 2026-08-12

| Gate | Status | Evidence |
| --- | --- | --- |
| `npm run secrets:scan` | locally_verified | Passed. |
| `npm run lint` | locally_verified | Passed. |
| `npm run typecheck` | locally_verified | Passed. |
| `npm run prisma:validate` | locally_verified | Passed. |
| `npm run test:core:unit` | locally_verified | Passed, 77/77. |
| `npm run test:public-site` | locally_verified | Passed, 3/3. |
| `npm run test:production-revision` | locally_verified | Passed, 13/13. |
| `npm run build` | locally_verified | Passed for public-site and hub. |
| Docker/PostgreSQL-dependent local gates | passed | Later local evidence passed under Node `24.14.1`: Core database `66`, concurrency `12`, and the listed backup/role/build gates; repeat under Node 22 before release. |
| Historical CI evidence | historical | GitHub Actions run `31550088933` for HEAD `2bb8696f7162b883d85381f2e2910f052b6ed9ce` completed successfully for both `Validate` and `Audit dependency lockfile`; it is not current-SHA evidence. |
| Production migration and backup authorization | production_authorization_pending | Requires authorized production operation and current backup/restore evidence. |
| Owner security ceremonies | manual_gate_pending | Owner factors and offline recovery acknowledgement require the documented human ceremony. |
| Cloudflare routing | manual_gate_pending | Production routing remains unchanged and requires separate authorized validation. |
| Authorized production application smoke | production_authorization_pending | No production smoke action is claimed for this revalidation. |

This revalidation records readiness evidence only. Public registration and live Intake remain disabled; no production enablement, migration, routing change, or production mutation is claimed.

## Historical final campaign status boundary — 2026-08-14

- Historical baseline `33f540a4b396aa8a55fa65ad9f950b0c36712aae` matched local and `origin/main` at that time. Exact GitHub Actions run `31821995102` passed `Validate` and `Audit dependency lockfile`, including Core DB integration, Intake role, backup/restore, concurrency, build, production image revision, runtime smoke, and Compose validation; this is not current worktree evidence.
- Docker Desktop restart restored Engine `29.6.2`. Real local production Compose is up with public-site, hub, intake, postgres, cloudflared, session-cleanup, and email-worker; health-local passed, all five built-service revisions matched the exact SHA, host application ports are loopback-only, direct local hub access without an Access assertion returned `403`, local hub health returned `200`, public site returned `200`, and disabled Intake `/api/catalog` returned `503`.
- The current ignored custom-format PostgreSQL backup was verified; disposable restore succeeded with 14 migration rows, and migrate status/deploy/status showed no pending migrations. Disposable Core DB integration passed `53/53`, concurrency `12/12`, restricted Intake database-role validation passed after 14 committed migrations, backup/restore exited 0, secrets scan, Prisma validation, production revision `13/13`, npm audit, and `git diff --check` passed.
- Live ingress returned public site `200`, `www` `200`, and hub `302` to the Cloudflare Access login; cloudflared registered four tunnel connections with connectivity prechecks passing. Owner state has one active OWNER, one ACTIVE TOTP factor, ten unused normal recovery codes, zero active administrative credentials, zero administrative recovery codes, and zero active elevations.
- Historical closeout status was `BIELOS_CLOSEOUT_TECHNICALLY_COMPLETE_MANUAL_HUMAN_ACTION_PENDING`; the current status is `BIELOS_POST_SMOKE_REPAIR_LOCALLY_COMPLETE_AWAITING_HUMAN_SMOKE` and the affected human smoke must be repeated. Do not claim `BIELOS_CLOSEOUT_COMPLETE` or invent credentials or smoke results.
- Cloudflare Access stays first, BielOS internal authentication second, loopback-only ports remain required, public registration and live Intake stay disabled, GymForge expansion remains frozen, `SecurityUnlock` runtime remains blocked, reserved modules remain inert, and AIP remains separate.

## Human enablement steps

1. Repeat only the affected post-smoke flows after this patch: as OWNER, grant/change/revoke disposable Project A MEMBER access without elevation and verify Project B denial/no leak plus last-owner protection; acquire `CORE_PROJECT_ARCHIVE` only for the archive flow; archive and verify read-only behavior; verify MEMBER admin/audit/session restrictions; then perform normal logout. Keep `BIELOS_INTAKE_ENABLED=false` and public registration disabled.
