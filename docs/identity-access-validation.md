# BielOS identity/access campaign validation

## Scope and status

The validation closeout started from `b70b42400a6234483bd353d1bbdad8f964d679ba` and the final validated implementation is `66908a4113f5bfa23e3c0b98a903067cd60193c2` on `main`; this closeout document is published afterward in documentation-only commits on `origin/main`. The implementation is complete in source and disabled by default for production. Dependency remediation, CI audit separation, disposable backup/restore, restricted-role validation, and remote runtime validation are green; durable production changes remain gated by human operations.

## Dependency order and task status

1. Baseline, threat model, dependency ledger, and reusable implementation skill — completed.
2. Identity/access schema, additive migrations, catalog, and helpers — completed.
3. Provider-neutral encrypted email outbox — completed.
4. Isolated public intake and feature gates — completed, production disabled.
5. Email verification, owner review, partial approval, and atomic activation — completed; DB contention unvalidated locally.
6. Module catalog, requests, feature permissions, grants, expiry, and owner review — completed; DB contention unvalidated locally.
7. Email/TOTP second factor, encrypted TOTP, recovery codes, device challenges, trusted devices, and ordinary recovery — completed; DB runtime unvalidated locally.
8. Separate administrative credential and session-bound `SecurityElevation` — completed; DB runtime unvalidated locally.
9. UI, audit, notifications, operations state, and opaque UI references — completed.
10. Adversarial validation, rollout, and publication — source/remote validation green; the Codex Security contract report is complete with one Low/P3 finding, while native workbench indexing and durable rollout remain external gates.

## Surfaces and safety state

- Public intake is isolated in `apps/intake`, with a restricted Prisma client and no public-site database import. Private/unlisted modules do not enter public responses. Missing feature flags, abuse secret, restricted database URL, or email transport keep intake unavailable.
- `/apply` builds and renders an unavailable state unless `NEXT_PUBLIC_INTAKE_URL` is configured. Production Compose forces `BIELOS_INTAKE_ENABLED=false`; no production provider or automatic enablement was added.
- Applications move through pending email, verified, review, partial/approved/rejected, and one-time activation states. Activation creates the user and grants atomically; delivery failure does not authorize activation.
- The catalog distinguishes visibility, runtime availability, and entitlement. GymForge is available; AIP and root.ark are unavailable; L-vault and H-vault remain private/inert.
- Module and feature requests are independently rate-limited for 24 hours. Owner review uses opaque request keys and active scoped elevation. Temporary grants fail closed after expiry.
- Login creates no session before the email/device ceremony. TOTP secrets are encrypted under `BIELOS_TOTP_ENCRYPTION_KEY`; recovery codes are hashed and one-use; trusted devices are user-scoped and revocable.
- Ordinary recovery uses generic responses, verified email, owner approval, password replacement, and session revocation. Administrative recovery is separate and uses an offline administrative recovery code.
- Administrative credentials are independent from the normal password. `SecurityElevation` protocol version is `1`, bound to owner, session, scope, and explicit timed/manual duration. Legacy `SecurityUnlock` rows grant nothing.
- Critical scopes include application review, activation reissue, module/feature access, account state/recovery approval, global roles, catalog changes, administrative credentials/recovery codes, project-owner access, and Core project archive.
- UI exposes PT-BR/English paths, safe statuses, and only opaque references. Audit metadata is bounded and hashed; no codes, secrets, passwords, raw bearer values, IPs, user agents, or provider errors are written.
- Operations reports only database probe state, email configured/unavailable, intake enabled/disabled, and worker not-checked. No queues, environment values, or provider identifiers are exposed.

## Evidence

- Focused/core unit suite: 67 passing.
- Public-site discovery: 3 passing.
- GymForge scoring: 8 passing.
- Core project validation: 5 passing.
- Production revision/Compose source tests: 10 passing.
- `npm run lint`: passed.
- `npm run typecheck`: passed for hub, intake, public-site, auth, and database.
- `npm run prisma:validate`: passed.
- `npm run secrets:scan`: passed.
- Node 22.20.0 `npm ci` with the committed lockfile: passed, including Prisma client generation.
- `npm audit --package-lock-only --audit-level=moderate`: passed with 0 vulnerabilities after upgrading Next.js and remediating brace-expansion, PostCSS, and sharp.
- Fixed dependency versions are Next.js `16.2.12`, PostCSS `8.5.18`, sharp `0.35.0`, and brace-expansion `5.0.9`; both Next applications resolve the same Next.js version.
- `npm run build`: public site and hub passed, including login verification, recovery, account security, and administrative security routes.
- CI now runs dependency audit and application validation as independent jobs, so an audit failure cannot skip the remaining validation gates.
- `git diff --check`: passed before publication.
- Core DB integration/concurrency suite: passed in remote CI; local execution was blocked because the Docker API was unavailable.
- Backup/restore evidence: passed in remote CI using a custom-format dump and a separate disposable restore database; no production database was accessed or modified.
- Restricted intake database-role evidence: passed in remote CI with direct access denied to User, Session, projects, catalog tables, outbox data, administrative/security tables, audit logs, and GymForge tables; public catalog, intake writes, activation, and the narrow verification enqueue capability passed.
- Image, runtime, and Compose validation: passed in remote CI, including loopback-only ports, public-site health, hub health, direct-origin hub denial, intake-disabled response, revision label, and Compose validation; local Docker remained unavailable.
- Exact pre-remediation remote CI for `b70b42400a6234483bd353d1bbdad8f964d679ba`: run `30733244283` failed at `Audit dependency lockfile`; the audit and validation jobs were previously coupled, so later steps were skipped.
- Exact post-remediation remote CI for validation commit `223528948a7732b9b1f5f6ea148759c0497439e6`: run `30736308059` passed both independent jobs, including 37 Core integration tests, concurrency tests, production image revision verification, and Compose validation.
- Exact final-SHA CI for `66908a4113f5bfa23e3c0b98a903067cd60193c2`: run `30738647448` completed successfully with both independent jobs (`Audit dependency lockfile` and `Validate`); later commits only synchronize closeout documentation.
- Codex Security diff scan: scan `68209414-195e-47e5-bd45-88bd257f1d48` reviewed `b70b42400a6234483bd353d1bbdad8f964d679ba...66908a4113f5bfa23e3c0b98a903067cd60193c2` with complete coverage. The sealed contract report contains one high-confidence Low/P3 information-disclosure finding (`CWE-200`) for the public intake catalog exposing an internal `ModuleCatalog.id`; two other candidates were validated and suppressed/ignored. The report was generated locally from the completed scan artifacts because the native workbench became terminal before indexing; no Critical, High, or Medium finding was reported.

## Migrations

`20260801090000_identity_access_foundation`, `20260801100000_add_intake_dedupe_controls`, `20260801110000_add_partial_application_state`, `20260801120000_account_security_verification`, `20260801130000_administrative_elevation`, `20260801140000_security_ui_keys`, `20260802090000_restrict_intake_database_access`, and `20260802100000_fix_intake_security_functions` are additive. Down-migrations and destructive rollback are not assumed safe; take and verify a backup before deployment.

No durable production migration was run. Migration deployment remains pending human role provisioning, verified operational backup policy, and authorized production smoke.

## Public catalog disclosure hotfix

- The Low/P3 `ModuleCatalog.id` disclosure (CWE-200) was fixed in implementation commit `d5e01c5e6f23538a32591dece35402142d9004e0` (`fix: remove internal module id from public catalog`).
- The public response now uses an explicit allowlisted projection containing only `key`, `name`, and `runtimeAvailability`; internal `id` remains available to repository logic for deduplication and module-decision persistence.
- The behavioral regression exercises the real handler-to-intake-repository catalog path, proves serialized `id` absence, preserves private-module exclusion and internal-ID submission/activation behavior in the database-role validation, and proves disabled or misconfigured intake remains fail-closed.
- Exact final CI for the fixing SHA: GitHub Actions run `30778813575` passed both `Validate` and `Audit dependency lockfile`.
- Intake remains disabled, email remains unconfigured, and no durable production migration occurred.

## Human enablement steps

1. Provision and verify restricted intake database credentials and grants; confirm the intake role cannot read private Core tables.
2. Deploy migrations against a backup, verify restore, then run DB integration and concurrency suites with PostgreSQL.
3. Select and configure a real email adapter, outbox encryption key, TOTP encryption key, abuse secret, public origin, and intake URL; keep test transport out of production.
4. Configure the owner’s second factor, separate administrative password, and offline administrative recovery codes through a human ceremony.
5. Configure public routing to the isolated intake service without host exposure, validate loopback-only origins, and run an authorized production smoke.
6. Confirm the post-remediation remote audit is green; do not use a breaking unrelated upgrade without review.
7. Only after all gates pass, change the explicit production feature flag and re-run the exact smoke and rollback checks.
