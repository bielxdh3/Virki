# BielOS identity/access campaign validation

## Scope and status

The campaign started from `677c9622029e4a2e63d5fb10ce79eed7a5b3b157` and is published on `main`. The implementation is complete in source and disabled by default for production. The campaign is blocked from a full green closeout by unavailable local Docker/PostgreSQL and a remote lockfile audit failure on the pre-existing `sharp` dependency.

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
10. Adversarial validation, rollout, and publication — partial/blocking external validation only.

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
- `npm run build`: public site and hub passed, including login verification, recovery, account security, and administrative security routes.
- `git diff --check`: passed before publication.
- Core DB integration/concurrency suite: blocked before execution because the local Docker API was unavailable.
- Backup/restore evidence: not available; no production database was accessed or modified.
- Image and Compose runtime validation: not available locally because Docker was unavailable.
- Exact remote CI for `d62e4bb0dcba05116ac7320b7f9555c4abe56f76`: run `30733166826` failed at `Audit dependency lockfile` on the existing high-severity `sharp` advisory; all later CI steps were skipped. No unrelated dependency upgrade was made.

## Migrations

`20260801090000_identity_access_foundation`, `20260801100000_add_intake_dedupe_controls`, `20260801110000_add_partial_application_state`, `20260801120000_account_security_verification`, `20260801130000_administrative_elevation`, and `20260801140000_security_ui_keys` are additive. Down-migrations and destructive rollback are not assumed safe; take and verify a backup before deployment.

## Human enablement steps

1. Provision and verify restricted intake database credentials and grants; confirm the intake role cannot read private Core tables.
2. Deploy migrations against a backup, verify restore, then run DB integration and concurrency suites with PostgreSQL.
3. Select and configure a real email adapter, outbox encryption key, TOTP encryption key, abuse secret, public origin, and intake URL; keep test transport out of production.
4. Configure the owner’s second factor, separate administrative password, and offline administrative recovery codes through a human ceremony.
5. Configure public routing to the isolated intake service without host exposure, validate loopback-only origins, and run an authorized production smoke.
6. Resolve or formally accept the existing `sharp` audit finding before treating remote CI as green; do not use a breaking unrelated upgrade without review.
7. Only after all gates pass, change the explicit production feature flag and re-run the exact smoke and rollback checks.
