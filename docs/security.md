# Security

Security is a first-class requirement for BielOS.

## Current MVP Rules

- Do not commit real secrets.
- Do not create or commit a real `.env` file.
- Do not commit Cloudflare tokens, Gmail data, Google Takeout exports, logs, IP addresses, local private paths, database dumps, or backup archives.
- Keep public pages generic and free of private operational details.
- Use environment variables for all deployment-specific configuration.

## Authentication

The hub uses BielOS internal authentication behind Cloudflare Access. Session cookies are HttpOnly and SameSite=Lax, and mutable hub forms use explicit CSRF tokens.

Current layers:

- Application session management.
- Password or passphrase verification using strong hashing.
- Session token hashing at rest.
- Persistent login rate limiting using privacy-safe identifier hashes.
- Cloudflare Access as an outer boundary for the private hub.
- Security unlock flow for sensitive modules.

## CSRF Protection

Internal BielOS hub forms include a server-generated CSRF token for mutable POST routes.

Protected mutation categories:

- login and logout;
- Core project lifecycle and project access;
- personal session management;
- existing mutable GymForge flows;
- every future mutable route before it ships.

CSRF tokens are signed by the hub process and expire after a short lifetime. Failed CSRF validation returns HTTP `403` before the protected state change is attempted.

CSRF token values must not be logged, stored in audit metadata, exposed in API responses, or reused as session tokens. In the current MVP, CSRF signing material is process-local memory, so tokens created before a hub process restart may stop validating and the user may need to reload the form.

## Database

The schema stores session tokens as hashes and includes a separate security unlock model. IP addresses should not be stored directly; if needed, store a salted hash or avoid persistence.

`Session.ipHash` and `Session.userAgent` were removed because they were unused and misleading. AuditLog is the intended path for minimal security event context, and it stores only sanitized metadata such as hashed user agent values.

Production Compose runs a small `session-cleanup` worker that periodically deletes expired or revoked sessions. The worker uses the same private database environment as the hub, publishes no ports, and logs only the number of inactive sessions removed.

Login rate limiting stores only a keyed hash of the normalized submitted login identifier, attempt count, window timestamps, and expiration timestamp. Login transactions for the same identifier are serialized with a PostgreSQL transaction-scoped advisory lock, retained attempts are capped at five, advisory-lock waits are limited to five seconds, and the authentication transaction is limited to 15 seconds. Password verification remains inside that boundary to preserve the strict concurrent verification cap; distinct identifiers use independent locks. It must not store raw email addresses, raw IP addresses, raw user agents, passwords, tokens, cookies, JWTs, or Cloudflare values. The limiter fails closed for login when configuration, locking, or database access is unavailable while returning the same generic login failure to the browser.

Production requires `BIELOS_RATE_LIMIT_HASH_SECRET` in the private `.env` file as a stable private secret for HMAC hashing login rate limit identifiers. Production does not derive it from `DATABASE_URL` or use the synthetic development/test fallback. Missing or empty production configuration fails closed with the generic login response. Do not commit, log, paste, or share a real value. Rotating this secret creates new buckets; old hashed buckets expire through normal retention and cannot be migrated because raw identifiers are not stored.

## Audit Logging

BielOS records minimal local audit logs for internal auth and security operations. Logs include generic event types, results, optional actor user ids, optional email hashes, short messages, and small sanitized metadata.

Audit logs must not store passwords, session tokens, cookies, raw authorization headers, Cloudflare secrets, raw IP addresses, private paths, or database dumps.

Audit logging is fail-soft in the MVP: if an audit write fails, the application logs only a fixed generic server-side warning and keeps the user-facing auth flow working. Auth maintenance commands use a shared bounded runner that discards operation and disconnect exceptions, attempts database disconnect, sets a nonzero exit state, and emits only a fixed command-specific message.

Audit retention defaults to `180` days through `AUDIT_LOG_RETENTION_DAYS`. Cleanup deletes only audit rows older than the retention cutoff by `createdAt` and prints only the deleted row count. It must not print audit metadata, identifiers, headers, cookies, tokens, JWTs, raw IPs, or private values.

See `docs/audit-logs.md`.

## Lint and Secret Scanning

CI runs secret scan, lint, typecheck, Prisma validation, Core unit tests, migrated PostgreSQL integration tests, real concurrency tests, build, production image build, and production Compose validation. The Core database suites use one synthetic PostgreSQL service and do not require production secrets.

The current hardening campaign passed the complete local gate, production image and Compose checks, production restart, unauthenticated health/Access checks, and loopback exposure checks. `CI remoto não confirmado.` for the consulted runtime and documentation SHAs because authenticated GitHub Actions evidence was unavailable.

The subsequent closeout and origin-authentication gate passed 35 unit, 47 aggregate database, 35 integration, and 12 concurrency tests plus build, production image, and production Compose validation. The dedicated limiter key remains only in the ignored private environment, and production was rebuilt after runtime fix commit `5f66fbb8640cf907338c5c6c27aa96f002ba0f77` with current migrations. Exact image-to-commit provenance remains operationally inferred because the image has no trustworthy revision label. All expected services run, public/local health passes, Cloudflare Access remains first, direct-origin login and logout requests without the required assertion return `403`, and application ports remain loopback-only. Authenticated OWNER smoke remains pending; MEMBER smoke is blocked by the absence of a disposable MEMBER identity.

Run locally:

```bash
npm run lint
npm run secrets:scan
```

The secret scan checks tracked files for obvious sensitive paths and content patterns, including real `.env` files, Cloudflare credential JSON files, Cloudflare token assignments, JWT-like values, private keys, database dumps, Google Takeout or Gmail export paths, database URLs with non-placeholder passwords, and common API key formats.

The scanner reports only file, line, and rule id. It must not print the matched secret value.

This is an MVP guardrail for committed files and new non-ignored local files. It does not replace careful review, GitHub secret scanning if enabled for the private repository, or a full historical repository scan.

## Public Surface

The public site can show the BielOS name, short description, public cards, generic status, and an enter button. It must not expose private modules beyond approved generic references.

## Core And Application Registry

The private hub contains BielOS Core and an application registry. GymForge is an available authenticated application. L-vault, root.ark, and H-vault remain inert reserved modules and must not gain routes, storage, ingestion, or runtime behavior without a separately approved design.

The UI language selector stores only an allowlisted locale value in the `bielos_locale` cookie. Supported values are `pt-BR` and `en`, with `pt-BR` as the fallback when the cookie is missing, invalid, or unsupported. On `biel.dev.br` and `hub.biel.dev.br`, the cookie may use the shared `.biel.dev.br` domain so the public site and private hub can honor the same preference. The cookie must not contain user identity, session data, secrets, tokens, or tracking identifiers.

root.ark is planned differently from the private hub modules: it may become a public-facing zero-knowledge compartment system. That is higher risk and requires a dedicated architecture phase before implementation. The server and admin must not be able to decrypt user files, and audit logs must never include file contents, keys, raw links, raw tokens, passphrases, or sensitive filenames.

GymForge is a gated social gym competition app, not a vault or public open internet app. Its private-hub MVP includes participant/exercise administration, attendance and workout flows, ranking/streak views, competition lifecycle/assignment, deterministic current-state scoring, and additive score correction. Existing Cloudflare Access, BielOS auth, CSRF, role checks, fixed `America/Sao_Paulo` date policy, sanitized audits, and private visibility remain mandatory.

Further GymForge expansion is frozen. Upload/photo proof, public registration, invitations, import/export, a public API, broad social behavior, and further scoring work remain blocked.

## BielOS Core Security Contract

- Cloudflare Access remains the first private-hub boundary; BielOS internal authentication and active-user checks remain the second.
- Global `OWNER` and `ADMIN` users manage project lifecycle. An active `MEMBER` sees authenticated-hub `PUBLIC` projects or projects with an explicit `ProjectAccess` row; descriptions are never returned for unauthorized projects.
- Core project reads require the supplied role to match the active persisted user role, so a crafted or stale principal cannot widen read scope.
- Project access levels do not grant global administration. Global `OWNER` may manage all levels; global `ADMIN` is limited to `VIEWER` and `EDITOR`; global `MEMBER` cannot manage access. Every project retains at least one project-owner row.
- Projects are archived rather than permanently deleted. Archived projects and their access history remain read-only in the initial Core runtime.
- Every mutation rechecks server-side authorization, validates CSRF, validates bounded allowlisted values, and returns generic failures without confirming hidden resources.
- Core audits contain only allowlisted event types, enum values, aggregate counts, and stable hashed resource references. They exclude names, slugs, descriptions, emails, raw identifiers, raw forms, secrets, cookies, tokens, token hashes, JWTs, headers, IPs, environment values, database URLs, logs, and unrestricted free text.
- Personal session management at `/core/security` selects only active-session identifiers, safe timestamps, and current-session state; revoked and expired rows are excluded. Users cannot inspect another user's sessions, current-session revocation is excluded from this surface, all-other revocation requires explicit confirmation, and administrators receive no broad session-spying capability.
- The audit activity view at `/core/security` is read-only and visible only to the global `OWNER`. It selects at most 50 newest rows and renders only allowlisted event/result values, safe resource categories, timestamps, and generic user/system actor state; unknown values collapse to generic labels, and raw metadata, messages, emails, and identifiers are not selected for the view.
- Operations UI reports only the current request/session and a timeout-bounded minimal database check as verified. Configured architecture and external/manual deployment checks are labeled separately. It does not access the Docker socket, raw logs, environment values, private Cloudflare identifiers, or external network services during page rendering; unknown state stays explicit.
- Core database tests run only against explicitly disposable test identities on allowlisted local/CI hosts, apply committed migrations, use synthetic fixtures, and remove their local Compose project even after failure.
- `SecurityUnlock` runtime behavior remains blocked by the completed design-only gate in `docs/security-unlock.md` because challenge issuance, approval, consumption, denial, recovery, and rate-limit semantics are not sufficiently defined. It can only become an additional scoped gate, never a replacement for existing access boundaries.

The complete contract is in `docs/modules/bielos-core.md`.

## GymForge Competition Score-Correction Security Contract

Competition score-correction Phase 2 design and Phase 3 implementation are `[DONE]`.

Private invitations are frozen with the rest of optional GymForge expansion.

- Automatic `baseScore` remains derived from current attendance, competition dates/rule, assignment, and ACTIVE participant state. Separate correction rows are additive only and never mutate attendance, workout, assignment, competition, or other source rows.
- Each correction delta is a nonzero integer in `-1000..1000`; all unrevoked rows sum into `activeAdjustment`, and `finalScore = baseScore + activeAdjustment` may be negative. Allowed attendance or competition metadata changes may recompute the current base, so the UI always separates current base, aggregate adjustment, and final score.
- Participants see only current base, aggregate adjustment, and final score. OWNER/ADMIN users use a compact private history/reason/revoke drawer. Both surfaces are available in PT-BR and English; there is no public route or GymForge API.
- Every correction mutation and guarded assignment, reactivation, or competition-status mutation rechecks server-side `OWNER` or `ADMIN`, validates CSRF, and returns generic user-facing failures. Creation uses an opaque UUID v4 `requestKey`; replay is idempotent, conflicting reuse fails generically, and keys are never logged, displayed, audited, or exported.
- Creation is limited to `ACTIVE` or `ENDED` competitions and currently assigned ACTIVE participants. Revocation is limited to `ACTIVE`, `ENDED`, or `ARCHIVED`; `DRAFT` rejects both mutation types.
- Creation is append-only, with no edit or hard delete. Revocation records `revokedAt` and `revokedByUserId`. Assignment removal is blocked until all active corrections for that pair are revoked; it must not implicitly revoke or alter source data.
- Disabled or archived participants are excluded from current scoring while history is retained. Reactivation with retained unrevoked corrections is blocked until explicit revocation, and reassignment cannot silently reactivate old rows because removal required revocation first. Moving a competition to `DRAFT` is likewise blocked while active corrections exist.
- Correction creation/revocation, assignment removal, reactivation, and `DRAFT` checks use serializable transactions with three bounded retries and generic failure handling.
- The additive `GymForgeCompetitionScoreCorrection` model stores correction id, competition/participant references, delta, optional admin reason, unique request key, nullable create/revoke actor references, and timestamps. Competition/participant relations restrict deletion. Actor relations use `SET NULL`; `revokedAt` remains authoritative when a revoker account is later removed.
- The additive migration indexes active pair and competition/participant history lookups and enforces nonzero bounded `pointsDelta`, reason length, request-key length, and valid revocation shape. Empty reasons normalize to null.
- The optional reason is private admin context. It is never shown to participants, included in audit logs, or exported by default.
- Correction-created and correction-revoked audits contain only stable hashed competition, participant, and correction references plus a generic result. They omit the raw audit actor id and all actor ids from metadata; actor attribution stays on the correction row. They never contain raw ids, names, reason, delta, score values, request keys, raw forms, or raw request data.
- Correction/revocation history is retained. Permanent competition deletion is blocked whenever any correction row exists, and restrictive participant history prevents cascade deletion.
- Ranking remains deterministic by final score, attendance count, longest streak, latest qualifying check-in, display-name sort, and finally internal participant id only as a non-displayed fallback.
- The committed additive migration was applied to production with `prisma migrate deploy` after a current custom-format PostgreSQL backup was created and verified; the post-deploy migration status is current.
- After the first correction write, dropping the table or rolling the application back to a pre-Phase-3 commit is unsafe because assignment, reactivation, and `DRAFT` guards live in the new runtime. Recovery requires a forward fix or verified restore.
- Eight focused scoring cases plus secret scan, lint, typecheck, Prisma validation, and production build pass. Local/public health, Cloudflare-first ordering, container state, and loopback exposure were verified after deploy; authenticated runtime smoke remains a manual follow-up because no authenticated browser session was available to the automation.

## Production Exposure Blockers

Do not expose the development server or `infra/docker-compose.yml` outside local development. Development compose host ports must stay bound to `127.0.0.1`.

Before exposing BielOS beyond a local trusted network:

- Use `infra/docker-compose.prod.yml`, not the development compose file.
- Serve through HTTPS so production session cookies marked `Secure` are sent by browsers.
- Configure an external boundary such as Cloudflare Access.
- Do not expose `hub.biel.dev.br` unless Cloudflare Access is enabled and tested.
- Keep development and production debug ports bound to `127.0.0.1` only.
- Do not expose port `3001` directly to the internet; it bypasses Cloudflare Access.
- Keep BielOS internal authentication enabled behind Cloudflare Access.
- Keep the private `.env` file outside Git.
- On public Linux servers or VPS hosts, also block inbound access to ports `3000` and `3001` with the host firewall.
- Keep the production `session-cleanup` worker enabled so expired or revoked sessions do not accumulate indefinitely.
- Repeat disposable backup/restore validation after meaningful schema or procedure changes.
- Keep persistent login rate limiting enabled before multi-user or broader private use.
- Preserve explicit CSRF protection on every current and future mutable hub route.

Cloudflare Access and BielOS internal authentication are separate layers. Access is not a replacement for internal auth, and internal auth is not a replacement for Access. Both are required for the private hub.

## Remote Exposure Hardening

Cloudflare Access protects `hub.biel.dev.br` at the edge before requests reach the BielOS Docker network.

BielOS internal authentication protects the hub inside the application after Access has allowed the request.

Phase 05.1 adds optional origin-side Cloudflare Access JWT validation for the hub. It reads the `cf-access-jwt-assertion` header, verifies the token against the Cloudflare Access JWKS endpoint for the configured team domain, checks issuer, audience, and expiration, and rejects the request when validation is required but missing or invalid.

Denied hub page requests return HTTP `403` with the Access unavailable screen. API login/logout denials also return HTTP `403`.

Enable it only with private local environment values:

- `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`
- `CLOUDFLARE_ACCESS_AUDIENCE=<Access application AUD tag>`
- `CLOUDFLARE_TEAM_DOMAIN=https://<team-name>.cloudflareaccess.com`

Keep `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development that does not run behind Cloudflare Access.

No raw JWTs, raw headers, Cloudflare tokens, or Access secrets should be logged or stored. This origin check does not replace BielOS internal authentication; both layers are still required for the hub.

The hub health endpoint, `GET /api/health`, is intentionally excluded from Cloudflare Access JWT validation so Docker and local health checks remain stable. It must stay limited to minimal liveness status and must not expose environment values, database URLs, Cloudflare configuration, user/session data, tokens, headers, cookies, or private operational data.

Cloudflare Tunnel running inside Docker must route to Docker service names, not host ports. Host-published `127.0.0.1` ports are for local debugging and health checks only.
