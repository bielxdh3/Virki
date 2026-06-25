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

Protected routes:

- `POST /api/login`
- `POST /api/logout`

CSRF tokens are signed by the hub process and expire after a short lifetime. Failed CSRF validation returns HTTP `403` before login or logout state changes are attempted.

CSRF token values must not be logged, stored in audit metadata, exposed in API responses, or reused as session tokens. In the current MVP, CSRF signing material is process-local memory, so tokens created before a hub process restart may stop validating and the user may need to reload the form.

## Database

The schema stores session tokens as hashes and includes a separate security unlock model. IP addresses should not be stored directly; if needed, store a salted hash or avoid persistence.

`Session.ipHash` and `Session.userAgent` were removed because they were unused and misleading. AuditLog is the intended path for minimal security event context, and it stores only sanitized metadata such as hashed user agent values.

Production Compose runs a small `session-cleanup` worker that periodically deletes expired or revoked sessions. The worker uses the same private database environment as the hub, publishes no ports, and logs only the number of inactive sessions removed.

Login rate limiting stores only a keyed hash of the normalized submitted login identifier, attempt count, window timestamps, and expiration timestamp. It must not store raw email addresses, raw IP addresses, raw user agents, passwords, tokens, cookies, JWTs, or Cloudflare values. The limiter fails closed for login when the limiter cannot be checked, while still returning the same generic login failure to the browser.

Set `BIELOS_RATE_LIMIT_HASH_SECRET` in the private `.env` file as a stable private secret for HMAC hashing login rate limit identifiers. Do not commit, log, paste, or share a real value. Rotating this secret invalidates existing rate limit buckets, which is acceptable for this limiter.

## Audit Logging

BielOS records minimal local audit logs for internal auth and security operations. Logs include generic event types, results, optional actor user ids, optional email hashes, short messages, and small sanitized metadata.

Audit logs must not store passwords, session tokens, cookies, raw authorization headers, Cloudflare secrets, raw IP addresses, private paths, or database dumps.

Audit logging is fail-soft in the MVP: if an audit write fails, the application logs a safe server-side warning and keeps the user-facing auth flow working.

Audit retention defaults to `180` days through `AUDIT_LOG_RETENTION_DAYS`. Cleanup deletes only audit rows older than the retention cutoff by `createdAt` and prints only the deleted row count. It must not print audit metadata, identifiers, headers, cookies, tokens, JWTs, raw IPs, or private values.

See `docs/audit-logs.md`.

## Lint and Secret Scanning

CI runs a root lint command and a basic repository secret scan before typecheck, Prisma validation, and build.

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

## Module Shell

The private hub may show an internal module shell registry with planned module names and locked statuses. This shell must not include private data fields, upload inputs, module APIs, vault storage, ingestion flows, encryption/key management, audit log UI, or real module logic. Each real module must complete `docs/module-security-template.md` before implementation.

root.ark is planned differently from the private hub modules: it may become a public-facing zero-knowledge compartment system. That is higher risk and requires a dedicated architecture phase before implementation. The server and admin must not be able to decrypt user files, and audit logs must never include file contents, keys, raw links, raw tokens, passphrases, or sensitive filenames.

GymForge is planned as a gated social gym competition app, not a vault and not a public open internet app. Invited or admin-created participants may see approved group and competition data after entry, but GymForge data must not be exposed outside the gated site. Its MVP foundation includes schema, an authenticated hub route, read-only aggregate counts, linked viewer status, admin-only participant management, and admin-only exercise catalog management for BielOS OWNER or ADMIN users. GymForge mutations use CSRF protection and sanitized audit events. Check-in creation, uploads, workout entry, import/export, public registration, invite acceptance, and competition workflows remain blocked until scoped implementation phases add explicit authorization, validation, CSRF, rate limiting, and audit coverage.

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
- Validate database backup and restore procedures.
- Keep persistent login rate limiting enabled before multi-user or broader private use.
- Extend explicit CSRF protection to any future mutable hub routes before they ship.

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
