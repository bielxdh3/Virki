# Security

Security is a first-class requirement for BielOS.

## Current MVP Rules

- Do not commit real secrets.
- Do not create or commit a real `.env` file.
- Do not commit Cloudflare tokens, Gmail data, Google Takeout exports, logs, IP addresses, local private paths, database dumps, or backup archives.
- Keep public pages generic and free of private operational details.
- Use environment variables for all deployment-specific configuration.

## Authentication

The first scaffold includes only a login screen placeholder and auth package contracts. Real authentication must be implemented before the hub contains private data.

Planned layers:

- Application session management.
- Password or passphrase verification using strong hashing.
- Session token hashing at rest.
- Cloudflare Access as an outer boundary for the private hub.
- Security unlock flow for sensitive modules.

## Database

The schema stores session tokens as hashes and includes a separate security unlock model. IP addresses should not be stored directly; if needed, store a salted hash or avoid persistence.

`Session.ipHash` and `Session.userAgent` were removed because they were unused and misleading. AuditLog is the intended path for minimal security event context, and it stores only sanitized metadata such as hashed user agent values.

## Audit Logging

BielOS records minimal local audit logs for internal auth and security operations. Logs include generic event types, results, optional actor user ids, optional email hashes, short messages, and small sanitized metadata.

Audit logs must not store passwords, session tokens, cookies, raw authorization headers, Cloudflare secrets, raw IP addresses, private paths, or database dumps.

Audit logging is fail-soft in the MVP: if an audit write fails, the application logs a safe server-side warning and keeps the user-facing auth flow working.

See `docs/audit-logs.md`.

## Public Surface

The public site can show the BielOS name, short description, public cards, generic status, and an enter button. It must not expose private modules beyond approved generic references.

## Production Exposure Blockers

Do not expose the development server or `infra/docker-compose.yml` outside local development.

Before exposing BielOS beyond a local trusted network:

- Use `infra/docker-compose.prod.yml`, not the development compose file.
- Serve through HTTPS so production session cookies marked `Secure` are sent by browsers.
- Configure an external boundary such as Cloudflare Access.
- Do not expose `hub.biel.dev.br` unless Cloudflare Access is enabled and tested.
- Keep production debug ports bound to `127.0.0.1` only.
- Do not expose port `3001` directly to the internet; it bypasses Cloudflare Access.
- Keep BielOS internal authentication enabled behind Cloudflare Access.
- Keep the private `.env` file outside Git.
- On public Linux servers or VPS hosts, also block inbound access to ports `3000` and `3001` with the host firewall.
- Validate database backup and restore procedures.
- Add persistent or edge-level rate limiting before multi-user or internet-facing use.
- Add explicit CSRF protection before broader write workflows are implemented.

Cloudflare Access and BielOS internal authentication are separate layers. Access is not a replacement for internal auth, and internal auth is not a replacement for Access. Both are required for the private hub.

## Remote Exposure Hardening

Cloudflare Access protects `hub.biel.dev.br` at the edge before requests reach the BielOS Docker network.

BielOS internal authentication protects the hub inside the application after Access has allowed the request.

Phase 05.1 adds optional origin-side Cloudflare Access JWT validation for the hub. It reads the `cf-access-jwt-assertion` header, verifies the token against the Cloudflare Access JWKS endpoint for the configured team domain, checks issuer, audience, and expiration, and rejects the request when validation is required but missing or invalid.

Enable it only with private local environment values:

- `CLOUDFLARE_ACCESS_JWT_REQUIRED=true`
- `CLOUDFLARE_ACCESS_AUDIENCE=<Access application AUD tag>`
- `CLOUDFLARE_TEAM_DOMAIN=https://<team-name>.cloudflareaccess.com`

Keep `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development that does not run behind Cloudflare Access.

No raw JWTs, raw headers, Cloudflare tokens, or Access secrets should be logged or stored. This origin check does not replace BielOS internal authentication; both layers are still required for the hub.

Cloudflare Tunnel running inside Docker must route to Docker service names, not host ports. Host-published `127.0.0.1` ports are for local debugging and health checks only.
