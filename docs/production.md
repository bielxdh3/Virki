# Production

Production is permanently hosted on the canonical remote Windows server through the trusted `servidor` OpenSSH alias (port 22). The development PC is not a production host.

## Development vs Production Compose

Development:

```bash
docker compose -f infra/docker-compose.yml up --build
```

The development compose file runs `npm run dev`. It is intended only for local development, and its host-published app ports are bound to loopback only:

- `127.0.0.1:${PUBLIC_SITE_PORT:-3000}:3000`
- `127.0.0.1:${HUB_PORT:-3001}:3001`

Production (remote server only):

```bash
npm run start:prod
```

Run `npm run preflight:prod` before any migration or deployment. The normal `*:prod` commands connect only to the remote server with non-interactive SSH, trusted host-key checking, repeated stability probes, and remote Docker checks. `npm run deploy:prod` transfers an exact clean `main` archive over SCP; the server-side runner requires its production-host marker, exact source-state marker, and full Git SHA before building. Fetch `origin` explicitly before deployment; the wrapper never pulls, resets, cleans, changes branches, or starts local production.

Production Compose also starts the isolated `intake`, `session-cleanup`, and `email-worker` services. Intake has no host-published port, receives only the restricted intake database URL, and defaults to disabled; it never receives the private Core `DATABASE_URL`. The workers have no published ports, depend on PostgreSQL health, and use the same private database environment as the hub. `session-cleanup` removes expired or revoked sessions every hour by default and applies audit log retention cleanup; `email-worker` polls the durable email outbox with bounded retries and the configured provider-neutral SMTP adapter.

Production host-published debug ports are also bound to loopback only:

- `127.0.0.1:${PUBLIC_SITE_PORT:-3000}:3000`
- `127.0.0.1:${HUB_PORT:-3001}:3001`

These bindings preserve local health checks while avoiding exposure on all host interfaces. Cloudflare Tunnel does not use these host-published ports when it runs inside Docker.

## Remote Production Validation

Run the remote deployment path:

```bash
npm run preflight:prod
npm run deploy:prod
npm run health:prod
npm run revision:prod
npm run status:ports
```

Then validate the basic behavior:

- Confirm the remote public site and hub health checks pass.
- Confirm `npm run status:ports` shows `127.0.0.1` bindings, never `0.0.0.0`.
- Confirm `hub.biel.dev.br` still reaches Cloudflare Access before BielOS internal authentication.
- If the release contains new migration files, run `prisma migrate deploy` from a separate tooling-capable operator environment with the private production `DATABASE_URL` after verifying a current backup. The production runtime image does not contain the Prisma CLI. This release contains no new migration files.
- Confirm login works with the seeded OWNER account through the live Access boundary.

Local `npm run health:local` remains disposable validation only and must not be used to start or accept BielOS production traffic.

## Do Not Expose `next dev`

`next dev` is not a production server. It is optimized for local feedback, verbose errors, source maps, file watching, and development behavior.

Only the production compose path should be used for a machine that is reachable beyond local development.

## Required Environment Variables

Production compose requires a private `.env` file. Do not commit it.

Required values:

- `DATABASE_URL`
- `POSTGRES_PASSWORD`
- `NEXT_PUBLIC_HUB_URL`

Recommended values:

- `POSTGRES_DB`
- `POSTGRES_USER`
- `PUBLIC_SITE_PORT`
- `HUB_PORT`
- `SESSION_CLEANUP_INTERVAL_SECONDS`
- `AUDIT_LOG_RETENTION_DAYS`
- `BIELOS_RATE_LIMIT_HASH_SECRET`
- `BIELOS_EMAIL_TRANSPORT`
- `BIELOS_EMAIL_OUTBOX_KEY`
- `BIELOS_EMAIL_SMTP_HOST`
- `BIELOS_EMAIL_SMTP_PORT`
- `BIELOS_EMAIL_SMTP_SECURE`
- `BIELOS_EMAIL_SMTP_USER`
- `BIELOS_EMAIL_SMTP_PASSWORD`
- `BIELOS_EMAIL_FROM`
- `BIELOS_EMAIL_REPLY_TO`
- `BIELOS_OWNER_EMAIL`
- `BIELOS_OWNER_PASSWORD`
- `CLOUDFLARE_ACCESS_JWT_REQUIRED`
- `CLOUDFLARE_ACCESS_AUDIENCE`
- `CLOUDFLARE_TEAM_DOMAIN`

`BIELOS_RATE_LIMIT_HASH_SECRET` is a private stable secret used to HMAC login, verification, and recovery rate limit identifiers. Do not commit, log, paste, or share a real value. Rotating it clears the practical continuity of existing rate limit buckets, which is acceptable.

## Cookie Security

The hub session cookie is `HttpOnly` and `SameSite=Lax`.

When `NODE_ENV=production`, the cookie is also marked `Secure`. That means browser delivery requires HTTPS in production.

## CI Validation

GitHub Actions validates the repository on pushes and pull requests to `main`.

CI has separate fail-closed dependency gates. The tooling gate consumes structured `npm audit --package-lock-only --json` output and accepts only the exact temporary GHSA-ggr8-5vv4-36mx path through `deepmerge-ts` 7.1.5, `@prisma/config` 6.19.3, and Prisma 6.19.3, including exact advisory metadata, paths, versions, severity, and vulnerability counts. Any drift or second advisory fails; a clean audit emits the exception-removal signal. It does not infer production reachability from the full development tree.

The production gate first installs a clean tree with `npm ci --omit=dev --omit=peer --omit=optional --ignore-scripts --no-audit`, then audits that actual tree and fails on any vulnerability or on Prisma CLI/config/deepmerge reachability while requiring `@prisma/client`. The production Docker build uses the same clean production-dependencies stage, then adds only the build-selected `tsx`/esbuild and musl Argon2 runtime closures plus generated Prisma client output; it never copies the full build `node_modules`. After the exact `org.opencontainers.image.revision` check, CI asserts that image boundary before the existing runtime and Compose gates. The GHSA remains tooling-only technical debt; human OWNER/MEMBER smoke remains a separate pending gate.

The secret scan is a private-repository MVP guardrail for obvious committed secrets. It does not require real Cloudflare, database, or owner credentials and must not be configured with real secret values.

## Production Revision Attestation

`infra/Dockerfile.prod` requires a lowercase 40-character `BIELOS_BUILD_REVISION` build argument and stores it only in the final image label `org.opencontainers.image.revision`. Missing, short, malformed, or non-lowercase revisions fail the build. Git metadata is not copied into the image, and the revision is not added to runtime environment variables, application responses, health data, headers, audit logs, or public metadata.

Use only the safe remote wrapper for production builds:

```bash
git fetch origin
npm run start:prod
npm run revision:prod
```

`npm run restart:prod` applies the same clean-source and SSH gates, then rebuilds/recreates the remote BielOS services without changing database migrations. `npm run revision:prod` verifies remote labels for `public-site`, `hub`, `intake`, `session-cleanup`, and `email-worker` against the accepted exact revision and never prints an unexpected observed value.

## Database Migrations

Production database updates use committed Prisma migrations from a separate tooling-capable operator environment:

```bash
npm run prisma:migrate:deploy
```

Supply the private production `DATABASE_URL` to that operator environment. Do not execute this inside the `hub` runtime container; it intentionally omits the Prisma CLI. `prisma db push` is only for disposable local databases. Do not use it for private, durable, or non-discardable production data.

## Database Backups

PostgreSQL backup and restore commands are documented in `docs/database.md`.

Backups must stay outside Git tracking. Do not commit dumps, copied database volumes, or backup archives. Restore validation must use a disposable database and should be repeated after meaningful schema or backup procedure changes.

## Cloudflare Status

Cloudflare Tunnel and Cloudflare Access are prepared through templates and documented for the confirmed Docker deployment path. Real Cloudflare credentials and dashboard configuration stay outside the repository.

Do not add Cloudflare account IDs, tunnel IDs, tokens, or Access policies to Git. Configure those later through private environment variables and external Cloudflare configuration.

Remote exposure must use the production compose file plus the Cloudflare compose override on `C:\BielOS`:

```bash
npm run start:prod
```

When `cloudflared` runs inside Docker, Cloudflare public hostname routes must use Docker service names:

- `biel.dev.br` -> `http://public-site:3000`
- `www.biel.dev.br` -> `http://public-site:3000`
- `hub.biel.dev.br` -> `http://hub:3001`

Do not use `localhost` in the Cloudflare dashboard for the Docker production path. Use `localhost` only if `cloudflared` is intentionally running directly on Windows outside Docker.

`hub.biel.dev.br` must remain protected by Cloudflare Access. Cloudflare Access is not a replacement for BielOS internal authentication, and BielOS internal authentication is not a replacement for Cloudflare Access. Both layers are required for the hub.

Exposing host port `3001` directly to the internet bypasses Cloudflare Access. If BielOS moves to a public Linux server or VPS, keep Docker ports bound to `127.0.0.1` and also block inbound internet access to `3000` and `3001` with the host firewall.

For hardened production, enable origin-side Access JWT validation in the private `.env` file:

```bash
CLOUDFLARE_ACCESS_JWT_REQUIRED=true
CLOUDFLARE_ACCESS_AUDIENCE=<Access application AUD tag>
CLOUDFLARE_TEAM_DOMAIN=https://<team-name>.cloudflareaccess.com
```

Keep `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` for local development outside Cloudflare Access. Never commit real Access values.

When origin-side Access JWT validation is enabled, denied hub page requests return HTTP `403` and render the Access unavailable screen. Docker and local health checks use `GET /api/health`, which stays minimal and does not require the Cloudflare Access JWT header.

`infra/Dockerfile.prod` is shared by both Next.js apps. Its default command starts the hub only as a manual fallback; production compose overrides `command` for both `public-site` and `hub`.

The `session-cleanup` service reuses the production image and runs a simple shell loop instead of a scheduler dependency:

```text
npm run sessions:cleanup --workspace @bielos/auth
```

The interval defaults to `3600` seconds and can be changed with `SESSION_CLEANUP_INTERVAL_SECONDS`. The worker must not publish ports and does not participate in Cloudflare Access or Tunnel routing.

The same worker runs audit log retention cleanup with `AUDIT_LOG_RETENTION_DAYS`, defaulting to `180`. It deletes only audit rows older than the retention cutoff and logs only the deleted-row count.

## Current Production Blockers

- Cloudflare Access JWT validation must be enabled with real private environment values and tested before treating the origin as production hardened.
- Edge-level or IP-based rate limiting is not configured in this repository.
- Restore validation is manual and must be repeated for future backup procedure changes.
- No TLS termination configured in this repository.
- Secret scanning and linting are basic MVP checks and should be expanded as the repository matures.

## Current production host state

The canonical production state is the remote `C:\BielOS` deployment. The development PC may retain its existing Docker volume as recovery data, but its BielOS production services must be stopped after remote acceptance and must not be restarted as production.

The current accepted remote revision is `ba1c80a05b76d8fc7539dcd90a47f8fa187ffd76`. Exact-SHA CI run `35630592690` passed all configured jobs, and the remote stack was rebuilt/restarted from that revision. Remote health, revision labels, loopback bindings, Cloudflare Tunnel process, disabled Intake state, and deManage preservation were verified after deployment. Authenticated human visual/behavior smoke remains the only open acceptance gate for the UI hotfix.

The current local dependency baseline is Next.js `16.3.5`, sharp `0.35.4`, and Nodemailer `10.0.10`. The production-tree audit is clean after omitting development dependencies; the accepted Prisma/deepmerge advisory remains constrained to the exact Prisma tooling path and is not a production dependency claim.
