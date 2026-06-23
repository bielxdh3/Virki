# Audit Logs

Phase 05 adds a minimal local audit log foundation for BielOS authentication and security events.

## What Is Logged

Audit logs may record:

- successful internal login
- failed internal login
- logout
- session revocation
- inactive session cleanup
- OWNER seed creation
- OWNER seed update

Each audit row stores:

- timestamp
- event type
- result
- optional actor user id
- optional actor email hash
- optional resource
- short message
- small sanitized metadata

## What Is Not Logged

Audit logs must not store:

- plaintext passwords
- password hashes
- session tokens
- token hashes
- cookies
- raw authorization headers
- Cloudflare tokens
- Cloudflare JWTs
- tunnel credentials
- raw IP addresses
- private file paths
- database dumps

Failed login attempts store an email hash instead of a raw email address.

## Request Context

The current request context is intentionally small:

- event source, such as `hub-login` or `logout-route`
- Cloudflare Access presence as a boolean
- user agent hash, not the raw user agent

Raw IP addresses are not stored. This avoids turning the audit log into a sensitive tracking dataset.

## Fail-Soft Behavior

Audit logging is fail-soft for the MVP.

If an audit write fails, BielOS logs a safe server-side warning and continues the login, logout, seed, or cleanup flow. Audit logging must not lock the owner out of the hub.

## Inspect Recent Logs Locally

Use:

```bash
npm run audit:recent
```

This root command runs inside the `hub` container so it can reach the Docker PostgreSQL service.

The command prints a limited, redacted view:

- timestamp
- event type
- result
- resource
- short message
- actor user id, if present
- short actor email hash prefix, if present

To inspect more rows inside the container, run:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T -e BIELOS_AUDIT_RECENT_LIMIT=50 hub npm run audit:recent --workspace @bielos/auth
```

## Database Setup

Phase 05 adds the `AuditLog` Prisma model.

For an existing local database, apply the schema with:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run prisma:push
```

Do not seed fake audit data.

See `docs/database.md` for the current MVP `prisma db push` workflow and the migration requirement before private/non-discardable data ingestion.

## Current Limitations

- No audit log UI exists yet.
- No export workflow exists yet.
- No retention policy exists yet.
- Audit metadata is intentionally minimal.
- Cloudflare Access JWT validation at the origin is still not implemented.

## Future Improvements

- Add retention and cleanup policy.
- Add origin-side Cloudflare Access JWT validation.
- Add a private audit viewer after authorization rules are stronger.
- Add filtering by event type and time range for local inspection.
