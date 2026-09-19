# Audit Logs

Phase 05 adds a minimal local audit log foundation for BielOS authentication and security events.

## What Is Logged

Audit logs may record:

- successful internal login
- failed internal login
- logout
- session revocation
- inactive session cleanup
- Cloudflare Access JWT validation success
- Cloudflare Access JWT validation failure
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
- raw Cloudflare Access headers
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
- Access JWT status, such as `valid`, `missing`, `invalid`, or `misconfigured`

Raw IP addresses are not stored. This avoids turning the audit log into a sensitive tracking dataset.

## Session Cleanup

The production `session-cleanup` worker runs the existing cleanup script on an interval. Its audit event is `AUTH_SESSION_CLEANUP` and metadata is limited to:

- source: `sessions-cleanup`
- deleted session count

It must not include session tokens, token hashes, cookies, raw IPs, JWTs, raw headers, or Cloudflare values.

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

For a new durable database, apply committed migrations with:

```bash
docker compose --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T hub npm run prisma:migrate:deploy
```

Do not seed fake audit data.

See `docs/database.md` for the migration workflow and the remaining disposable-local use of `prisma db push`.

## Current Behavior And Limitations

- The global `OWNER` has a private, read-only view with stable `(createdAt,id)` cursor pagination across the retained history. Each page is bounded to 50 rows.
- Filters are constrained to activity/infrastructure, time range, safe taxonomy category, result, actor kind, resource kind, event code, and bounded event/resource search. Unknown values fail closed to empty/default filters.
- Rows show human labels first. Technical event codes and category details are behind disclosure. No actor email, identifier, message, metadata, or private payload is exposed in the screen.
- Retention visibility shows the configured bounded retention window and oldest/newest retained timestamps. The cleanup worker still reports only a deleted-row count.
- OWNER-only export is a CSRF-protected sanitized CSV action bounded to 500 rows and records an `AUDIT_LOG_EXPORTED` event. Export contains timestamp, safe category, human event label, result, safe resource, and user/system actor state only.
- Local CLI inspection remains bounded and redacted. Cloudflare Access JWT validation is optional and depends on private environment configuration.

## Remaining boundaries

- Revisit the retention period only when operational requirements justify a change.
- Module-owned event detail remains in the owning module; Core does not copy module logs into the inbox or audit surface.
- Human authenticated visual acceptance is still required for layout, narrow-width behavior, and export interaction.
