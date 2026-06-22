# Authentication Hardening

Phase 02.1 hardens the internal hub authentication layer without adding module unlocks, OAuth, public registration, Cloudflare credentials, or real secrets.

## Middleware Protection

`apps/hub/src/proxy.ts` protects hub routes by default. In Next.js 16 this proxy file is the supported replacement for the older middleware file convention.

Public paths:

- `/login`
- `/api/login`
- static assets
- Next.js internal static/image assets

All other hub paths require the `bielos_session` cookie before the request proceeds.

The middleware runs in the Next.js middleware runtime and only checks for cookie presence. It does not query Prisma there. Actual session validity is checked in server code through `getSessionByToken`.

## Logout Validation

`POST /api/logout` reads the session cookie and validates it against the database before revocation.

If the cookie is missing, expired, revoked, or invalid, the route does not revoke anything. It still clears the browser cookie and redirects to `/login`.

## Rate Limit Strategy

Login uses a basic in-memory limiter in `packages/auth`.

Current behavior:

- Keyed by normalized email.
- Allows 5 failed attempts per 15-minute window.
- Clears the counter after a successful login.
- Returns the same generic login error to avoid revealing whether the email or password was wrong.

This is suitable for a local/self-hosted MVP with a single application process. It is not durable across restarts and is not shared across multiple app instances.

Persistent database-backed rate limiting is intentionally not added yet because it would require a new table or schema change. Add it when deployment shape and abuse requirements are clearer.

## CSRF Posture

Session cookies use `SameSite=Lax`, `HttpOnly`, and `Secure` in production.

Login and logout are POST-only routes. The current MVP does not include a dedicated CSRF token. SameSite cookie behavior is the current baseline.

Add explicit CSRF tokens before exposing broader write actions from the hub.

## Expired Session Cleanup

Sessions have explicit expiration timestamps, and logout sets `revokedAt`.

Cleanup command:

```bash
npm run sessions:cleanup
```

This deletes expired and revoked sessions from the database.

## Remaining Limitations

- No persistent distributed rate limit.
- No CSRF token beyond SameSite cookie posture.
- No audit log for login/logout events.
- No module-level sensitive unlock.
- No Cloudflare Access integration yet.
- No public registration, OAuth, email reset, or magic links.
