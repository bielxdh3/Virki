# Authentication Hardening

Phase 02.1 hardens the internal hub authentication layer without adding module unlocks, OAuth, public registration, Cloudflare credentials, or real secrets.

## Middleware Protection

`apps/hub/src/proxy.ts` protects hub routes by default. In Next.js 16 this proxy file is the supported replacement for the older middleware file convention.

Public paths:

- `/login`
- `/api/login`
- `/api/health`
- static assets
- Next.js internal static/image assets

All other hub paths require the `bielos_session` cookie before the request proceeds.

The middleware runs in the Next.js middleware runtime and only checks for cookie presence. It does not query Prisma there. Actual session validity is checked in server code through `getSessionByToken`.

## Logout Validation

`POST /api/logout` reads the session cookie and validates it against the database before revocation.

If the cookie is missing, expired, revoked, or invalid, the route does not revoke anything. It still clears the browser cookie and redirects to `/login`.

## Rate Limit Strategy

Login uses a persistent database-backed limiter in `packages/auth`.

Current behavior:

- Keyed by a server-side HMAC of the normalized submitted login identifier.
- Stores no raw email, raw IP address, raw user agent, password, token, cookie, JWT, or Cloudflare value.
- Allows 5 failed attempts per 15-minute window per hashed identifier.
- Clears the bucket after a successful login.
- Expires old buckets after 24 hours.
- Fails closed when the limiter cannot be checked, returning the same generic login failure to the browser.
- Returns the same generic login error to avoid revealing whether the email or password was wrong.

This keeps the limiter durable across hub restarts and shared by hub instances that use the same database and hash key.

## CSRF Posture

Session cookies use `SameSite=Lax`, `HttpOnly`, and `Secure` in production.

Login and logout are POST-only routes and require an explicit CSRF token. Missing or invalid CSRF tokens return HTTP `403` before login or logout state changes are attempted.

Extend explicit CSRF tokens before exposing broader write actions from the hub.

## Expired Session Cleanup

Sessions have explicit expiration timestamps, and logout sets `revokedAt`.

Cleanup command:

```bash
npm run sessions:cleanup
```

This deletes expired and revoked sessions from the database.

Production Compose also starts a `session-cleanup` worker that runs this command on an interval without publishing ports.

## Audit Logging

Login, logout, session revocation, session cleanup, OWNER seed, and Cloudflare Access JWT validation events write minimal audit logs. Audit metadata must not include passwords, session tokens, cookies, raw headers, raw IPs, JWTs, Cloudflare secrets, private paths, or database dumps.

## Cloudflare Access

Cloudflare Access is the outer boundary for `hub.biel.dev.br`, and BielOS internal auth remains the second layer. Optional origin-side Access JWT validation can reject hub requests with HTTP `403` when required and missing or invalid. The hub health endpoint stays available for local and Docker health checks.

## Remaining Limitations

- No edge-level or IP-based rate limit in this repository.
- No module-level sensitive unlock.
- No public registration, OAuth, email reset, or magic links.
