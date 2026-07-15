# Authentication Hardening

Phase 02.1 hardens the internal hub authentication layer without adding module unlocks, OAuth, public registration, Cloudflare credentials, or real secrets.

## Middleware Protection

`apps/hub/src/proxy.ts` protects hub routes by default. In Next.js 16 this proxy file is the supported replacement for the older middleware file convention.

Public paths:

- `/login`
- `/api/login`
- `/api/logout`
- `/api/health`
- static assets
- Next.js internal static/image assets

All other hub paths require the `bielos_session` cookie before the request proceeds. Logout bypasses only this cookie-presence proxy so its route can enforce Cloudflare Access first and then CSRF before any mutation.

The middleware runs in the Next.js middleware runtime and only checks for cookie presence. It does not query Prisma there. Actual session validity is checked in server code through `getSessionByToken`.

## Logout Validation

`POST /api/logout` first validates the required Cloudflare Access assertion and CSRF token, then reads the session cookie and validates it against the database before revocation. A direct-origin request without the required Access assertion returns HTTP `403` instead of being redirected by the session proxy.

If the cookie is missing, expired, revoked, or invalid, the route does not revoke anything. It still clears the browser cookie and redirects to `/login`.

## Rate Limit Strategy

Login uses a persistent database-backed limiter in `packages/auth`.

Current behavior:

- Keyed by a server-side HMAC of the normalized submitted login identifier.
- Stores no raw email, raw IP address, raw user agent, password, token, cookie, JWT, or Cloudflare value.
- Allows 5 failed attempts per 15-minute window per hashed identifier.
- Serializes same-identifier authentication attempts in PostgreSQL so concurrent failures cannot overwrite increments or exceed the verification limit.
- Limits PostgreSQL advisory-lock waits to 5 seconds and the authentication transaction to 15 seconds; timeout or database failure returns the generic fail-closed result.
- Clears the bucket after a successful login.
- Expires old buckets after 24 hours.
- Fails closed when the limiter cannot be checked, returning the same generic login failure to the browser.
- Returns the same generic login error to avoid revealing whether the email or password was wrong.

This keeps the limiter durable across hub restarts and shared by hub instances that use the same database and hash key. Password verification intentionally remains inside the locked transaction because moving it outside would allow more than five same-identifier verifications under concurrency. Database tests show bounded same-identifier completion, distinct-identifier independence, and fail-closed lock timeout. The accepted cost is holding one pool connection during Argon2 verification; the private Access boundary and current single hub replica keep this proportionate. Edge/IP controls remain future work.

Production requires `BIELOS_RATE_LIMIT_HASH_SECRET` in the private `.env` file as a stable private value. It is used only to HMAC login rate limit identifiers and must not be committed, logged, or shared. Production never derives this key from `DATABASE_URL` and never uses the synthetic development/test fallback. Missing production configuration fails closed with the generic login response. Rotating the key creates new buckets because no raw identifier exists to migrate; existing hashed buckets expire through normal retention.

Authentication prunes expired limiter rows with an indexed `expiresAt` delete before processing. Per-request cleanup remains appropriate for the current small private-hub volume and guarantees stale rows do not persist indefinitely; moving it into maintenance would add coordination without a reproduced operational benefit.

Real PostgreSQL route tests invoke `POST /api/login` with actual requests, forms, CSRF validation, limiter rows, redirects, session creation, response-cookie attributes, and sanitized audits. They cover required Access denial, missing/invalid CSRF, invalid and rate-limited credentials, missing fields, normalized success, inactive users, unavailable production configuration, and concurrent requests.

## CSRF Posture

Session cookies use `SameSite=Lax`, `HttpOnly`, and `Secure` in production.

Explicit CSRF tokens protect login, logout, Core project lifecycle mutations, Core project-access mutations, personal session mutations, and existing mutable GymForge flows. Missing or invalid CSRF tokens return HTTP `403` before state changes are attempted, and every future mutable browser route must add the same protection before shipping.

CSRF token values must not be logged, stored in audit metadata, or reused as session tokens. Signing material is process-local in the current single-hub-replica deployment, so a form created before a process restart may require reload. Multiple hub replicas would require shared signing material or another separately approved strategy.

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
- The dedicated production limiter key is configured privately and the closeout runtime is deployed; the value remains outside Git and operational output.
- Authenticated production OWNER browser smoke remains pending because interactive authentication was not completed. MEMBER smoke is blocked until an existing disposable MEMBER identity is available or creation is explicitly authorized. `CI remoto não confirmado.`
- No module-level sensitive unlock.
- No public registration, OAuth, email reset, or magic links.
