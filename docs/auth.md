# Authentication

BielOS Phase 02 adds internal application authentication for the private hub.

Cloudflare Access protects the private Hub as the external boundary, and this document describes the internal session layer used by `apps/hub` behind it.

## Architecture

- Auth logic lives in `packages/auth`.
- Database access is performed through `packages/database`.
- The hub reads and writes the session cookie through Next.js route handlers and server components.
- Middleware protects private hub routes by default before the request reaches route handlers or pages.
- The public site does not use or expose authentication details.
- Trusted-device verification and a bounded server-side remembered-browser grant are separate from ordinary sessions.

## Password Hashing

Passwords are hashed with Argon2id through the `@node-rs/argon2` package.

Only password hashes are stored in the `User.passwordHash` field. Plaintext passwords are accepted only at login or during local seed execution and are not persisted.

## Session Storage

Successful login generates a cryptographically secure random session token.

The raw token is sent to the browser as a cookie. The database stores only a SHA-256 hash of that token in `Session.tokenHash`.

Sessions have an explicit expiration timestamp. Logout revokes the current session by setting `Session.revokedAt`.

Expired and revoked sessions can be removed with:

```bash
npm run sessions:cleanup
```

## Cookie Behavior

The session cookie is named `bielos_session`.

Cookie settings:

- `HttpOnly`
- `SameSite=Lax`
- `Secure` in production
- Path `/`
- Explicit expiration matching the database session expiration

## Remembered-browser behavior

After a new or known browser completes the required email/TOTP ceremony, its trusted-device row may carry a server-side remembered-browser grant for seven absolute days. A password is still required after logout. A valid grant can create a new ordinary session without repeating email or TOTP; expiry, revocation, account recovery, password reset, TOTP changes, account blocking/deactivation, and revoke-all security actions invalidate it. Administrative elevation is never remembered by this mechanism.

## Seed Flow

The first OWNER user is created locally with:

```bash
npm run seed:owner
```

Required environment variables:

- `BIELOS_OWNER_EMAIL`
- `BIELOS_OWNER_PASSWORD`

The seed command upserts the OWNER user and hashes the password with Argon2id. Never commit a real `.env` file or real seed credentials.

## Not Implemented Yet

- Public registration
- OAuth
- Email password reset
- Magic links
- Module-level sensitive unlocks
