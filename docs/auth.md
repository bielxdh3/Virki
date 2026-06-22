# Authentication

BielOS Phase 02 adds internal application authentication for the private hub.

Cloudflare Access is still planned as an external boundary later. This phase only implements the internal session layer used by `apps/hub`.

## Architecture

- Auth logic lives in `packages/auth`.
- Database access is performed through `packages/database`.
- The hub reads and writes the session cookie through Next.js server actions and server components.
- The public site does not use or expose authentication details.

## Password Hashing

Passwords are hashed with Argon2id through the `@node-rs/argon2` package.

Only password hashes are stored in the `User.passwordHash` field. Plaintext passwords are accepted only at login or during local seed execution and are not persisted.

## Session Storage

Successful login generates a cryptographically secure random session token.

The raw token is sent to the browser as a cookie. The database stores only a SHA-256 hash of that token in `Session.tokenHash`.

Sessions have an explicit expiration timestamp. Logout revokes the current session by setting `Session.revokedAt`.

## Cookie Behavior

The session cookie is named `bielos_session`.

Cookie settings:

- `HttpOnly`
- `SameSite=Lax`
- `Secure` in production
- Path `/`
- Explicit expiration matching the database session expiration

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
- Cloudflare Access integration
- Module-level sensitive unlocks
- Audit logs
- Rate limiting
