# Security model

## Boundaries

- Unknown hosts and unauthenticated protected routes fail closed.
- The ADMIN host requires Cloudflare Access and then validates the Access JWT and BielOS ADMIN session server-side.
- The USER portal does not require the ADMIN Access assertion.
- Application ports bind to loopback. PostgreSQL and the OIDC issuer have no host-published ports.
- A project receives its own OIDC result, never the BielOS session cookie.

## Authentication and sessions

- Passwords use Argon2id. Authentication failures are generic and rate-limited.
- Session tokens are opaque, stored as hashes, rotated on authentication, and revocable.
- Cookies are host-only, HttpOnly, SameSite=Lax, and Secure in production.
- TOTP seeds and protected email/OIDC payloads are encrypted at rest with environment-held keys.
- TOTP setup, confirmation, disablement, recovery-code rotation, and account recovery use single-use or replay-protected proofs. High-risk ADMIN actions require current elevation where their action policy defines it.
- The one-time `20260922090000_total_identity_security_rebaseline` transition invalidated active sessions and temporary elevations and revoked remembered devices while retaining credentials and MFA material. The current `20261001000000_security_polish` migration is additive: it revokes pending or verified device challenges and transforms recovery data, but does not revoke existing sessions, elevations, or remembered devices. Production migration history is reconciled only for the exact verified legacy ledger described in the deployment runbook; an unknown history fails closed.

## Authorization

- Roles are ADMIN and USER only. Anonymous visitors have no stored authority.
- Every protected ADMIN page and action checks Cloudflare Access, the BielOS session, role, CSRF token, and any required fresh proof on the server.
- A USER receives only explicit project-entry grants. Disabled accounts, connections, or revoked grants deny authorization.
- Redirect URIs are exact HTTPS allowlist matches. Wildcards, credentials, fragments, and noncanonical values are rejected.
- Authorization state is rechecked by the issuer when it completes the OIDC interaction.

## OIDC profile

BielOS uses `oidc-provider` with Authorization Code, PKCE S256 required, short-lived one-time authorization codes, client binding, required state, and nonce for OpenID requests. It exposes only `openid`, `profile`, and `email` claims. Refresh tokens, client credentials, dynamic registration, request objects, device flow, and introspection are disabled; token revocation is supported.

Signing keys and the OIDC cookie key are private runtime configuration. Public JWKs are published by standard discovery/JWKS endpoints. Never place private JWK values in source, browser bundles, logs, or audit metadata. Keep stable key IDs and rotate keys through a tested overlap window that covers the maximum issued token lifetime.

## Audit and redaction

Audit entries contain event type, result, actor reference, resource, safe message, timestamp, and sanitized structured metadata. Connection/client references are hashed. Audit views use stable cursor pagination and event filters. Never record passwords, session values, cookies, TOTP seeds, recovery plaintext, client secrets, private keys, bearer tokens, or raw credential payloads.

Operational logs are summarized without returning their contents. Secret scans run in CI and locally before publication or deployment.

## Verification limits

Automated tests cover the local authorization policy and OIDC adapter behavior. Deployment smoke checks the direct loopback OIDC discovery route and ADMIN boundary. External Cloudflare policy, DNS, and real account sign-in still require operator verification; do not infer them from a successful build.
