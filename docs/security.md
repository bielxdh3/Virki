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
- A remembered-browser grant lasts at most seven days after strong verification. It may skip a repeat email/TOTP login ceremony on that trusted browser; it never substitutes for Cloudflare Access on the ADMIN host, an active ADMIN session, or action-scoped elevation. Remembered grants are revocable and are cleared by account recovery/deactivation.
- TOTP seeds and protected email/OIDC payloads are encrypted at rest with environment-held keys.
- TOTP setup, confirmation, disablement, recovery-code rotation, and account recovery use single-use or replay-protected proofs. High-risk ADMIN actions require current elevation where their action policy defines it.
- The separate ADMIN credential can be recovered only from an active ADMIN session using the normal account password and an unused one-time administrative recovery code. That flow rotates its ten replacement codes and revokes pending/active elevations. Cross-account recovery requires a different active ADMIN. Sole-ADMIN lockout is a real operational recovery gap classified `HARDENING_POST_DEPLOY`, not a general deployment gate: there is no in-product operator bypass, and an actual lockout requires stopping privileged operations and escalating to the system owner.
- The one-time `20260922090000_total_identity_security_rebaseline` transition invalidated active sessions and temporary elevations and revoked remembered devices while retaining credentials and MFA material. The current `20261001000000_security_polish` migration is additive: it revokes pending or verified device challenges and transforms recovery data, but does not revoke existing sessions, elevations, or remembered devices. Production migration history is reconciled only for the exact verified legacy ledger described in the deployment runbook; an unknown history fails closed.

## Authorization

- Roles are ADMIN and USER only. Anonymous visitors have no stored authority.
- Every protected ADMIN page checks Cloudflare Access, the current BielOS session, and the current role on the server. Mutating actions also check request origin and CSRF; fresh proof is required when the action policy specifies it.
- A USER receives only explicit project-entry grants. Disabled accounts, connections, or revoked grants deny authorization.
- Redirect URIs are exact HTTPS allowlist matches. Wildcards, credentials, fragments, and noncanonical values are rejected.
- Authorization state is rechecked by the issuer when it completes the OIDC interaction.
- Login and recovery throttles are keyed, persistent counters. Source-address limits can affect unrelated users sharing a NAT/proxy; trusted forwarding must be configured correctly and limits must not be weakened to hide that operational tradeoff.
- Public recovery responses are generic but not promised constant-time. Eligible accounts perform extra transactional work and queue mail; unknown/ineligible accounts return earlier. This remains a timing side channel and generic wording alone is not proof against account enumeration.

## OIDC profile

BielOS uses `oidc-provider` with Authorization Code, PKCE S256 required, short-lived one-time authorization codes, client binding, required state, and nonce for OpenID requests. It exposes only `openid`, `profile`, and `email` claims. Refresh tokens, client credentials, dynamic registration, request objects, device flow, and introspection are disabled; token revocation is supported.

Signing keys and the OIDC cookie key are private runtime configuration. Public JWKs are published by standard discovery/JWKS endpoints. Never place private JWK values in source, browser bundles, logs, or audit metadata. Keep stable key IDs and rotate keys through a tested overlap window that covers the maximum issued token lifetime.

The OIDC data-encryption key supports one bounded overlap key via `BIELOS_OIDC_ADAPTER_KEY_PREVIOUS`. New ciphertext is always written with `BIELOS_OIDC_ADAPTER_KEY`; reads may fall back to the previous key only during rotation. Operators should introduce the new current key while retaining the old value as previous, allow short-lived OIDC artifacts to expire and rotate stored project client secrets through the supported application flow, then remove the previous key. Do not keep an indefinite key ring.

## Audit and redaction

Audit entries contain event type, result, actor reference, resource, safe message, timestamp, and sanitized structured metadata. Connection/client references are hashed. Audit views use stable cursor pagination and event filters. Never record passwords, session values, cookies, TOTP seeds, recovery plaintext, client secrets, private keys, bearer tokens, or raw credential payloads.

Operational logs are summarized without returning their contents. Secret scans run in CI and locally before publication or deployment.

## Production hardening classifications

These are repository-side classifications; they do not assert that the live production headers or host have been inspected. Stronger CSP nonce/hash directives are a `HARDENING_POST_DEPLOY` item: the current Hub, public-site, and issuer configurations set `frame-ancestors 'none'` but do not configure nonce/hash-based script or style policies. HSTS currently sets `max-age=31536000` without `includeSubDomains` or `preload`; those extensions are also `HARDENING_POST_DEPLOY` and require an owner review of every affected hostname before adoption.

Account recovery bearer keys are already stored as SHA-256 `AccountRecoveryRequest.requestKeyHash` values, and the recovery flow hashes presented keys for lookup and comparison. The separate `SecurityElevation.requestKey` is stored in cleartext as a ceremony selector; it is bound to the current ADMIN user and session, limited to a pending and unexpired ceremony, and does not replace the emailed verification code. Hashing this distinct selector is bounded at-rest hardening classified `HARDENING_POST_DEPLOY`, not an evidenced authentication bypass or deployment gate. Do not describe account-recovery key hashing as missing or claim that all request-key fields are hashed.

## Verification limits

Automated tests cover the local authorization policy and OIDC adapter behavior. Deployment smoke checks the direct loopback OIDC discovery route and ADMIN boundary. External Cloudflare policy, DNS, and real account sign-in still require operator verification; do not infer them from a successful build.
