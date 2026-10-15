# Security model

## Boundaries

- Unknown hosts and unauthenticated protected routes fail closed.
- The ADMIN host requires Cloudflare Access and then validates the Access JWT and Virki ADMIN session server-side.
- The USER portal does not require the ADMIN Access assertion.
- Application ports bind to loopback. PostgreSQL and the OIDC issuer have no host-published ports.
- A project receives its own OIDC result, never the Virki session cookie.

## Authentication and sessions

- Passwords use Argon2id. Authentication failures are generic and rate-limited.
- Session tokens are opaque, stored as hashes, rotated on authentication, and revocable.
- Cookies are host-only, HttpOnly, SameSite=Lax, and Secure in production.
- Password verification (Argon2id) runs outside database transactions: a short transaction reserves the attempt on the per-attempt and per-account counters, the hash is checked without holding locks, and only a verified password clears the counters. Unknown or ineligible accounts still verify against a dummy hash.
- A browser becomes a trusted device only after the whole login ceremony succeeds: email proof for EMAIL accounts, email proof plus TOTP for TOTP accounts. A remembered-browser grant is created at that point and lasts at most seven days. It may skip a repeat USER login ceremony on that browser; ADMIN logins never use it and always complete a fresh second factor. It never substitutes for Cloudflare Access on the ADMIN host, an active ADMIN session, or action-scoped elevation. Remembered grants are revocable and are cleared by account recovery/deactivation.
- Login ceremonies that mail a code are budgeted even after a correct password: six per 15 minutes per trusted device (or per account for untrusted browsers) and twenty per source address. A repeated start from the same browser within 60 seconds reuses the pending ceremony instead of mailing another code. Exhausted budgets produce the same generic login failure.
- Emailed one-time codes are stored only as keyed (`h2:`) digests; unkeyed legacy digests are rejected.
- TOTP seeds and protected email/OIDC payloads are encrypted at rest with environment-held keys.
- TOTP setup, confirmation, disablement, recovery-code rotation, and account recovery use single-use or replay-protected proofs. High-risk ADMIN actions require current elevation where their action policy defines it.
- The separate ADMIN credential must differ from the normal account password at setup, change, and recovery (checked with the stored Argon2 hash), and an ADMIN account recovery cannot set a normal password equal to the active ADMIN credential. An ADMIN whose two passwords are still equal can elevate only to change the ADMIN credential. An elevation's duration starts when its emailed code is verified, not when it is requested.
- The separate ADMIN credential can be recovered only from an active ADMIN session using the normal account password and an unused one-time administrative recovery code. That flow rotates its ten replacement codes and revokes pending/active elevations. Cross-account recovery requires a different active ADMIN. Sole-ADMIN lockout is a real operational recovery gap classified `HARDENING_POST_DEPLOY`, not a general deployment gate: there is no in-product operator bypass, and an actual lockout requires stopping privileged operations and escalating to the system owner.
- The one-time `20260922090000_total_identity_security_rebaseline` transition invalidated active sessions and temporary elevations and revoked remembered devices while retaining credentials and MFA material. The current `20261001000000_security_polish` migration is additive: it revokes pending or verified device challenges and transforms recovery data, but does not revoke existing sessions, elevations, or remembered devices. Production migration history is reconciled only for the exact verified legacy ledger described in the deployment runbook; an unknown history fails closed.

## Authorization

- Roles are ADMIN and USER only. Anonymous visitors have no stored authority.
- Every protected ADMIN page checks Cloudflare Access, the current Virki session, and the current role on the server. Mutating actions also check request origin and CSRF; fresh proof is required when the action policy specifies it.
- A USER receives only explicit project-entry grants. Disabled accounts, connections, or revoked grants deny authorization.
- Redirect URIs are exact HTTPS allowlist matches. Wildcards, credentials, fragments, and noncanonical values are rejected.
- Authorization state is rechecked by the issuer when it completes the OIDC interaction.
- Login and recovery throttles are keyed, persistent counters. Source-address limits can affect unrelated users sharing a NAT/proxy; trusted forwarding must be configured correctly and limits must not be weakened to hide that operational tradeoff. The issuer's `/auth` limit gives each browser carrying a central session cookie its own bucket (30 per 15 minutes) under a 300-per-source ceiling, so many signed-in users behind one NAT address are not throttled together; cookie-less requests share the 30-per-source bucket. `/token` and `/token/revocation` are limited to 600 per 15 minutes per source address and client. These source keys rely on `cf-connecting-ip`, which is trustworthy only because every public request reaches the hosts through the Cloudflare tunnel; per-account and per-device limits do not depend on it.
- Public recovery requests take at least 500 ms whether or not the account exists, masking the extra transactional work done for eligible accounts. Database stalls longer than that floor can still leak timing; generic wording plus the floor reduces, but does not prove the absence of, account enumeration.
- A public recovery request never expires another request. While the owner holds an email-verified request (awaiting approval or approved), new requests are not created. Verifying one request expires the owner's other unverified requests; approval expires the remaining pending ones; completion expires every sibling. Approval rotates the secret request key and emails a new one-time link; the page opened with the previous link does not unlock.
- New USER accounts are invited, not given an administrator-chosen password: the account is created without a password and a one-time, 72-hour link (an approved recovery request) lets the person choose their own.
- Password recovery, recovery-code MFA replacement, TOTP removal, and account deactivation revoke central sessions and delete every stored OIDC artifact for the account (provider sessions, grants, codes, opaque access tokens) in the same transaction. The issuer refuses to store a code or token whose provider grant no longer exists, so an exchange racing the revocation cannot persist a new token. Already-issued signed ID tokens cannot be recalled and remain valid until their provider-default lifetime ends.

## OIDC profile

Virki uses `oidc-provider` with Authorization Code, PKCE S256 required, short-lived one-time authorization codes, client binding, required state, and nonce for OpenID requests. It exposes only `openid`, `profile`, and `email` claims. Refresh tokens, client credentials, dynamic registration, request objects, device flow, and introspection are disabled; token revocation is supported.

Signing keys and the OIDC cookie key are private runtime configuration. Public JWKs are published by standard discovery/JWKS endpoints. Never place private JWK values in source, browser bundles, logs, or audit metadata. Keep stable key IDs and rotate keys through a tested overlap window that covers the maximum issued token lifetime.

The OIDC data-encryption key supports one bounded overlap key via `VIRKI_OIDC_ADAPTER_KEY_PREVIOUS`. New ciphertext is always written with `VIRKI_OIDC_ADAPTER_KEY`; reads may fall back to the previous key only during rotation. Operators should introduce the new current key while retaining the old value as previous, allow short-lived OIDC artifacts to expire and rotate stored project client secrets through the supported application flow, then remove the previous key. Do not keep an indefinite key ring.

Subject identifiers are the internal account ID and are shared across connected projects, so projects can correlate a person. Switching to pairwise subjects would change every existing `sub` and break project account linking; it is an owner decision that needs a coordinated client migration, not a silent change.

## Audit and redaction

Audit entries contain event type, result, actor reference, resource, safe message, timestamp, and sanitized structured metadata. Connection/client references are hashed. Audit views use stable cursor pagination and event filters. Never record passwords, session values, cookies, TOTP seeds, recovery plaintext, client secrets, private keys, bearer tokens, or raw credential payloads.

Operational logs are summarized without returning their contents. Secret scans run in CI and locally before publication or deployment.

## Production hardening classifications

These are repository-side classifications; they do not assert that the live production headers or host have been inspected. The Hub and portal send a per-request nonce CSP (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`); `form-action` is omitted only on the portal login pages, whose posts end in a redirect to the relying party. The issuer sends `default-src 'none'`, adding `script-src 'self'` (plus the provider's hash for its `form_post` auto-submit script) only on `/auth`. The static public site cannot carry a nonce, so its CSP still allows inline scripts; it restricts sources, objects, base URIs, forms and framing but is not a meaningful script-injection barrier. HSTS currently sets `max-age=31536000` without `includeSubDomains` or `preload`; those extensions are also `HARDENING_POST_DEPLOY` and require an owner review of every affected hostname before adoption.

Account recovery bearer keys are already stored as SHA-256 `AccountRecoveryRequest.requestKeyHash` values, and the recovery flow hashes presented keys for lookup and comparison. The separate `SecurityElevation.requestKey` is stored in cleartext as a ceremony selector; it is bound to the current ADMIN user and session, limited to a pending and unexpired ceremony, and does not replace the emailed verification code. Hashing this distinct selector is bounded at-rest hardening classified `HARDENING_POST_DEPLOY`, not an evidenced authentication bypass or deployment gate. Do not describe account-recovery key hashing as missing or claim that all request-key fields are hashed.

## Verification limits

Automated tests cover the local authorization policy and OIDC adapter behavior. Deployment smoke checks the direct loopback OIDC discovery route and ADMIN boundary. External Cloudflare policy, DNS, and real account sign-in still require operator verification; do not infer them from a successful build.
