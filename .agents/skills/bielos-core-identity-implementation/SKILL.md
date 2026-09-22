---
name: bielos-core-identity-implementation
description: Implement BielOS identity, authentication, account security, recovery, project entry grants, or OIDC integration.
---

# BielOS identity implementation

BielOS is an identity, authentication/SSO, security, project-entry-access, and audit gateway. It authenticates users and controls entry to external relying applications; each application owns its experience and internal authorization.

## Workflow

1. Read `AGENTS.md`, the current schema and migration chain, the affected server boundary, and the relevant auth/audit/operations code.
2. Keep stored roles to ADMIN and USER. Treat anonymous traffic as untrusted and deny by default.
3. Enforce authorization on the server and recheck mutable account, connection, and grant state at the operation boundary.
4. Store hashes for bearer identifiers; encrypt TOTP material, OIDC client secrets, and protected protocol payloads with dedicated environment-held keys.
5. Preserve credentials, MFA, recovery, account-security state, and compatible security audit data. Invalidate sessions or transient grants only when documented and safer.
6. Use committed Prisma migrations. Never use production `prisma db push`. Require a tested backup restore before destructive production schema work.
7. Add focused tests for each nontrivial security transition, including replay, concurrency, authorization, and safe error behavior where relevant.
8. Run the focused tests, schema validation, typecheck, lint, build, and `git diff --check` as appropriate. Report unavailable infrastructure without weakening controls.

## Required invariants

- Project access is an explicit USER-to-external-project grant. BielOS stores no project-internal roles or permissions.
- OIDC uses Authorization Code with required PKCE S256, exact HTTPS redirect allowlists, short-lived one-time codes, client binding, state, and nonce for OpenID requests.
- Project clients never receive the central BielOS session cookie.
- Authentication failures are generic; sensitive routes use CSRF, rate limiting, replay protection, and server-side checks.
- High-risk ADMIN actions require fresh proof according to their action policy.
- Audit metadata is sanitized and never contains credentials, secrets, bearer material, or raw tokens.
- Cloudflare Access remains required on the ADMIN host; portal access does not inherit an ADMIN-only Access rule.
- Production is remote-only through the configured SSH target, with stable preflight, exact source revision, verified backup, and no effect on deManage.
