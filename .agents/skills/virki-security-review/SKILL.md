---
name: virki-security-review
description: Review Virki authentication, authorization, OIDC, Cloudflare Access, sessions, CSRF, audit, deployment, or data-migration security.
---

# Virki security review

Keep findings evidence-based and scoped. Do not print secrets or private production values. A review in a single-agent task is a fresh pass by the same agent; never imply independent review provenance.

## Trust boundaries

1. Public page and unauthenticated protocol metadata.
2. USER portal session and explicit project grant.
3. ADMIN Cloudflare Access assertion and Virki ADMIN session.
4. External relying application and its own local session.
5. Private Compose network, database, and remote production host.

## Review checklist

- Unknown hosts and anonymous protected routes fail closed.
- ADMIN routes verify the Access JWT and Virki role server-side; missing or invalid Access is forbidden.
- USER access never inherits an ADMIN-only Access policy.
- Session values are opaque, hashed at rest, host-only in cookies, revocable, and absent from logs.
- Mutable actions enforce CSRF and fresh proof where required.
- Login and recovery errors do not disclose account existence; rate limits fail closed.
- MFA, recovery, and one-time protocol data resist replay and concurrent reuse.
- OIDC enforces Authorization Code, PKCE S256, exact redirect URIs, state, nonce, issuer/client binding, expiry, and live grant checks.
- Audit data contains safe identifiers and redacted context only; pagination and filters do not bypass authorization.
- Public site exposes no private account, project, audit, or operational data.
- Docker publishes only intended loopback ports; database and issuer stay private.
- Production migrations have a verified backup/restore path and exact source revision.
- Production operations do not touch deManage, remove persistent data, expose ports, or weaken Access.

## Output

State the security verdict, actionable findings with file/line evidence, checks run, checks unavailable, and material limits. Do not label an incomplete review comprehensive or independent.
