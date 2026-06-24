---
name: bielos-security-review
description: Use when reviewing BielOS security, authentication, Cloudflare Access, CSRF, session handling, Docker exposure, secrets, audit logs, or production hardening.
---

# BielOS Security Review Skill

Use this skill for security-sensitive BielOS work.

Keep output minimal and precise.

Do not narrate routine inspection.

Do not paste long logs.

Never print secret values.

## Security Model

BielOS uses layered security:

1. Cloudflare Tunnel without opening router ports.
2. Cloudflare Access before the private hub.
3. Optional origin-side Cloudflare Access JWT validation.
4. BielOS internal authentication.
5. Session token hashing at rest.
6. HttpOnly session cookies.
7. SameSite cookie protections.
8. CSRF tokens for mutable hub routes.
9. Audit logs without raw secrets or raw identifiers.
10. Docker host-published ports bound to `127.0.0.1`.

Do not weaken any layer unless the user explicitly asks.

## Sensitive Data Rules

Never expose:

- `.env`;
- Cloudflare tunnel token;
- Cloudflare account IDs if treated as private;
- Cloudflare Access JWT;
- cookies;
- session tokens;
- raw auth headers;
- raw request headers;
- raw IP addresses;
- database URL with password;
- private keys;
- credential JSON;
- database dumps;
- backups;
- Google Takeout;
- Gmail exports;
- Gmail attachments;
- logs containing private values.

Use placeholders only.

## Review Checklist

Check for:

- direct exposure of `hub` or port `3001`;
- Docker ports not bound to `127.0.0.1`;
- committed `.env` or `.env.*`;
- Cloudflare credential JSON;
- hardcoded tokens;
- hardcoded passwords;
- JWTs or cookies in logs;
- raw IP storage;
- raw user agent storage if avoidable;
- weak auth changes;
- CSRF bypasses;
- mutable routes without CSRF;
- audit logs that include sensitive values;
- public-site leaking private internals;
- docs exposing too much operational detail for public release.

## Auth and Session Rules

For auth/session work:

- Do not expose whether a specific email exists.
- Keep login failures generic.
- Keep session token raw value out of the database.
- Store only hashes of session tokens.
- Logout must revoke session state and clear cookie.
- Cleanup must not log session tokens.
- Rate limiting must not reveal sensitive account state.

## Cloudflare Rules

For Cloudflare work:

- Cloudflare Access is not a replacement for BielOS internal auth.
- BielOS internal auth is not a replacement for Cloudflare Access.
- Origin-side JWT validation must verify issuer, audience, signature, and expiration when enabled.
- Missing or invalid required Access JWT must return HTTP `403`.
- Do not commit real Access AUD values or tunnel tokens.

## Output Format

Use only:

- Status
- Security verdict
- Findings
- Required fixes
- Acceptable limitations
- Validations run
- Validations not run

Use severity when useful:

- Critical
- High
- Medium
- Low
- Note

Do not exaggerate. Do not speculate as fact.

If no obvious issue is found, say:

`Nenhum problema crítico encontrado no escopo revisado.`

Still list limitations if validation was incomplete.
