# BielOS Identity and Access Threat Model

Scope: the identity/access campaign and its interaction with the existing private Core boundary. This is a repository-scoped design artifact, not a claim that every control is already implemented.

## Assets and actors

- Assets: account identity, verified email control, passwords, TOTP secrets, recovery material, sessions, module grants, feature permissions, owner authority, administrative credential, elevation state, audit integrity, and availability.
- Actors: unauthenticated applicant, authenticated user, global owner, compromised session, automated abuser, malicious public client, compromised email account, and database/operator attacker.
- Security invariants: least privilege, generic public/recovery behavior, one-time/replay-safe transitions, atomic state changes, fail-closed expiry, sanitized audit, and layered Cloudflare/internal authentication.

## Trust boundaries and controls

| Boundary | Attacker-controlled input | Required control |
| --- | --- | --- |
| Public browser → `/apply` | method, origin, content type, body, email, reasons, module identifiers | strict same-origin policy, bounded schema, public catalog allowlist, generic response, HMAC abuse identifier, cooldown |
| Intake → database | normalized applicant data and requested modules | restricted credential/capability, no private reads, uniqueness and transaction constraints |
| Email transport → ceremony | delivery outcome, link/code replay, provider failure | hashed material, expiry, invalidation, idempotent outbox, deterministic test transport, production fail-closed |
| Browser → hub | cookies, CSRF, paths, identifiers, roles | Cloudflare first, session validation, CSRF, server authorization, scoped queries, generic errors |
| User → module access | module/feature IDs and reasons | declared permission allowlist, owner-only grants, cooldown transaction, IDOR checks, expiry fail-closed |
| Login/device/recovery | password, factor, opaque device ID, recovery code | rate limit, no session before device verification, one-time factors, encrypted TOTP, hashed recovery codes |
| Owner → critical action | admin password, email factor, scope, duration | separate credential, versioned session-bound elevation, allowlist, atomic consume/revoke, immediate visibility |
| Runtime → audit/ops | event metadata and provider/database errors | bounded allowlist, hashes only, no raw secrets/identifiers/logs, truthful unknown state |

## Threat coverage

- Enumeration: generic application, verification, login, recovery, and access responses; never expose account existence or status by email.
- Flooding/DoS: bounded bodies/fields, persistent HMAC abuse keys, independent cooldowns, rate limits, bounded outbox retries, and query limits.
- Replay: challenge hashes, expiry, reissue invalidation, compare-and-consume transactions, and one-time recovery/device/elevation material.
- Duplicate/concurrent transitions: normalized unique identities, unique request keys, serializable or equivalently locked transactions, and idempotent outbox creation.
- Token leakage: no raw links/codes at rest or in logs/UI; no passwords in email; no cookies, hashes, JWTs, IPs, or user agents in audit.
- Public/private confusion: isolated intake capability, no public private/unlisted catalog payloads, no public Core administration API, strict CORS/origin policy.
- IDOR/stale authorization: persisted-principal checks inside each query/transaction; active user and grant expiry checked at use time.
- Role escalation: only global `OWNER` manages global/account/module-critical state; module-local rights never grant global authority.
- TOTP/recovery/device abuse: encrypted secret, one-time hashed codes, regeneration invalidation, device-bound challenges, own-resource scoping, and generic recovery.
- Admin compromise/elevation reuse: separate admin password, email factor, protocol version, user/session/scope binding, explicit duration, revoke on recovery/session invalidation, and legacy rows non-authoritative.
- Audit leakage: bounded event/result/resource categories and sanitized metadata only.
- Deployment misconfiguration: public intake and email-dependent features disabled when transport, restricted credential, owner factors, backup, routing, or smoke authorization are missing.

## Existing repository controls that must remain

The existing Core documents establish Cloudflare Access before BielOS auth, origin JWT denial, loopback-only ports, session-token hashing, CSRF, bounded audit, owner-only administration, and additive migration/backup gates. `docs/security-unlock.md` explicitly keeps the current `SecurityUnlock` schema design-only; this campaign replaces it only with a versioned protocol whose legacy rows grant no authority.

## Assumptions and proof gaps

- No production email provider is selected; delivery and public intake remain disabled until configured.
- The separate intake credential and production routing require deployment evidence, not source-only assertions.
- Human owner setup and offline recovery-code acknowledgement cannot be automated safely.
- Production smoke, backup/restore, exact remote CI, and external Cloudflare checks require their own authorized environment and are reported only when evidenced.
