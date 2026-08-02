---
name: bielos-core-identity-implementation
description: Use for BielOS identity, public intake, account lifecycle, module access, 2FA, recovery, or critical-operation elevation implementation.
---

# BielOS Core Identity Implementation

Use this skill for the identity-access campaign described by
`docs/identity-access-campaign.md`. Keep the public site independent from the
private Core database and keep every production-only capability disabled until
its required configuration and human security ceremony are complete.

## Workflow

1. Read `AGENTS.md`, the campaign decision document, the relevant Core
   security documents, the Prisma schema, migrations, auth/session/CSRF/audit
   code, and deployment configuration before editing.
2. Work one Meta task at a time in dependency order. Keep one migration chain,
   one shared ledger, and one owner for each lifecycle boundary.
3. Reuse existing Prisma, session, CSRF, audit, locale, and test-database
   helpers. Add no abstraction or dependency without a concrete current use.
4. Apply authorization at the server boundary and re-check it inside the
   transaction for every mutable operation. Use generic failures for public
   and recovery flows.
5. Store only hashes for bearer material. Encrypt TOTP secrets with a
   dedicated application key. Never log or render tokens, codes, passwords,
   cookies, hashes, IPs, user agents, provider errors, or raw reasons.
6. Use additive committed migrations only. Never use production `db push`.
   Require disposable migration/rollback evidence and a current backup before
   durable deployment.
7. Keep production email and public intake fail-closed until a real transport,
   restricted intake credential, owner factors, backup, routing, and smoke
   authorization are present.
8. Validate behavior through real handlers and transactions. Include one
   focused regression or concurrency check for each non-trivial security path.
9. Run `git diff --check`, focused tests, and proportional repository gates;
   report unavailable infrastructure instead of weakening controls.

## Required invariants

- A catalog record never creates a runtime route or entitlement authority.
- Public responses never disclose account existence, private modules, status by
  email, raw abuse identifiers, or delivery details.
- Verification, activation, access grants, cooldowns, revocations, recovery,
  and elevation transitions are one-time or atomic as defined by the campaign.
- Expiry always fails closed; stale authorization is rechecked from persisted
  state.
- `SecurityUnlock` elevation is versioned, scoped, session-bound, time-bounded
  or explicitly confirmed manual-until-revoked, and never replaces ordinary
  authorization or Cloudflare Access.
- Existing legacy `APPROVED` unlock rows grant no authority until the new
  protocol is established.
- Public-site builds remain database-free; origin ports remain loopback-only;
  Cloudflare Access remains before BielOS internal auth.

## Task boundaries

Keep these boundaries separate and integrate only after their dependencies
pass: baseline/threat model, data foundation, email delivery, isolated intake,
owner review/activation, module access, ordinary 2FA/recovery,
administrative elevation, integrated UI/operations, and final adversarial
validation/rollout documentation.

Do not expand GymForge, implement reserved module runtimes, add global search,
export, public administration, OAuth/OIDC provider behavior, account-deletion
execution, or production provider selection.

## Security review checklist

Before marking a task complete, check enumeration, replay, duplicate and
concurrent transitions, IDOR, CSRF, CORS/origin policy, rate-limit bypass,
role escalation, token leakage, TOTP/recovery-code exposure, device challenge
replay, elevation reuse, indefinite elevation, audit leakage, DoS, missing
email configuration, migration safety, backup/restore, and truthful deployment
state.

When the original issue is a security finding, establish the source-to-sink
path, reproduce or encode a focused regression, patch the narrowest complete
boundary, and rerun the exploit and legitimate-control checks before broader
gates.
