# BielOS Core SecurityUnlock Boundary

## Decision

`SecurityUnlock` runtime behavior remains blocked. The current schema is a reserved foundation, not a complete security protocol.

Known fields are user, optional project, purpose, status, challenge hash, approval time, expiry, and timestamps. Existing documentation says an unlock may protect a sensitive module, but it does not define enough behavior to issue, verify, approve, consume, revoke, or recover an unlock safely.

## Existing Intent

- The unlock is an additional scoped security gate.
- It may be associated with a user, a project, and a purpose.
- It has an explicit state and expiration.
- Only hashed challenge material may be stored.
- It must remain inside the private hub.

An unlock never replaces Cloudflare Access, BielOS internal authentication, active-user checks, CSRF, project visibility, or `ProjectAccess` authorization.

## Unresolved Security Decisions

Runtime implementation requires explicit answers for all of the following:

- Who creates a request and which roles may approve or deny it.
- Whether requesters and approvers must be different users.
- How challenge material is generated, delivered, verified, rotated, and destroyed.
- Whether `LOGIN`, `SENSITIVE_MODULE`, and `RECOVERY` require separate protocols.
- Whether an approval is one-time, action-count bounded, or valid for a time window.
- How consumption is recorded and made atomic with the protected action.
- How denial, revocation, expiration, and abandoned requests are represented.
- Whether project scope is mandatory for project-sensitive actions.
- Which operations require an unlock and which are prohibited even with one.
- Rate limits, replay protection, concurrent approval handling, and retry policy.
- Recovery authority and protection against an administrator approving their own recovery.
- Retention and cleanup behavior for expired or denied rows.

The current model has no consumption or revocation fields, no approver identity, no denial timestamp, and no protocol/version marker. Adding guessed behavior around `challengeHash` would create replay, privilege-escalation, and ambiguous-recovery risks.

## Required Future Protocol

A future approved design must define:

1. A versioned request and challenge format with cryptographic entropy.
2. Exact role and separation-of-duty rules per purpose.
3. Server-side project authorization before unlock evaluation.
4. Short expiration and one-time or explicitly bounded use.
5. Transactional compare-and-consume behavior.
6. Generic errors that do not disclose request, user, project, or challenge validity.
7. CSRF for request, approval, denial, revocation, and protected mutations.
8. Bounded persistent rate limiting without raw IP, email, token, or challenge logging.
9. Sanitized audit events containing only purpose, result, generic scope, and hashed references.
10. Cleanup, retention, backup, restore, and rollback behavior.
11. Focused tests for replay, expiry, race conditions, cross-project IDOR, role escalation, and recovery abuse.

## Data And Audit Restrictions

Never expose or log raw challenge values, challenge hashes, cookies, session tokens, JWTs, headers, IPs, passwords, recovery material, environment values, database URLs, request bodies, or unrestricted reason text.

No unlock data is shown in operations or audit activity views. A future requester-facing view may show only its own safe status, purpose category, and expiration after authorization is rechecked.

## Implementation Gate

Runtime stays blocked until the unresolved decisions above are approved and any required additive schema migration has a current backup, reviewed SQL, rollback limitations, authorization tests, and a complete deploy plan. No Core phase may treat an existing `APPROVED` row as authority before that protocol exists.

## Campaign verification

The current local campaign found no runtime path that treats a legacy `SecurityUnlock` row as authority. Administrative elevation uses the separate versioned, session-bound ceremony in `packages/auth/src/administration.ts`; routine OWNER project participant/access changes do not invoke that ceremony, while higher-risk administrative operations still do. `SecurityUnlock` therefore remains explicitly `FROZEN_BY_APPROVED_BOUNDARY` rather than being activated by inference.
