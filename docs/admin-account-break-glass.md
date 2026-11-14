# Sole-ADMIN account recovery

This is a fail-safe escalation procedure, not an application recovery feature. Virki intentionally has no self-approval or hidden ADMIN-creation route.

## Deployment classification

Sole-ADMIN lockout is a real operational recovery gap classified as `HARDENING_POST_DEPLOY`, not a general deployment blocker. The deployment migration guard requires at least one ADMIN identity and preserves ADMIN/USER counts; it does not require multiple ADMIN accounts or provide an offline reset. An active sole ADMIN who can still sign in with the normal account password can recover an ACTIVE separate administrative credential using the verified mailbox, a saved unused administrative recovery code, or a currently active TOTP factor after these changes are reviewed, merged and deployed. If the ADMIN becomes unable to authenticate, privileged changes must stop until the incident is safely resolved.

The fail-safe behavior is intentional. A separately reviewed and rehearsed operator recovery mechanism remains desirable future hardening. Do not represent production as having that mechanism until one exists and has been validated, and do not use an unsafe emergency bypass in its place.

## Use the supported in-product recovery when possible

An active ADMIN who can still sign in with the normal Virki account password can recover a forgotten **ACTIVE** separate administrative credential from the Hub security page in three ways:

1. **Verified e-mail (new):** supply the normal account password to start a short-lived email OTP challenge, then supply the normal password again, the six-digit OTP, and a new confirmed administrative password. This requires an active ADMIN session on the Hub, its existing Cloudflare Access boundary, CSRF protection, the verified mailbox, and persisted request/proof rate limits. The email proof is bound to the original verified mailbox, session, credential version and ten-minute expiry; it is consumed once in the same serializable transaction as the credential rotation and audit. The recovery revokes pending and active elevations, other sessions and remembered browsers, rotates all ten recovery codes, and emails a change notification. The normal account password and ADMIN role are unchanged. A recovery OTP is **never** an elevation grant.
2. **Saved recovery code:** supply the normal account password and one unused administrative recovery code. This rotates the administrative credential and all ten recovery codes, revokes pending/active elevations and older sessions, and rejects a revoked or missing privileged credential. A saved code does not bypass first-time credential setup or explicit revocation.
3. **Active TOTP:** supply the normal account password and a fresh six-digit code from the currently active TOTP authenticator, plus the new confirmed administrative password. The accepted TOTP time step is single-use; completing the recovery rotates ten administrative recovery codes and revokes old administrative passkeys, elevations and other sessions while preserving the normal login password and the active TOTP factor.

All three methods display replacement codes only once. Store them outside the application in the approved credential store. None is an anonymous reset link or an elevation grant; the normal login password and an active ADMIN session are still required. They do not recover a lost normal login password.

This procedure does not reset the normal Virki account password, restore a disabled account, or bypass Cloudflare Access. USER/ADMIN account recovery that changes the normal account password requires a different active ADMIN to approve it; an ADMIN cannot approve their own recovery.

## If the sole ADMIN cannot authenticate

If the only ADMIN cannot authenticate using a valid ADMIN session/normal password, or has no eligible verified mailbox, unused administrative recovery code, or active TOTP factor, stop privileged account changes. Do not try to repair the account with direct SQL, database-console edits, role promotion, a fabricated session, Cloudflare Access changes, or a copied credential from another environment. No supported offline operator reset command exists in this repository.

1. Open an incident with a non-secret identifier. Record the affected surface, observed failure, time, and the exact recovery capability that is unavailable. Do not place passwords, recovery codes, tokens, cookies, or database contents in the incident record.
2. Have the designated system owner verify the operator's identity through a pre-registered channel independent of the inaccessible Virki account. Require a second authorized person to approve any future privileged recovery mechanism; if that independent verification or approval is unavailable, keep the change blocked.
3. Preserve the current production state and verified backups. Do not start a deploy, migration, database mutation, or Access-policy change as a workaround. Use only the repository's guarded exact-revision operations and never touch deManage.
4. Before changing production, the owner must authorize a separately reviewed and tested recovery mechanism with a disposable-database rehearsal, a verified backup/restore path, explicit target-account confirmation, least-privilege access, audit recording, and post-recovery revocation/rotation of sessions, device grants, elevations, and one-time proofs as appropriate.
5. Resume privileged operations only after the approved recovery procedure has been independently validated and its evidence attached to the incident.

Until such an executable procedure is added and validated, sole-ADMIN lockout is an operational recovery gap. The safe action is to preserve state and escalate to the designated system owner; it is not to bypass the application boundary.
