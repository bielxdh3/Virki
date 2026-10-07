# Sole-ADMIN account recovery

This is a fail-safe escalation procedure, not an application recovery feature. Virki intentionally has no self-approval or hidden ADMIN-creation route.

## Deployment classification

Sole-ADMIN lockout is a real operational recovery gap classified as `HARDENING_POST_DEPLOY`, not a general deployment blocker. The deployment migration guard requires at least one ADMIN identity and preserves ADMIN/USER counts; it does not require multiple ADMIN accounts or provide an offline reset. A sole ADMIN who can still authenticate with the normal account password and an unused recovery code can use the supported in-product flow below. If that ADMIN becomes unable to authenticate, privileged changes must stop until the incident is safely resolved.

The fail-safe behavior is intentional. A separately reviewed and rehearsed operator recovery mechanism remains desirable future hardening. Do not represent production as having that mechanism until one exists and has been validated, and do not use an unsafe emergency bypass in its place.

## Use the supported in-product recovery when possible

An active ADMIN who can still sign in with the normal Virki account password can recover a lost separate administrative credential from the Hub security page with one unused administrative recovery code. The operation replaces that credential, invalidates the used code set, displays ten new codes once, and revokes pending or active elevations. Store the replacement codes outside the application in the organization's approved credential store.

This procedure does not reset the normal Virki account password, restore a disabled account, or bypass Cloudflare Access. USER/ADMIN account recovery that changes the normal account password requires a different active ADMIN to approve it; an ADMIN cannot approve their own recovery.

## If the sole ADMIN cannot authenticate

If the only ADMIN has lost the normal account password, access to the verified email address, the ADMIN recovery codes, or access to the account itself, stop privileged account changes. Do not try to repair the account with direct SQL, database-console edits, role promotion, a fabricated session, Cloudflare Access changes, or a copied credential from another environment. No supported operator reset command exists in this repository.

1. Open an incident with a non-secret identifier. Record the affected surface, observed failure, time, and the exact recovery capability that is unavailable. Do not place passwords, recovery codes, tokens, cookies, or database contents in the incident record.
2. Have the designated system owner verify the operator's identity through a pre-registered channel independent of the inaccessible Virki account. Require a second authorized person to approve any future privileged recovery mechanism; if that independent verification or approval is unavailable, keep the change blocked.
3. Preserve the current production state and verified backups. Do not start a deploy, migration, database mutation, or Access-policy change as a workaround. Use only the repository's guarded exact-revision operations and never touch deManage.
4. Before changing production, the owner must authorize a separately reviewed and tested recovery mechanism with a disposable-database rehearsal, a verified backup/restore path, explicit target-account confirmation, least-privilege access, audit recording, and post-recovery revocation/rotation of sessions, device grants, elevations, and one-time proofs as appropriate.
5. Resume privileged operations only after the approved recovery procedure has been independently validated and its evidence attached to the incident.

Until such an executable procedure is added and validated, sole-ADMIN lockout is an operational recovery gap. The safe action is to preserve state and escalate to the designated system owner; it is not to bypass the application boundary.
