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

## Offline dual-approval *review evidence* (not a recovery mechanism)

`scripts/sole-admin-approval-verify.mjs` is a **read-only, local evidence verifier** intended to help review a *future* exceptional procedure. It does **not** reset a credential, issue a session or token, consume an approval, inspect PostgreSQL, contact staging/production, or authorize a database write. A valid output means **only** that two signatures on the same bounded request matched the separately pinned public keys. It does not prove a human's identity, that two human beings approved, backup validity, current account state, non-replay, or ownership of a deployment.

The exceptional path remains **blocked** until the independent authorized people and their key custody have been formally established, an executable mechanism has passed independent security review and disposable-database rehearsal, backups have been independently verified, and the owner has explicitly approved the exact environment and action. **Do not use this verifier's output to waive normal ADMIN protection.** No first-login ADMIN elevation, OIDC secret rotation, or account state change follows automatically.

### Prerequisites outside Virki

1. Identify the incident, the exact account and its verified email, the intended **staging or production** deployment, and the specific credential version. Confirm the normal account password and verified email/strong-factor availability through normal authorized channels, **without collecting either secret in an incident ticket**.
2. Obtain independently verified identity/ownership evidence through a *previously established, out-of-band* channel. Designate an **OWNER** and a different **INDEPENDENT_REVIEWER** with separate key custody. Reusing the owner's second key is not independent approval. If no independent, authorized reviewer or pre-established trust anchor exists, **stop**; do not enroll new trust keys in the middle of a lockout as a substitute for pre-existing authority.
3. Obtain a recent, independently verified backup/restore rehearsal, the exact accepted source revision, an independently checked target identity and credential version, and a deployment reference. A database snapshot alone is not proof of current state. Record only non-secret identifiers/digests in the review bundle.
4. An independent custodian prepares the public **Ed25519** registry (`registry.json`) containing exactly one `OWNER` and one `INDEPENDENT_REVIEWER` key with distinct public key fingerprints. The byte-exact SHA-256 of the registry is registered in a **separate trusted custody channel before the incident**. Neither signer can choose or replace that pinned digest, or approve the registry containing their own substitute key. Private signing keys must remain in each custodian's trusted offline signing environment, never in this repo, GitHub, CLI flags, chat, or the Virki host.

### Review bundle contract (version 1)

The registry is a compact UTF-8 JSON object with keys `schema`, `environment`, `deploymentRef`, `approvers`. Its schema is `virki-independent-approver-registry-v1`; `approvers` contains exactly two objects, each with `keyId`, `role` (`OWNER` or `INDEPENDENT_REVIEWER`), and a canonical SPKI PEM `publicKeyPem`. Duplicate fields, reused keys, mismatched roles, and ambiguous/padded JSON fail validation. The SHA-256 pin is computed over the **exact registry file bytes**, not a pasted public key or an unverified value in the bundle.

The `bundle.json` object contains only `request` and `approvals`. The request is signed by both parties and contains precisely the following fields:

| Field | Required invariant |
| --- | --- |
| `schema` | `virki-sole-admin-recovery-review-v1` |
| `action` | `REVIEW_SEPARATE_ADMIN_CREDENTIAL_RECOVERY_ONLY` — not a grant to mutate |
| `incidentId` | Non-secret case identifier, 8–80 safe characters |
| `environment`, `deploymentRef` | Exact designated staging/production and specific instance |
| `targetUserId`, `targetEmailSha256` | Explicit ADMIN identity, SHA-256 of normalized email; independently rechecked |
| `sourceRevision`, `backupSha256` | Exact 40-character source SHA-1 and verified 64-character backup SHA-256 |
| `credentialKeyVersion` | Positive integer from a trusted state check; must be rechecked at execution |
| `nonce` | Unique 128-bit hex challenge for this incident; future writer must atomically consume it |
| `issuedAt`, `expiresAt` | Canonical UTC ISO timestamps; at most 24 hours apart and currently valid |

The signer signs `VIRKI_SOLE_ADMIN_RECOVERY_REVIEW_V1\n` concatenated with the UTF-8 JSON of the request in the exact field order above. `approvalSigningPayload(request)` produces those bytes. Each `approvals` entry is `{ "keyId": "...", "signature": "..." }` with a canonical base64url-encoded 64-byte Ed25519 signature. Both approvers must inspect and independently validate **the same exact fields and backup/identity evidence before signing**. The signer is responsible for protecting private keys; the verifier never reads them.

`expected.json` is a **separately sourced** plain JSON object with these seven current-state fields: `environment`, `deploymentRef`, `targetUserId`, `targetEmailSha256`, `sourceRevision`, `backupSha256`, `credentialKeyVersion`. It must **not** be generated from `bundle.json`. Generating `expected.json` from the signed request defeats the independent target/environment binding. The verifier checks exact match but cannot authenticate the truth of those values. The CLI requires **all three JSON files in compact `JSON.stringify` format**, without whitespace padding, BOM, duplicate keys or trailing newlines; this prevents a human seeing one field while a parser selects a later duplicate.

Run this **locally only** against non-secret files (the trust-store digest must come from its independent custody source):

```powershell
node scripts/sole-admin-approval-verify.mjs --bundle <bundle.json> --registry <registry.json> --registry-sha256 <pre-established-registry-sha256> --expected <independently-verified-expected.json>
```

On successful signature verification the tool prints a request digest and `NO_CREDENTIAL_MUTATION_AUTHORIZED`; on any failure it prints only a generic denial. There is no operational reset switch, API endpoint, or deployment flag hidden in this flow. Test without a real account using `node --test scripts/sole-admin-approval.test.mjs`.

### Remaining mandatory security gates before any future executable recovery

The current validator is intentionally stateless: the same valid bundle can be checked again. A future **separately authorized and reviewed implementation** must securely consume the nonce **once** in a serialized transaction; pin the actual DB/deployment/account/credential version; require fresh normal-account authentication, independent MFA/email proof and an active Cloudflare Access boundary as appropriate; revalidate live identity, key revocation and approval expiry *after* all locks; fence races, account suspension and multiple-ADMIN misidentification; rotate only the separate ADMIN credential; revoke outstanding sessions, grants and elevations; generate new recovery codes with one-time protected display; and persist auditable non-secret records without exposing passwords, email proofs, recovery codes, private keys or hashes. It must never replace a password hash via ad hoc SQL, promote a USER or issue a fabricated session.

Before an actual staging or production operation, independently test the exact candidate on a disposable restored database with adversarial/replay/concurrent attempts, verify an independent restoration point, complete the dual-person review and owner approval, and then authorize the **specific** live action separately. A green verifier result, unit test suite, or DRAFT PR is **not** approval to recover the account or rotate the OIDC client secret.
