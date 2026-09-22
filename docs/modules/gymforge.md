# GymForge Planning Document

GymForge now has an implemented MVP foundation inside the private BielOS hub. This document records the module boundary and remaining gates. It does not enable body metrics, health records, photo check-ins, upload, import/export, public registration, invite acceptance, a public API, unsafe competition deletion, or broad social feed behavior.

GymForge is intended as a gated social gym competition app for Gabriel and invited friends. It is not a public open internet app and it is not a zero-knowledge vault. Data may be visible inside the approved group, but it must not be exposed outside the gated site.

## Module Identity

- Module name: GymForge.
- Module owner: BielOS owner.
- Module purpose: Gated social gym app for attendance, streaks, workouts, and group competitions.
- Current status: MVP foundation, including competition score correction, implemented behind Cloudflare Access and BielOS internal auth.

## Data Classification

- Classification: internal group data, with sensitive health-adjacent fields possible in future phases.
- Private data types: GymForge may store participant display names, participant status/role, attendance check-ins, optional attendance notes, exercise catalog entries, workout entries/sets and notes, competition metadata, additive score-correction history with private admin reasons, and derived ranking/streak views.
- Data explicitly not collected: body metrics, health records, progress photos, check-in photos, uploads, passwords, secrets, raw logs, raw headers, raw IPs, JWTs, cookies, private keys, database dumps, backups, Gmail exports, Google Takeout exports, import/export files, and invite acceptance data.
- Public or non-private data, if any: Module name and high-level status only. GymForge runtime data must stay inside the private hub.

## Access Model

- GymForge remains behind Cloudflare Access and BielOS internal authentication.
- Current participant records are admin-created; invite acceptance is not implemented.
- There is no open public registration.
- Internal users may see approved group or competition data after entry.
- OWNER/ADMIN users may manage participants, exercise catalog entries, competitions, and competition score corrections.
- Data does not need zero-knowledge encryption, but access must remain gated.

## Current MVP Scope

- Implemented: attendance check-ins and admin correction, streak/ranking views, workout notes and one-set exercise logging, admin participant and exercise catalog management, competition lifecycle and participant assignment, deterministic current-state scoring, additive score correction, and safe deletion for non-ACTIVE competitions with zero assignments and no correction history.
- Workout creation/editing intentionally supports exactly one set. An update fails safely before mutation if the stored workout unexpectedly has zero or multiple sets; explicit deletion transactionally removes all dependent sets.
- Competition score-correction Phase 2 design and Phase 3 implementation are `[DONE]`.
- Further expansion is frozen; private invitations are not an active phase, and invite acceptance remains unavailable.
- Blocked until explicitly unfrozen and scoped: private invitations and invite acceptance, upload/photo proof, public registration, import/export, unsafe competition deletion, a public API, and broad social feed behavior.

## Storage Model

- Storage location: Existing private PostgreSQL database through Prisma.
- Database tables or files: GymForge participant, exercise, attendance, workout/set, competition, assignment, and competition score-correction records; file storage is not enabled.
- Encryption or key-management needs: No zero-knowledge model expected. Future design must still define storage protection for group data and uploaded proof photos.
- Search/indexing behavior: Not enabled.
- Derived data or caches: Ranking, streak, and automatic competition base scores are computed from current persisted records; active additive corrections are summed separately into the final score.

## Competition Score-Correction Phases 2 And 3

Phase 2 design and Phase 3 private-hub implementation are complete. The following is the compact runtime contract.

### Scoring Invariants

- `baseScore` remains the deterministic automatic score computed from current qualifying attendance, the current competition date range and scoring rule, current assignment, and current ACTIVE participant state.
- Corrections never edit attendance, workout, assignment, competition, or other source rows. Each correction is a separate additive row.
- Each `pointsDelta` is a nonzero integer from `-1000` through `1000`. Multiple unrevoked rows sum without a separate aggregate clamp: `activeAdjustment = sum(pointsDelta)` and `finalScore = baseScore + activeAdjustment`.
- `finalScore` may be negative. A correction does not make an unassigned, disabled, or archived participant eligible for current scoring.
- Attendance correction and allowed competition date/rule changes may legitimately recompute `baseScore` after a score correction was created. The UI must always label the current base, aggregate active adjustment, and final score separately; corrections are not historical score snapshots.
- Ranking order is stable: final score descending, attendance count descending, longest streak descending, latest qualifying check-in descending, display name ascending, then internal participant id ascending only as a non-displayed deterministic fallback.

### Mutation And Lifecycle Rules

- Every correction mutation and every assignment, reactivation, or competition-status mutation that enforces a correction invariant is a server-side action that validates CSRF and current BielOS `OWNER` or `ADMIN` authority and returns only generic user-facing failures.
- Creation is allowed only for an `ACTIVE` or `ENDED` competition and a currently assigned participant whose current status is `ACTIVE`. `DRAFT` and `ARCHIVED` competitions reject creation.
- Creation is append-only. There is no correction edit or hard-delete action.
- Revocation is allowed only for an unrevoked row in an `ACTIVE`, `ENDED`, or `ARCHIVED` competition. It atomically sets `revokedAt` and `revokedByUserId`; `DRAFT` rejects revocation.
- Removing a competition assignment is blocked while that competition/participant pair has any unrevoked correction. The admin must revoke those rows first; neither the guard nor revocation mutates assignment or scoring-source data.
- Disabling or archiving a participant excludes that participant from current scoring while retaining all correction history. Reactivation with an assigned unrevoked correction must be blocked until explicit revocation, and reassignment cannot reactivate old corrections because assignment removal already required their revocation.
- Moving a competition back to `DRAFT` while it has unrevoked corrections must be blocked so corrections cannot become trapped in a status that disallows revocation.
- Creation, assignment removal, participant reactivation, `DRAFT` transition, and correction revocation checks use serializable transactions with three bounded retries and generic failure handling.
- `requestKey` is an opaque UUID v4 idempotency value. Replaying the same key and mutation does not add a second row; reuse with different mutation data fails generically. It is not displayed, exported, or audited.

### Prisma And Migration Shape

- The additive `GymForgeCompetitionScoreCorrection` model stores `id`, competition/participant references, `pointsDelta`, optional `reason`, unique `requestKey`, nullable create/revoke actor references, and create/revoke timestamps.
- Actions require and store the actor. Both actor relations use `onDelete: SetNull`; a non-null `revokedAt` continues to preserve revocation even if the revoker account is later removed.
- Competition and participant relations use restrictive deletion behavior. Correction rows must never cascade away with a competition, participant, assignment, or actor.
- Indexes cover active pair lookup and ordered competition/participant history in addition to the unique request key.
- The additive migration enforces a nonzero `pointsDelta` in `-1000..1000`, reason length at most 240, request-key length, and valid revocation shape. Server validation mirrors the input bounds and normalizes an empty reason to null.

### Visibility, Audit, And Retention

- Approved participants see only `baseScore`, the aggregate `activeAdjustment`, and `finalScore`; they never see individual correction rows, reasons, actor data, request keys, or raw ids.
- OWNER/ADMIN users get a compact private drawer with correction history, reason, and allowed revoke control. Participant and admin surfaces are available in PT-BR and English. The optional reason is private admin context capped at 240 characters and is never participant-visible, written to audit logs, or included in exports by default.
- No public route or GymForge API is added. The feature remains inside the existing authenticated private hub page and server-action boundary.
- Successful create/revoke audit events use only stable hashed competition, participant, and correction references plus a generic result. They omit the raw audit actor id and all actor ids from metadata; authoritative actor attribution remains on the correction row. They never include raw ids, request keys, names, reason, delta, score values, raw forms, or raw request data.
- Correction and revocation history is retained. Permanent competition deletion is blocked whenever any correction history exists, and restrictive participant history prevents participant deletion from removing corrections.
- The committed additive migration is applied to canonical remote production; the remote `_prisma_migrations` ledger includes `20260714100000_add_gymforge_score_corrections`. No pending migration remains for the current source revision.
- After the first correction write, dropping the table or rolling the application back to a pre-Phase-3 commit is unsafe because the assignment, reactivation, and `DRAFT` guards live in the new runtime. Recovery requires a forward fix or verified restore.

## Migration Plan

- Prisma schema changes: Additive score-correction model implemented.
- Migration files: Committed additive migration present and applied to canonical remote production.
- Backfill requirements: None.
- Deployment gate: For future migration-bearing releases, take a current verified backup, then run production `prisma migrate deploy` from the tooling-capable operator environment.
- Rollback approach: Before the first write, ordinary application rollback remains possible if schema compatibility is preserved. After the first write, use a forward fix or verified restore; do not run a pre-Phase-3 application against live correction data.
- Disposable validation plan: Eight focused scoring cases plus secret scan, lint, typecheck, Prisma validation, and build pass before commit; the current production migration state has been verified against the remote ledger.

## Backup And Restore

- Backup impact: Current GymForge records are covered by the existing PostgreSQL backup procedure.
- Restore validation impact: Existing PostgreSQL restore validation applies.
- Data that must never be exported: Raw credentials, secrets, raw tokens, private logs, and any future data not explicitly approved for export.
- Disaster recovery notes: Existing PostgreSQL backup and restore procedures apply. Future upload/import/export work needs separate backup and restore design before use.

## Access Control

- Required user roles: Linked ACTIVE participants for participant actions; OWNER or ADMIN for administration and correction actions.
- Cloudflare Access assumptions: Cloudflare Access remains the outer boundary for the private hub.
- BielOS internal auth requirements: Current GymForge uses BielOS internal auth behind Cloudflare Access. Participant actions require a linked ACTIVE GymForge participant; admin management requires OWNER or ADMIN.
- Module-specific unlocks: Not expected for ordinary competition data, but future design must revisit this if sensitive health data is added.
- Cross-module access boundaries: GymForge must not share workout, participant, or competition data with other modules without explicit design.

## Audit Events

- Events to record: Current implementation audits participant, exercise, attendance, workout, competition lifecycle/assignment/deletion, and score-correction create/revoke actions with the sanitized contracts above. Future phases must define events for invite acceptance, photo proof upload, and broader destructive lifecycle changes.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: Workout details, body metrics, photo contents, raw upload paths, secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, private paths, and backup contents.

## Retention And Deletion

- Retention period: Not defined.
- Deletion behavior: Participants may delete only their own workout entries after explicit confirmation, while OWNER/ADMIN users may delete any workout entry. Workout deletion transactionally removes all dependent sets. Admins may permanently delete only non-ACTIVE competitions with zero assignments and zero correction rows; any correction history permanently blocks competition deletion.
- Cleanup command or worker: Not defined.
- User-visible deletion expectations: Future design must define participant removal, competition history retention, photo proof retention, and backup implications.

## Threat Model

- Primary assets: Participant records, attendance records, streaks, workout logs, and competition data; check-in proof photos remain future work.
- Abuse cases: Unauthorized entry, participant impersonation, fake check-ins, photo proof leakage, overexposed leaderboards, unsafe exports, unsafe logging, and backup leakage.
- Accidental exposure risks: Public routes, screenshots, shared devices, logs, exports, debug output, browser cache, and notification text.
- Local machine risks: Local filesystem exposure, Docker volume handling, and untracked generated files.
- Remote access risks: Gating misconfiguration, direct origin exposure, invite leakage, brute force of participant credentials or invites, and denial of service.

## Failure Modes

- Database unavailable: Future implementation must fail closed for writes and sensitive reads.
- Backup unavailable: Future implementation must block non-discardable ingestion until backup and restore are validated.
- Auth unavailable: Module access must not proceed; any future invite flow must also fail closed.
- Cloudflare unavailable: Remote exposure behavior must be defined before launch.
- Partial write, upload, or import failure: Future implementation must define atomicity, cleanup, and rollback.
- Unexpected workout set cardinality: Editing must fail safely before mutation; explicit deletion must still transactionally remove every dependent set.

## UI Safety Constraints

- New private data fields require scoped approval.
- No upload inputs until approved: Required.
- No secret display: Required.
- No raw logs or audit metadata display: Required.
- Safe empty states: Must distinguish implemented MVP foundation features from blocked future features.
- Group visibility must remain explicit before showing any new participant, streak, workout, or competition data beyond the current approved views.

## API Safety Constraints

- Current mutation surface: Authenticated server actions; no GymForge API is enabled.
- CSRF requirements: Required for every mutable action.
- Auth checks: Required for every GymForge read and mutation.
- Rate limits: Required for login/join, check-ins, uploads, participant management, and competition mutations.
- Request and response redaction: Required.
- Error message behavior: Generic for auth, invite, and access failures.

## Secrets Handling

- Required env names: None in this phase.
- Placeholder-only docs: Required for any future env.
- Rotation behavior: Future design required if invite signing, upload signing, or service secrets are introduced.
- Logging restrictions: Never log secrets, tokens, invite secrets, private keys, raw headers, raw IPs, cookies, JWTs, workout details, body metrics, check-in photo contents, upload paths, or private notes.

## Import And Export Rules

- Import sources: Not enabled.
- Export formats: Not enabled.
- Manual confirmation requirements: Required before any future export.
- Redaction requirements: Required before any future export outside the group.
- Files that must stay out of Git: Any dumps, exports, backups, uploads, check-in photos, workout records, body metric records, private notes, or generated archives.

## Remaining Scoped Phases

Competition score-correction Phases 2 and 3 are `[DONE]`.

GymForge expansion is frozen. Private invitations and invite acceptance are not active phases. Upload/photo proof, public registration, import/export, unsafe competition deletion, a public API, and broad social visibility remain blocked.

## Validation Checklist

- Secret scan: Required for this planning document.
- Lint: Required when runtime code is added.
- Typecheck: Required when runtime code is added.
- Build: Required when UI or runtime code is added.
- Prisma validation: Required when schema changes are added.
- Migration validation: Required when migrations are added.
- Backup and restore validation: Existing PostgreSQL procedures apply and must be revalidated before storage changes.
- Local auth or gated-entry check: Required for current and future routes.
- Cloudflare exposure check: Required before remote access.
- Negative tests for unauthorized access: Required for current mutations and future visibility changes.
- Workout integrity: Creation/editing supports exactly one set; update rejects unexpected zero/multi-set records; explicit deletion transactionally removes all dependent sets.
- Score-correction Phase 3: Eight scoring cases and required repository validations pass. Production migration state is applied and remote health/revision checks pass; database-backed mutation smoke and authenticated UI smoke remain user-controlled validation gates.
