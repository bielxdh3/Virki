# GymForge Planning Document

GymForge now has an implemented MVP foundation inside the private BielOS hub. This document records the module boundary and remaining gates. It does not enable body metrics, health records, photo check-ins, upload, import/export, public registration, invite acceptance, score-correction runtime, unsafe competition deletion, or broad social feed behavior.

GymForge is intended as a gated social gym competition app for Gabriel and invited friends. It is not a public open internet app and it is not a zero-knowledge vault. Data may be visible inside the approved group, but it must not be exposed outside the gated site.

## Module Identity

- Module name: GymForge.
- Module owner: BielOS owner.
- Module purpose: Gated social gym app for attendance, streaks, workouts, and group competitions.
- Current status: MVP foundation implemented behind Cloudflare Access and BielOS internal auth.

## Data Classification

- Classification: internal group data, with sensitive health-adjacent fields possible in future phases.
- Private data types: GymForge may store participant display names, participant status/role, attendance check-ins, optional attendance notes, exercise catalog entries, workout entries, workout sets, optional workout/set notes, competition metadata, and derived read-only ranking/streak views.
- Data explicitly not collected: body metrics, health records, progress photos, check-in photos, uploads, passwords, secrets, raw logs, raw headers, raw IPs, JWTs, cookies, private keys, database dumps, backups, Gmail exports, Google Takeout exports, import/export files, invite acceptance data, and manually corrected competition scores.
- Public or non-private data, if any: Module name and high-level status only. GymForge runtime data must stay inside the private hub.

## Access Model

- GymForge remains behind Cloudflare Access and BielOS internal authentication.
- Current participant records are admin-created; invite acceptance is not implemented.
- There is no open public registration.
- Internal users may see approved group or competition data after entry.
- Admin users may manage participants, exercise catalog entries, competitions, and challenges.
- Data does not need zero-knowledge encryption, but access must remain gated.

## Current MVP Scope

- Implemented: attendance check-ins and admin correction, streak/ranking views, workout notes and one-set exercise logging, admin participant and exercise catalog management, competition lifecycle and participant assignment, deterministic automatic base scoring, and safe deletion for non-ACTIVE competitions with zero assignments.
- Workout creation/editing intentionally supports exactly one set. An update fails safely before mutation if the stored workout unexpectedly has zero or multiple sets; explicit deletion transactionally removes all dependent sets.
- Design complete but runtime blocked: competition score-correction Phase 2 is documented below. Phase 3 implementation is next and must add the schema, migration, server actions, UI, and tests before corrections can be used.
- Blocked until scoped or implemented: upload and photo proof, public registration, invite acceptance, import/export, score-correction runtime, deletion of ACTIVE or assigned competitions, and broad social feed behavior.

## Storage Model

- Storage location: Existing private PostgreSQL database through Prisma.
- Database tables or files: GymForge participant, exercise, attendance, workout/set, competition, and assignment records; file storage is not enabled.
- Encryption or key-management needs: No zero-knowledge model expected. Future design must still define storage protection for group data and uploaded proof photos.
- Search/indexing behavior: Not enabled.
- Derived data or caches: Ranking, streak, and competition base-score views are computed from current persisted records; manual score correction is not enabled.

## Competition Score-Correction Phase 2 Design

Phase 2 design is complete. This section is an implementation contract only; score-correction runtime remains blocked until Phase 3.

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
- Creation, assignment removal, participant reactivation, and correction revocation checks must be atomic and concurrency-safe. Phase 3 must use a consistent transaction/locking order or serializable transactions with bounded retry so a concurrent assignment removal cannot race correction creation.
- `requestKey` is an opaque, high-entropy idempotency value. Replaying the same key and same mutation must not add a second row; a key reused with different mutation data fails generically. It must not be displayed, exported, or audited.

### Planned Prisma And Migration Shape

- Add `GymForgeCompetitionScoreCorrection` with `id`, `competitionId`, `participantId`, `pointsDelta`, optional `reason`, unique `requestKey`, nullable `createdByUserId`, `createdAt`, nullable `revokedAt`, and nullable `revokedByUserId`.
- The creation actor is required by the action and populated on insert, but both actor foreign keys remain nullable so `User` relations can use `onDelete: SetNull` without deleting correction history.
- Competition and participant relations use restrictive deletion behavior. Correction rows must never cascade away with a competition, participant, assignment, or actor.
- Planned indexes cover active pair lookup and ordered history: `(competitionId, participantId, revokedAt)`, `(competitionId, createdAt)`, and `(participantId, createdAt)`, in addition to the unique `requestKey` index.
- The additive migration must include database checks equivalent to `pointsDelta <> 0 AND pointsDelta BETWEEN -1000 AND 1000` and `reason IS NULL OR char_length(reason) <= 240`. Server validation mirrors these checks and normalizes an empty reason to null.

### Visibility, Audit, And Retention

- Approved participants see only `baseScore`, the aggregate `activeAdjustment`, and `finalScore`; they never see individual correction rows, reasons, actor data, request keys, or raw ids.
- OWNER/ADMIN users get a compact private drawer with correction history and an allowed revoke control. The optional reason is private admin context capped at 240 characters and is never participant-visible, written to audit logs, or included in exports by default.
- No public route or GymForge API is added. The feature remains inside the existing authenticated private hub page and server-action boundary.
- Successful create/revoke audit events use only stable hashed references for the competition, participant, and correction plus a generic result. They do not populate a raw audit actor id; authoritative actor attribution remains on the correction row. They never include any raw ids, request keys, names, reason text, point deltas, base/adjustment/final scores, form payloads, or raw request data.
- Correction and revocation history is retained. Permanent competition deletion is blocked whenever any correction history exists, and restrictive participant history prevents participant deletion from removing corrections.
- The schema migration is additive and safe to deploy before runtime use. Dropping the table after any correction has been written is destructive and requires a verified backup plus a forward migration or explicit history-preservation plan.

## Migration Plan

- Prisma schema changes: Implemented for the current MVP foundation.
- Migration files: Implemented for the current MVP foundation.
- Backfill requirements: None.
- Rollback approach: Use a scoped migration and the documented restore procedure. For the planned correction table, rollback is non-destructive only before use; after use, preserve history through backup and a forward migration rather than dropping it.
- Disposable validation plan: Required before future schema changes, upload, import/export, assignment/scoring rule changes, or Phase 3 score-correction work.

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

- Events to record: Current implementation audits participant creation/status changes, exercise creation/status changes, attendance check-in creation, admin attendance correction creation/removal, workout creation/update/deletion, competition creation, competition updates, competition archival, competition deletion, and competition assignment updates with sanitized metadata. Phase 3 must implement the stricter score-correction create/revoke audit contract above; future phases must define events for invite acceptance, photo proof upload, and broader destructive lifecycle changes.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: Workout details, body metrics, photo contents, raw upload paths, secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, private paths, and backup contents.

## Retention And Deletion

- Retention period: Not defined.
- Deletion behavior: Participants may delete only their own workout entries after explicit confirmation, while OWNER/ADMIN users may delete any workout entry. Workout deletion transactionally removes all dependent sets before deleting the workout. Admins may permanently delete only non-ACTIVE competitions with zero participant assignments; after Phase 3, any correction history also permanently blocks competition deletion. ACTIVE, assigned, or correction-bearing competitions must be archived or retained.
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

Competition score-correction Phase 2 design is complete, and Phase 3 implementation is next. Score-correction runtime remains blocked until its additive migration, authorization, CSRF, concurrency guards, sanitized audit events, private UI, and tests are implemented. Upload/photo proof, public registration, invite acceptance, import/export, unsafe competition deletion, and broader social visibility still require separate explicit design and validation. Existing private-hub auth, role checks, CSRF, audit sanitization, backup/restore, and data-integrity rules must remain in place.

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
- Score-correction Phase 3: Must validate score arithmetic, integer/reason database checks, idempotency, status/role/CSRF gates, atomic assignment/reactivation guards, revocation history, current-state recomputation, stable tie breaks, visibility, audit redaction, restrictive deletion, and migration rollback behavior before runtime is enabled.
