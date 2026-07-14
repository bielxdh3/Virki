# GymForge Planning Document

GymForge now has an implemented MVP foundation inside the private BielOS hub. This document records the module boundary and remaining gates. It does not enable body metrics, health records, photo check-ins, upload, import/export, public registration, invite acceptance, scoring corrections, unsafe competition deletion, or broad social feed behavior.

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

- Implemented: attendance check-ins and admin correction, streak/ranking views, workout notes and one-set exercise logging, admin participant and exercise catalog management, competition lifecycle and participant assignment, deterministic automatic scoring, and safe deletion for non-ACTIVE competitions with zero assignments.
- Workout creation/editing intentionally supports exactly one set. An update fails safely before mutation if the stored workout unexpectedly has zero or multiple sets; explicit deletion transactionally removes all dependent sets.
- Blocked until scoped: upload and photo proof, public registration, invite acceptance, import/export, score correction, deletion of ACTIVE or assigned competitions, and broad social feed behavior.

## Storage Model

- Storage location: Existing private PostgreSQL database through Prisma.
- Database tables or files: GymForge participant, exercise, attendance, workout/set, competition, and assignment records; file storage is not enabled.
- Encryption or key-management needs: No zero-knowledge model expected. Future design must still define storage protection for group data and uploaded proof photos.
- Search/indexing behavior: Not enabled.
- Derived data or caches: Ranking, streak, and competition score views are computed from persisted records; manual score correction is not enabled.

## Migration Plan

- Prisma schema changes: Implemented for the current MVP foundation.
- Migration files: Implemented for the current MVP foundation.
- Backfill requirements: None.
- Rollback approach: Use a scoped migration for schema rollback and the documented restore procedure for data recovery.
- Disposable validation plan: Required before future schema changes, upload, import/export, assignment/scoring rule changes, or score correction work.

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

- Events to record: Current implementation audits participant creation/status changes, exercise creation/status changes, attendance check-in creation, admin attendance correction creation/removal, workout creation/update/deletion, competition creation, competition updates, competition archival, competition deletion, and competition assignment updates with sanitized metadata. Future phases must define audit events for invite acceptance, photo proof upload, score corrections, and broader destructive lifecycle changes.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: Workout details, body metrics, photo contents, raw upload paths, secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, private paths, and backup contents.

## Retention And Deletion

- Retention period: Not defined.
- Deletion behavior: Participants may delete only their own workout entries after explicit confirmation, while OWNER/ADMIN users may delete any workout entry. Workout deletion transactionally removes all dependent sets before deleting the workout. Admins may permanently delete only non-ACTIVE competitions with zero participant assignments; ACTIVE or assigned competitions must be archived or retained.
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

Future work requires explicit design and validation for upload/photo proof, public registration, invite acceptance, import/export, score correction, unsafe competition deletion, and broader social visibility. Existing private-hub auth, role checks, CSRF, audit sanitization, backup/restore, and data-integrity rules must remain in place.

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
