# GymForge Planning Document

GymForge now has an implemented MVP foundation inside the private BielOS hub. This document records the module boundary and remaining gates. It does not enable body metrics, health records, photo check-ins, upload, import/export, public registration, invite acceptance, workout editing/deletion, admin attendance correction, scoring corrections, unsafe competition deletion, or broad social feed behavior.

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

- GymForge should have a barrier before entering the site.
- Users may join only by invite or admin-created account.
- There is no open public registration.
- Internal users may see approved group or competition data after entry.
- Admin users may manage participants, exercise catalog entries, competitions, and challenges.
- Data does not need zero-knowledge encryption, but access must remain gated.

## Planned Features

- Gym attendance recording.
- Gym visit streaks.
- Future photo or camera check-in proof.
- Workout notes.
- Exercise logging.
- Sets, reps, and load tracking.
- Group streak comparison.
- Participation or challenge competition views.
- Admin-managed exercise catalog.
- Admin-managed users and participants.
- Admin-managed competitions or challenges.

## Storage Model

- Storage location: Not defined.
- Database tables or files: None in this phase.
- Encryption or key-management needs: No zero-knowledge model expected. Future design must still define storage protection for group data and uploaded proof photos.
- Search/indexing behavior: Not enabled.
- Derived data or caches: Not enabled.

## Migration Plan

- Prisma schema changes: None in this phase.
- Migration files: None in this phase.
- Backfill requirements: None.
- Rollback approach: Documentation-only rollback.
- Disposable validation plan: Required before future schema changes, storage, upload, import/export, editing/deletion, assignment rule changes, scoring rule changes, or score correction work.

## Backup And Restore

- Backup impact: None in this phase.
- Restore validation impact: None in this phase.
- Data that must never be exported: Raw credentials, secrets, raw tokens, private logs, and any future data not explicitly approved for export.
- Disaster recovery notes: Existing PostgreSQL backup and restore procedures apply. Future upload/import/export work needs separate backup and restore design before use.

## Access Control

- Required user roles: Admin and participant roles, pending module design.
- Cloudflare Access assumptions: Deployment boundary must be decided before exposure. The app is gated, not open public.
- BielOS internal auth requirements: Current GymForge uses BielOS internal auth behind Cloudflare Access. Participant actions require a linked ACTIVE GymForge participant; admin management requires OWNER or ADMIN.
- Module-specific unlocks: Not expected for ordinary competition data, but future design must revisit this if sensitive health data is added.
- Cross-module access boundaries: GymForge must not share workout, participant, or competition data with other modules without explicit design.

## Audit Events

- Events to record: Current implementation audits participant creation/status changes, exercise creation/status changes, attendance check-in creation, workout creation, competition creation, competition updates, competition archival, competition deletion, and competition assignment updates with sanitized metadata. Future phases must define audit events for invite acceptance, photo proof upload, workout editing/deletion, admin attendance correction, score corrections, and broader destructive lifecycle changes.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: Workout details, body metrics, photo contents, raw upload paths, secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, private paths, and backup contents.

## Retention And Deletion

- Retention period: Not defined.
- Deletion behavior: Admins may permanently delete only non-ACTIVE competitions with zero participant assignments. Competitions that are ACTIVE or have assignments must be archived or retained.
- Cleanup command or worker: Not defined.
- User-visible deletion expectations: Future design must define participant removal, competition history retention, photo proof retention, and backup implications.

## Threat Model

- Primary assets: Future participant accounts, attendance records, streaks, workout logs, competition data, and check-in proof photos.
- Abuse cases: Unauthorized entry, participant impersonation, fake check-ins, photo proof leakage, overexposed leaderboards, unsafe exports, unsafe logging, and backup leakage.
- Accidental exposure risks: Public routes, screenshots, shared devices, logs, exports, debug output, browser cache, and notification text.
- Local machine risks: Local filesystem exposure, Docker volume handling, and untracked generated files.
- Remote access risks: Gating misconfiguration, direct origin exposure, invite leakage, brute force of participant credentials or invites, and denial of service.

## Failure Modes

- Database unavailable: Future implementation must fail closed for writes and sensitive reads.
- Backup unavailable: Future implementation must block non-discardable ingestion until backup and restore are validated.
- Auth or invite flow unavailable: Module access must not proceed.
- Cloudflare unavailable: Remote exposure behavior must be defined before launch.
- Partial write, upload, or import failure: Future implementation must define atomicity, cleanup, and rollback.

## UI Safety Constraints

- No private data fields until approved: Required.
- No upload inputs until approved: Required.
- No secret display: Required.
- No raw logs or audit metadata display: Required.
- Safe empty states: Must distinguish implemented MVP foundation features from blocked future features.
- Group visibility must remain explicit before showing any new participant, streak, workout, or competition data beyond the current approved views.

## API Safety Constraints

- Allowed methods: None in this phase.
- CSRF requirements: Required for any future mutable route.
- Auth checks: Required for all future routes.
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

## Required Architecture Phase

Before future implementation beyond the current MVP foundation, GymForge needs scoped design for:

- gated entry model
- invite or admin-created account lifecycle
- participant roles
- admin roles
- exercise catalog management
- attendance and streak semantics
- photo check-in proof rules
- workout logging schema
- competition/challenge rules
- group visibility boundaries
- abuse controls for fake check-ins
- retention and deletion
- audit events
- backup and restore behavior

## Validation Checklist

- Secret scan: Required for this planning document.
- Lint: Required when runtime code is added.
- Typecheck: Required when runtime code is added.
- Build: Required when UI or runtime code is added.
- Prisma validation: Required when schema changes are added.
- Migration validation: Required when migrations are added.
- Backup and restore validation: Required before ingestion.
- Local auth or gated-entry check: Required before routes are added.
- Cloudflare exposure check: Required before remote access.
- Negative tests for unauthorized access: Required before implementation.
