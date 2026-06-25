# GymForge MVP Architecture

GymForge is not implemented yet. This document defines the MVP architecture gate only and does not add runtime code, UI, routes, APIs, auth code, upload, database schema, Prisma migrations, workout tracking logic, private data storage, or private data ingestion.

GymForge is a gated social gym competition app for Gabriel and invited or admin-created participants. It is not a zero-knowledge vault and not an open public internet app. Approved participants may see group competition and streak data inside the gated area.

## MVP Boundary

- Included: participant accounts, admin participant management, admin exercise catalog, attendance check-ins, streaks, workout notes, exercise logs, and simple group ranking.
- Future but planned: photo proof for check-ins.
- Excluded from MVP: body metrics, health records, public registration, public profiles, open internet access, imports, exports, file upload, broad social feed, payments, and third-party integrations.
- Security posture: gated community with explicit auth and role checks, not public access and not zero-knowledge encryption.

## Entry Model

- Participants enter only through invite or admin-created account.
- Open public registration is not allowed.
- Invite acceptance must not reveal whether an email or account exists.
- Invalid, expired, or already-used invites must return generic errors.
- Entry and mutable routes must require CSRF protection.
- Login and invite flows must use existing rate limiting or a future module-specific limiter.

## Participant Model

- Participant identity should be separate from public identity.
- Minimal MVP fields should cover display name, status, role, join state, and timestamps.
- Participant status should support active, invited, disabled, and removed or archived states.
- Participants may view their own workout logs and approved group ranking data.
- Removed or disabled participants must lose access without deleting required audit history.

## Admin Role

- Admins may create invites or accounts.
- Admins may disable or archive participants.
- Admins may manage exercise catalog entries.
- Admins may create and manage competitions or challenges.
- Admin actions must be audited with sanitized metadata only.
- Admin access must not bypass general logging, CSRF, or validation rules.

## Exercise Catalog

- Catalog entries should define exercise name, category, active status, and optional notes.
- Admins manage catalog entries.
- Participants select from active catalog entries when logging workouts.
- Catalog changes should preserve historical workout meaning.
- Deleting catalog entries should be avoided; prefer deactivate/archive.

## Attendance Check-Ins

- A check-in records that a participant attended the gym on a date or time window.
- MVP should allow at most one streak-counting attendance check-in per participant per local day unless an admin override exists.
- Check-ins should store participant id, timestamp, effective local date, source, and optional note.
- Check-ins must not store raw IP addresses, raw user agents, secrets, tokens, cookies, JWTs, or raw headers.
- Admin correction rules must be designed before edits or backfills are implemented.

## Streak Rules

- A streak is a count of consecutive qualifying attendance days.
- Streaks should be computed from attendance records or stored as derived data that can be rebuilt.
- Time zone must be explicit and stable for the group.
- Missed days break the streak unless a future competition rule defines grace days.
- Manual admin corrections must be audited.

## Future Photo Proof

- Photo proof is future work and not part of the first implementation.
- Future photo proof must define upload limits, storage location, access rules, retention, deletion, and abuse controls.
- Photo contents, private paths, upload URLs, raw filenames, and storage keys must not be written to audit logs.
- Group visibility for proof photos must be explicit before upload exists.

## Workout Notes

- Participants may record notes for their own workouts.
- Notes are visible to the author by default.
- Sharing notes with the group must be an explicit future choice.
- Notes must be excluded from audit metadata.
- Notes must not be used as a place for secrets, credentials, medical records, or private keys.

## Exercise Logs

- Exercise logs attach to a participant and optional workout date/session.
- MVP fields may include exercise, sets, reps, load, unit, note, and timestamp.
- Exercise log details are private to the participant by default.
- Aggregated competition views may show approved summary data only.
- Validation must reject impossible or unsafe numeric values.

## Competition And Ranking

- MVP rankings may compare attendance count, current streak, longest streak, or challenge participation.
- Ranking data is visible only to approved group participants.
- Competition definitions should include name, date range, scoring rule, active status, and participant scope.
- Scoring rules must be deterministic and explainable.
- Ties and late check-ins must have explicit rules.

## Group Visibility

- Approved group participants may see display names, ranking position, streak summaries, and competition participation.
- Participants may see their own detailed logs.
- Detailed workout notes and exercise logs are not group-visible unless a future design explicitly enables it.
- Disabled, removed, or non-participants must not see group data.
- Public users must not see any GymForge data.

## Abuse Cases

- Fake check-ins.
- Invite leakage or sharing.
- Participant impersonation.
- Admin account compromise.
- Overexposed rankings or screenshots.
- Photo proof leakage in a future phase.
- Spam check-ins or workout logs.
- Unsafe exports or debug logs.

MVP controls should include gated entry, generic auth errors, rate limiting, one qualifying check-in per day, audit events for admin actions and check-ins, and clear group visibility boundaries. Stronger proof, geofencing, or device checks are not required for MVP unless abuse becomes real.

## Retention And Deletion

- Attendance and ranking data retention should be defined before implementation.
- Participant removal should disable access and preserve required audit records.
- Workout notes and logs need a user deletion path before broad use.
- Competition history may be retained for group continuity, but participant removal behavior must be explicit.
- Backup and restore implications must be documented before non-discardable GymForge data is created.

## Audit Events

Audit events should cover:

- participant invited
- participant created
- participant disabled or archived
- participant role changed
- exercise catalog created, updated, deactivated, or archived
- attendance check-in created
- attendance check-in corrected by admin
- workout log created, updated, or deleted
- competition created, updated, started, ended, or archived
- ranking recalculation failure if stored rankings are used

Audit logs must never include workout note text, exercise detail payloads, photo contents, raw filenames, upload paths, raw invite links, invite secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, passwords, private keys, or database URLs.

## Validation Checklist

- Secret scan passes.
- Runtime implementation adds lint, typecheck, build, and Prisma validation.
- Prisma migration exists before schema changes are used.
- Invite and login failures remain generic.
- Public users cannot access GymForge routes.
- Disabled or removed participants cannot access GymForge data.
- Participants can view their own logs.
- Approved group participants can view only approved competition and streak data.
- Admin-only actions reject participant users.
- Missing or invalid CSRF on mutable routes returns HTTP 403.
- Rate limits apply to login, invite acceptance, and high-risk mutations.
- Audit events contain only sanitized metadata.
- Backup and restore behavior is validated before non-discardable data exists.
