# GymForge MVP Architecture

GymForge has an implemented MVP foundation behind the private BielOS hub. This document defines the architecture boundary for that implementation and the remaining gates. It does not enable photo upload, public registration, invite acceptance, import/export, a public API, unsafe competition deletion, or broad social feed behavior.

GymForge is a gated social gym competition app for Gabriel and invited or admin-created participants. It is not a zero-knowledge vault and not an open public internet app. Approved participants may see group competition and streak data inside the gated area.

## MVP Boundary

- Implemented foundation: authenticated private hub route, participant/exercise administration, attendance check-ins and correction, fixed `America/Sao_Paulo` dates, single-set workout entry/edit/delete, ranking/streak views, competition lifecycle and assignment, deterministic current-state scoring, additive score correction, and safe deletion for non-ACTIVE competitions with zero assignments and no correction history.
- `[DONE]`: competition score-correction Phase 2 design and Phase 3 implementation.
- Further expansion is frozen; private invitations are not an active phase, and invite acceptance remains unavailable.
- Blocked until explicitly unfrozen and scoped: private invitations and invite acceptance, upload/photo proof, public registration, import/export, unsafe competition deletion, a public API, and broad social feed behavior.
- Included in the MVP boundary: participant accounts, admin participant management, admin exercise catalog, attendance check-ins, streaks, workout notes, exercise logs, simple group ranking, and competition metadata.
- Future but planned: photo proof for check-ins.
- Excluded from MVP: body metrics, health records, public registration, public profiles, open internet access, imports, exports, file upload, broad social feed, payments, and third-party integrations.
- Security posture: gated community with explicit auth and role checks, not public access and not zero-knowledge encryption.

## Entry Model

- Current MVP participant records are admin-created; invite acceptance is not implemented.
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

- Admins currently manage participant records; private invitations are next in Phase 4, while invite creation and acceptance remain unavailable until that phase is complete.
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
- The MVP allows at most one streak-counting attendance check-in per participant per local day unless an admin correction applies.
- MVP day boundaries use a fixed `America/Sao_Paulo` GymForge policy and store the effective attendance date as a canonical UTC date for uniqueness and future streak computation.
- Check-ins should store participant id, timestamp, effective local date, source, and optional note.
- Check-ins must not store raw IP addresses, raw user agents, secrets, tokens, cookies, JWTs, or raw headers.
- Admin correction is limited to OWNER/ADMIN users, requires CSRF, uses the fixed `America/Sao_Paulo` effective date policy, prevents duplicate participant/date attendance, and writes sanitized audit events.

## Streak Rules

- A streak is a count of consecutive qualifying attendance days.
- Streaks should be computed from attendance records or stored as derived data that can be rebuilt.
- Time zone must be explicit and stable for the group.
- MVP timezone is fixed to `America/Sao_Paulo`; it must not infer private user location.
- Missed days break the streak unless a future competition rule defines grace days.
- Manual admin corrections must be audited.

## Future Photo Proof

- Photo proof is future work and not part of the first implementation.
- Future photo proof must define upload limits, storage location, access rules, retention, deletion, and abuse controls.
- Photo contents, private paths, upload URLs, raw filenames, and storage keys must not be written to audit logs.
- Group visibility for proof photos must be explicit before upload exists.

## Workout Notes

- Participants may record notes for their own workouts.
- Participants may edit or delete only their own workout entries; OWNER/ADMIN users may edit or delete any participant workout entry.
- Notes are visible to the author by default.
- Sharing notes with the group must be an explicit future choice.
- Notes must be excluded from audit metadata.
- Notes must not be used as a place for secrets, credentials, medical records, or private keys.

## Exercise Logs

- Exercise logs attach to a participant and optional workout date/session.
- The current MVP intentionally creates and edits exactly one exercise set per workout, with exercise, set number, reps, load, unit, note, and timestamp fields.
- Editing transactionally replaces that one set through the same validation rules used by creation and fails safely before mutation if the stored workout unexpectedly has zero or multiple sets.
- Explicit workout deletion transactionally removes every dependent set before deleting the workout, including unexpected multi-set records.
- Exercise log details are private to the participant by default.
- Aggregated competition views may show approved summary data only.
- Validation must reject impossible or unsafe numeric values.

## Competition And Ranking

- MVP rankings may compare attendance count, current streak, longest streak, or challenge participation.
- Ranking data is visible only to approved group participants.
- Initial ranking foundation uses attendance records only and does not expose workout details, attendance notes, or workout notes.
- Current deterministic ranking and competition base scoring are derived from current attendance, competition date/rule, assignment, and ACTIVE participant state, so workout edits and deletions do not change scoring.
- Initial competition foundation supports admin-created and admin-editable competition metadata, admin-only explicit participant assignment, admin-only archival, admin-only safe deletion for non-ACTIVE competitions with zero assignments, and read-only deterministic scoring display.
- Competition definitions should include name, date range, scoring rule, active status, and participant scope.
- Scoring rules must be deterministic and explainable.
- Ties and late check-ins must have explicit rules.
- Deletion of ACTIVE, assigned, or correction-bearing competitions and broader admin adjudication require later scoped phases.

## Competition Assignment And Scoring

This section is implemented for explicit participant assignment, deterministic current-state scoring, admin-only competition lifecycle, additive score correction, and safe deletion for non-ACTIVE competitions with zero assignments and no correction history.

There is no GymForge public API; unsafe deletion and broad social behavior remain blocked.

- Participant assignment should be explicit: an admin assigns ACTIVE GymForge participants to a competition before scoring includes them.
- Participant scope should support at least `ALL_ACTIVE_AT_START` and `EXPLICIT_PARTICIPANTS`; MVP implementation should prefer explicit assignment when prizes, challenges, or sensitive group visibility are involved.
- Disabled or archived participants are excluded from current scoring. Their correction history is retained, and reactivation/reassignment must not silently make stale corrections effective again.
- Competition date ranges use GymForge effective attendance dates, not raw timestamps, and must use the existing fixed `America/Sao_Paulo` MVP timezone policy.
- An attendance counts for a competition only when `countsForStreak=true`, the effective date is within the competition range, and the participant is in scope.
- Open-ended ranges are allowed for draft display, but ACTIVE competitions should have explicit start and end rules before automatic scoring is enabled.
- Initial scoring rule types should be limited to attendance count, current streak inside range, longest streak inside range, or a simple weighted combination of attendance and streak.
- Attendance-count scoring gives one point per qualifying effective date and must ignore duplicate records if unexpected duplicates exist.
- Streak scoring counts consecutive qualifying effective dates inside the competition range; missed days break the streak unless a later rule explicitly defines grace days.
- Tie breakers are deterministic: higher final score, higher attendance count, higher longest streak, latest qualifying check-in, display name sort, then internal participant id only as a non-displayed fallback.
- Score corrections must use only the append-only additive/revocation flow defined below. They never mutate attendance, workout, competition, assignment, or other scoring-source rows.
- Visibility rules show display name, rank, current base score, aggregate active adjustment, final score, attendance count, streak summary, and safe competition metadata to approved group participants.
- Competition views must not expose workout notes, attendance notes, raw participant ids, raw audit metadata, raw request data, private exports, cookies, JWTs, headers, IPs, secrets, or database details.
- Audit events include competition lifecycle, deletion, assignment, and correction create/revoke actions with sanitized metadata. Correction audit metadata follows the stricter redaction contract below.
- Existing competition audit metadata stays sanitized. Score-correction audit metadata is narrower: stable hashed resource references and a generic result only.
- Validation must cover role checks, CSRF failures returning HTTP 403, date-boundary tests for `America/Sao_Paulo`, disabled/archived participant exclusion, duplicate attendance safety, final-score arithmetic, tie-break determinism, and visibility restrictions.

## Competition Score-Correction Phases 2 And 3

Phase 2 design and Phase 3 private-hub implementation are `[DONE]`.

### Current-State Score Model

- `baseScore` is always recomputed from current qualifying attendance, current competition dates and scoring rule, current assignment, and current ACTIVE participant state.
- An unrevoked correction row contributes only when that participant is currently assigned and ACTIVE. A correction never creates scoring eligibility.
- `activeAdjustment` is the sum of every unrevoked row for the competition/participant pair. Each row has a nonzero integer `pointsDelta` in `-1000..1000`; multiple rows may make the aggregate exceed that per-row range.
- `finalScore = baseScore + activeAdjustment`, with no zero floor. Negative final scores are valid.
- Correcting attendance or making an otherwise allowed competition date/rule change may alter the current base and final score without changing correction history. This is deterministic current-state scoring, not a snapshot of the score when an admin acted.
- The scoreboard always separates current base, aggregate adjustment, and final. Its stable order is final score, attendance count, longest streak, latest qualifying check-in, display-name sort, then internal participant id as a non-displayed fallback.

### Authorization, State, And Atomicity

- Every correction mutation and every assignment, reactivation, or competition-status mutation that enforces a correction invariant stays in a server action behind Cloudflare Access and BielOS internal auth, validates CSRF, rechecks `OWNER` or `ADMIN`, and uses generic user-facing errors. There is no public route or GymForge API.
- Create accepts only an `ACTIVE` or `ENDED` competition and a currently assigned participant whose status is `ACTIVE`. `DRAFT` and `ARCHIVED` reject creation.
- Revoke accepts only an unrevoked correction in an `ACTIVE`, `ENDED`, or `ARCHIVED` competition. `DRAFT` rejects revocation.
- Creation is append-only. Existing rows cannot be edited or hard-deleted. Revocation atomically records `revokedAt` and `revokedByUserId` and preserves the original row.
- Assignment removal is all-or-nothing and rejects any requested removal that has an unrevoked correction. The admin must revoke first; the assignment flow must not revoke corrections or alter attendance/workout/source rows on the admin's behalf.
- Disabling or archiving a participant excludes the participant while preserving corrections. Reactivation with a retained assignment and unrevoked corrections is blocked until explicit revocation. Reassignment cannot revive old rows because removal was impossible until all active rows were revoked.
- A transition back to `DRAFT` is blocked while any correction is unrevoked, because DRAFT cannot revoke it.
- Correction creation/revocation, assignment removal, participant reactivation, and `DRAFT` transition checks use serializable transactions with three bounded retries and generic failures. Concurrent operations cannot leave an active correction without its required assignment/state.

### Persistence And Idempotency

- The additive `GymForgeCompetitionScoreCorrection` model stores `id`, competition/participant references, `pointsDelta`, optional `reason`, unique `requestKey`, nullable create/revoke actor references, and create/revoke timestamps.
- Competition and participant relations restrict deletes. Actor relations use `onDelete: SetNull`; actions require and store the actor, while non-null `revokedAt` preserves revocation if the revoker account is later removed.
- Indexes support `(competitionId, participantId, revokedAt)` active lookup plus `(competitionId, createdAt)` and `(participantId, createdAt)` history lookup. `requestKey` has a unique index.
- The additive SQL migration enforces nonzero `pointsDelta` in `-1000..1000`, reason length at most 240, request-key length, and valid revocation shape; server validation stores a blank reason as null.
- `requestKey` is an opaque UUID v4 idempotency key. The same key and mutation returns without a duplicate insert; reuse with different data fails generically. Request keys are never displayed, audited, or exported.

### Private UI, Audit, And Retention

- Participants see only the aggregate adjustment beside current base and final score. They never see correction rows, reason, actors, request keys, or internal ids.
- OWNER/ADMIN users see compact history, private reason, and revoke controls in a private drawer. Participant and admin surfaces are available in PT-BR and English. The reason is never participant-visible, audited, or exported by default.
- Correction-created and correction-revoked audit events contain only stable hashed competition, participant, and correction references plus a generic result. They omit the raw audit actor id and all actor ids from metadata because actor attribution stays on the correction row, and exclude raw ids, names, reason, delta, score values, raw forms, request keys, and raw request data.
- Correction and revocation rows are retained. Permanent competition deletion is blocked whenever any correction exists, even after every row is revoked; restrictive participant history also prevents correction loss through participant deletion.
- The committed additive migration has not been applied to production. Deployment waits for a current verified backup and `prisma migrate deploy`.
- After the first correction write, dropping the table or rolling the application back to a pre-Phase-3 commit is unsafe because assignment, reactivation, and `DRAFT` guards live in the new runtime. Recovery requires a forward fix or verified restore.

## Group Visibility

- Approved group participants may see display names, ranking position, streak summaries, and competition participation.
- Participants may see their own detailed logs.
- Group ranking may show active participant display names, total attendance count, current streak, and latest check-in date.
- Competition ranking may show current base score, aggregate active adjustment, and final score, but never participant-facing correction history or reason text.
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

- Attendance and ranking retention remains to be defined for long-term production use.
- Participant removal should disable access and preserve required audit records.
- Workout notes and logs have an authenticated user deletion path for the author's own entries and OWNER/ADMIN deletion for any entry; deletion transactionally removes every dependent set.
- Competition history may be retained for group continuity. Permanent competition deletion is limited to non-ACTIVE competitions with zero participant assignments and zero correction rows; assigned, ACTIVE, or correction-bearing competitions must be archived or retained.
- Score-correction creation and revocation history is preserved. There is no correction cleanup worker, edit, or hard-delete path.
- Current GymForge records use the existing PostgreSQL backup and restore procedures; storage changes require renewed validation.

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
- competition created, updated, started, ended, archived, or safely deleted
- competition score correction created or revoked
- ranking recalculation failure if stored rankings are used

Audit logs must never include workout note text, exercise detail payloads, score-correction reasons or deltas, score payloads, raw resource ids, request keys, raw form/request data, photo contents, raw filenames, upload paths, raw invite links, invite secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, passwords, private keys, or database URLs.

## Validation Checklist

- Secret scan passes.
- Runtime changes require lint, typecheck, build, and Prisma validation as relevant.
- Prisma migration exists before schema changes are used.
- Invite and login failures remain generic.
- Public users cannot access GymForge routes.
- Disabled or removed participants cannot access GymForge data.
- Participants can view their own logs.
- Approved group participants can view only approved competition and streak data.
- Admin-only actions reject participant users.
- Missing or invalid CSRF on mutable routes returns HTTP 403.
- Rate limits remain required for login, future invite acceptance, and high-risk mutations.
- Audit events contain only sanitized metadata.
- Workout creation/editing preserves exactly one set, update rejects unexpected zero/multi-set records without mutation, and explicit deletion transactionally removes all dependent sets.
- Existing PostgreSQL backup and restore validation applies; storage changes require renewed validation.
- Eight focused scoring cases cover supported rules, date handling, additive/negative totals, eligibility, invalid inputs, input-order invariance, all deterministic tie breakers including hidden ids, and aggregate bounds. Secret scan, lint, typecheck, Prisma validation, and build pass; migration deployment and authenticated runtime smoke remain gated on backup/deploy.
