# GymForge Planning Document

GymForge is not implemented yet. This document is a planning gate only and does not enable private data ingestion, workout tracking, body metrics, upload, import/export, UI, routes, APIs, database schema, Prisma migrations, or tracking logic.

## Module Identity

- Module name: GymForge.
- Module owner: BielOS owner.
- Module purpose: Reserved future training workspace for workout planning and progress tracking, only if explicitly designed later.
- Current status: Planning only. Implementation is blocked.

## Data Classification

- Classification: sensitive.
- Private data types: Not approved yet. Must be enumerated before implementation.
- Data explicitly not collected: workouts, body metrics, health records, progress photos, uploads, passwords, secrets, raw logs, raw headers, raw IPs, JWTs, cookies, private keys, database dumps, backups, Gmail exports, Google Takeout exports, and any real private records.
- Public or non-private data, if any: Module name and locked/planned status only.

## Storage Model

- Storage location: Not defined.
- Database tables or files: None in this phase.
- Encryption or key-management needs: Future design required before any workout or body metric storage exists.
- Search/indexing behavior: Not enabled.
- Derived data or caches: Not enabled.

## Migration Plan

- Prisma schema changes: None in this phase.
- Migration files: None in this phase.
- Backfill requirements: None.
- Rollback approach: Documentation-only rollback.
- Disposable validation plan: Required before any future schema, storage, or tracking work.

## Backup And Restore

- Backup impact: None in this phase.
- Restore validation impact: None in this phase.
- Data that must never be exported: Any future workout, body metric, photo, or health-adjacent contents unless explicitly designed and approved.
- Disaster recovery notes: Future design must define restore behavior before ingestion.

## Access Control

- Required user roles: OWNER by default, pending module design.
- Cloudflare Access assumptions: Cloudflare Access remains the outer boundary for `hub.biel.dev.br`.
- BielOS internal auth requirements: BielOS internal auth remains required after Cloudflare Access.
- Module-specific unlocks: Required before sensitive body metric or health-adjacent data access is implemented.
- Cross-module access boundaries: GymForge must not share training, body metric, or health-adjacent data with other modules without explicit design.

## Audit Events

- Events to record: Future design must define view, create, update, delete, import, export, and unlock events if those actions are added.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: Workout details, body metrics, progress photos, health-adjacent contents, notes, secrets, tokens, cookies, JWTs, raw headers, raw IPs, raw user agents, file contents, private paths, and backup contents.

## Retention And Deletion

- Retention period: Not defined.
- Deletion behavior: Not defined.
- Cleanup command or worker: Not defined.
- User-visible deletion expectations: Future design must define permanent deletion, retention exceptions, recovery expectations, and backup implications.

## Threat Model

- Primary assets: Future workout plans, training history, body metrics, progress media, and health-adjacent notes.
- Abuse cases: Unauthorized access, accidental exposure, unsafe export, unsafe logging, inference from trends, and backup leakage.
- Accidental exposure risks: UI previews, logs, exports, debug output, backups, screenshots, browser cache, and notification text.
- Local machine risks: Local filesystem exposure, Docker volume handling, and untracked generated files.
- Remote access risks: Cloudflare Access misconfiguration and direct origin exposure.

## Failure Modes

- Database unavailable: Future implementation must fail closed for writes and sensitive reads.
- Backup unavailable: Future implementation must block non-discardable ingestion until backup and restore are validated.
- Cloudflare Access unavailable: Hub access should remain blocked remotely.
- Internal auth unavailable: Module access must not proceed.
- Partial write or import failure: Future implementation must define atomicity, cleanup, and rollback.

## UI Safety Constraints

- No private data fields until approved: Required.
- No upload inputs until approved: Required.
- No secret display: Required.
- No raw logs or audit metadata display: Required.
- Safe empty states: Must state that GymForge is locked and not collecting data.

## API Safety Constraints

- Allowed methods: None in this phase.
- CSRF requirements: Required for any future mutable route.
- Auth checks: Required for all future routes.
- Rate limits: Required for sensitive mutations, imports, and exports.
- Request and response redaction: Required.
- Error message behavior: Generic for auth and access failures.

## Secrets Handling

- Required env names: None in this phase.
- Placeholder-only docs: Required for any future env.
- Rotation behavior: Future design required if secrets are introduced.
- Logging restrictions: Never log secrets, tokens, private keys, raw headers, raw IPs, cookies, JWTs, workout details, body metrics, health-adjacent contents, progress media, or private notes.

## Import And Export Rules

- Import sources: Not enabled.
- Export formats: Not enabled.
- Manual confirmation requirements: Required before any future export.
- Redaction requirements: Required before any future export.
- Files that must stay out of Git: Any dumps, exports, backups, uploads, workout records, body metric records, progress media, private notes, or generated archives.

## Validation Checklist

- Secret scan: Required for this planning document.
- Lint: Required when runtime code is added.
- Typecheck: Required when runtime code is added.
- Build: Required when UI or runtime code is added.
- Prisma validation: Required when schema changes are added.
- Migration validation: Required when migrations are added.
- Backup and restore validation: Required before ingestion.
- Local auth check: Required before routes are added.
- Cloudflare Access check: Required before remote exposure.
- Negative tests for unauthorized access: Required before implementation.
