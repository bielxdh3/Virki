# Module Security Design Template

Use this template before implementing any real BielOS module. A module shell entry is not enough to start collecting private data.

## Module Identity

- Module name:
- Module owner:
- Module purpose:
- Current status:

## Data Classification

- Classification: internal, sensitive, or highly sensitive.
- Private data types:
- Data explicitly not collected:
- Public or non-private data, if any:

## Storage Model

- Storage location:
- Database tables or files:
- Encryption or key-management needs:
- Search/indexing behavior:
- Derived data or caches:

## Migration Plan

- Prisma schema changes:
- Migration files:
- Backfill requirements:
- Rollback approach:
- Disposable validation plan:

## Backup And Restore

- Backup impact:
- Restore validation impact:
- Data that must never be exported:
- Disaster recovery notes:

## Access Control

- Required user roles:
- Cloudflare Access assumptions:
- BielOS internal auth requirements:
- Module-specific unlocks:
- Cross-module access boundaries:

## Audit Events

- Events to record:
- Event result values:
- Sanitized metadata only:
- Data explicitly excluded from audit logs:

## Retention And Deletion

- Retention period:
- Deletion behavior:
- Cleanup command or worker:
- User-visible deletion expectations:

## Threat Model

- Primary assets:
- Abuse cases:
- Accidental exposure risks:
- Local machine risks:
- Remote access risks:

## Failure Modes

- Database unavailable:
- Backup unavailable:
- Cloudflare Access unavailable:
- Internal auth unavailable:
- Partial write or import failure:

## UI Safety Constraints

- No private data fields until approved:
- No upload inputs until approved:
- No secret display:
- No raw logs or audit metadata display:
- Safe empty states:

## API Safety Constraints

- Allowed methods:
- CSRF requirements:
- Auth checks:
- Rate limits:
- Request and response redaction:
- Error message behavior:

## Secrets Handling

- Required env names:
- Placeholder-only docs:
- Rotation behavior:
- Logging restrictions:

## Import And Export Rules

- Import sources:
- Export formats:
- Manual confirmation requirements:
- Redaction requirements:
- Files that must stay out of Git:

## Validation Checklist

- Secret scan:
- Lint:
- Typecheck:
- Build:
- Prisma validation:
- Migration validation:
- Backup and restore validation:
- Local auth check:
- Cloudflare Access check:
- Negative tests for unauthorized access:
