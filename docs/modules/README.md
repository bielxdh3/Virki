# Module Planning Index

This directory contains planning documents only. No real module implementation, private data ingestion, upload, storage, routes, APIs, UI, schema, migrations, tracking, import/export, or encryption/key-management is enabled by these documents.

## Module Documents

- `l-vault.md`: L-vault planning only. Implementation is blocked.
- `root-ark.md`: root.ark planning only. Implementation is blocked.
- `h-vault.md`: H-vault planning only. Implementation is blocked.
- `gymforge.md`: GymForge planning only. Implementation is blocked.

## Implementation Status

- BielOS Core: shell registry entry only; real expansion is blocked.
- L-vault: planning document complete; implementation blocked.
- root.ark: planning document complete; implementation blocked.
- H-vault: planning document complete; implementation blocked.
- GymForge: planning document complete; implementation blocked.

## Required Gate

Every real module must complete its own module-specific security and data design before implementation. The base template is `../module-security-template.md`.

The completed design must define purpose, data classification, private data types, excluded data, storage, migrations, backup and restore impact, access control, audit events, retention, threat model, failure modes, UI constraints, API constraints, secrets handling, import/export rules, and validation.

## Blocked Items

The following remain blocked for every module until explicitly designed and approved:

- runtime code
- UI
- routes
- APIs
- uploads
- database schema
- Prisma migrations
- encryption or key-management code
- tracking logic
- private data storage
- private data ingestion
- import/export
- public exposure

## Data Safety

No private data ingestion is enabled by the module shell or these planning documents. Module pages, APIs, storage, and imports must not be added until the relevant module design is complete and validated.
