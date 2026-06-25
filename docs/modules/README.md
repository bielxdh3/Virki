# Module Planning Index

This directory contains planning documents only. No real module implementation, private data ingestion, upload, storage, routes, APIs, UI, schema, migrations, tracking, import/export, or encryption/key-management is enabled by these documents.

## Module Documents

- `l-vault.md`: L-vault planning only. Implementation is blocked.
- `root-ark.md`: root.ark public zero-knowledge compartment planning only. Implementation is blocked.
- `h-vault.md`: H-vault planning only. Implementation is blocked.
- `gymforge.md`: GymForge gated social gym competition planning only. Implementation is blocked.

## Implementation Status

- BielOS Core: shell registry entry only; real expansion is blocked.
- L-vault: planning document complete; implementation blocked.
- root.ark: public zero-knowledge compartment planning revised; implementation blocked until a dedicated architecture phase is complete.
- H-vault: planning document complete; implementation blocked.
- GymForge: gated social gym competition planning revised; implementation blocked until a dedicated architecture or MVP phase is complete.

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

For root.ark specifically, public exposure, compartment access, capability links, encrypted blob storage, metadata handling, key lifecycle, revocation, and deletion remain blocked until a dedicated architecture phase is complete.

For GymForge specifically, gated entry, invite or admin-created accounts, attendance, streaks, photo check-ins, workout logging, exercise catalog, competitions, group visibility, retention, deletion, and abuse controls remain blocked until a dedicated architecture or MVP phase is complete.

## Data Safety

No private data ingestion is enabled by the module shell or these planning documents. Module pages, APIs, storage, and imports must not be added until the relevant module design is complete and validated.
