# Module Planning Index

This directory contains module planning and design documents. GymForge now has an implemented MVP foundation in the private hub; the other module documents remain planning-only. These documents do not enable private data ingestion, upload, import/export, or encryption/key-management by themselves.

## Module Documents

- `l-vault.md`: L-vault planning only. Implementation is blocked.
- `root-ark.md`: root.ark public zero-knowledge compartment planning only. Implementation is blocked.
- `h-vault.md`: H-vault planning only. Implementation is blocked.
- `gymforge.md`: GymForge gated social gym competition module plan, updated to reflect the implemented MVP foundation.
- `gymforge-mvp.md`: GymForge MVP architecture and current implementation boundary.

## Implementation Status

- BielOS Core: shell registry entry only; real expansion is blocked.
- L-vault: planning document complete; implementation blocked.
- root.ark: public zero-knowledge compartment planning revised; implementation blocked until a dedicated architecture phase is complete.
- H-vault: planning document complete; implementation blocked.
- GymForge: MVP foundation implemented behind the private hub. Current capabilities include participant and exercise administration, attendance check-ins and correction, single-set workout entry/edit/delete, ranking/streak views, competition lifecycle and assignment, deterministic current-state scoring, and additive score correction. Score-correction Phases 2 and 3 are `[DONE]`; the private invitation Phase 4 is `[NEXT]`.

## Required Gate

Every real module must complete its own module-specific security and data design before implementation. The base template is `../module-security-template.md`.

The completed design must define purpose, data classification, private data types, excluded data, storage, migrations, backup and restore impact, access control, audit events, retention, threat model, failure modes, UI constraints, API constraints, secrets handling, import/export rules, and validation.

## Blocked Items

For not-yet-implemented modules, the following remain blocked until explicitly designed and approved:

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

For GymForge specifically, upload/photo proof, public registration, invite acceptance until Phase 4, import/export, unsafe competition deletion, a public API, and broad social feed behavior remain blocked until scoped phases complete their design and implementation checks.

## Data Safety

No private data ingestion is enabled by the module shell or these planning documents themselves. New module surfaces must wait for validated module design; GymForge additions remain limited by its blockers above.
