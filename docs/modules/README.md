# Application And Module Planning Index

This directory contains application and reserved-module planning documents. BielOS Core is the private hub platform and workspace, not a module. Core expansion is the active path. GymForge is an available integrated application, while L-vault, root.ark, and H-vault remain reserved and inert.

## BielOS Core

- Status: active expansion authorized.
- Existing foundations: `Project`, `ProjectAccess`, `Session`, `SecurityUnlock`, and `AuditLog`.
- Next gate: Core-specific security and architecture design.
- Future Core phases must not be treated as complete until implemented and validated.

## Available Applications

- GymForge: available at `/gymforge` behind the existing private-hub boundaries. Implemented capabilities include participant and exercise administration, attendance check-ins and correction, single-set workout entry/edit/delete, ranking/streak views, competition lifecycle and assignment, deterministic current-state scoring, and additive score correction.
- GymForge expansion is frozen. Private invitations, public registration, import/export, photo proof/uploads, APIs, broad social features, and further scoring work are not active roadmap items.

## Reserved Modules

- L-vault: planning document complete; runtime implementation blocked.
- root.ark: public zero-knowledge planning revised; runtime implementation blocked, with architecture work still required before any future implementation.
- H-vault: planning document complete; runtime implementation blocked.

## Module Documents

- `l-vault.md`: L-vault planning only. Implementation is blocked.
- `root-ark.md`: root.ark public zero-knowledge compartment planning only. Implementation is blocked.
- `h-vault.md`: H-vault planning only. Implementation is blocked.
- `gymforge.md`: GymForge gated social gym competition module plan, updated to reflect the implemented MVP foundation.
- `gymforge-mvp.md`: GymForge MVP architecture and current implementation boundary.

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

For GymForge specifically, all further feature expansion is frozen. Existing functionality remains available, but invitations, upload/photo proof, public registration, import/export, a public API, broad social features, and further scoring work are not active phases.

## Data Safety

Planning documents and inert reserved-module entries do not enable private data ingestion. New module surfaces must wait for explicit authorization and validated module design. Existing GymForge data remains confined to its authenticated application, and Core work must preserve the established Cloudflare Access and BielOS internal authentication boundaries.
