# Application And Module Planning Index

This directory contains application and reserved-module planning documents. BielOS Core is the private platform/workspace, not a module. The 2026-09-18 direct campaign is published at `a9f867f6d06eeae71e00f5fae910978382260468`; exact-SHA CI passed. The local production stack is converged; authenticated human smoke remains external. Public registration and live Intake remain disabled. GymForge remains available with expansion frozen, while L-vault, root.ark, and H-vault remain reserved and inert.

## BielOS Core

- Status: existing Core project-detail, participant-access, recovery, audit, capability, operations, and platform surfaces are implemented locally. Runtime-sensitive checks were repeated with Node `22.20.0`; environment-backed Docker/PostgreSQL, exact-SHA CI, and authenticated human smoke remain release gates.
- Existing foundations: `Project`, `ProjectAccess`, `Session`, `SecurityUnlock`, and `AuditLog`.
- Security and architecture gate: complete in `bielos-core.md`.
- Implemented surfaces: project registry/lifecycle, authorization-aware project detail workspace, project access, personal sessions, safe operations visibility, owner-only audit activity, and typed application registry integration.
- Completed verification: historical database-backed integration/concurrency validation and historical authenticated OWNER/MEMBER production smoke; current authenticated smoke is not claimed.
- Maintenance boundary: the local production deployment is verified; authenticated human smoke remains pending. `SecurityUnlock` runtime remains blocked by its design boundary.

## Hub And Application Boundary

BielOS owns hub navigation, registry, identity/security boundaries, and Core policy. Future applications may be embedded, separately deployed, locally external, or remotely external only through an explicitly designed contract that preserves independent operation, explicit authentication and authorization, least privilege, failure isolation, privacy classification, version compatibility, and user approval where required. Redirect origin is not authentication, and sharing the BielOS database is not the default integration model. No external integration is implemented by this direction.

## Available Applications

- GymForge: available at `/gymforge` behind the existing private-hub boundaries. Implemented capabilities include participant and exercise administration, attendance check-ins and correction, single-set workout entry/edit/delete, ranking/streak views, competition lifecycle and assignment, deterministic current-state scoring, and additive score correction.
- GymForge expansion is frozen. Private invitations, public registration, import/export, photo proof/uploads, APIs, broad social features, and further scoring work are not active roadmap items.
- The typed hub registry lists GymForge as an available application linked to `/gymforge`; this is integration only and does not expand GymForge behavior.

## Reserved Modules

- L-vault: planning document complete; runtime implementation blocked.
- root.ark: public zero-knowledge planning revised; runtime implementation blocked, with architecture work still required before any future implementation.
- H-vault: planning document complete; runtime implementation blocked.

## Module Documents

- `bielos-core.md`: BielOS Core security, authorization, lifecycle, session, audit, and operations design.
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
