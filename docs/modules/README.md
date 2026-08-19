# Application And Module Planning Index

This directory contains application and reserved-module planning documents. BielOS Core is the private platform/workspace, not a module. The current post-smoke repair is `BIELOS_POST_SMOKE_REPAIR_LOCALLY_COMPLETE_AWAITING_HUMAN_SMOKE` in an uncommitted worktree; local validation passed under unsupported Node `24.14.1`, and affected OWNER/MEMBER project, audit, restriction, and logout smoke must be repeated under the existing layered boundaries. Public registration and live Intake remain disabled. GymForge remains available with expansion frozen, while L-vault, root.ark, and H-vault remain reserved and inert.

## BielOS Core

- Status: existing Core project-detail and platform surfaces are implemented; historical technical/runtime evidence is retained, while the uncommitted post-smoke repair has complete local validation under unsupported Node `24.14.1` and only the bounded affected human ceremony remains. Repeat validation under Node `>=22.13.0 <23` before release.
- Existing foundations: `Project`, `ProjectAccess`, `Session`, `SecurityUnlock`, and `AuditLog`.
- Security and architecture gate: complete in `bielos-core.md`.
- Implemented surfaces: project registry/lifecycle, authorization-aware project detail workspace, project access, personal sessions, safe operations visibility, owner-only audit activity, and typed application registry integration.
- Completed verification: historical database-backed integration/concurrency validation and historical authenticated OWNER/MEMBER production smoke; current authenticated smoke is not claimed.
- Maintenance boundary: no deployment or publication is authorized in the current uncommitted repair; `SecurityUnlock` runtime remains blocked by its design boundary.

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
