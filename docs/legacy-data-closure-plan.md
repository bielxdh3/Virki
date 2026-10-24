# Legacy data and workload closure plan

Status date: 2026-10-19
Disposition: operator evidence and policy decisions are required before any data migration, constraint, or workload-driven index change.

This document defines a guarded, aggregate-only way to collect the minimum evidence for HIGH-16, MED-20, MED-22, and LOW-08. The inventory command was added for a future operator-approved, isolated PostgreSQL 17 restore. It was not pointed at a live database or a production backup during this task. Its output is evidence for review, not authorization to mutate data.

## Collection boundary

Use a protected, operator-controlled restore of an approved backup in a disposable environment. Treat the restored data as production-sensitive. Do not copy a backup, connection URL, raw row, or secret into this repository, a task transcript, CI, or a shared report. This repository task has not accessed production, SSH, a real database, a production snapshot, Cloudflare, GitHub, or deManage.

Run the inventory from the exact reviewed Virki source revision whose migrations are applied. The command refuses a mismatched configured host/database, connected PostgreSQL server address, schema, migration set, database/schema creation privilege, or read-only transaction. It requires PostgreSQL 17 and a dedicated login with no role memberships or elevated role attributes. It reads account email values only in process memory to compute the exact `normalizeEmail` aggregates; it does not print or write row values. On any failed preflight it returns a generic failure and no result document.

The reader must connect to the approved database, have `USAGE` on `public` and `information_schema`, and have table-level `SELECT` on only the eight inventory relations (`User`, `Session`, `SecurityElevation`, `UserProjectGrant`, `AccountRecoveryRequest`, `EmailOutboxMessage`, `ProjectConnection`, `_prisma_migrations`). It must not own database objects; have database `CREATE`/`TEMPORARY`, schema `CREATE`, or access to another application schema; hold any privilege on other `public` relations, sequences, or routines; hold write or column-write privileges on the eight inventory relations; or receive matching user/`PUBLIC` default ACL grants. The script checks effective ACLs (including `PUBLIC` and column grants), role attributes and memberships, object ownership, schema/database privileges, row-level-security state on inventory tables, and transaction read-only state before reading rows. Do not reuse the application, migrator, bootstrap, maintenance, or human administrator credential.

After an owner has approved the restore, created the dedicated reader, and separately supplied its protected `DATABASE_URL`, run from the reviewed worktree:

```powershell
$env:DATABASE_URL = '<reader URL supplied through the approved secret channel>'
npm run inventory:legacy-data -- --expected-host '<approved database host>' --expected-database '<approved database name>' --expected-server-address '<approved PostgreSQL server IP>' --confirm-target
```

The placeholders above are not valid targets. Do not put a real credential in a command, source file, report, or shell history. Save the emitted JSON only in an access-controlled operator evidence location, then provide the reviewed aggregate values without endpoint details. Record source SHA, restore identity, PostgreSQL version, and collection time separately. A mismatch or failed preflight means stop and diagnose outside the product repository; do not weaken the guard to make a target pass.

The inventory's `pg_stat_user_tables` counters are cumulative since the statistics reset and may be reset or incomplete on a restored database. They are not query frequency, latency, or representative access-path evidence. The source inventory does not record query-level calls or parameter skew. Gather those separately under an approved observability process, redact identifiers, and retain only time window, calls per query shape, row/key skew, read/write rates, and representative plan summaries. Do not run `EXPLAIN ANALYZE` on production as part of this procedure.

## Finding-specific evidence and decisions

### HIGH-16 — elevation/session lifecycle

The runtime authorization path rechecks the user, session owner, active session state, elevation scope, status, and expiry in the protected transaction. An elevation linked to no session or another user's session is representable in the schema but does not authorize a protected action. Session cleanup can leave an ACTIVE manual elevation row without a valid session; it is inert under current authorization.

Review these aggregates:

- `counts.elevation.missingSession`
- `counts.elevation.ownerMismatch`
- `counts.elevation.activeManualWithInvalidSession`
- `counts.elevation.duplicateTupleGroups`
- `counts.elevation.duplicateActiveGroups`

Before proposing an FK or uniqueness rule, the operator and security owner must decide the intended deletion/lifecycle behavior (cascade, retained/revoked history, or another explicit policy), the allowed number of effective ACTIVE grants per `(userId, sessionId, scope)`, and how duplicate active rows are resolved without broad revocation or loss of auditability. Confirm that account deletion behavior and historical audit retention remain compatible. Keep HIGH-16 blocked until inventory, policy, and a disposable-restore migration rehearsal agree. Do not delete or rewrite rows from aggregate counts alone.

### MED-20 — canonical email and account state

The current identity helper defines canonical email as JavaScript `trim().toLowerCase()`; it does not apply additional Unicode normalization. The admin action permits only the exact consistent ACTIVE-to-INACTIVE and INACTIVE-to-ACTIVE pairs. BLOCKED, PENDING_ACTIVATION, and inconsistent pairs cannot be changed through the toggle.

Status on 2026-10-24: `BLOCKED_UNVERIFIED`. The issue #60 code review did not have an operator-approved isolated restore or aggregate inventory output. It therefore cannot establish whether case-mismatched legacy email values or canonical collisions exist. Keep lookup and recovery behavior unchanged until the read-only inventory below and the account-resolution policy are reviewed; do not backfill from this source review.

Review `counts.accountEmails` (`totalUsers`, `normalizedNull`, `normalizedBlank`, `normalizationMismatch`, `collisionGroupCount`, and `collisionMemberCount`) plus all eight `counts.accountStates` status/`isActive` buckets. Collision groups are counted by the canonical helper, not by locale-sensitive database collation.

Before any backfill, constraint, or recovery-lookup change, approve the canonicalization contract and a per-account resolution process for null/blank/mismatched values and collisions. A collision must be resolved against verified ownership; do not merge accounts, select an arbitrary winner, or issue recovery based on an alternate identity match. Decide explicitly how `BLOCKED` and `PENDING_ACTIVATION` accounts transition. Preserve password hashes, MFA/recovery metadata, sessions, and security audit history. Rehearse any change on the approved restore, then rerun aggregate inventory and reconciliation.

### MED-22 — outbox lease and grant/reviewer attribution

The worker can now reclaim a PROCESSING row whose lease is NULL through the existing compare-and-swap claim path. Attempt-count fencing prevents a stale finalizer from overwriting a later claim. This application behavior does not prove that legacy rows or all status/timestamp combinations are consistent.

Review `counts.outbox` (`processingWithoutLease`, `expiredProcessingLease`, `strayLease`, `sentWithoutTimestamp`, `terminalFailureWithoutTimestamp`, and `sentTimestampOnOtherStatus`) and `counts.grantAndReview` (`orphanedGrantors`, `selfReviewedRequests`, and `missingReviewers`).

Before CHECK/FK constraints, decide and document the valid status-to-lease/timestamp state table, treatment of in-flight and terminal rows, retry ownership, and deployment ordering for a worker version that accepts NULL leases. For grant attribution, decide whether a removed grantor is restricted, nulled, or represented by a retained audit identity; do not silently lose attribution. Preserve the existing self-review prohibition and the reviewer `ON DELETE SET NULL` behavior unless a separately reviewed retention policy changes it. Compare the exact candidate migration with current and restored migration state before applying it anywhere.

### LOW-08 — query plans and index choices

Review `counts.workload` for estimated rows, total relation bytes, and table-level scan/write counters. Those values help describe table scale and cumulative activity only. They do not support index selection by themselves.

No candidate index is authorized by the current synthetic PostgreSQL 17 plans. The synthetic elevation SQL does not match either source caller exactly; the audit plan covers only category/date filtering; and the recorded outbox plan predates the NULL-lease branch. `ProjectConnection.createdByUserId` and `AccountRecoveryRequest.reviewedByUserId` lack leading child indexes, but this source fact does not establish deletion cost or a useful index.

For each proposed index, obtain a representative plan for the exact source query shape, the relevant predicates/order/limit, row counts and key skew, calls per time window, read/write volume, current index size, and a bounded write-cost comparison. Keep elevation list and authorization plans separate. Include the NULL-lease OR branch in any outbox plan. Test candidates on the approved restore or a faithful synthetic copy, document storage/write trade-offs, and require a separate review before proposing DDL. Do not create, drop, or reindex anything based only on this inventory.

## Closure gates

For each finding, retain the aggregate result, the exact source SHA and migration state, the owner-approved policy, and the result of a disposable-restore rehearsal. Keep row-level evidence under the operator's existing protected data process; do not attach it here. Close an individual finding only after its own acceptance evidence is complete. Local code tests or a successful read-only inventory do not close the real-data, migration-compatibility, workload, hosted CI/CodeQL/SARIF, production topology, or human-acceptance gates.
