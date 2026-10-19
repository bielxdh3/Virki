# LOW-08 index and query-plan evidence

Date: 2026-10-19
Status: synthetic PostgreSQL 17 comparison completed; production workload evidence remains unavailable.

## Scope and source inventory

The query shapes below were taken from the current source and mapped to Prisma indexes in `packages/database/prisma/schema.prisma`:

| Workload | Current index definitions | Source query |
|---|---|---|
| Authentication identity lookup | `User.emailNormalized` unique; `User.email` unique | User lookup by normalized email during login |
| Active session list | `Session(userId)`, `Session(expiresAt)` | `apps/hub/src/app/account/security/actions.ts:105` |
| Admin elevation list | `SecurityElevation(userId, sessionId, scope)`, `(status, expiresAt)`, `(sessionId)` | `listActiveSecurityElevations` filters user/session/status and expiry/manual state, orders by `createdAt DESC`, and takes 20; it does not filter scope. |
| Admin elevation authorization | Same current index definitions | `hasActiveSecurityElevation` filters user/session/scope/status and expiry/manual state; it has no ordering or list limit. |
| Filtered audit page | Category, result, actor, resource and time composites; event/action/request indexes | `packages/auth/src/audit-query.ts:24-55`; consumed at `apps/hub/src/app/admin/audit/page.tsx:17` |
| Outbox claim | `(status, availableAt)`, `(status, processingLeaseExpiresAt)` | `packages/auth/src/email.ts:136-151` |

The disposable model included the columns needed by these query predicates and ordering, with the relevant Prisma index shapes. It did not reproduce every column, relation, trigger, production data distribution, or production storage characteristic.

## Disposable workload

PostgreSQL 17 used image `postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`. The owned container ran with `--network none` and a temporary filesystem only, and was removed after the run. SQL inputs, logs, and container metadata are retained under `.superpowers/sdd/2026-10-19-virki-final-gates/query-plan/`.

Final synthetic cardinalities and assumptions:

- 20,000 users with unique normalized emails; 10,000 were marked ADMIN for elevation rows.
- 301,000 sessions: 300,000 distributed evenly across 20,000 users, plus 1,000 extra rows for one skewed account. Ten percent were expired and 80 percent revoked.
- 50,000 elevations across 10,000 users, with 20 percent marked ACTIVE and a mix of expired and current rows.
- 300,000 audit rows spread evenly across 12 categories and a repeating 730-day timestamp range.
- 50,000 outbox rows with QUEUED, RETRYABLE_FAILURE, PROCESSING, and SENT states; half of PROCESSING leases were expired. Pending availability timestamps were due.

The first, larger data load exceeded the isolated temporary filesystem before producing plans. That container was removed. The successful run used the reduced counts above. No workspace service or shared integration container was used.

## Current index plans

All queries used `EXPLAIN (ANALYZE, BUFFERS, TIMING OFF)` on the disposable database. Observed times are a single-run sample, not a capacity forecast.

| Query | Observed plan | Sample observation |
|---|---|---|
| Normalized email | Unique index scan on `User_emailNormalized_key` | One row; 3 shared blocks read; 0.084 ms execution |
| Active sessions | Bitmap index/heap scan on `Session_userId_idx`, filter revocation/expiry, then top-N sort | 1,015 account rows visited; 200 remained after filters; 31 blocks read plus 6 hits; 1.045 ms |
| Synthetic elevation approximation | Index scan on `SecurityElevation_userId_sessionId_scope_idx`, then status/expiry filter and sort | 5 matching key rows, one accepted; 7 blocks read; 0.170 ms. The retained SQL adds `ORDER BY createdAt DESC LIMIT 1`, so it matches neither runtime caller exactly. |
| Audit page | Backward scan on `AuditLog_category_createdAt_id_idx` | Returned 51 rows without a sort; 33 hits and 21 reads; 0.433 ms |
| Outbox claim | Bitmap OR/heap scan followed by top-N sort | 11,250 rows reached the heap; 396 shared blocks; 4.001 ms. The existing planner selected the lease index for both OR branches and filtered `availableAt` afterward. |

These plans show the audit composite matching its filter and ordering. The outbox query still sorts after combining its OR branches. The synthetic counts do not establish whether either behavior is costly for a real operator workload.

## Candidate session index

The isolated comparison added this temporary index only to the disposable database:

```sql
CREATE INDEX CONCURRENTLY "Session_active_user_recent_candidate_idx"
  ON "Session" ("userId", "createdAt" DESC, "id" DESC)
  WHERE "revokedAt" IS NULL;
```

For the same active-session query, the candidate plan used an ordered index scan and removed the explicit sort. It returned 50 rows while checking `expiresAt` as a filter. The candidate index occupied 3,480 kB and built in 112.679 ms on this synthetic dataset. Its observed query time was 0.160 ms, compared with 1.045 ms for the earlier baseline. The baseline ran before candidate creation and the candidate ran after index creation and analysis; cache states differ, so the elapsed times do not prove a latency improvement.

A one-shot 50,000-row insert comparison took 492.990 ms with the existing session indexes and 532.107 ms with the candidate index, about 7.9 percent slower in that sample. It also dirtied more buffers. This is directional only: the two tables ran sequentially, there were no repeated trials, and local cache/write state affects the result. The candidate adds storage and write maintenance. No index was committed or proposed for production based on this sample.

The synthetic outbox plan predates the local null-lease recovery branch. Its SQL includes only `processingLeaseExpiresAt <= now()` and does not measure the additional `processingLeaseExpiresAt IS NULL` branch now used by the worker. The retained plan remains historical synthetic evidence and does not establish the current combined query cost. No outbox candidate was justified. Any future index change needs an operator workload and write-volume comparison; do not add a blanket index set.

## Query coverage and index candidates

The audit plan represents only a category-and-date filter with descending time order. It does not cover the full audit page's result, actor, resource, event/action, request, or prefix-search OR combinations. Its plan is a narrow synthetic shape, not a representative profile of all audit queries.

`ProjectConnection.createdByUserId` and `AccountRecoveryRequest.reviewedByUserId` are foreign-key child columns without leading-key indexes. This source observation alone does not establish slow deletion, a frequent join, or a beneficial index. No user-deletion workload or operator storage/write budget was available, so these indexes remain unchanged.

## Operator-owned read-only inventory and workload evidence

LOW-08 remains `BLOCKED_UNVERIFIED` until representative cardinalities, skew, query frequency, and write volume are available. Use the guarded aggregate inventory described in [legacy-data closure plan](legacy-data-closure-plan.md) only after operator approval. It requires an independently supplied connection host, database name, PostgreSQL server address, a matching PostgreSQL 17 schema/migration state, and a dedicated read-only role; it emits counts, estimates, table sizes, and aggregate table scan/write counters only. This mission did not connect it to any real database.

That inventory does not capture query plans. For a later index decision, the operator should provide only redacted or synthetic plan evidence that matches each actual query shape above, along with approximate row counts and key skew, calls per time window, read/write volume, and current index size. Use separate approval for any plan capture that executes a query; do not put raw email, user, session, grant, or request identifiers into a shared report. Keep plans for the elevation list and authorization check separate, and include the null-lease outbox branch before interpreting its combined plan.

## Evidence files

- `01-schema-and-data.sql` and `01-schema-and-data-final.sql.log` — selected synthetic schema and load.
- `02-current-plans.sql` — current query statements; `02-current-plans-final.sql.log` is the successful run with an elevation row that matches the seeded ACTIVE query.
- `03-candidate-and-write-cost.sql` and `03-candidate-and-write-cost-final.sql.log` — temporary candidate index, plan, size, and insert samples.
- `container-final.txt` — pinned image, network isolation, and run note.
