# Manual PostgreSQL live rollback: isolated native execution evidence

This is a **DEV-only PostgreSQL 17** recovery experiment, not the owner-installed
native manual-release executor. Nothing here authorizes an installation,
production backup, role mutation, service restart, Docker image load, deployment,
or `/srv/virki` change. The hosted `main` route is untouched.

The existing `scripts/lib/offline-pg-disposable-controller.sh` now supports the
fixed cases `manual_fenced_rollback` and `manual_fence_sigkill` under its
pre-existing isolation gate: PostgreSQL UID 70, a networkless, read-only,
capability-dropped container, private in-memory PGDATA and Unix socket,
pre-pinned image digest, and protected container-owner intent. The executable
uses actual `psql`, `pg_dump -Fc` and `pg_restore --exit-on-error` binaries.
No PostgreSQL URL, SQL, database name, Docker target or role is caller-selected.

The real-database sequence is:

1. Durably create the exclusive `.attempted` latch **before any PostgreSQL
   mutation**, then insert the unique `attempted` control journal entry and
   record `maintenance`.
2. Fence the isolated `virki_manual_writer` LOGIN role using PostgreSQL
   `ALTER ROLE ... NOLOGIN`, terminate its already-connected sleeping session,
   prove zero remaining sessions and reject a new client connection. Persist
   `writer_fenced`. Never restore LOGIN automatically, including on success.
3. Create and digest the custom-format backup, verify its archive inventory,
   create an **absent, separate** `virki_restore` database, restore without
   `--clean` or overwriting any existing clone, compare the synthetic private
   records, and test the migration on that clone before live fixture DDL.
4. For `manual_fenced_rollback`, record the rollback checkpoints, verify a
   separate rollback clone, restore the source fixture, prove the before/after
   identity/schema fingerprint, leave the private route at predecessor, and
   retain maintenance/latch and the writer's NOLOGIN state. No restart command.
5. For `manual_fence_sigkill`, kill only the child after `writer_fenced` is
   durable; the independently running PostgreSQL supervisor observes the
   remaining latch, `writer_fenced` journal, blocked writer and predecessor
   route. Any attempted replay must be refused.

Run the two cases through the pinned local Docker Desktop transport using
`VIRKI_OFFLINE_PG_CONTAINER_TEST=1` and `node --test --test-name-pattern='manual_fenced_rollback|manual_fence_sigkill' scripts/offline-pg-recovery-container.test.mjs`.
Tests never bind a network port or production volume. This is a **fixture-specific
writer fence**, not proof that all production writers, job workers, migrations,
Cloudflare ingress or privileged PostgreSQL sessions are stopped.

**Missing mandatory native gates:** independently audited root-installed
executable/closure and exact hashes; authenticated owner manual-source and
activation approval at the final use point; externally anchored witness CAS and
monotonic signed floor; host process/service/Tunnel and **all database writer**
quiescence with a verified no-auto-restart policy; production identity and
database connection pinning; immutable off-host backup custody and capacity;
actual protected PostgreSQL role/ACL compatibility; restart/crash recovery on
the native host; independent security peer GO and hosted release gates.
Never use the fixture's synthetic writer role to claim those guarantees.
