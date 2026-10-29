// DEV-only expectations for the first REAL Prisma schema-engine DDL in a
// networkless disposable PostgreSQL clone. Static design, not live proof.
export const INTERRUPT_TIMING = Object.freeze({
  blockerSeconds: 240,
  engineTimeoutMs: 175000,
  observationTimeoutMs: 120000,
});

function refuse() { throw new Error("Disposable first Prisma DDL observation refused."); }

/** Lock only a table that is truly modified by the immutable migration SQL. */
export function assertCommittedFirstDdl(text) {
  if (typeof text !== "string" || text.length > 16384) refuse();
  const first = /ALTER\s+TABLE\s+"([A-Za-z]+)"\s+ADD\s+COLUMN\s+"([A-Za-z]+)"\s+([A-Z]+)\s*;/iu.exec(text);
  if (first?.[1] !== "ProjectConnection" || first?.[2] !== "launchUrl" ||
      first?.[3] !== "TEXT") refuse();
  return Object.freeze({ table: first[1], column: first[2], type: first[3] });
}

/** Query actual blocked SQL, owned holder and PostgreSQL lock compatibility. */
export function deriveBlockedDdlProbe() {
  // A SHARE UPDATE EXCLUSIVE holder allows preliminary AccessShareLock reads,
  // but conflicts with the real ALTER's AccessExclusiveLock. PG visibility
  // alone does not prove which user-space process owns the waiting backend:
  // orchestrator also checks the actual Linux engine UID/PPID/executable.
  return `SELECT COUNT(*) ${blockedDdlFrom()}`;
}

function blockedDdlFrom() {
  return `FROM pg_locks l
  JOIN pg_stat_activity a ON a.pid = l.pid
  JOIN pg_locks h ON h.pid = ANY(pg_blocking_pids(a.pid))
  JOIN pg_stat_activity b ON b.pid = h.pid
  WHERE a.datname = 'virki_clone'
    AND a.pid <> pg_backend_pid()
    AND a.usename = 'postgres'
    AND a.client_addr IS NULL
    AND a.wait_event_type = 'Lock'
    AND a.query ~ '^CREATE EXTENSION IF NOT EXISTS pgcrypto;[[:space:]]+ALTER[[:space:]]+TABLE[[:space:]]+"ProjectConnection"[[:space:]]+ADD[[:space:]]+COLUMN[[:space:]]+"launchUrl"[[:space:]]+TEXT;'
    AND l.relation = 'public."ProjectConnection"'::regclass
    AND l.mode = 'AccessExclusiveLock'
    AND l.granted = false
    AND h.relation = l.relation
    AND h.mode = 'ShareUpdateExclusiveLock'
    AND h.granted = true
    AND b.datname = 'virki_clone'
    AND b.query LIKE '%pg_sleep(${INTERRUPT_TIMING.blockerSeconds})%'
    AND b.query LIKE '%LOCK TABLE "ProjectConnection" IN SHARE UPDATE EXCLUSIVE MODE%'`;
}

/** Only one PostgreSQL connection to the exact migration DDL is a valid target. */
export function deriveBlockedDdlBackendIdentityProbe() {
  return `SELECT DISTINCT a.pid::text || '|' || ` +
    `(EXTRACT(EPOCH FROM a.backend_start) * 1000000)::bigint::text ${blockedDdlFrom()}`;
}

export function parseBlockedDdlBackendIdentity(output) {
  const match = /^([1-9][0-9]{0,9})\|([1-9][0-9]{15})$/u.exec(output);
  if (!match || Number(match[1]) > 2147483647) refuse();
  return Object.freeze({ pid: Number(match[1]), startedMicroseconds: match[2] });
}

function validIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !Number.isSafeInteger(value.pid) || value.pid < 1 || value.pid > 2147483647 ||
      typeof value.startedMicroseconds !== "string" ||
      !/^[1-9][0-9]{15}$/u.test(value.startedMicroseconds)) refuse();
}

/** Verify live exact migration SQL + owner lock + original session epoch atomically
 * with the termination. Zero or multiple matches means NO backend is killed.
 * The sole PostgreSQL server lives in the owner-verified, networkless container. */
export function deriveBlockedDdlBackendTermination(value) {
  validIdentity(value);
  return `SELECT CASE WHEN COUNT(*) = 1 THEN pg_terminate_backend(MIN(pid), 5000) ` +
    `ELSE FALSE END FROM (SELECT DISTINCT a.pid ${blockedDdlFrom()} ` +
    `AND a.pid = ${value.pid} ` +
    `AND (EXTRACT(EPOCH FROM a.backend_start) * 1000000)::bigint = ${value.startedMicroseconds}` +
    `) AS uniquely_pinned_disposable_backend`;
}

export function deriveBlockedDdlBackendAbsence(value) {
  validIdentity(value);
  return `SELECT COUNT(*) FROM pg_stat_activity a WHERE a.pid = ${value.pid} ` +
    `AND a.datname = 'virki_clone' ` +
    `AND (EXTRACT(EPOCH FROM a.backend_start) * 1000000)::bigint = ${value.startedMicroseconds}`;
}
