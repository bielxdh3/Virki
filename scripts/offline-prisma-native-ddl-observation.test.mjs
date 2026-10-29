import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  INTERRUPT_TIMING, assertCommittedFirstDdl, deriveBlockedDdlProbe,
  deriveBlockedDdlBackendIdentityProbe, deriveBlockedDdlBackendTermination,
  parseBlockedDdlBackendIdentity,
} from "./lib/offline-prisma-native-ddl-observation.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const runner = readFileSync(path.join(ROOT, "scripts/offline-prisma-native-run.mjs"), "utf8");
const fixture = readFileSync(path.join(ROOT, "scripts/fixtures/offline-prisma-native/interrupt.mjs"), "utf8");

test("real committed first DDL is fixed to ProjectConnection.launchUrl; mutation fails closed", () => {
  const sql = readFileSync(path.join(ROOT,
    "packages/database/prisma/migrations/20261001000000_security_polish/migration.sql"), "utf8");
  assert.deepEqual(assertCommittedFirstDdl(sql),
    { table: "ProjectConnection", column: "launchUrl", type: "TEXT" });
  assert.throws(() => assertCommittedFirstDdl(sql.replace('"launchUrl"', '"another"')), /refus/iu);
  assert.throws(() => assertCommittedFirstDdl(sql.replace('"ProjectConnection"', '"Session"')), /refus/iu);
});

test("wait query attributes exact first ALTER to a real ungranted lock and private blocker", () => {
  const sql = deriveBlockedDdlProbe();
  assert.match(sql, /pg_blocking_pids\(a\.pid\)/u);
  assert.match(sql, /a\.query ~ /u);
  // The real Prisma 6.19.3 engine submits the complete migration SQL, which
  // starts with CREATE EXTENSION before the blocked ALTER TABLE statement.
  assert.match(sql, /a\.query ~ '\^CREATE EXTENSION IF NOT EXISTS pgcrypto;/u);
  assert.match(sql, /a\.wait_event_type = 'Lock'/u);
  assert.match(sql, /a\.datname = 'virki_clone'/u);
  assert.match(sql, /l\.mode = 'AccessExclusiveLock'/u);
  assert.match(sql, /l\.granted = false/u);
  assert.match(sql, /h\.mode = 'ShareUpdateExclusiveLock'/u);
  assert.match(sql, /h\.granted = true/u);
  assert.match(sql, /"ProjectConnection"/u);
  assert.match(sql, /"launchUrl"/u);
  assert.doesNotMatch(sql, /h\.mode = 'AccessExclusiveLock'/u);
});

test("backend identity is a strict unique PG pid+microsecond start pair", () => {
  const identity = deriveBlockedDdlBackendIdentityProbe();
  assert.match(identity, /a\.pid::text/u);
  assert.match(identity, /a\.backend_start/u);
  assert.match(identity, /pg_blocking_pids\(a\.pid\)/u);
  assert.match(identity, /h\.mode = 'ShareUpdateExclusiveLock'/u);
  assert.deepEqual(parseBlockedDdlBackendIdentity("421|1790000000000000"),
    { pid: 421, startedMicroseconds: "1790000000000000" });
  for (const invalid of ["0|1790000000000000", "421|0", "421|1790000000000000\n422|1790000000000000",
    "421 |1790000000000000", "421|1790000000000000|junk", "421|1790000000000000\n", "a|1790000000000000"])
    assert.throws(() => parseBlockedDdlBackendIdentity(invalid), /refus/iu);
});

test("backend termination is guarded by same live DDL, owner lock, database and immutable identity", () => {
  const candidate = { pid: 421, startedMicroseconds: "1790000000000000" };
  const sql = deriveBlockedDdlBackendTermination(candidate);
  assert.match(sql, /pg_terminate_backend\(/u);
  assert.match(sql, /pg_blocking_pids\(a\.pid\)/u);
  assert.match(sql, /a\.datname = 'virki_clone'/u);
  assert.match(sql, /a\.query ~ '\^CREATE EXTENSION IF NOT EXISTS pgcrypto;/u);
  assert.match(sql, /a\.pid = 421\b/u);
  assert.match(sql, /1790000000000000/u);
  assert.match(sql, /COUNT\(\*\) = 1|count\(\*\) = 1/u);
  assert.match(sql, /h\.mode = 'ShareUpdateExclusiveLock'/u);
  assert.doesNotMatch(sql, /pg_terminate_backend\(421\)/u);
  for (const invalid of [null, {}, { pid: 0, startedMicroseconds: "1790000000000000" },
    { pid: 421, startedMicroseconds: "0" }, { pid: 421, startedMicroseconds: "1790000000000000;DROP TABLE users" }])
    assert.throws(() => deriveBlockedDdlBackendTermination(invalid), /refus/iu);
});

test("runner pins one backend before exact SIGKILL and terminates it before private holder release", () => {
  const pinned = runner.indexOf("deriveBlockedDdlBackendIdentityProbe()");
  const engineKilled = runner.indexOf("exact_prisma_schema_engine_sigkill_sent");
  const pgKilled = runner.indexOf("real_prisma_postkill_waiting_backend_terminated");
  const lockReleased = runner.indexOf("engine-interrupt-release-private-lock");
  const retryP3009 = runner.indexOf('nodePrisma(URL_CLONE, ["deploy"], { expectedCode: "P3009" })');
  assert.ok(pinned > 0 && pinned < engineKilled);
  assert.ok(engineKilled < pgKilled && pgKilled < lockReleased && lockReleased < retryP3009);
  assert.match(runner, /real_prisma_postkill_waiting_backend_absent/u);
});

test("blocker lifetime > actual CLI engine timeout > wall observation deadline", () => {
  assert.ok(INTERRUPT_TIMING.blockerSeconds * 1000 > INTERRUPT_TIMING.engineTimeoutMs + 30000);
  assert.ok(INTERRUPT_TIMING.engineTimeoutMs > INTERRUPT_TIMING.observationTimeoutMs + 30000);
  assert.ok(INTERRUPT_TIMING.observationTimeoutMs >= 90000);
  assert.ok(INTERRUPT_TIMING.blockerSeconds <= 240);
});

test("Stage5 runner invokes DDL/UID+PPID probe before kill and retains P2 result/cleanup guards", () => {
  assert.match(runner, /assertCommittedFirstDdl\(readFileSync/u);
  assert.match(runner, /deriveBlockedDdlProbe\(\)/u);
  assert.match(runner, /SHARE UPDATE EXCLUSIVE MODE/u);
  assert.doesNotMatch(runner, /LOCK TABLE \\"ProjectConnection\\" IN ACCESS EXCLUSIVE MODE/u);
  assert.match(runner, /Date\.now\(\) \+ INTERRUPT_TIMING\.observationTimeoutMs/u);
  assert.match(runner, /EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED/u);
  assert.match(runner, /PRISMA_CLI_EXITED_BEFORE_DDL/u);
  assert.match(runner, /real_prisma_schema_engine_ddl_blocked_on_pg_lock/u);
  assert.match(runner, /isVerifiedPrismaInvocationResult\(output/u);
  assert.match(runner, /isVerifiedSuccessfulCleanup\(\{/u);
  assert.match(fixture, /process\.getuid\(\) !== 1000/u);
  assert.match(fixture, /parentArgs\.includes\(PRISMA\)/u);
  assert.match(fixture, /EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED/u);
  assert.match(fixture, /timeout: INTERRUPT_TIMING\.engineTimeoutMs/u);
});
