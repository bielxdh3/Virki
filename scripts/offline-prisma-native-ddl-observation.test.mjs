import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  INTERRUPT_TIMING, assertCommittedFirstDdl, deriveBlockedDdlProbe,
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
  assert.match(fixture, /process\.getuid\(\) !== 70/u);
  assert.match(fixture, /parentArgs\.includes\(PRISMA\)/u);
  assert.match(fixture, /EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED/u);
  assert.match(fixture, /timeout: INTERRUPT_TIMING\.engineTimeoutMs/u);
});
