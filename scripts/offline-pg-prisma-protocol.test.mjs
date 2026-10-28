import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  digestDisposablePrismaMigrations, inspectDisposablePgPrismaCheckpoint,
  reserveDisposablePgPrismaCheckpoint,
} from "./lib/offline-pg-prisma-protocol.mjs";

const linux = { skip: process.platform !== "linux" };
const sourceSha = "a".repeat(40);
const migrationPlanSha256 = "b".repeat(64);

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-pg-prisma-boundary-"));
  chmodSync(root, 0o700);
  const migrations = path.join(root, "migrations");
  const checkpoint = path.join(root, "checkpoint");
  mkdirSync(migrations, { mode: 0o700 });
  mkdirSync(checkpoint, { mode: 0o700 });
  writeFileSync(path.join(migrations, "migration_lock.toml"), 'provider = "postgresql"\n', { mode: 0o600 });
  const directory = path.join(migrations, "20261028000000_test_boundary");
  mkdirSync(directory, { mode: 0o700 });
  const sql = path.join(directory, "migration.sql");
  writeFileSync(sql, "CREATE TABLE boundary_test(id int);\n", { mode: 0o600 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, migrations, checkpoint, sql, directory };
}

test("source manifest fingerprints real Prisma migration SQL, rejects symlink and tamper", linux, (t) => {
  const f = fixture(t);
  const first = digestDisposablePrismaMigrations(f.migrations);
  assert.match(first.migrationPlanSha256, /^[0-9a-f]{64}$/u);
  assert.equal(first.migrationCount, 1);
  assert.equal(first.prismaEngineExecuted, false);
  assert.equal(first.deployAuthorized, false);
  assert.equal(digestDisposablePrismaMigrations(f.migrations).migrationPlanSha256, first.migrationPlanSha256);
  writeFileSync(f.sql, "CREATE TABLE boundary_test(id text);\n");
  assert.notEqual(digestDisposablePrismaMigrations(f.migrations).migrationPlanSha256, first.migrationPlanSha256);
  rmSync(f.sql);
  symlinkSync(path.join(f.root, "foreign"), f.sql);
  assert.throws(() => digestDisposablePrismaMigrations(f.migrations));
});

test("protocol fingerprints the actual reviewed committed Prisma SQL migration tree", linux, () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const actual = path.join(root, "packages/database/prisma/migrations");
  const result = digestDisposablePrismaMigrations(actual);
  assert.ok(result.migrationCount >= 5);
  assert.match(result.migrationPlanSha256, /^[a-f0-9]{64}$/u);
  assert.equal(result.productionProof, false);
});

test("durable private one-shot checkpoint remains NON_AUTHORIZING and replay stays denied", linux, (t) => {
  const f = fixture(t);
  const previous = process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL;
  process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL = "1";
  t.after(() => previous === undefined ? delete process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL :
    process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL = previous);
  const request = { directory: f.checkpoint, sourceSha, migrationPlanSha256 };
  const created = reserveDisposablePgPrismaCheckpoint(request);
  assert.equal(created.status, "CHECKPOINTED_NEEDS_INDEPENDENT_EXECUTOR");
  for (const flag of ["productionProof", "backupVerified", "restoreVerified", "prismaMigrationVerified",
    "healthVerified", "rollbackVerified", "deployAuthorized", "transferAuthorized", "dockerLoadAuthorized"])
    assert.equal(created[flag], false, flag);
  const read = inspectDisposablePgPrismaCheckpoint(f.checkpoint);
  assert.equal(read.checkpointSha256, created.checkpointSha256);
  assert.equal(read.status, "UNRECONCILED_DISPOSABLE_ATTEMPT");
  assert.throws(() => reserveDisposablePgPrismaCheckpoint(request), /refused/iu);
  assert.deepEqual(readdirSync(f.checkpoint), [".offline-pg-prisma-attempt"]);
});

test("crash after synchronized checkpoint leaves latch intact and prevents automatic retry", linux, (t) => {
  const f = fixture(t);
  const moduleFile = fileURLToPath(new URL("./lib/offline-pg-prisma-protocol.mjs", import.meta.url));
  const script = `import {reserveDisposablePgPrismaCheckpoint} from ${JSON.stringify(moduleFile)};\n` +
    `reserveDisposablePgPrismaCheckpoint(${JSON.stringify({ directory: f.checkpoint, sourceSha, migrationPlanSha256 })});\n` +
    `process.kill(process.pid, 'SIGKILL');\n`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { PATH: process.env.PATH, VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL: "1" },
    timeout: 5000, encoding: "utf8", maxBuffer: 4096,
  });
  assert.equal(child.signal, "SIGKILL");
  assert.equal(child.stdout, "");
  assert.equal(inspectDisposablePgPrismaCheckpoint(f.checkpoint).status, "UNRECONCILED_DISPOSABLE_ATTEMPT");
  assert.throws(() => reserveDisposablePgPrismaCheckpoint({ directory: f.checkpoint, sourceSha, migrationPlanSha256 }));
});

test("partial write, foreign files, unsafe directory and malformed identity refuse without clearing latch", linux, (t) => {
  const f = fixture(t);
  const previous = process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL;
  process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL = "1";
  t.after(() => previous === undefined ? delete process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL :
    process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL = previous);
  const request = { directory: f.checkpoint, sourceSha, migrationPlanSha256 };
  writeFileSync(path.join(f.checkpoint, ".offline-pg-prisma-attempt"), '{"version":1', { mode: 0o600 });
  assert.throws(() => inspectDisposablePgPrismaCheckpoint(f.checkpoint));
  assert.throws(() => reserveDisposablePgPrismaCheckpoint(request));
  assert.equal(readFileSync(path.join(f.checkpoint, ".offline-pg-prisma-attempt"), "utf8"), '{"version":1');
  assert.throws(() => reserveDisposablePgPrismaCheckpoint({ ...request, sourceSha: "invalid" }));
  assert.throws(() => reserveDisposablePgPrismaCheckpoint({ ...request,
    DATABASE_URL: "postgresql://forbidden.invalid/db" }));
  chmodSync(f.checkpoint, 0o777);
  assert.throws(() => reserveDisposablePgPrismaCheckpoint(request));
});

test("without explicit DEV-only opt-in or outside Linux, no checkpoint is created", (t) => {
  if (process.platform !== "linux") return t.skip("Linux pinned directory APIs required");
  const f = fixture(t);
  const previous = process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL;
  delete process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL;
  t.after(() => previous === undefined ? delete process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL :
    process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL = previous);
  assert.throws(() => reserveDisposablePgPrismaCheckpoint({ directory: f.checkpoint, sourceSha, migrationPlanSha256 }));
  assert.deepEqual(readdirSync(f.checkpoint), []);
});
