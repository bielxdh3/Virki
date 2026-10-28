import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  verifyDisposablePrismaMigrations, verifyDisposablePrismaDatabaseHistory,
  verifyCommittedStage2PrismaMigrations,
} from "./lib/offline-prisma-native-source.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
function fixture(t) {
  const dir = mkdtempSync(path.join(tmpdir(), "virki-prisma-source-"));
  const names = ["0_init", "20261028000000_fixture"];
  writeFileSync(path.join(dir, "migration_lock.toml"), 'provider = "postgresql"\n');
  for (const name of names) {
    mkdirSync(path.join(dir, name));
    writeFileSync(path.join(dir, name, "migration.sql"), `-- ${name}\nCREATE TABLE ${name === "0_init" ? "a" : "b"}(id int);\n`);
  }
  t.after(() => rmSync(dir, { force: true, recursive: true }));
  return { dir, names };
}

test("independent source hashes bind every real raw SQL byte and database migration row", (t) => {
  const f = fixture(t);
  const proof = verifyDisposablePrismaMigrations(f.dir);
  assert.equal(proof.length, 2);
  assert.ok(proof.every((entry) => /^[a-f0-9]{64}$/u.test(entry.checksum)));
  const history = proof.map((entry) => `${entry.name}|${entry.checksum}`).join("\n");
  assert.doesNotThrow(() => verifyDisposablePrismaDatabaseHistory(proof, history));
  assert.throws(() => verifyDisposablePrismaDatabaseHistory(proof, history.replace(proof[1].checksum, sha("wrong"))), /refus/iu);
  assert.throws(() => verifyDisposablePrismaDatabaseHistory(proof, history + "\n20990101_unreviewed|" + sha("unknown")), /refus/iu);
  assert.throws(() => verifyDisposablePrismaDatabaseHistory(proof, proof[0].name + "|" + proof[0].checksum), /refus/iu);
});

test("mutated SQL bytes and additional unreviewed migration file are rejected", (t) => {
  const f = fixture(t);
  const first = verifyDisposablePrismaMigrations(f.dir);
  writeFileSync(path.join(f.dir, f.names[1], "migration.sql"), "DROP TABLE protected;\n");
  const altered = verifyDisposablePrismaMigrations(f.dir);
  assert.notEqual(first[1].checksum, altered[1].checksum);
  assert.throws(() => verifyDisposablePrismaDatabaseHistory(altered,
    first.map((row) => `${row.name}|${row.checksum}`).join("\n")), /refus/iu);
  writeFileSync(path.join(f.dir, f.names[1], "unexpected.sql"), "SELECT 1;");
  assert.throws(() => verifyDisposablePrismaMigrations(f.dir), /refus/iu);
});

test("actual committed 0_init plus dated migrations are all independently hashed", () => {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const proof = verifyDisposablePrismaMigrations(path.join(root, "packages/database/prisma/migrations"));
  assert.equal(proof.length, 11);
  assert.equal(proof[0].name, "0_init");
  assert.equal(proof.at(-1).name, "20261025190000_user_passkeys");
  assert.deepEqual(verifyCommittedStage2PrismaMigrations(path.join(root, "packages/database/prisma/migrations")), proof);
});

test("committed stage2 digest anchors refuse any synthetic or changed migration tree", (t) => {
  const f = fixture(t);
  assert.throws(() => verifyCommittedStage2PrismaMigrations(f.dir), /refus/iu);
});
