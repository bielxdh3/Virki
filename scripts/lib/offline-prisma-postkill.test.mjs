import assert from "node:assert/strict";
import test from "node:test";
import {
  summarizePrismaPostkillOutput, classifyPrismaPostkillExit,
  assertPrismaPostkillDatabaseState,
} from "./offline-prisma-postkill.mjs";

test("zero exit after independently verified schema-engine SIGKILL is a latched anomaly, never success", () => {
  assert.deepEqual(classifyPrismaPostkillExit({ status: 0, signal: null, error: null }),
    { zeroExitAnomaly: true, cliFailed: false });
  assert.deepEqual(classifyPrismaPostkillExit({ status: 1, signal: null, error: null }),
    { zeroExitAnomaly: false, cliFailed: true });
  for (const marker of [
    { status: null, signal: "SIGKILL", error: null },
    { status: 0, signal: "SIGKILL", error: null },
    { status: 0, signal: null, error: "ETIMEDOUT" },
    { status: -1, signal: null, error: null },
    { status: 1, signal: null, error: null, unexpected: true },
  ]) assert.throws(() => classifyPrismaPostkillExit(marker), /refus/iu);
});

test("Postkill stdout/stderr summaries are bounded and never record arbitrary private text", () => {
  const original = "Prisma schema loaded from /tmp/virki-prisma/schema.prisma\n" +
    "database opaque-private-metadata=private.example\n" +
    "passwordHash=SECRET\nError: P3009\n";
  const diagnostic = summarizePrismaPostkillOutput(original);
  assert.equal(diagnostic.byteLength, Buffer.byteLength(original));
  assert.match(diagnostic.sha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(diagnostic.safeLines,
    ["Prisma schema loaded from /tmp/virki-prisma/schema.prisma", "Error: P3009"]);
  assert.doesNotMatch(JSON.stringify(diagnostic), /SECRET|private\.example|opaque-private-metadata/u);
  assert.throws(() => summarizePrismaPostkillOutput("z".repeat(32769)), /refus/iu);
  assert.throws(() => summarizePrismaPostkillOutput(null), /refus/iu);
});

test("fresh P3009 retry is permitted only when migration is unfinished and first column is absent", () => {
  assert.equal(assertPrismaPostkillDatabaseState("1|0|0|0"), true);
  for (const row of ["0|1|0|1", "1|0|0|1", "0|0|0|0", "1|0|1|0", "2|0|0|0", "1|0|0|0\n1|0|0|0", "1|0|0|0|0"])
    assert.throws(() => assertPrismaPostkillDatabaseState(row), /refus/iu);
});
