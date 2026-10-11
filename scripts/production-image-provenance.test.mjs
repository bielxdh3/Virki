import assert from "node:assert/strict";
import test from "node:test";
import { verifyImageProvenance } from "./lib/production-image-provenance.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const correct = `revision=${revision}\nrun_id=42\nplatform=linux/amd64\nruntime_digest=sha256:${"a".repeat(64)}\nmigrator_digest=sha256:${"b".repeat(64)}\n`;
const expected = { revision, runId: 42, platform: "linux/amd64" };
const corruptLine = (prefix, invalid) => correct.split("\n").map((line) => line.startsWith(prefix) ? invalid : line).join("\n");

test("accepts exact-run, platform and immutable GHCR digests", () => {
  assert.deepEqual(verifyImageProvenance(correct, expected), {
    runtimeDigest: `sha256:${"a".repeat(64)}`,
    migratorDigest: `sha256:${"b".repeat(64)}`,
  });
});

test("rejects foreign run, SHA, platform, digest, extra content and control bytes", () => {
  const rejected = [
    [correct, { ...expected, runId: 43 }],
    [correct, { ...expected, revision: "f".repeat(40) }],
    [correct, { ...expected, platform: "linux/arm64" }],
    [corruptLine("runtime_digest=", "runtime_digest=sha256:INVALID"), expected],
    [correct + "extra=true\n", expected],
    [correct.padEnd(513, "x"), expected],
    [correct.split("\n").join("\r\n"), expected],
    [correct.slice(0, -1), expected],
    [corruptLine("migrator_digest=", `migrator_digast=sha256:${"b".repeat(64)}`), expected],
    [corruptLine("run_id=", "run_id=042"), expected],
  ];
  for (const [source, options] of rejected) {
    assert.throws(() => verifyImageProvenance(source, options));
  }
});
