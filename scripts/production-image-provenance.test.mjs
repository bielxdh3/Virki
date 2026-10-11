import assert from "node:assert/strict";
import test from "node:test";
import { verifyImageProvenance } from "./lib/production-image-provenance.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const correct = `revision=${revision}\nrun_id=42\nplatform=linux/amd64\nruntime_digest=sha256:${"a".repeat(64)}\nmigrator_digest=sha256:${"b".repeat(64)}\n`;
const expected = { revision, runId: 42, platform: "linux/amd64" };

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
    [correct.replace("sha256:", "sha256:x"), expected],
    [correct + "extra=true\n", expected],
    [correct.replace("\n", "\r\n"), expected],
    [correct.slice(0, -1), expected],
    [correct.replace("migrator_digest=", "migrator_digast="), expected],
    [correct.replace("run_id=42", "run_id=042"), expected],
  ];
  for (const [source, options] of rejected) {
    assert.throws(() => verifyImageProvenance(source, options));
  }
});
