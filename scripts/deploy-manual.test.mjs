import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runManualOperator, sameSignedManualPretransfer } from "./deploy-manual.mjs";

const program = fileURLToPath(new URL("./deploy-manual.mjs", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url)).replace(/[\\/]$/u, "");
function stageFixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-manual-cli-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const stagingParent = path.join(root, "stage");
  mkdirSync(stagingParent, { mode: 0o700 });
  return { root, stagingParent };
}

test("CLI refuses missing owner trust before a source-to-staging sink is reached", async (t) => {
  const { root, stagingParent } = stageFixture(t);
  const result = await runManualOperator({
    candidateDirectory: path.join(root, "untrusted"),
    trustedDirectory: path.join(root, "missing-trust"),
    stagingParent, repositoryRoot,
  });
  assert.equal(result.status, "MANUAL_PRETRANSFER_NOT_READY");
  assert.equal(result.transferAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.deepEqual(readdirSync(stagingParent), []);
});

test("post-copy candidate must be separately reauthenticated, not just match manifest hash", () => {
  const before = {
    status: "OFFLINE_PRETRANSFER_INSPECTED_ONLY", revision: "a".repeat(40),
    signedManifestSha256: "b".repeat(64), transferAuthorized: false, deployAuthorized: false,
    signedEnvelopeSha256: "e".repeat(64),
  };
  assert.equal(sameSignedManualPretransfer(before, { ...before }), true);
  assert.equal(sameSignedManualPretransfer(before, {
    ...before, status: "OFFLINE_NOT_READY",
  }), false);
  assert.equal(sameSignedManualPretransfer(before, { ...before, deployAuthorized: true }), false);
  assert.equal(sameSignedManualPretransfer(before, { ...before, revision: "c".repeat(40) }), false);
  assert.equal(sameSignedManualPretransfer(before, { ...before, signedManifestSha256: "d".repeat(64) }), false);
  assert.equal(sameSignedManualPretransfer(before, { ...before, signedEnvelopeSha256: "f".repeat(64) }), false);
});

test("CLI refuses caller-provided authorization, fake witness, or candidate-picked host command", async (t) => {
  const { root, stagingParent } = stageFixture(t);
  for (const extra of [{ witnessCasAuthorized: true }, { hostBootstrapVerified: true }, { sshCommand: "true" }, { ownerSignatureValid: true }]) {
    const result = await runManualOperator({ candidateDirectory: root, trustedDirectory: root, stagingParent, repositoryRoot, ...extra });
    assert.equal(result.status, "MANUAL_OPERATOR_INPUT_REJECTED");
  }
  assert.deepEqual(readdirSync(stagingParent), []);
});

test("CLI parses exact flags, fails closed and never shells out to GitHub/GHCR or contacts production", (t) => {
  const { root, stagingParent } = stageFixture(t);
  const bad = spawnSync(process.execPath, [program, "--candidate", root, "--trust", root,
    "--stage-parent", stagingParent, "--force"], { shell: false, encoding: "utf8", timeout: 10_000 });
  assert.equal(bad.status, 2);
  assert.equal(JSON.parse(bad.stdout).status, "MANUAL_OPERATOR_INPUT_REJECTED");
  const missing = spawnSync(process.execPath, [program, "--candidate", path.join(root, "candidate"), "--trust", path.join(root, "absent"),
    "--stage-parent", stagingParent], { shell: false, encoding: "utf8", timeout: 10_000 });
  assert.equal(missing.status, 2);
  assert.equal(JSON.parse(missing.stdout).status, "MANUAL_PRETRANSFER_NOT_READY");
  assert.deepEqual(readdirSync(stagingParent), []);
});
