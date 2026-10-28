import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { offlineRepositoryRoot, runOfflineContingencyPreflight } from "./offline-contingency-preflight.mjs";

const INPUT = {
  candidateDirectory: "/operator/candidate",
  trustedDirectory: "/operator/trust",
  repositoryRoot: "/operator/repository",
};

test("the CLI repository root is canonical, without the URL directory trailing separator", () => {
  assert.equal(offlineRepositoryRoot, realpathSync.native(offlineRepositoryRoot));
});

test("contingency preflight refuses absent independent trust without invoking a verifier", async () => {
  let calls = 0;
  const result = await runOfflineContingencyPreflight({ ...INPUT, trustedDirectory: "" }, {
    inspect: async () => { calls += 1; },
  });
  assert.equal(calls, 0);
  assert.equal(result.status, "OFFLINE_NOT_READY");
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.transferAuthorized, false);
});

test("verified signed candidate still cannot claim release authorization", async () => {
  const result = await runOfflineContingencyPreflight(INPUT, {
    inspect: async (options) => {
      assert.deepEqual(options, INPUT);
      return {
        status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED", revision: "a".repeat(40),
        signedManifestSha256: "b".repeat(64),
        deployAuthorized: false, transferAuthorized: false,
      };
    },
  });
  assert.deepEqual(result, {
    status: "OFFLINE_PRETRANSFER_INSPECTED_ONLY",
    revision: "a".repeat(40),
    signedManifestSha256: "b".repeat(64),
    deployAuthorized: false, transferAuthorized: false,
  });
});

test("unexpected verifier result, forged authorization, and exceptions fail closed", async () => {
  const invalid = [
    { status: "APPROVED", revision: "a".repeat(40), signedManifestSha256: "b".repeat(64) },
    { status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED", revision: "a".repeat(40), signedManifestSha256: "b".repeat(64), deployAuthorized: true, transferAuthorized: false },
    { status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED", revision: "a".repeat(40), signedManifestSha256: "b".repeat(64), deployAuthorized: false, transferAuthorized: true },
    { status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED", revision: "not-sha", signedManifestSha256: "b".repeat(64), deployAuthorized: false, transferAuthorized: false },
  ];
  for (const payload of invalid) {
    const result = await runOfflineContingencyPreflight(INPUT, { inspect: async () => payload });
    assert.equal(result.status, "OFFLINE_NOT_READY");
    assert.equal(result.deployAuthorized, false);
  }
  const error = await runOfflineContingencyPreflight(INPUT, { inspect: async () => { throw Error("sensitive operational details"); } });
  assert.deepEqual(error, { status: "OFFLINE_NOT_READY", deployAuthorized: false, transferAuthorized: false });
});

test("CLI without explicit private paths stops without connecting to production", () => {
  const result = spawnSync(process.execPath, ["scripts/offline-contingency-preflight.mjs"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /OFFLINE_NOT_READY/u);
  assert.doesNotMatch(result.stdout + result.stderr, /password|secret|private key/iu);
});

test("symlinked CLI entry cannot silently return success without running preflight", {
  skip: process.platform !== "linux",
}, () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-preflight-link-"));
  try {
    const alias = path.join(dir, "alias.mjs");
    symlinkSync(fileURLToPath(new URL("./offline-contingency-preflight.mjs", import.meta.url)), alias);
    const result = spawnSync(process.execPath, [alias], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stdout, /OFFLINE_NOT_READY/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preserve-symlinks-main cannot produce silent exit zero from an aliased CLI directory", {
  skip: process.platform !== "linux",
}, () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-preflight-dir-link-"));
  try {
    const original = path.dirname(fileURLToPath(new URL("./offline-contingency-preflight.mjs", import.meta.url)));
    const aliasDir = path.join(dir, "scripts");
    symlinkSync(original, aliasDir, "dir");
    const result = spawnSync(process.execPath, [
      "--preserve-symlinks-main", path.join(aliasDir, "offline-contingency-preflight.mjs"),
    ], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stdout, /OFFLINE_NOT_READY/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
