import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  C1_MAX_CONTEXT_BYTES,
  OWNER_APPROVAL_DOMAIN,
  appendAuthStateTransition,
  canonicalJsonBytes,
  computeBoundContractDigest,
  evaluateC1ToC4IntegrationCandidate,
  initAnchoredAuthState,
  loadAndVerifyAuthState,
  recoverAuthStateWithEpochFence,
  sha256Hex,
} from "./c1-c4-contract.mjs";

const THIS_DIR = path.dirname(fileURLToPath(import.meta.url));
const C4_DIR = path.resolve(THIS_DIR, "../native-owner-authority");
const LINUX_NATIVE_SKIP = process.platform !== "linux"
  ? "Linux-only native C1->C4 daemon integration test"
  : (typeof process.getuid === "function" && process.getuid() === 0
    ? "Non-root Linux user required for native C4 daemon integration test"
    : false);

function buildSyntheticFixture(tmpDir, role = "runtime") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const pinSha256 = sha256Hex(publicKey.export({ type: "spki", format: "der" }));

  const contextBuffers = {
    "source": Buffer.from("SYNTHETIC_C1_SOURCE_TAR_V1\n", "utf8"),
    "dockerfile": Buffer.from("FROM scratch\nCOPY . /\n", "utf8"),
    "offline-npm-cacache": Buffer.from("SYNTHETIC_NPM_CACACHE_V1\n", "utf8"),
    "offline-prisma-engines": Buffer.from("SYNTHETIC_PRISMA_ENGINES_V1\n", "utf8"),
  };

  const fileSyncManifest = {
    ignoreSource: "root-dockerignore",
    ignoreRulesSha256: "a".repeat(64),
    includedPaths: ["apps/hub/package.json", "Dockerfile"],
    excludedPaths: [".git", ".env", "secrets/prod.key"],
  };
  const fileSyncManifestSha256 = sha256Hex(canonicalJsonBytes({
    ignoreSource: fileSyncManifest.ignoreSource,
    ignoreRulesSha256: fileSyncManifest.ignoreRulesSha256,
    includedPaths: [...fileSyncManifest.includedPaths].sort(),
    excludedPaths: [...fileSyncManifest.excludedPaths].sort(),
  }));

  const nonce = "0123456789abcdef0123456789abcdef";
  const contract = {
    c1BaseSha: "dfe721e254a6e28e9cffa073a74a881cf1019d73",
    c4BaseSha: "816713cfa80893b4e50dfb2870a634c65f460443",
    sourceCommit: "caf3df893ab8909150a2c0197d2741d6f73e40cf",
    buildPlanSha256: "b".repeat(64),
    executablePolicySha256: "c".repeat(64),
    fileSyncManifestSha256,
    nonce,
    epoch: 1,
    role,
    contexts: Object.entries(contextBuffers).map(([name, buf]) => ({
      name,
      treeDigest: `sha256:${sha256Hex(Buffer.from(`tree:${name}`, "utf8"))}`,
      streamDigest: `sha256:${sha256Hex(buf)}`,
      streamLength: buf.length,
      entryCount: 1,
    })),
  };

  const output = {
    outputImageId: `sha256:${"d".repeat(64)}`,
    ociManifestDigest: `sha256:${"e".repeat(64)}`,
    exporterMode: "staged-nonpublishing",
    exporterFlags: { store: false, push: false, pushByDigest: false, unpack: false },
    workerReceiptPairAdmitted: false,
    deployAuthorized: false,
    workerReceipt: { workerIdentity: "virki-worker-c1-synthetic", receiptSha256: "f".repeat(64) },
  };

  const custody = {
    ownerUid: 25111,
    ownerGid: 25111,
    buildkitDaemonUid: 25112,
    buildkitDaemonGid: 25112,
    workerUid: 25113,
    workerGid: 25113,
    keyCustodyMode: "isolated-spki-pin",
  };

  const contractDigestHex = computeBoundContractDigest({ contract, output, custody });
  const signatureBase64 = crypto.sign(
    null,
    Buffer.concat([OWNER_APPROVAL_DOMAIN, Buffer.from(contractDigestHex, "utf8")]),
    privateKey,
  ).toString("base64");

  const approval = {
    keyId: "ephemeral-c4-owner-01",
    contractSha256: contractDigestHex,
    signatureBase64,
  };

  const policy = {
    owner: {
      keyId: "ephemeral-c4-owner-01",
      publicKeyPem,
      pinSha256,
    },
    revokedKeyIds: [],
    revokedPinsSha256: [],
  };

  const subDir = fs.mkdtempSync(path.join(tmpDir, "fx-"));
  const stateFilePath = path.join(subDir, "c1-c4-auth-state.json");
  initAnchoredAuthState(stateFilePath, contract.sourceCommit);
  const stateAfterPrep = appendAuthStateTransition(stateFilePath, {
    epoch: 1,
    nonce,
    contractSha256: contractDigestHex,
    status: "PREPARED",
  });

  const witness = {
    minEpoch: 1,
    minSequence: stateAfterPrep.sequenceFloor,
    expectedHeadSha256: stateAfterPrep.headEntrySha256,
  };

  return {
    privateKey,
    contract,
    contractDigestHex,
    contextBuffers,
    fileSyncManifest,
    output,
    custody,
    approval,
    policy,
    stateFilePath,
    witness,
  };
}

test("C1->C4 integration contract accepts valid synthetic runtime and migrator candidates as non-authorizing", (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1c4-pos-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  for (const role of ["runtime", "migrator"]) {
    const fx = buildSyntheticFixture(tmpDir, role);
    const res = evaluateC1ToC4IntegrationCandidate(fx);
    assert.equal(res.status, "DEFENSIVE_VERIFIED_NON_AUTHORIZING");
    assert.equal(res.deployAuthorized, false);
    assert.equal(res.workerReceiptPairAdmitted, false);
    assert.equal(res.signAckStatus, 22);
    assert.equal(res.contractSha256, fx.contractDigestHex);
  }
});

test("C1->C4 state serializes independent writers and retains its Linux lock inode", { skip: process.platform !== "linux" }, async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1c4-writers-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
  const statePath = path.join(tmpDir, "state.json");
  initAnchoredAuthState(statePath, "a".repeat(40));
  const runWriter = (nonce) => new Promise((resolve, reject) => {
    const script = 'import { appendAuthStateTransition } from "./c1-c4-contract.mjs"; appendAuthStateTransition(process.argv[1], { epoch: 1, nonce: process.argv[2], contractSha256: "b".repeat(64), status: "PREPARED" });';
    const child = spawn(process.execPath, ["--input-type=module", "-e", script, statePath, nonce], { cwd: THIS_DIR, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => code === 0 ? resolve() : reject(new Error(`writer exited: ${code}/${signal}`)));
  });
  await runWriter("1".repeat(32));
  const lockBefore = fs.statSync(`${statePath}.lock`);
  await Promise.all(["2", "3", "4", "5"].map((n) => runWriter(n.repeat(32))));
  const state = loadAndVerifyAuthState(statePath);
  assert.equal(state.sequenceFloor, 5);
  assert.equal(new Set(state.entries.map((entry) => entry.nonce)).size, 5);
  const lockAfter = fs.statSync(`${statePath}.lock`);
  assert.equal(lockAfter.ino, lockBefore.ino);
  assert.equal(lockAfter.dev, lockBefore.dev);
});

test("C1->C4 integration rejects provenance, FileSync ignore, exporter, signature, state, rollback, and custody violations", (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1c4-neg-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  // 1. Provenance: tampered context bytes, >64 MiB ceiling, Array ctx / toJSON hijack
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.contextBuffers.source = Buffer.from("TAMPERED", "utf8");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /streamDigest mismatch|byte length mismatch/);

    const fxBig = buildSyntheticFixture(tmpDir);
    fxBig.contract.contexts[0].streamLength = C1_MAX_CONTEXT_BYTES + 1;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxBig), /64 MiB bounds/);

    const fxArr = buildSyntheticFixture(tmpDir);
    const arrCtx = [];
    Object.assign(arrCtx, fxArr.contract.contexts[0]);
    fxArr.contract.contexts[0] = arrCtx;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxArr), /plain object/);
  }

  // 2. FileSync manifest & ignore-rule parent/child conflict, traversal, and manifest SHA drift
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.fileSyncManifest.includedPaths.push(".git/config");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /ignore-rule conflict/);

    const fxTrav = buildSyntheticFixture(tmpDir);
    fxTrav.fileSyncManifest.includedPaths.push("../outside");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxTrav), /traversal/);

    const fxDrift = buildSyntheticFixture(tmpDir);
    fxDrift.fileSyncManifest.includedPaths.push("apps/hub/next.config.ts");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxDrift), /fileSyncManifestSha256 mismatch/);
  }

  // 3. Output / exporter safety & non-authorizing guard
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.output.exporterFlags.push = true;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /exporterFlags/);

    const fxMode = buildSyntheticFixture(tmpDir);
    fxMode.output.exporterMode = "oci-push";
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxMode), /unsafe exporterMode/);

    const fxAuth = buildSyntheticFixture(tmpDir);
    fxAuth.output.deployAuthorized = true;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxAuth), /deployAuthorized must remain false/);

    const fxAdmit = buildSyntheticFixture(tmpDir);
    fxAdmit.output.workerReceiptPairAdmitted = true;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxAdmit), /workerReceiptPairAdmitted must remain false/);
  }

  // 4. Owner signature, domain separation, revocation, and private PEM rejection
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.approval.signatureBase64 = Buffer.alloc(64, 0x41).toString("base64");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /signature verification failed/);

    const fxDom = buildSyntheticFixture(tmpDir);
    fxDom.approval.signatureBase64 = crypto.sign(
      null,
      Buffer.from(fxDom.contractDigestHex, "utf8"),
      fxDom.privateKey,
    ).toString("base64");
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxDom), /signature verification failed/);

    const fxRev = buildSyntheticFixture(tmpDir);
    fxRev.policy.revokedPinsSha256.push(fxRev.policy.owner.pinSha256);
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxRev), /revoked/);

    const fxPrivPem = buildSyntheticFixture(tmpDir);
    fxPrivPem.policy.owner.publicKeyPem = fxPrivPem.privateKey.export({ type: "pkcs8", format: "pem" });
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxPrivPem), /private key PEM forbidden/);
  }

  // 5. Persistent state tampering, fault fence, ABORTED lifecycle, and epoch recovery
  {
    const fx = buildSyntheticFixture(tmpDir);
    const raw = JSON.parse(fs.readFileSync(fx.stateFilePath, "utf8"));
    raw.entries[0].nonce = "f".repeat(32);
    fs.writeFileSync(fx.stateFilePath, JSON.stringify(raw));
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /entry digest tampered/);

    const fxFault = buildSyntheticFixture(tmpDir);
    const faulted = JSON.parse(fs.readFileSync(fxFault.stateFilePath, "utf8"));
    faulted.faulted = true;
    fs.writeFileSync(fxFault.stateFilePath, JSON.stringify(faulted));
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxFault), /faulted/);

    const fxAbort = buildSyntheticFixture(tmpDir);
    appendAuthStateTransition(fxAbort.stateFilePath, {
      epoch: 1,
      nonce: fxAbort.contract.nonce,
      contractSha256: fxAbort.contractDigestHex,
      status: "ABORTED",
    });
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxAbort), /no active PREPARED/);

    const fxFence = buildSyntheticFixture(tmpDir);
    const fenced = recoverAuthStateWithEpochFence(fxFence.stateFilePath);
    assert.equal(fenced.currentEpoch, 2);
    assert.equal(fs.existsSync(`${fxFence.stateFilePath}.lock`), process.platform === "linux");
    assert.equal(fs.existsSync(`${fxFence.stateFilePath}.lock.reclaim`), false);
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxFence), /does not match active state epoch/);

    // Repeated recovery uses the same lock across epochs.
    const fenced2 = recoverAuthStateWithEpochFence(fxFence.stateFilePath);
    assert.equal(fenced2.currentEpoch, 3);
    assert.equal(fs.existsSync(`${fxFence.stateFilePath}.lock.reclaim`), false);

    const fenced3 = recoverAuthStateWithEpochFence(fxFence.stateFilePath);
    assert.equal(fenced3.currentEpoch, 4);
    assert.equal(fs.existsSync(`${fxFence.stateFilePath}.lock`), process.platform === "linux");
  }

  // 6. Anti-rollback witness regression & fork detection even when sequenceFloor > minSequence
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.witness.minSequence = 99;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /rollback detected/);

    const fxFork = buildSyntheticFixture(tmpDir);
    appendAuthStateTransition(fxFork.stateFilePath, {
      epoch: 1,
      nonce: "fedcba9876543210fedcba9876543210",
      contractSha256: "1".repeat(64),
      status: "PREPARED",
    });
    fxFork.witness.expectedHeadSha256 = "0".repeat(64);
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxFork), /fork detected/);
  }

  // 7. Identity & key custody separation
  {
    const fx = buildSyntheticFixture(tmpDir);
    fx.custody.buildkitDaemonUid = fx.custody.ownerUid;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fx), /must be distinct/);

    const fxGid = buildSyntheticFixture(tmpDir);
    fxGid.custody.workerGid = fxGid.custody.ownerGid;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxGid), /must be distinct/);

    const fxKey = buildSyntheticFixture(tmpDir);
    fxKey.custody.privateKeyPem = "forbidden";
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxKey), /private key material forbidden/);

    // Mutating a custody GID post-approval must fail contract-digest / signature binding
    const fxGidTamper = buildSyntheticFixture(tmpDir);
    fxGidTamper.custody.buildkitDaemonGid = 25999;
    assert.throws(() => evaluateC1ToC4IntegrationCandidate(fxGidTamper), /approval\.contractSha256 mismatch/);
  }
});

test("C1->C4 live native C4 daemon integration preserves SIGN_ACK denial (status 22)", { skip: LINUX_NATIVE_SKIP }, async (t) => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1c4-bin-"));
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "virki-c1c4-run-"));
  t.after(() => {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(runDir, { recursive: true, force: true });
  });

  const gccFlags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now"];
  const srvBin = path.join(binDir, "srv");
  const cliBin = path.join(binDir, "cli");
  execFileSync("/usr/bin/gcc", [...gccFlags, path.join(C4_DIR, "native-owner-authority.c"), "-o", srvBin]);
  execFileSync("/usr/bin/gcc", [...gccFlags, path.join(C4_DIR, "owner-authority-client-fixture.c"), "-o", cliBin]);

  const sockPath = path.join(runDir, "owner.sock");
  const ledgerDir = path.join(runDir, "ledger");
  fs.mkdirSync(ledgerDir, { mode: 0o700 });

  const fx = buildSyntheticFixture(runDir);
  const proc = spawn(srvBin, ["--socket", sockPath, "--ledger-dir", ledgerDir, "--dev-allow-same-uid"], { stdio: ["ignore", "pipe", "inherit"] });

  t.after(async () => {
    if (proc.exitCode !== null || proc.signalCode !== null) return;
    await new Promise((resolve) => {
      const killTimer = setTimeout(() => { proc.kill("SIGKILL"); }, 3000);
      proc.once("exit", () => { clearTimeout(killTimer); resolve(); });
      proc.kill("SIGTERM");
    });
  });

  await new Promise((resolve, reject) => {
    let out = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; proc.kill("SIGKILL"); reject(new Error("C4 daemon startup timeout")); }
    }, 5000);
    proc.stdout.on("data", (d) => {
      out += d.toString("utf8");
      if (!settled && out.includes("VIRKI_OWNER_AUTHORITY_READY:") && out.includes("\n")) {
        settled = true; clearTimeout(timer); resolve();
      }
    });
    proc.on("error", (err) => { if (!settled) { settled = true; clearTimeout(timer); reject(err); } });
    proc.on("exit", (code, sig) => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error(`C4 daemon exited: ${code}/${sig}`)); } });
  });

  const runCli = (action, nonce = fx.contract.nonce, scope = "", epoch = 1) => {
    const out = execFileSync(cliBin, [sockPath, action, nonce, scope, String(epoch)], { encoding: "utf8" });
    const res = {};
    for (const line of out.trim().split("\n")) {
      const idx = line.indexOf("=");
      if (idx !== -1) res[line.slice(0, idx)] = line.slice(idx + 1);
    }
    return res;
  };

  const st = runCli("status");
  assert.equal(st.STATUS, "0");
  assert.equal(Number(st.EPOCH), fx.contract.epoch);

  const begin = runCli("begin");
  assert.equal(begin.STATUS, "0");
  const sign = runCli("sign", fx.contract.nonce, begin.SCOPE_TOKEN, Number(st.EPOCH));
  assert.equal(sign.STATUS, "22", "SIGN_ACK must remain unconditionally denied in C1->C4 integration");

  const contractEval = evaluateC1ToC4IntegrationCandidate(fx);
  assert.equal(contractEval.signAckStatus, Number(sign.STATUS));
  assert.equal(contractEval.epoch, Number(st.EPOCH));
  assert.equal(contractEval.deployAuthorized, false);

  assert.equal(runCli("abort", fx.contract.nonce, begin.SCOPE_TOKEN, Number(st.EPOCH)).STATUS, "0");
});
