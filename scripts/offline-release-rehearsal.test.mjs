import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";
import { signOfflineBuilderManifest, signOfflineOwnerApproval } from "./lib/offline-release-signing.mjs";
import { rehearseOfflineReleaseLocally } from "./lib/offline-release-rehearsal.mjs";
import { recordOfflineReleaseAcceptance } from "./lib/offline-release-ledger.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const predecessor = "a".repeat(40);
const hostIdentity = "b".repeat(64);
const sourceGitAvailable = process.platform === "linux" && process.getuid?.() === 0;
const nativeKernel = sourceGitAvailable && !/microsoft|wsl/iu.test(os.release());
const gitEnv = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_AUTHOR_DATE: "1700000000 +0000", GIT_COMMITTER_DATE: "1700000000 +0000" };

function git(...args) {
  return execFileSync("git", args, { env: gitEnv, encoding: "utf8", timeout: 10_000 }).trim();
}

function fixture(t) {
  // All inputs, trusted pins, archives and state are generated inside a
  // disposable root-owned test directory; no installed trust root is touched.
  const base = mkdtempSync("/var/lib/virki-rehearsal-test-");
  chmodSync(base, 0o700);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const work = path.join(base, "builder");
  mkdirSync(work, { mode: 0o700 });
  git("init", "-q", "-b", "main", work);
  git("-C", work, "config", "user.name", "Rehearsal Fixture");
  git("-C", work, "config", "user.email", "fixture@example.invalid");
  writeFileSync(path.join(work, "README.md"), "offline source fixture\n");
  git("-C", work, "add", "README.md");
  git("-C", work, "commit", "-qm", "fixture source");
  const revision = git("-C", work, "rev-parse", "HEAD");
  const trustedGit = path.join(base, "trusted.git");
  git("init", "-q", "--bare", "-b", "main", trustedGit);
  git("-C", work, "push", "-q", trustedGit, "main:main");
  chmodSync(trustedGit, 0o700);
  const pin = path.join(base, "trusted-source.sha");
  writeFileSync(pin, `${revision}\n`, { mode: 0o600 });
  const candidate = path.join(base, "candidate");
  mkdirSync(candidate, { mode: 0o700 });
  const archive = path.join(candidate, "source.tar");
  git(`--git-dir=${trustedGit}`, "archive", "--format=tar", `--output=${archive}`, revision);
  chmodSync(archive, 0o600);
  const archiveBytes = readFileSync(archive);
  const restoreLog = Buffer.from("synthetic isolated backup and restore prerequisite log\n");
  const restoreReceipt = {
    version: 1, kind: "backup-restore", sourceSha: revision, status: "PASS", exitCode: 0,
    rawLogSha256: sha256(restoreLog), predecessorSha: predecessor,
  };
  const backupRestore = { receiptBytes: Buffer.from(JSON.stringify(restoreReceipt)), rawLogBytes: restoreLog };
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const pinKey = (key) => ({
    publicKeyPem: key.export({ type: "spki", format: "pem" }),
    pinSha256: sha256(key.export({ type: "spki", format: "der" })),
  });
  const trustedKeys = { builder: pinKey(builder.publicKey), owner: pinKey(owner.publicKey) };
  const manifest = {
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git", source_sha: revision,
    source_archive_sha256: sha256(archiveBytes), source_archive_size_bytes: archiveBytes.length,
    platform: "linux/amd64", host_identity_sha256: hostIdentity, predecessor_sha: predecessor,
    runtime_image: { archive_sha256: "c".repeat(64), archive_size_bytes: 2048, image_id: `sha256:${"d".repeat(64)}` },
    migrator_image: { archive_sha256: "e".repeat(64), archive_size_bytes: 4096, image_id: `sha256:${"f".repeat(64)}` },
    evidence: {
      ci_report_sha256: "1".repeat(64), scanner_report_sha256: "2".repeat(64),
      scanner_rules_commit: "3".repeat(40), finding_review_sha256: "4".repeat(64),
      runtime_smoke_sha256: "5".repeat(64), migrator_smoke_sha256: "6".repeat(64),
      backup_restore_sha256: sha256(backupRestore.receiptBytes),
    },
    issued_at: 1_800_000_000 - 100, expires_at: 1_800_000_000 + 900,
    nonce: "0123456789abcdef0123456789abcdef", sequence: 1,
  };
  const expected = {
    sourceSha: revision, sourceArchiveSha256: manifest.source_archive_sha256,
    sourceArchiveSizeBytes: archiveBytes.length, platform: "linux/amd64",
    hostIdentitySha256: hostIdentity, predecessorSha: predecessor,
    runtimeImage: { archiveSha256: manifest.runtime_image.archive_sha256,
      archiveSizeBytes: manifest.runtime_image.archive_size_bytes, imageId: manifest.runtime_image.image_id },
    migratorImage: { archiveSha256: manifest.migrator_image.archive_sha256,
      archiveSizeBytes: manifest.migrator_image.archive_size_bytes, imageId: manifest.migrator_image.image_id },
    ciReportSha256: manifest.evidence.ci_report_sha256,
    scannerReportSha256: manifest.evidence.scanner_report_sha256,
    scannerRulesCommit: manifest.evidence.scanner_rules_commit,
    findingReviewSha256: manifest.evidence.finding_review_sha256,
    runtimeSmokeSha256: manifest.evidence.runtime_smoke_sha256,
    migratorSmokeSha256: manifest.evidence.migrator_smoke_sha256,
    backupRestoreSha256: manifest.evidence.backup_restore_sha256, lastSequence: 0,
  };
  const ledgerState = { version: 1, anchorSha: predecessor, entries: [] };
  const directory = path.join(base, "ledger");
  mkdirSync(directory, { mode: 0o700 });
  writeFileSync(path.join(directory, "ledger.json"), JSON.stringify(ledgerState), { mode: 0o600 });
  const sourceGit = { sourceArchivePath: archive, candidateSourceSha: revision,
    candidateArchiveSha256: sha256(archiveBytes), candidateArchiveSizeBytes: archiveBytes.length,
    trustedGitDirectory: trustedGit, trustedShaPinPath: pin };
  function signManifest(value = manifest) {
    const manifestBytes = encodeCanonicalOfflineReleaseManifest(value);
    const signed = signOfflineBuilderManifest({ manifestBytes, builderPrivateKey: builder.privateKey });
    const approved = signOfflineOwnerApproval({ manifestBytes, reviewedManifestSha256: signed.manifestSha256,
      ownerPrivateKey: owner.privateKey });
    return { manifestBytes, signatures: { builder: signed.builderSignatureBase64, owner: approved.ownerSignatureBase64 } };
  }
  const request = { ...signManifest(), trustedKeys, expected, nowSeconds: 1_800_000_000,
    sourceGit, backupRestore, ledgerState };
  return { base, candidate, archive, directory, pin, trustedGit, manifest, restoreReceipt,
    request, signManifest, revision, ledgerState };
}

test("rehearsal verifies signer, pinned Git blobs, restore prerequisites and ordered ledger without authorizing or writing", { skip: !sourceGitAvailable }, async (t) => {
  const f = fixture(t);
  const before = readFileSync(path.join(f.directory, "ledger.json"));
  const result = await rehearseOfflineReleaseLocally(f.request);
  assert.deepEqual(result, {
    status: "LOCAL_REHEARSAL_ONLY_RELEASE_BLOCKED", deployAuthorized: false,
    sourceSha: f.revision, sequence: 1,
    manifestSha256: sha256(f.request.manifestBytes),
    simulatedLedgerHeadSha: f.revision,
  });
  assert.deepEqual(readFileSync(path.join(f.directory, "ledger.json")), before);
  assert.equal(existsSync(path.join(f.directory, ".offline-release.lock")), false);
  assert.equal(Object.hasOwn(result, "approvalToken"), false);
});

test("rehearsal refuses stale signatures, missing independent Git pin and mismatched real archive bytes", { skip: !sourceGitAvailable }, async (t) => {
  const f = fixture(t);
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    signatures: { ...f.request.signatures, owner: f.request.signatures.builder } }), /signature/u);
  writeFileSync(f.pin, `${"f".repeat(40)}\n`);
  await assert.rejects(rehearseOfflineReleaseLocally(f.request), /pin|SHA/u);
  writeFileSync(f.pin, `${f.revision}\n`);
  const bytes = readFileSync(f.archive);
  const altered = Buffer.from(bytes);
  altered[altered.indexOf(Buffer.from("offline source fixture"))] ^= 1;
  writeFileSync(f.archive, altered);
  const modifiedManifest = { ...f.manifest, source_archive_sha256: sha256(altered) };
  const forged = f.signManifest(modifiedManifest);
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request, ...forged,
    sourceGit: { ...f.request.sourceGit, candidateArchiveSha256: sha256(altered) },
    expected: { ...f.request.expected, sourceArchiveSha256: sha256(altered) } }), /blob content differs/u);
});

test("rehearsal denies absent, contradictory or unbound backup/restore receipts and logs", { skip: !sourceGitAvailable }, async (t) => {
  const f = fixture(t);
  const receipt = JSON.parse(f.request.backupRestore.receiptBytes.toString("utf8"));
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    backupRestore: { ...f.request.backupRestore, rawLogBytes: Buffer.from("unknown restore trace") } }), /restore.*log/u);
  const failedReceipt = { ...receipt, status: "FAIL" };
  const failedBytes = Buffer.from(JSON.stringify(failedReceipt));
  const failedManifest = { ...f.manifest, evidence: {
    ...f.manifest.evidence, backup_restore_sha256: sha256(failedBytes),
  } };
  // Even a valid new pair of signatures over the failing receipt cannot turn
  // an unsuccessful synthetic backup/restore into a completed prerequisite.
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    ...f.signManifest(failedManifest),
    expected: { ...f.request.expected, backupRestoreSha256: sha256(failedBytes) },
    backupRestore: { ...f.request.backupRestore, receiptBytes: failedBytes } }), /backup-restore receipt is unsuccessful/u);
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request, backupRestore: {} }), /backup-restore prerequisites/u);
});

test("rehearsal refuses stale sequence, false predecessor and replayed/corrupted ledger history", { skip: !sourceGitAvailable }, async (t) => {
  const f = fixture(t);
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    ledgerState: { ...f.ledgerState, anchorSha: "0".repeat(40) } }), /ledger/u);
  const old = { sequence: 1, priorSha: predecessor, nextSha: f.revision,
    manifestSha256: sha256(f.request.manifestBytes), nonce: f.manifest.nonce,
    approvalDigest: "7".repeat(64) };
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    ledgerState: { ...f.ledgerState, entries: [old] } }), /sequence|ledger/u);
  await assert.rejects(rehearseOfflineReleaseLocally({ ...f.request,
    ledgerState: { ...f.ledgerState, entries: [{ ...old, priorSha: "f".repeat(40) }] } }), /ledger/u);
});

test("real disposable ledger recorder leaves an exclusive durable latch across process exit", { skip: !nativeKernel }, async (t) => {
  const f = fixture(t);
  const result = await rehearseOfflineReleaseLocally(f.request);
  const request = { directory: f.directory, manifestSha256: result.manifestSha256,
    priorSha: predecessor, nextSha: result.sourceSha, nonce: f.manifest.nonce,
    sequence: result.sequence, approvalDigest: sha256(f.request.signatures.owner) };
  const script = `import { recordOfflineReleaseAcceptance } from ${JSON.stringify(new URL("./lib/offline-release-ledger.mjs", import.meta.url).href)}; recordOfflineReleaseAcceptance(JSON.parse(process.env.VIRKI_DISPOSABLE_LEDGER_REQUEST));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8", timeout: 15_000,
    env: { ...process.env, VIRKI_DISPOSABLE_LEDGER_REQUEST: JSON.stringify(request) },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(readFileSync(path.join(f.directory, "ledger.json"), "utf8")).entries.length, 0);
  assert.equal(existsSync(path.join(f.directory, ".offline-release.lock")), true);
  assert.throws(() => recordOfflineReleaseAcceptance(request), /EEXIST|refused/u);
});
