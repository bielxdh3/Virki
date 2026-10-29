import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { inspectUntrustedSourceGitForPreview } from "./trusted-source-git.mjs";
import { inspectManualOwnerApproval, inspectManualRootSourceForPreview,
  recheckInstalledManualOwnerAtUseTime, verifyInstalledManualRootSource } from "./trusted-manual-source.mjs";

const hash = (v) => createHash("sha256").update(v).digest("hex");
const DOMAIN = Buffer.from("VIRKI_MANUAL_ROOT_SOURCE_APPROVAL_V1\0");
function git(args) {
  return execFileSync("/usr/bin/git", args, { encoding: "utf8", timeout: 10000,
    env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent",
      LC_ALL: "C", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null", GIT_NO_REPLACE_OBJECTS: "1",
      GIT_AUTHOR_DATE: "1700000000 +0000",
      GIT_COMMITTER_DATE: "1700000000 +0000" } }).trim();
}
function fixture(t) {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0, "Run isolated owner-trust previews as WSL root");
  const base = mkdtempSync("/var/lib/virki-manual-w32-");
  chmodSync(base, 0o700);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const repo = path.join(base, "builder");
  const trustedGitDirectory = path.join(base, "independent.git");
  git(["init", "-q", "-b", "main", repo]);
  git(["-C", repo, "config", "user.name", "W32 test"]);
  git(["-C", repo, "config", "user.email", "w32@example.invalid"]);
  writeFileSync(path.join(repo, "README.md"), "Main branch remains pinned\n");
  git(["-C", repo, "add", "."]);
  git(["-C", repo, "commit", "-qm", "main"]);
  const main = git(["-C", repo, "rev-parse", "HEAD"]);
  git(["-C", repo, "checkout", "-qb", "owner-approved-pr86"]);
  writeFileSync(path.join(repo, "README.md"), "Manual object, outside main\n");
  git(["-C", repo, "add", "."]);
  git(["-C", repo, "commit", "-qm", "manual"]);
  const manual = git(["-C", repo, "rev-parse", "HEAD"]);
  git(["init", "--bare", "-q", "-b", "main", trustedGitDirectory]);
  git(["-C", repo, "push", "-q", trustedGitDirectory, "main:main"]);
  git(["-C", repo, "push", "-q", trustedGitDirectory,
    "owner-approved-pr86:refs/heads/owner-approved-pr86"]);
  chmodSync(trustedGitDirectory, 0o700);
  const archiveDirectory = path.join(base, "candidate");
  mkdirSync(archiveDirectory, { mode: 0o700 });
  const archivePath = path.join(archiveDirectory, "source.tar");
  git([`--git-dir=${trustedGitDirectory}`, "archive", "--format=tar",
    `--output=${archivePath}`, manual]);
  chmodSync(archivePath, 0o600);
  const archiveSizeBytes = readFileSync(archivePath).length;
  const archiveSha256 = hash(readFileSync(archivePath));
  const trustDirectory = path.join(base, "root-trust");
  mkdirSync(trustDirectory, { mode: 0o700 });
  const commitPinPath = path.join(base, "manual.sha");
  const ownerPinPath = path.join(base, "owner.spki.sha256");
  writeFileSync(commitPinPath, manual + "\n", { mode: 0o600 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" });
  writeFileSync(ownerPinPath, hash(publicKey.export({ format: "der", type: "spki" })) + "\n",
    { mode: 0o600 });
  const owner = { version: 1, keyId: "owner-w32-test", publicKeyPem };
  const counter = { version: 1, lastAcceptedSequence: 6, approvedSequence: 7,
    revokedKeyIds: [], revokedPinsSha256: [] };
  const document = { version: 1, mode: "owner-manual-source-sha-v1",
    repository: "https://github.com/bielxdh3/Virki.git", sourceSha: manual,
    ciSourceBranch: "owner-approved-pr86", sourceArchiveSha256: archiveSha256,
    ciReportSha256: hash("only a digest in a test fixture, not real CI"),
    runtimeImageId: "sha256:" + "a".repeat(64),
    migratorImageId: "sha256:" + "b".repeat(64),
    hostIdentitySha256: "c".repeat(64),
    sequence: 7, validFromSeconds: 1700000000, validUntilSeconds: 1700003600 };
  const candidate = {
    sourceSha: document.sourceSha, sourceArchiveSha256: document.sourceArchiveSha256,
    ciReportSha256: document.ciReportSha256, runtimeImageId: document.runtimeImageId,
    migratorImageId: document.migratorImageId, hostIdentitySha256: document.hostIdentitySha256,
  };
  const save = (file, data) => writeFileSync(path.join(trustDirectory, file),
    Buffer.from(JSON.stringify(data)), { mode: 0o600 });
  const resign = () => {
    const sig = sign(null, Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(document))]), privateKey)
      .toString("base64");
    save("approval.json", { document, signatureBase64: sig });
  };
  save("owner-key.json", owner);
  save("counter.json", counter);
  resign();
  const preview = () => inspectManualRootSourceForPreview({
    trustDirectory, commitPinPath, ownerPinPath, trustedGitDirectory,
    archivePath, archiveSha256, archiveSizeBytes, candidate, nowSeconds: 1700000010,
  });
  const pure = () => inspectManualOwnerApproval({
    ownerBytes: readFileSync(path.join(trustDirectory, "owner-key.json")),
    approvalBytes: readFileSync(path.join(trustDirectory, "approval.json")),
    counterBytes: readFileSync(path.join(trustDirectory, "counter.json")),
    independentlyPinnedOwnerSpkiSha256: readFileSync(ownerPinPath, "utf8").trim(),
    independentlyPinnedCommitSha: readFileSync(commitPinPath, "utf8").trim(),
    candidate, nowSeconds: 1700000010,
  });
  return { base, main, manual, trustedGitDirectory, trustDirectory, ownerPinPath,
    commitPinPath, archivePath, archiveSha256, archiveSizeBytes, owner, counter, document,
    candidate, save, resign, preview, pure };
}

test("non-main exact commit is authenticated only through root-installed owner proof", async (t) => {
  const f = fixture(t);
  assert.notEqual(f.main, f.manual);
  assert.equal(git([`--git-dir=${f.trustedGitDirectory}`, "show-ref",
    "--verify", "--hash", "refs/heads/main"]), f.main);
  const report = await f.preview();
  assert.equal(report.status, "OWNER_MANUAL_SOURCE_PREVIEW_ONLY");
  assert.equal(report.sourceSha, f.manual);
  assert.equal(report.archiveSha256, f.archiveSha256);
  assert.equal(report.ciSourceBranch, "owner-approved-pr86");
  assert.equal(report.sequence, 7);
  assert.equal(report.expiresAt, f.document.validUntilSeconds);
  assert.equal(report.approvalSha256,
    hash(readFileSync(path.join(f.trustDirectory, "approval.json"))));
  assert.equal(report.deployAuthorized, false);
  assert.equal(Object.isFrozen(report), true);
  await assert.rejects(inspectUntrustedSourceGitForPreview({
    sourceArchivePath: f.archivePath, candidateSourceSha: f.manual,
    candidateArchiveSha256: f.archiveSha256, candidateArchiveSizeBytes: f.archiveSizeBytes,
    trustedGitDirectory: f.trustedGitDirectory, trustedShaPinPath: f.commitPinPath,
  }), /main|refused/u, "the existing hosted gate MUST remain main-only");
});

test("without actual owner-provisioned native verifier, release remains blocked", async (t) => {
  const f = fixture(t);
  await assert.rejects(verifyInstalledManualRootSource({
    candidateDirectory: path.dirname(f.archivePath), trustDirectory: f.trustDirectory,
  }), /refused/u);
  await assert.rejects(verifyInstalledManualRootSource({
    candidateDirectory: path.dirname(f.archivePath),
  }), /refused/u);
  assert.throws(() => recheckInstalledManualOwnerAtUseTime({
    candidate: f.candidate, nowSeconds: 1700000010, ownerKeyPem: f.owner.publicKeyPem,
  }), /refused/u, "uninstalled caller cannot inject clock, signing identity or authority");
  assert.throws(() => recheckInstalledManualOwnerAtUseTime({ candidate: f.candidate }),
    /refused/u, "uninstalled pure source tree cannot serve as root authority");
});

test("missing root key, attacker replacing pin and untrusted symlink are rejected", async (t) => {
  const f = fixture(t);
  writeFileSync(f.ownerPinPath, "f".repeat(64) + "\n");
  await assert.rejects(f.preview(), /refused/u);
  writeFileSync(f.ownerPinPath, hash("wrong") + "\n");
  await assert.rejects(f.preview(), /refused/u);
  const link = path.join(f.base, "alias");
  symlinkSync(f.trustDirectory, link);
  await assert.rejects(inspectManualRootSourceForPreview({
    trustDirectory: link, commitPinPath: f.commitPinPath, ownerPinPath: f.ownerPinPath,
    trustedGitDirectory: f.trustedGitDirectory, archivePath: f.archivePath,
    archiveSha256: f.archiveSha256, archiveSizeBytes: f.archiveSizeBytes,
    candidate: f.candidate, nowSeconds: 1700000010,
  }), /refused/u);
});

test("revoked key, replay counter and expired owner permit fail closed", async (t) => {
  const f = fixture(t);
  f.counter.revokedKeyIds.push(f.owner.keyId);
  f.save("counter.json", f.counter);
  assert.throws(f.pure, /revoked|refused/u);
  f.counter.revokedKeyIds.length = 0;
  f.counter.lastAcceptedSequence = 7;
  f.counter.approvedSequence = 7;
  f.save("counter.json", f.counter);
  assert.throws(f.pure, /counter|refused/u);
  f.counter.lastAcceptedSequence = 6;
  f.counter.approvedSequence = 8;
  f.save("counter.json", f.counter);
  assert.throws(f.pure, /sequence|refused/u);
  f.counter.approvedSequence = 7;
  f.save("counter.json", f.counter);
  f.document.validUntilSeconds = 1700000005;
  f.resign();
  assert.throws(f.pure, /expired|refused/u);
});

test("signature must cover exact SHA, CI branch, image IDs, host and report digest", async (t) => {
  const f = fixture(t);
  for (const [key, replacement] of [
    ["sourceSha", f.main],
    ["ciSourceBranch", "main"],
    ["runtimeImageId", "sha256:" + "d".repeat(64)],
    ["hostIdentitySha256", "e".repeat(64)],
    ["ciReportSha256", "f".repeat(64)],
  ]) {
    const original = f.document[key];
    f.document[key] = replacement;
    f.resign();
    assert.throws(f.pure, /refused/u, `unsigned candidate must not drive ${key}`);
    f.document[key] = original;
  }
  f.resign();
  f.document.sourceSha = f.main; // actual signed file remains unchanged
  assert.doesNotThrow(f.pure);
  const bytes = readFileSync(path.join(f.trustDirectory, "approval.json"));
  bytes[bytes.indexOf(Buffer.from("owner-approved-pr86"))] ^= 1;
  writeFileSync(path.join(f.trustDirectory, "approval.json"), bytes);
  assert.throws(f.pure, /refused/u);
});

test("the Git verifier refuses tampered real TAR, missing objects and SHA pin divergence", async (t) => {
  const f = fixture(t);
  const bytes = readFileSync(f.archivePath);
  bytes[bytes.indexOf(Buffer.from("Manual object"))] ^= 1;
  writeFileSync(f.archivePath, bytes);
  await assert.rejects(f.preview(), /refused|differs from Git/u);
  writeFileSync(f.archivePath, Buffer.from(bytes)); // the following source pin check occurs before Git
  writeFileSync(f.commitPinPath, f.main + "\n");
  await assert.rejects(f.preview(), /refused/u);
  const linked = path.join(f.base, "other-hardlink");
  linkSync(path.join(f.trustDirectory, "owner-key.json"), linked);
  await assert.rejects(f.preview(), /refused/u);
});

test("missing and extra trust files, writable files, symlink pins and altered pinned key fail", async (t) => {
  const f = fixture(t);
  const extra = path.join(f.trustDirectory, "unapproved.txt");
  writeFileSync(extra, "untrusted", { mode: 0o600 });
  await assert.rejects(f.preview(), /refused/u);
  rmSync(extra);
  const keyFile = path.join(f.trustDirectory, "owner-key.json");
  chmodSync(keyFile, 0o666);
  await assert.rejects(f.preview(), /refused/u);
  chmodSync(keyFile, 0o600);
  const pinAlias = path.join(f.base, "pin-alias");
  symlinkSync(f.ownerPinPath, pinAlias);
  await assert.rejects(inspectManualRootSourceForPreview({
    trustDirectory: f.trustDirectory, ownerPinPath: pinAlias,
    commitPinPath: f.commitPinPath, trustedGitDirectory: f.trustedGitDirectory,
    archivePath: f.archivePath, archiveSha256: f.archiveSha256,
    archiveSizeBytes: f.archiveSizeBytes, candidate: f.candidate,
    nowSeconds: 1700000010,
  }), /refused/u);
  const old = readFileSync(keyFile);
  rmSync(keyFile);
  await assert.rejects(f.preview(), /ENOENT|refused/u);
  writeFileSync(keyFile, old, { mode: 0o600 });
  assert.equal((await f.preview()).deployAuthorized, false);
});

test("owner SPKI pin revocation, unauthorized noncanonical documents and overlong expiry are refused", (t) => {
  const f = fixture(t);
  f.counter.revokedPinsSha256.push(readFileSync(f.ownerPinPath, "utf8").trim());
  f.save("counter.json", f.counter);
  assert.throws(f.pure, /refused/u);
  f.counter.revokedPinsSha256.length = 0;
  f.save("counter.json", f.counter);
  f.document.validUntilSeconds = 1700000000 + 86401;
  f.resign();
  assert.throws(f.pure, /refused/u);
  f.document.validUntilSeconds = 1700003600;
  f.resign();
  const file = path.join(f.trustDirectory, "approval.json");
  const canonical = JSON.parse(readFileSync(file, "utf8"));
  writeFileSync(file, JSON.stringify(canonical, null, 2));
  assert.throws(f.pure, /canonical|refused/u);
  f.resign();
  canonical.document.extraTrust = "user";
  writeFileSync(file, JSON.stringify(canonical));
  assert.throws(f.pure, /fields|refused/u);
});

test("preview cannot verify one archive while claiming the signed digest of another", async (t) => {
  const f = fixture(t);
  await assert.rejects(inspectManualRootSourceForPreview({
    trustDirectory: f.trustDirectory, ownerPinPath: f.ownerPinPath,
    commitPinPath: f.commitPinPath, trustedGitDirectory: f.trustedGitDirectory,
    archivePath: f.archivePath, archiveSha256: "f".repeat(64),
    archiveSizeBytes: f.archiveSizeBytes, candidate: f.candidate,
    nowSeconds: 1700000010,
  }), /refused/u);
});

test("signed SHA must be an available intact independent Git commit, never an unsigned ref alias", async (t) => {
  const f = fixture(t);
  const commit = path.join(f.trustedGitDirectory, "objects",
    f.manual.slice(0, 2), f.manual.slice(2));
  rmSync(commit);
  await assert.rejects(f.preview(), /refused|Git/u);
  // Even an independently pinned commit cannot be silently fetched.
  const origin = git([`--git-dir=${f.trustedGitDirectory}`, "config", "--get", "core.bare"]);
  assert.equal(origin, "true");
});
