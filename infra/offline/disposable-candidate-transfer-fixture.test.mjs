import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  renameSync, rmSync, statfsSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { encodeCanonicalOfflineReleaseManifest } from "../../scripts/lib/offline-release-attestation.mjs";
import { rehearseDisposableCandidateTransfer } from "./disposable-candidate-transfer-fixture.mjs";

const enabled = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 && process.env.VIRKI_OFFLINE_TRANSFER_FIXTURE === "1" &&
  statfsSync(os.tmpdir()).type === 0x01021994;
const fixtureOnly = { skip: enabled ? false : "isolated Linux root tmpfs required" };
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonical = (obj) => Buffer.from(JSON.stringify(obj));
const host = "9".repeat(64);
const SHA = "a".repeat(40);
const predecessor = "b".repeat(40);
const names = ["backup-restore.json", "ci-report.json", "finding-review.json", "manifest.json",
  "migrator-smoke.json", "migrator.tar", "runtime-smoke.json", "runtime.tar",
  "scanner-report.json", "signatures.json", "source.tar"];

function fixture(t) {
  const fixtureRoot = mkdtempSync(path.join(os.tmpdir(), "virki-offline-transfer-fixture-"));
  chmodSync(fixtureRoot, 0o700);
  t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const candidateDirectory = path.join(fixtureRoot, "candidate");
  const operatorDirectory = path.join(fixtureRoot, "operator");
  const stagingDirectory = path.join(fixtureRoot, "staging");
  for (const directory of [candidateDirectory, operatorDirectory, stagingDirectory])
    mkdirSync(directory, { mode: 0o700 });
  const files = {
    "source.tar": Buffer.alloc(4096, 1), "runtime.tar": Buffer.alloc(4096, 2),
    "migrator.tar": Buffer.alloc(4096, 3), "ci-report.json": Buffer.from('{"stage":"fixture"}'),
    "scanner-report.json": Buffer.from('{"scan":"fixture"}'),
    "finding-review.json": Buffer.from('{"review":"fixture"}'),
    "runtime-smoke.json": Buffer.from('{"runtime":"fixture"}'),
    "migrator-smoke.json": Buffer.from('{"migrator":"fixture"}'),
    "backup-restore.json": Buffer.from('{"restore":"fixture"}'),
  };
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const pin = (pair, keyId) => ({ keyId,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: hash(pair.publicKey.export({ type: "spki", format: "der" })) });
  const now = Math.floor(Date.now() / 1000);
  const manifest = encodeCanonicalOfflineReleaseManifest({
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git", source_sha: SHA,
    source_archive_sha256: hash(files["source.tar"]),
    source_archive_size_bytes: files["source.tar"].length, platform: "linux/amd64",
    host_identity_sha256: host, predecessor_sha: predecessor,
    runtime_image: { archive_sha256: hash(files["runtime.tar"]),
      archive_size_bytes: files["runtime.tar"].length, image_id: "sha256:" + "1".repeat(64) },
    migrator_image: { archive_sha256: hash(files["migrator.tar"]),
      archive_size_bytes: files["migrator.tar"].length, image_id: "sha256:" + "2".repeat(64) },
    evidence: { ci_report_sha256: hash(files["ci-report.json"]),
      scanner_report_sha256: hash(files["scanner-report.json"]), scanner_rules_commit: "c".repeat(40),
      finding_review_sha256: hash(files["finding-review.json"]),
      runtime_smoke_sha256: hash(files["runtime-smoke.json"]),
      migrator_smoke_sha256: hash(files["migrator-smoke.json"]),
      backup_restore_sha256: hash(files["backup-restore.json"]) },
    issued_at: now - 10, expires_at: now + 600, nonce: "d".repeat(32), sequence: 1,
  });
  files["manifest.json"] = manifest;
  files["signatures.json"] = canonical({
    builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), manifest]),
      builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"),
      Buffer.from(hash(manifest), "hex")]), owner.privateKey).toString("base64"),
  });
  for (const [name, data] of Object.entries(files))
    writeFileSync(path.join(candidateDirectory, name), data, { flag: "wx", mode: 0o600 });
  const policy = { version: 2, mode: "offline-signed-v1", enabled: true,
    ownerAssuranceAccepted: true, hostIdentitySha256: host, ledgerAnchorSha: predecessor,
    platform: "linux/amd64", builder: pin(builder, "fixture-builder"),
    owner: pin(owner, "fixture-owner"), revokedKeyIds: [], revokedPinsSha256: [] };
  const ledger = { version: 1, anchorSha: predecessor, entries: [] };
  const transfer = { version: 1, mode: "disposable-candidate-transfer-v1", hostIdentitySha256: host,
    files: names.map((name) => ({ name, sizeBytes: files[name].length, sha256: hash(files[name]) })) };
  for (const [name, bytes] of Object.entries({ "trust-policy.json": canonical(policy),
    "ledger.json": canonical(ledger), "transfer-pins.json": canonical(transfer) }))
    writeFileSync(path.join(operatorDirectory, name), bytes, { flag: "wx", mode: 0o600 });
  return { request: { fixtureRoot, candidateDirectory, operatorDirectory, stagingDirectory,
    measuredHostIdentitySha256: host }, files, transfer };
}

test("copies exact independently pinned signed candidate into private staging without GitHub or deployment authority", fixtureOnly, async (t) => {
  const f = fixture(t);
  const result = await rehearseDisposableCandidateTransfer(f.request);
  assert.equal(result.status, "DISPOSABLE_CANDIDATE_TRANSFER_STAGED_ONLY");
  assert.equal(result.filesStaged, 11);
  assert.equal(result.transferAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.independentHostIdentityVerified, false);
  assert.deepEqual(readdirSync(path.join(f.request.stagingDirectory, "published")).sort(), names);
  for (const name of names)
    assert.deepEqual(readFileSync(path.join(f.request.stagingDirectory, "published", name)), f.files[name]);
  await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
});

test("rejects tampered bytes or independently pinned host / manifest before transfer", fixtureOnly, async (t) => {
  for (const mutate of [
    (f) => writeFileSync(path.join(f.request.candidateDirectory, "source.tar"), Buffer.alloc(4096, 8)),
    (f) => { const p = path.join(f.request.operatorDirectory, "transfer-pins.json");
      writeFileSync(p, canonical({ ...f.transfer, hostIdentitySha256: "f".repeat(64) })); },
    (f) => { const p = path.join(f.request.operatorDirectory, "transfer-pins.json");
      writeFileSync(p, canonical({ ...f.transfer, files: f.transfer.files.map((x) =>
        x.name === "manifest.json" ? { ...x, sha256: "0".repeat(64) } : x) })); },
    (f) => writeFileSync(path.join(f.request.candidateDirectory, "signatures.json"), "fake"),
  ]) {
    const f = fixture(t); mutate(f);
    await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
    assert.deepEqual(readdirSync(f.request.stagingDirectory), []);
  }
});

test("refuses hardlinks, symlinks, foreign roots, unexpected input and world-writeable file", fixtureOnly, async (t) => {
  for (const mutate of [
    (f) => { const p = path.join(f.request.candidateDirectory, "runtime.tar");
      linkSync(p, path.join(f.request.fixtureRoot, "linked")); },
    (f) => { const p = path.join(f.request.candidateDirectory, "runtime.tar");
      renameSync(p, p + ".saved"); symlinkSync(p + ".saved", p); },
    (f) => chmodSync(path.join(f.request.candidateDirectory, "source.tar"), 0o666),
    (f) => writeFileSync(path.join(f.request.candidateDirectory, "surprise"), "oops"),
    (f) => { const p = f.request.stagingDirectory;
      renameSync(p, p + ".saved"); symlinkSync(p + ".saved", p); },
  ]) {
    const f = fixture(t); mutate(f);
    await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
  }
});

test("post-pin inode swaps and interrupted transfer leave a durable failure latch", fixtureOnly, async (t) => {
  for (const phase of ["afterPreflight", "chunkCopied", "beforePublish"]) {
    const f = fixture(t);
    await assert.rejects(rehearseDisposableCandidateTransfer(f.request, {
      onPhase(current) {
        if (current !== phase) return;
        if (phase === "afterPreflight") {
          const p = path.join(f.request.candidateDirectory, "source.tar");
          renameSync(p, p + ".moved");
          writeFileSync(p, Buffer.alloc(4096, 9));
        } else if (phase === "beforePublish") {
          const p = path.join(f.request.stagingDirectory, ".incoming", "source.tar");
          renameSync(p, p + ".moved");
          writeFileSync(p, Buffer.alloc(4096, 9));
        } else throw new Error("PRIVATE_SECRET_SHOULD_NEVER_PRINT");
      },
    }), (error) => !String(error).includes("PRIVATE_SECRET_SHOULD_NEVER_PRINT"));
    assert.equal(readdirSync(f.request.stagingDirectory).includes("published"), false);
    await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
  }
});

test("operator trust tampering during the upload and pre-existing orphan both block atomic publication", fixtureOnly, async (t) => {
  for (const phase of ["afterPreflight", "beforePublish"]) {
    const f = fixture(t);
    await assert.rejects(rehearseDisposableCandidateTransfer(f.request, {
      onPhase(current) {
        if (current !== phase) return;
        const name = path.join(f.request.operatorDirectory, "transfer-pins.json");
        const bytes = readFileSync(name);
        writeFileSync(name, Buffer.concat([bytes, Buffer.from(" ")]));
      },
    }));
    assert.equal(readdirSync(f.request.stagingDirectory).includes("published"), false);
  }
  const f = fixture(t);
  mkdirSync(path.join(f.request.stagingDirectory, ".incoming"), { mode: 0o700 });
  await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
  assert.deepEqual(readdirSync(f.request.stagingDirectory), [".incoming"]);
});

test("real SIGKILL during FD upload leaves an fsynced orphan and refuses retry", fixtureOnly, async (t) => {
  const f = fixture(t);
  const childFile = fileURLToPath(new URL("./disposable-candidate-transfer-kill-fixture.mjs", import.meta.url));
  const child = spawnSync(process.execPath, [childFile], {
    encoding: "utf8", timeout: 8000,
    env: { PATH: process.env.PATH ?? "", HOME: "/tmp", TMPDIR: "/tmp",
      VIRKI_OFFLINE_TRANSFER_FIXTURE: "1", VIRKI_OFFLINE_TRANSFER_KILL_TEST: "1",
      VIRKI_OFFLINE_TRANSFER_REQUEST: JSON.stringify(f.request) },
  });
  assert.equal(child.signal, "SIGKILL");
  assert.deepEqual(readdirSync(f.request.stagingDirectory), [".incoming"]);
  assert.equal(readdirSync(path.join(f.request.stagingDirectory, ".incoming")).length > 0, true);
  await assert.rejects(rehearseDisposableCandidateTransfer(f.request));
});

test("cannot run from source checkout, with caller-selected destination, or on unprivileged host", async () => {
  await assert.rejects(rehearseDisposableCandidateTransfer({}));
  const file = fileURLToPath(new URL("./disposable-candidate-transfer-fixture.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [file], { encoding: "utf8", timeout: 4000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /no command-line transfer entrypoint/u);
});

test("direct CLI through symlinked repository directory must also refuse before any staging", fixtureOnly, (t) => {
  const f = fixture(t);
  const repository = fileURLToPath(new URL("../../", import.meta.url));
  const alias = path.join(f.request.fixtureRoot, "repo-alias");
  symlinkSync(repository, alias, "dir");
  const aliasMain = path.join(alias, "infra", "offline", "disposable-candidate-transfer-fixture.mjs");
  for (const flags of [[], ["--preserve-symlinks-main"],
    ["--preserve-symlinks", "--preserve-symlinks-main"]]) {
    const child = spawnSync(process.execPath, [...flags, aliasMain], {
      encoding: "utf8", timeout: 5000,
      env: { PATH: process.env.PATH ?? "", HOME: "/tmp", TMPDIR: "/tmp",
        VIRKI_OFFLINE_TRANSFER_FIXTURE: "1" },
    });
    assert.equal(child.status, 2, `flags=${flags.join(",")}: ${child.stderr}`);
    assert.match(child.stderr, /no command-line transfer entrypoint/u);
    assert.doesNotMatch(child.stderr, /ERR_MODULE_NOT_FOUND|Error \[/u);
    assert.equal(child.stdout, "");
    assert.deepEqual(readdirSync(f.request.stagingDirectory), []);
  }
  const mirror = path.join(f.request.fixtureRoot, "module-alias");
  const nested = path.join(mirror, "infra", "offline");
  mkdirSync(nested, { recursive: true, mode: 0o700 });
  symlinkSync(path.join(repository, "scripts"), path.join(mirror, "scripts"), "dir");
  symlinkSync(path.join(repository, "infra", "offline", "trusted-host-entry.mjs"),
    path.join(nested, "trusted-host-entry.mjs"));
  const mainFileAlias = path.join(nested, "disposable-candidate-transfer-fixture.mjs");
  symlinkSync(path.join(repository, "infra", "offline", "disposable-candidate-transfer-fixture.mjs"),
    mainFileAlias);
  for (const flags of [[], ["--preserve-symlinks-main"]]) {
    const child = spawnSync(process.execPath, [...flags, mainFileAlias], {
      encoding: "utf8", timeout: 5000,
      env: { PATH: process.env.PATH ?? "", HOME: "/tmp", TMPDIR: "/tmp",
        VIRKI_OFFLINE_TRANSFER_FIXTURE: "1" },
    });
    assert.equal(child.status, 2, `direct file symlink flags=${flags.join(",")}: ${child.stderr}`);
    assert.match(child.stderr, /no command-line transfer entrypoint/u);
    assert.doesNotMatch(child.stderr, /ERR_MODULE_NOT_FOUND|Error \[/u);
    assert.deepEqual(readdirSync(f.request.stagingDirectory), []);
  }
});
