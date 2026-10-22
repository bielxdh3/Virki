import assert from "node:assert/strict";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, realpathSync, rmSync, statfsSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import { createServer } from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { encodeCanonicalOfflineReleaseManifest } from "../../scripts/lib/offline-release-attestation.mjs";

// Execute ONLY inside an ephemeral, isolated Linux container. The tests write
// /etc/machine-id and recursively clear fixture paths under /etc and /var/lib.
// The environment opt-in and /.dockerenv are insufficient isolation proof.
// Confirm ALL of the writable test roots are empty, genuine tmpfs mounts
// before even copying the fixture implementation.
const TMPFS_MAGIC = 0x01021994;
const fixtureMounts = ["/etc", "/var/lib", "/usr/local/lib/virki", "/run"];
const isolatedRoots = fixtureMounts.every((directory) => {
  try {
    const stat = lstatSync(directory);
    return statfsSync(directory).type === TMPFS_MAGIC &&
      stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0 &&
      realpathSync.native(directory) === directory;
  } catch {
    return false;
  }
});
if (process.env.VIRKI_COORDINATOR_DISPOSABLE_CONTAINER !== "1" ||
    !existsSync("/.dockerenv") || process.platform !== "linux" ||
    process.arch !== "x64" || process.getuid?.() !== 0 || !isolatedRoots ||
    existsSync("/etc/machine-id") || existsSync("/etc/virki") ||
    existsSync("/var/lib/virki") ||
    readdirSync("/usr/local/lib/virki").length !== 0) {
  throw new Error("Coordinator fixture refused: empty isolated tmpfs /etc, /var/lib and /usr/local/lib/virki inside disposable root Linux container required");
}
const realRelease = os.release;
// Docker Desktop containers inherit the WSL kernel; simulate ONLY that kernel
// detection in this disposable fixture. Production never has this bypass.
if (/microsoft|wsl/iu.test(os.release())) os.release = () => "6.12.0-disposable-linux-test";

// Copy the real implementation and its exact static ESM dependency closure
// into an independently root-owned 0600 installed tree inside the container.
// A writable source checkout must always fail the coordinator's native gate.
const INSTALL = "/usr/local/lib/virki/offline-release";
const TRUSTED_ENTRY = path.join(INSTALL, "infra/offline/trusted-release-coordinator.mjs");
const root = fileURLToPath(new URL("../../", import.meta.url));
for (const relative of [
  "infra/offline/trusted-release-coordinator.mjs",
  "infra/offline/trusted-image-import.mjs",
  "infra/offline/trusted-image-loader.mjs",
  "infra/offline/trusted-host-entry.mjs",
  "infra/offline/trusted-source-git.mjs",
  "scripts/lib/offline-release-ledger.mjs",
  "scripts/lib/offline-release-attestation.mjs",
  "scripts/lib/offline-docker-tar-verifier.mjs",
  "scripts/lib/offline-trusted-release-policy.mjs",
  "scripts/lib/offline-source-tar-verifier.mjs",
]) {
  const pathname = path.join(INSTALL, relative);
  mkdirSync(path.dirname(pathname), { recursive: true, mode: 0o700 });
  copyFileSync(path.join(root, relative), pathname);
  chmodSync(pathname, 0o600);
}
const { coordinateTrustedOfflineRelease } = await import(pathToFileURL(TRUSTED_ENTRY));
const { importApprovedOfflineImage, importApprovedOfflineImages } = await import(pathToFileURL(
  path.join(INSTALL, "infra/offline/trusted-image-import.mjs")));

const FIXED = "/var/lib/virki";
const LEDGER = path.join(FIXED, "offline-release");
const POLICY = "/etc/virki/offline-release";
const GIT = path.join(FIXED, "offline-source/trusted.git");
const PIN = "/etc/virki/offline-source-commit.sha";
const ANCHOR = "a".repeat(40);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const keyPin = (keyId, key) => ({ keyId, publicKeyPem: key.export({ format: "pem", type: "spki" }),
  pinSha256: hash(key.export({ format: "der", type: "spki" })) });
const pad = (size) => (512 - size % 512) % 512;

function tar(entries) {
  const result = [];
  for (const { name, bytes } of entries) {
    const data = Buffer.from(bytes);
    const header = Buffer.alloc(512);
    header.write(name, 0, "ascii");
    const octal = (start, width, value) => {
      header.write(value.toString(8).padStart(width - 1, "0") + "\0", start, "ascii");
    };
    octal(100, 8, 0o644);
    octal(108, 8, 0);
    octal(116, 8, 0);
    octal(124, 12, data.length);
    octal(136, 12, 0);
    header.fill(32, 148, 156);
    header.write("0", 156, "ascii");
    header.write("ustar", 257, "ascii");
    header.write("00", 263, "ascii");
    octal(148, 8, header.reduce((sum, value) => sum + value, 0));
    result.push(header, data, Buffer.alloc(pad(data.length)));
  }
  result.push(Buffer.alloc(1024));
  return Buffer.concat(result);
}
function dockerSave(revision, role) {
  const layer = tar([{ name: "app.txt", bytes: role }]);
  const config = Buffer.from(JSON.stringify({
    os: "linux", architecture: "amd64",
    config: { User: "node:node", Labels: {
      "org.opencontainers.image.revision": revision,
      "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki",
    } },
    rootfs: { type: "layers", diff_ids: [`sha256:${hash(layer)}`] },
  }));
  const id = hash(config);
  const layerPath = `${"a".repeat(64)}/layer.tar`;
  const bytes = tar([
    { name: `${id}.json`, bytes: config },
    { name: layerPath, bytes: layer },
    { name: "manifest.json", bytes: JSON.stringify([
      { Config: `${id}.json`, RepoTags: null, Layers: [layerPath] },
    ]) },
  ]);
  return { bytes, image_id: `sha256:${id}`, archive_sha256: hash(bytes), archive_size_bytes: bytes.length };
}
function git(...args) {
  return execFileSync("/usr/bin/git", args, { encoding: "utf8", timeout: 10000,
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_DATE: "1700000000 +0000", GIT_COMMITTER_DATE: "1700000000 +0000" } }).trim();
}
function writeJson(file, value) {
  writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
  chmodSync(file, 0o600);
}
function buildFixture() {
  // This container starts with empty dedicated roots; another test must never
  // run in parallel against these fixed paths.
  mkdirSync("/etc/virki", { recursive: true, mode: 0o755 });
  mkdirSync(POLICY, { recursive: true, mode: 0o700 });
  mkdirSync(FIXED, { recursive: true, mode: 0o755 });
  mkdirSync(path.join(FIXED, "offline-source"), { recursive: true, mode: 0o700 });
  mkdirSync(LEDGER, { recursive: true, mode: 0o700 });
  mkdirSync(path.join(FIXED, "offline-staging"), { recursive: true, mode: 0o700 });
  chmodSync(POLICY, 0o700);
  chmodSync(LEDGER, 0o700);
  chmodSync(path.join(FIXED, "offline-source"), 0o700);
  chmodSync(path.join(FIXED, "offline-staging"), 0o700);
  writeFileSync("/etc/machine-id", "0123456789abcdef0123456789abcdef\n", { mode: 0o644 });
  const hostId = hash("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0" + "0123456789abcdef0123456789abcdef");
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const work = mkdtempSync(path.join(FIXED, "offline-staging", "builder-"));
  git("init", "-q", "-b", "main", work);
  git("-C", work, "config", "user.name", "Disposable Fixture");
  git("-C", work, "config", "user.email", "fixture@example.invalid");
  writeFileSync(path.join(work, "README.md"), "independent Git source\n");
  git("-C", work, "add", ".");
  git("-C", work, "commit", "-qm", "signed fixture");
  const sourceSha = git("-C", work, "rev-parse", "HEAD");
  git("init", "--bare", "-q", "-b", "main", GIT);
  git("-C", work, "push", "-q", GIT, "main:main");
  chmodSync(GIT, 0o700);
  writeFileSync(PIN, sourceSha + "\n", { mode: 0o600 });
  const directory = mkdtempSync(path.join(FIXED, "offline-staging", "candidate-"));
  chmodSync(directory, 0o700);
  git(`--git-dir=${GIT}`, "archive", "--format=tar", `--output=${path.join(directory, "source.tar")}`, sourceSha);
  chmodSync(path.join(directory, "source.tar"), 0o600);
  const source = readFileSync(path.join(directory, "source.tar"));
  const runtime = dockerSave(sourceSha, "runtime");
  const migrator = dockerSave(sourceSha, "migrator");
  const reports = [
    ["ci-report.json", "ci_report_sha256"], ["scanner-report.json", "scanner_report_sha256"],
    ["finding-review.json", "finding_review_sha256"], ["runtime-smoke.json", "runtime_smoke_sha256"],
    ["migrator-smoke.json", "migrator_smoke_sha256"], ["backup-restore.json", "backup_restore_sha256"],
  ];
  const evidence = { scanner_rules_commit: sourceSha };
  reports.forEach(([name, field], index) => {
    const bytes = Buffer.from(JSON.stringify({ fixture: true, index }));
    evidence[field] = hash(bytes);
    writeFileSync(path.join(directory, name), bytes, { mode: 0o600 });
  });
  for (const [name, value] of [["runtime.tar", runtime.bytes], ["migrator.tar", migrator.bytes]]) {
    writeFileSync(path.join(directory, name), value, { mode: 0o600 });
  }
  const policy = { version: 2, mode: "offline-signed-v1", enabled: true, ownerAssuranceAccepted: true,
    hostIdentitySha256: hostId, ledgerAnchorSha: ANCHOR, platform: "linux/amd64",
    builder: keyPin("independent-builder", builder.publicKey),
    owner: keyPin("independent-owner", owner.publicKey), revokedKeyIds: [], revokedPinsSha256: [] };
  const ledger = { version: 1, anchorSha: ANCHOR, entries: [] };
  writeJson(path.join(POLICY, "trust-policy.json"), policy);
  writeJson(path.join(LEDGER, "ledger.json"), ledger);
  const manifest = { version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git", source_sha: sourceSha,
    source_archive_sha256: hash(source), source_archive_size_bytes: source.length,
    platform: "linux/amd64", host_identity_sha256: hostId, predecessor_sha: ANCHOR,
    runtime_image: { archive_sha256: runtime.archive_sha256, archive_size_bytes: runtime.archive_size_bytes,
      image_id: runtime.image_id },
    migrator_image: { archive_sha256: migrator.archive_sha256, archive_size_bytes: migrator.archive_size_bytes,
      image_id: migrator.image_id }, evidence,
    issued_at: Math.floor(Date.now() / 1000) - 10, expires_at: Math.floor(Date.now() / 1000) + 300,
    nonce: "d".repeat(32), sequence: 1 };
  function resign() {
    const bytes = encodeCanonicalOfflineReleaseManifest(manifest);
    writeFileSync(path.join(directory, "manifest.json"), bytes, { mode: 0o600 });
    writeJson(path.join(directory, "signatures.json"), {
      builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), bytes]), builder.privateKey).toString("base64"),
      owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"),
        Buffer.from(hash(bytes), "hex")]), owner.privateKey).toString("base64"),
    });
  }
  resign();
  return { directory, work, sourceSha, manifest, resign, policy, ledger, runtime, migrator };
}
function reset() {
  rmSync(POLICY, { recursive: true, force: true });
  rmSync(LEDGER, { recursive: true, force: true });
  rmSync("/var/lib/virki/offline-source", { recursive: true, force: true });
  rmSync("/var/lib/virki/offline-staging", { recursive: true, force: true });
  rmSync("/var/lib/virki/offline-import-quarantine", { recursive: true, force: true });
  rmSync(PIN, { force: true });
}
function locked() { return existsSync(path.join(LEDGER, ".offline-release.lock")); }
function state() { return JSON.parse(readFileSync(path.join(LEDGER, "ledger.json"), "utf8")); }
async function setupIsolatedImportSink(t) {
  const endpoint = "/run/virki-offline-import";
  rmSync(endpoint, { recursive: true, force: true });
  mkdirSync(endpoint, { recursive: true, mode: 0o700 });
  chmodSync(endpoint, 0o700);
  const fake = path.join(endpoint, "docker");
  copyFileSync(path.join(root, "infra/offline/fixtures/fake-image-import-docker"), fake);
  chmodSync(fake, 0o700);
  writeFileSync("/etc/virki/offline-import-cli.sha256", hash(readFileSync(fake)) + "\n", { mode: 0o600 });
  const socket = path.join(endpoint, "docker.sock");
  const listener = createServer();
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(socket, resolve);
  });
  chmodSync(socket, 0o600);
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  mkdirSync(path.join(FIXED, "offline-import-quarantine"), { mode: 0o700 });
  return endpoint;
}
function childScript(extra = "") {
  return `import os from "node:os";
    os.release = () => "6.12.0-disposable-linux-test";
    ${extra}
    const { coordinateTrustedOfflineRelease } = await import(${JSON.stringify(pathToFileURL(TRUSTED_ENTRY).href)});
    const result = await coordinateTrustedOfflineRelease({ candidateDirectory: process.env.VIRKI_FIXTURE_CANDIDATE });
    process.stdout.write(result.status);
  `;
}
function runChild(directory, extra = "") {
  return spawnSync(process.execPath, ["--input-type=module", "-e", childScript(extra)],
    { encoding: "utf8", env: { ...process.env, VIRKI_FIXTURE_CANDIDATE: directory }, timeout: 20000 });
}
async function runParallel(directory) {
  const start = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", childScript()],
      { env: { ...process.env, VIRKI_FIXTURE_CANDIDATE: directory } });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, output }));
  });
  return Promise.all([start(), start()]);
}

test("disposable Linux root transaction coordinator denies, reserves once and persists locks", async (t) => {
  t.after(() => { reset(); os.release = realRelease; });
  await t.test("uninstalled checkout code is never a trusted coordinator", async () => {
    const { coordinateTrustedOfflineRelease: uninstalled } =
      await import("./trusted-release-coordinator.mjs");
    assert.equal((await uninstalled({ candidateDirectory: "/invalid" })).status, "blocked");
  });
  await t.test("signed builder and owner + host-pinned Git stage only and durably reserve once", async () => {
    reset();
    const f = buildFixture();
    const result = await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory });
    assert.equal(result.status, "staged");
    assert.equal(result.deployAuthorized, false);
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), true);
  });
  await t.test("wrong owner signature blocks before reservation", async () => {
    reset();
    const f = buildFixture();
    const pathname = path.join(f.directory, "signatures.json");
    const value = JSON.parse(readFileSync(pathname, "utf8"));
    value.owner = value.builder;
    writeJson(pathname, value);
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("wrong builder signature and expired signed release block before reservation", async () => {
    reset();
    const f = buildFixture();
    const pathname = path.join(f.directory, "signatures.json");
    const value = JSON.parse(readFileSync(pathname, "utf8"));
    value.builder = value.owner;
    writeJson(pathname, value);
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    f.manifest.expires_at = Math.floor(Date.now() / 1000) - 1;
    f.manifest.issued_at = f.manifest.expires_at - 100;
    f.resign();
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("host Git pin remains independent of fully signed candidate", async () => {
    reset();
    const f = buildFixture();
    writeFileSync(PIN, "f".repeat(40) + "\n");
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("independent Git rejects a new owner-signed TAR with non-Git file contents", async () => {
    reset();
    const f = buildFixture();
    const archive = path.join(f.directory, "source.tar");
    const original = readFileSync(archive);
    const changed = Buffer.from(original);
    const offset = changed.indexOf(Buffer.from("independent Git source"));
    assert.ok(offset > 0);
    changed[offset] ^= 1;
    writeFileSync(archive, changed);
    f.manifest.source_archive_sha256 = hash(changed);
    f.resign();
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("host signer revocation blocks trusted candidate", async () => {
    reset();
    const f = buildFixture();
    f.policy.revokedKeyIds.push("independent-owner");
    writeJson(path.join(POLICY, "trust-policy.json"), f.policy);
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("rollback, nonce replay and forged ledger history are denied", async () => {
    reset();
    const f = buildFixture();
    const head = "f".repeat(40);
    const entry = { sequence: 1, priorSha: ANCHOR, nextSha: head,
      manifestSha256: "1".repeat(64), nonce: "d".repeat(32), approvalDigest: "2".repeat(64) };
    writeJson(path.join(LEDGER, "ledger.json"), { ...f.ledger, entries: [entry] });
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    f.manifest.predecessor_sha = head;
    f.manifest.sequence = 2;
    f.resign();
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
    // Replay reaches the O_EXCL ledger boundary: rejected attempts leave a
    // durable latch that an operator must reconcile, never auto-clear.
    assert.equal(locked(), true);
    reset();
    const damaged = buildFixture();
    writeJson(path.join(LEDGER, "ledger.json"), {
      ...damaged.ledger, entries: [{ ...entry, priorSha: "c".repeat(40) }],
    });
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: damaged.directory })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("two racing processes yield exactly one staged, one blocked, one persisted lock", async () => {
    reset();
    const f = buildFixture();
    const result = await runParallel(f.directory);
    assert.equal(result.every((entry) => entry.code === 0), true, JSON.stringify(result));
    assert.deepEqual(result.map((entry) => entry.output).sort(), ["blocked", "staged"]);
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
  });
  await t.test("SIGKILL at attempted journal leaves permanent fail-closed lock", async () => {
    reset();
    const f = buildFixture();
    const child = runChild(f.directory, `
      import fs from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      const oldWrite = fs.writeSync;
      fs.writeSync = (fd, ...args) => {
        oldWrite(fd, Buffer.from("partial"));
        process.kill(process.pid, "SIGKILL");
      };
      syncBuiltinESMExports();
    `);
    assert.equal(child.signal, "SIGKILL", child.stderr);
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
    assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
  });
  await t.test("caller may supply only candidateDirectory, never trust or ledger fields", async () => {
    reset();
    const f = buildFixture();
    for (const extra of [
      { signerKeys: {} }, { gitPin: "f".repeat(40) }, { ledgerHead: ANCHOR },
      { directory: LEDGER }, { expected: {} }, { deploy: true },
    ]) assert.equal((await coordinateTrustedOfflineRelease({
      candidateDirectory: f.directory, ...extra,
    })).status, "blocked");
    assert.equal(locked(), false);
  });
  await t.test("no native host => blocked before ledger lock", async () => {
    reset();
    const f = buildFixture();
    const prior = os.release;
    os.release = () => "6.18.33.1-microsoft-standard-WSL2";
    try {
      assert.equal((await coordinateTrustedOfflineRelease({ candidateDirectory: f.directory })).status, "blocked");
      assert.equal(locked(), false);
    } finally { os.release = prior; }
  });
  await t.test("one signed attempt imports BOTH images from detached FDs despite an in-place rewrite", async () => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t);
    const original = readFileSync(path.join(f.directory, "runtime.tar"));
    const originalMigrator = readFileSync(path.join(f.directory, "migrator.tar"));
    writeFileSync(path.join(endpoint, "mutate-source"), path.join(f.directory, "runtime.tar"));
    const result = await importApprovedOfflineImages({ candidateDirectory: f.directory });
    assert.equal(result.status, "IMPORTED_BOTH_UNTAGGED_ATTEMPT_LOCKED");
    assert.deepEqual(result.imageIds, [f.runtime.image_id, f.migrator.image_id]);
    assert.equal(result.dockerTagAuthorized, false);
    assert.equal(result.deployAuthorized, false);
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
    assert.deepEqual(readFileSync(path.join(endpoint, "consumed.sha256"), "utf8").trim().split("\n"),
      [hash(original), hash(originalMigrator)]);
    assert.notEqual(hash(readFileSync(path.join(f.directory, "runtime.tar"))), hash(original),
      "attacker actually overwrote the original TAR before Docker read its inherited FD");
    assert.deepEqual(readdirSync(path.join(FIXED, "offline-import-quarantine")), []);
    const calls = readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n");
    assert.equal(calls.length, 7);
    assert.equal(calls.every((line) => !/\bimage (?:tag|run|start|push)\b/u.test(line)), true);
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status,
      "blocked", "same reserved attempt cannot re-import after mutation or partial work");
    assert.equal((await importApprovedOfflineImage({ candidateDirectory: f.directory, role: "runtime" })).status,
      "blocked", "legacy single-role callers are always forbidden");
  });
  await t.test("invalid owner signature blocks all Docker image operations and ledger mutation", async () => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t);
    const signaturePath = path.join(f.directory, "signatures.json");
    const envelope = JSON.parse(readFileSync(signaturePath, "utf8"));
    writeJson(signaturePath, { ...envelope, owner: envelope.builder });
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    assert.deepEqual(readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n")
      .map((call) => call.includes(" version --format")), [true]);
  });
  await t.test("unreachable dedicated daemon refuses before consuming owner approval or attempted lock", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync(path.join(endpoint, "daemon-unavailable"), "1");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    assert.deepEqual(readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n")
      .map((call) => call.includes(" version --format")), [true]);
  });
  await t.test("daemon transport failure is not mistaken for a missing image", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync(path.join(endpoint, "inspect-error"), "1");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), true, "authenticated attempt remains latched after failed daemon precondition");
    assert.equal(existsSync(path.join(endpoint, "consumed.sha256")), false);
  });
  await t.test("post-load Docker identity mismatch denies acceptance, leaves exclusive attempt lock and no tag", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync(path.join(endpoint, "wrong-inspect"), "1");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
    assert.equal(existsSync(path.join(endpoint, "consumed.sha256")), true);
    const calls = readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n");
    assert.equal(calls.length, 6);
    assert.equal(calls.every((line) => !/\bimage (?:tag|run|start|push)\b/u.test(line)), true);
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n").length, 7);
  });
  await t.test("failed Docker load leaves attempted lock, no image acceptance and no second import", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync(path.join(endpoint, "fail-load"), "1");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), true);
    assert.equal(state().entries.length, 0);
    assert.equal(existsSync(path.join(endpoint, "consumed.sha256")), true);
    assert.equal(existsSync(path.join(endpoint, "loaded.json")), false);
    assert.deepEqual(readdirSync(path.join(FIXED, "offline-import-quarantine")), []);
    const before = readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n");
    assert.equal(before.length, 4, "one health probe, two negative inspect proofs and failed load");
    assert.equal(before.every((line) => !/\bimage (?:tag|run|start|push)\b/u.test(line)), true);
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n").length,
      before.length + 1, "retry only probes daemon health before existing ledger lock denies");
  });
  await t.test("second-image Docker load failure retains attempt lock and first image isolated", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync(path.join(endpoint, "fail-second-load"), "1");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), true);
    assert.deepEqual(readFileSync(path.join(endpoint, "consumed.sha256"), "utf8").trim().split("\n"),
      [f.runtime.archive_sha256, f.migrator.archive_sha256]);
    assert.equal(JSON.parse(readFileSync(path.join(endpoint, "loaded.json"), "utf8")).length, 1);
    assert.deepEqual(readdirSync(path.join(FIXED, "offline-import-quarantine")), []);
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
  });
  await t.test("an in-place modified signed TAR cannot reach Docker or reserve admission", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    const archive = path.join(f.directory, "runtime.tar");
    const changed = readFileSync(archive);
    changed[changed.length - 1] ^= 1;
    writeFileSync(archive, changed);
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    assert.deepEqual(readFileSync(path.join(endpoint, "calls"), "utf8").trim().split("\n")
      .map((call) => call.includes(" version --format")), [true]);
  });
  await t.test("a mutated or unpinned Docker executable cannot reserve an attempt or execute", async (t2) => {
    reset();
    const f = buildFixture();
    const endpoint = await setupIsolatedImportSink(t2);
    writeFileSync("/etc/virki/offline-import-cli.sha256", "f".repeat(64) + "\n");
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    assert.equal(existsSync(path.join(endpoint, "calls")), false);
    writeFileSync("/etc/virki/offline-import-cli.sha256",
      hash(readFileSync(path.join(endpoint, "docker"))) + "\n");
    writeFileSync(path.join(endpoint, "docker"), Buffer.concat([
      readFileSync(path.join(endpoint, "docker")), Buffer.from("\n// attacker mutation\n"),
    ]));
    assert.equal((await importApprovedOfflineImages({ candidateDirectory: f.directory })).status, "blocked");
    assert.equal(locked(), false);
    assert.equal(existsSync(path.join(endpoint, "calls")), false);
  });
  await t.test("caller cannot supply signed identity, docker path, host or fake admission", async () => {
    for (const payload of [
      { candidateDirectory: "/tmp/untrusted", role: "runtime", dockerExecutable: "/tmp/evil" },
      { candidateDirectory: "/tmp/untrusted", role: "runtime", approved: true },
      { candidateDirectory: "/tmp/untrusted", role: "runtime", expectedArchiveSha256: "f".repeat(64) },
      { candidateDirectory: "/tmp/untrusted", role: "runtime", dockerHost: "unix:///var/run/docker.sock" },
    ]) {
      assert.equal((await importApprovedOfflineImages(payload)).status, "blocked");
    }
  });
});
