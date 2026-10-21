import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { encodeCanonicalOfflineReleaseManifest } from "./lib/offline-release-attestation.mjs";
import { prepareVerifiedOfflineTransportPlan, validateOfflineSshConfiguration } from "./offline-production-transport.mjs";

const sha = (s) => s.repeat(40);
const digest = (s) => s.repeat(64);
const hash = (b) => createHash("sha256").update(b).digest("hex");
const revision = sha("a");
const predecessor = sha("b");
const hostIdentity = digest("9");
const now = Math.floor(Date.now() / 1000);
const nativeLinux = process.platform === "linux";
const STAGES = [
  "tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check",
];
function claimedCi() {
  const start = Date.parse("2026-10-21T14:00:00.000Z");
  return {
    runId: "e5f8bc3d5c", sourceBranch: "main", sourceHead: revision,
    startedUtc: new Date(start).toISOString(),
    finishedUtc: new Date(start + 300_000).toISOString(),
    nodeVersion: "v22.23.3", npmVersion: "10.9.9",
    stagedPatchSha256: hash(""), workingTreePatchSha256: hash(""),
    untrackedFiles: [], exitCode: 0, failedStages: [],
    unitTestsFailureCount: 0, unitTestsFailures: [],
    integrationTestsFailureCount: 0, integrationTestsFailures: [],
    productionOperationsFailureCount: 0, productionOperationsFailures: [],
    stages: STAGES.map((name, i) => ({
      name, startedUtc: new Date(start + i * 10_000 + 1000).toISOString(),
      finishedUtc: new Date(start + i * 10_000 + 2000).toISOString(),
      durationMs: 1000, exitCode: 0,
    })),
  };
}
function fixture(t) {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-transport-test-"));
  chmodSync(base, 0o700);
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const candidateDirectory = path.join(base, "candidate");
  const trustedDirectory = path.join(base, "trusted");
  const repositoryRoot = path.join(base, "repo");
  mkdirSync(candidateDirectory, { mode: 0o700 });
  mkdirSync(trustedDirectory, { mode: 0o700 });
  mkdirSync(repositoryRoot, { mode: 0o700 });
  const files = {
    "source.tar": Buffer.alloc(1024, 1),
    "runtime.tar": Buffer.alloc(1024, 2),
    "migrator.tar": Buffer.alloc(1024, 3),
    "ci-report.json": Buffer.from(JSON.stringify(claimedCi())),
    "scanner-report.json": Buffer.from('{"test":true}'),
    "finding-review.json": Buffer.from('{"test":true}'),
    "runtime-smoke.json": Buffer.from('{"test":true}'),
    "migrator-smoke.json": Buffer.from('{"test":true}'),
    "backup-restore.json": Buffer.from('{"test":true}'),
  };
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(path.join(candidateDirectory, name), contents, { flag: "wx", mode: 0o600 });
  }
  const builder = generateKeyPairSync("ed25519");
  const owner = generateKeyPairSync("ed25519");
  const pin = ({ publicKey }, keyId) => ({
    keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: hash(publicKey.export({ type: "spki", format: "der" })),
  });
  const manifest = {
    version: 1, release_gate: "OWNER_APPROVED_OFFLINE_SIGNED_AMD64_V1",
    repository: "https://github.com/bielxdh3/Virki.git",
    source_sha: revision, source_archive_sha256: hash(files["source.tar"]),
    source_archive_size_bytes: files["source.tar"].length, platform: "linux/amd64",
    host_identity_sha256: hostIdentity, predecessor_sha: predecessor,
    runtime_image: { archive_sha256: hash(files["runtime.tar"]), archive_size_bytes: files["runtime.tar"].length, image_id: "sha256:" + digest("1") },
    migrator_image: { archive_sha256: hash(files["migrator.tar"]), archive_size_bytes: files["migrator.tar"].length, image_id: "sha256:" + digest("2") },
    evidence: {
      ci_report_sha256: hash(files["ci-report.json"]),
      scanner_report_sha256: hash(files["scanner-report.json"]),
      scanner_rules_commit: sha("c"),
      finding_review_sha256: hash(files["finding-review.json"]),
      runtime_smoke_sha256: hash(files["runtime-smoke.json"]),
      migrator_smoke_sha256: hash(files["migrator-smoke.json"]),
      backup_restore_sha256: hash(files["backup-restore.json"]),
    },
    issued_at: now - 100, expires_at: now + 1000,
    nonce: "d".repeat(32), sequence: 1,
  };
  const bytes = encodeCanonicalOfflineReleaseManifest(manifest);
  const signatures = {
    builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), bytes]), builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"), Buffer.from(hash(bytes), "hex")]), owner.privateKey).toString("base64"),
  };
  writeFileSync(path.join(candidateDirectory, "manifest.json"), bytes, { flag: "wx", mode: 0o600 });
  writeFileSync(path.join(candidateDirectory, "signatures.json"), JSON.stringify(signatures), { flag: "wx", mode: 0o600 });
  const policy = {
    version: 2, mode: "offline-signed-v1", enabled: true, ownerAssuranceAccepted: true,
    hostIdentitySha256: hostIdentity, ledgerAnchorSha: predecessor, platform: "linux/amd64",
    builder: pin(builder, "builder-test-2026"), owner: pin(owner, "owner-test-2026"),
    revokedKeyIds: [], revokedPinsSha256: [],
  };
  const operator = {
    version: 1, mode: "offline-signed-v1", enabled: true, expectedRevision: revision,
    sshAlias: "virki-prod", host: "virki.example.test", port: 2222, root: "/srv/virki",
    knownHostsSha256: "", runtimeExpandedBytes: 6 * 1024 ** 3,
    migratorExpandedBytes: 5 * 1024 ** 3, databaseBytes: 4 * 1024 ** 3,
  };
  const knownHosts = Buffer.from("[virki.example.test]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB8t6CnF3Qj4Khd7mmYhjUhTKiiMQ8EoPtWxgUux7e4\n");
  operator.knownHostsSha256 = hash(knownHosts);
  const ledger = { version: 1, anchorSha: predecessor, entries: [] };
  for (const [name, contents] of Object.entries({
    "trust-policy.json": Buffer.from(JSON.stringify(policy)),
    "ledger.json": Buffer.from(JSON.stringify(ledger)),
    "transport-policy.json": Buffer.from(JSON.stringify(operator)),
    "ssh-known-hosts": knownHosts,
  })) writeFileSync(path.join(trustedDirectory, name), contents, { flag: "wx", mode: 0o600 });
  return { base, candidateDirectory, trustedDirectory, repositoryRoot, files, manifest,
    policy, operator, knownHosts, builder, owner };
}

function replaceSignedCi(f, rawCi) {
  writeFileSync(path.join(f.candidateDirectory, "ci-report.json"), rawCi);
  const manifest = structuredClone(f.manifest);
  manifest.evidence.ci_report_sha256 = hash(rawCi);
  const bytes = encodeCanonicalOfflineReleaseManifest(manifest);
  const signatures = {
    builder: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_BUILDER_MANIFEST_V1\0"), bytes]),
      f.builder.privateKey).toString("base64"),
    owner: sign(null, Buffer.concat([Buffer.from("VIRKI_OFFLINE_OWNER_APPROVAL_V1\0"), Buffer.from(hash(bytes), "hex")]),
      f.owner.privateKey).toString("base64"),
  };
  writeFileSync(path.join(f.candidateDirectory, "manifest.json"), bytes);
  writeFileSync(path.join(f.candidateDirectory, "signatures.json"), JSON.stringify(signatures));
}

test("SSH policy rejects unsafe settings and host mismatches before remote actions", () => {
  const config = { sshAlias: "virki-prod", host: "virki.example.test", port: 2222, root: "/srv/virki" };
  const ssh = "hostname virki.example.test\nport 2222\nuser debian\nstricthostkeychecking yes\nproxycommand none\nproxyjump none\n";
  assert.equal(validateOfflineSshConfiguration(ssh, config).hostname, config.host);
  for (const bad of [
    ssh.replace("yes", "no"),
    ssh.replace("2222", "22"),
    ssh.replace("virki.example.test", "attacker.example"),
    ssh.replace("proxycommand none", "proxycommand sh -c evil"),
    ssh.replace("user debian", "user "),
    ssh.replace("proxyjump none", "proxyjump attacker"),
  ]) assert.throws(() => validateOfflineSshConfiguration(bad, config));
});

test("complete owner-signed candidate with 19 claimed stages reaches strict Git gate, never SSH on a non-repository", async (t) => {
  if (!nativeLinux) return t.skip("Linux protected test fixtures required");
  const f = fixture(t);
  await assert.rejects(prepareVerifiedOfflineTransportPlan({
    candidateDirectory: f.candidateDirectory,
    trustedDirectory: f.trustedDirectory,
    repositoryRoot: f.repositoryRoot,
  }), /Production command failed/iu);
});

test("even newly re-signed local CI with failed stage is refused before Git or SSH", async (t) => {
  if (!nativeLinux) return t.skip("Linux protected test fixtures required");
  const f = fixture(t);
  const fakeCi = claimedCi();
  fakeCi.stages[12].exitCode = 1;
  replaceSignedCi(f, Buffer.from(JSON.stringify(fakeCi)));
  await assert.rejects(prepareVerifiedOfflineTransportPlan({
    candidateDirectory: f.candidateDirectory,
    trustedDirectory: f.trustedDirectory,
    repositoryRoot: f.repositoryRoot,
  }), /Invalid offline CI manifest.*stage 13/iu);
});

test("fails closed for missing independently protected inputs (no SSH and no deploy)", async (t) => {
  if (!nativeLinux) return t.skip("POSIX protected trust policy requires Linux");
  const fixtureValue = fixture(t);
  for (const inputs of [
    {},
    { candidateDirectory: fixtureValue.candidateDirectory },
    { candidateDirectory: fixtureValue.candidateDirectory, repositoryRoot: fixtureValue.repositoryRoot },
    { candidateDirectory: fixtureValue.candidateDirectory, trustedDirectory: fixtureValue.candidateDirectory, repositoryRoot: fixtureValue.repositoryRoot },
  ]) {
    await assert.rejects(prepareVerifiedOfflineTransportPlan(inputs));
  }
});

test("fails closed on altered owner pin or revoked owner key before contacting a host", async (t) => {
  if (!nativeLinux) return t.skip("POSIX root-protected fixture requires Linux");
  const f = fixture(t);
  const p = path.join(f.trustedDirectory, "trust-policy.json");
  const original = readFileSync(p);
  for (const mutation of [
    (data) => { data.owner.pinSha256 = digest("f"); },
    (data) => { data.revokedPinsSha256 = [data.owner.pinSha256]; },
    (data) => { data.revokedKeyIds = [data.owner.keyId]; },
    (data) => { data.ownerAssuranceAccepted = false; },
    (data) => { data.hostIdentitySha256 = digest("0"); },
  ]) {
    const data = JSON.parse(original);
    mutation(data);
    writeFileSync(p, JSON.stringify(data));
    await assert.rejects(prepareVerifiedOfflineTransportPlan({
      candidateDirectory: f.candidateDirectory, trustedDirectory: f.trustedDirectory,
      repositoryRoot: f.repositoryRoot,
    }), /key|revoked|accepted|host marker mismatch/iu);
  }
});

test("rejects mismatched candidate SHA, missing signature, changed evidence and untrusted extra policy files", async (t) => {
  if (!nativeLinux) return t.skip("Linux-only staged candidate inspector");
  const f = fixture(t);
  const request = { candidateDirectory: f.candidateDirectory, trustedDirectory: f.trustedDirectory, repositoryRoot: f.repositoryRoot };
  const manifestFile = path.join(f.candidateDirectory, "manifest.json");
  const original = readFileSync(manifestFile);
  writeFileSync(manifestFile, Buffer.from(original.toString("utf8").replace(revision, sha("f"))));
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
  writeFileSync(manifestFile, original);
  const report = path.join(f.candidateDirectory, "scanner-report.json");
  const saved = readFileSync(report);
  writeFileSync(report, '{"tampered":true}');
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
  writeFileSync(report, saved);
  writeFileSync(path.join(f.candidateDirectory, "trust-policy.json"), JSON.stringify(f.policy), { flag: "wx" });
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
});

test("rejects private trust folder symlink/hardlink, foreign repo root and operator policy substitution", async (t) => {
  if (!nativeLinux) return t.skip("POSIX protected trust root required");
  const f = fixture(t);
  const request = { candidateDirectory: f.candidateDirectory, trustedDirectory: f.trustedDirectory, repositoryRoot: f.repositoryRoot };
  const alias = path.join(f.base, "alias");
  symlinkSync(f.trustedDirectory, alias, "dir");
  await assert.rejects(prepareVerifiedOfflineTransportPlan({ ...request, trustedDirectory: alias }));
  const file = path.join(f.trustedDirectory, "ssh-known-hosts");
  const copy = path.join(f.base, "linked-hosts");
  linkSync(file, copy);
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
  rmSync(copy);
  const policy = path.join(f.trustedDirectory, "transport-policy.json");
  const saved = readFileSync(policy);
  writeFileSync(policy, JSON.stringify({ ...f.operator, expectedRevision: sha("f") }));
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
  writeFileSync(policy, saved);
});

test("separately protected host-key pin, revision and capacity estimates cannot be omitted or forged", async (t) => {
  if (!nativeLinux) return t.skip("Linux-only owner-protected trust required");
  const f = fixture(t);
  const request = {
    candidateDirectory: f.candidateDirectory,
    trustedDirectory: f.trustedDirectory,
    repositoryRoot: f.repositoryRoot,
  };
  const policyFile = path.join(f.trustedDirectory, "transport-policy.json");
  for (const change of [
    { knownHostsSha256: digest("0") },
    { runtimeExpandedBytes: 0 },
    { databaseBytes: 0 },
    { expectedRevision: sha("f") },
    { sshAlias: "-oProxyCommand=evil" },
    { root: "/srv/../demanage" },
    { enabled: false },
  ]) {
    writeFileSync(policyFile, JSON.stringify({ ...f.operator, ...change }));
    await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
  }
});

test("absent owner signature and omitted candidate file fail before Git or SSH", async (t) => {
  if (!nativeLinux) return t.skip("Linux-only signed staging required");
  const f = fixture(t);
  const request = {
    candidateDirectory: f.candidateDirectory,
    trustedDirectory: f.trustedDirectory,
    repositoryRoot: f.repositoryRoot,
  };
  rmSync(path.join(f.candidateDirectory, "signatures.json"));
  await assert.rejects(prepareVerifiedOfflineTransportPlan(request));
});

test("no one-step transfer, Docker load, untrusted source execution or GHCR command is exposed", () => {
  const local = spawnSync(process.execPath, [new URL("./offline-production-transport.mjs", import.meta.url).pathname], {
    encoding: "utf8", timeout: 4000,
  });
  assert.notEqual(local.status, 0);
  assert.doesNotMatch(local.stdout, /deployAuthorized.*true|transferAuthorized.*true|deployed/iu);
});
