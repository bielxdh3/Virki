import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { approvalSigningPayload, verifySoleAdminApprovalBundle } from "./lib/sole-admin-approval.mjs";

const NOW = new Date("2026-11-06T18:05:00.000Z");
const expected = Object.freeze({
  environment: "staging",
  deploymentRef: "virki-staging-instance-20261106",
  targetUserId: "cstagingsoleadmin123",
  targetEmailSha256: "a".repeat(64),
  sourceRevision: "f".repeat(40),
  backupSha256: "b".repeat(64),
  credentialKeyVersion: 7
});

function fixture() {
  const owner = generateKeyPairSync("ed25519");
  const reviewer = generateKeyPairSync("ed25519");
  const request = {
    schema: "virki-sole-admin-recovery-review-v1",
    action: "REVIEW_SEPARATE_ADMIN_CREDENTIAL_RECOVERY_ONLY",
    incidentId: "INC-20261106-ADMIN-01",
    ...expected,
    nonce: "e".repeat(32),
    issuedAt: "2026-11-06T18:00:00.000Z",
    expiresAt: "2026-11-06T18:30:00.000Z"
  };
  const registry = {
    schema: "virki-independent-approver-registry-v1",
    environment: "staging",
    deploymentRef: expected.deploymentRef,
    approvers: [
      { keyId: "owner-2026", role: "OWNER", publicKeyPem: owner.publicKey.export({ type: "spki", format: "pem" }) },
      { keyId: "reviewer-2026", role: "INDEPENDENT_REVIEWER", publicKeyPem: reviewer.publicKey.export({ type: "spki", format: "pem" }) }
    ]
  };
  const registryBytes = Buffer.from(JSON.stringify(registry), "utf8");
  const expectedRegistrySha256 = createHash("sha256").update(registryBytes).digest("hex");
  const approval = (keyId, key) => ({ keyId, signature: sign(null, approvalSigningPayload(request), key).toString("base64url") });
  const bundle = { request, approvals: [approval("owner-2026", owner.privateKey), approval("reviewer-2026", reviewer.privateKey)] };
  const verify = (changes = {}) => verifySoleAdminApprovalBundle({ bundle, registryBytes, expectedRegistrySha256, expected, now: NOW, ...changes });
  return { owner, reviewer, request, registry, registryBytes, expectedRegistrySha256, approval, bundle, verify };
}

test("accepts two distinct pinned, signed, short-lived review approvals", () => {
  const value = fixture().verify();
  assert.equal(value.valid, true);
  assert.equal(value.incidentId, "INC-20261106-ADMIN-01");
  assert.equal(value.permitsCredentialMutation, false);
  assert.equal(value.requiresIndependentHumanVerification, true);
  assert.equal(value.approvers.length, 2);
});

test("fails closed if the trusted approver registry fingerprint is not pinned", () => {
  const f = fixture();
  assert.throws(() => f.verify({ expectedRegistrySha256: undefined }));
  assert.throws(() => f.verify({ expectedRegistrySha256: "0".repeat(64) }));
  assert.throws(() => f.verify({ registryBytes: Buffer.concat([f.registryBytes, Buffer.from(" ")]) }));
});

test("rejects unrelated or duplicated signers", () => {
  const f = fixture();
  f.bundle.approvals[1] = f.approval("owner-2026", f.owner.privateKey);
  assert.throws(() => f.verify());
});

test("rejects a second key ID backed by the same Ed25519 public key", () => {
  const f = fixture();
  f.registry.approvers[1].publicKeyPem = f.registry.approvers[0].publicKeyPem;
  const registryBytes = Buffer.from(JSON.stringify(f.registry));
  assert.throws(() => f.verify({ registryBytes, expectedRegistrySha256: createHash("sha256").update(registryBytes).digest("hex") }));
});

test("rejects a valid signature made by a key with the wrong assigned role", () => {
  const f = fixture();
  f.bundle.approvals[0] = f.approval("reviewer-2026", f.reviewer.privateKey);
  f.bundle.approvals[1] = f.approval("owner-2026", f.owner.privateKey);
  // Order does not convey role; both unique valid signatures still pass.
  assert.equal(f.verify().valid, true);
  f.registry.approvers[1].role = "OWNER";
  const registryBytes = Buffer.from(JSON.stringify(f.registry));
  assert.throws(() => f.verify({ registryBytes, expectedRegistrySha256: createHash("sha256").update(registryBytes).digest("hex") }));
});

test("rejects modification of signed target, version, action or backup", () => {
  for (const [key, value] of [
    ["targetUserId", "canotheradmin987654"],
    ["credentialKeyVersion", 8],
    ["action", "CREATE_ADMIN"],
    ["backupSha256", "c".repeat(64)],
    ["nonce", "d".repeat(32)]
  ]) {
    const f = fixture();
    f.bundle.request[key] = value;
    assert.throws(() => f.verify(), `must reject changed ${key}`);
  }
});

test("rejects mismatched externally expected environment, target and revision", () => {
  for (const [key, value] of [
    ["environment", "production"], ["deploymentRef", "virki-other-env"],
    ["targetUserId", "canotheradmin987654"], ["targetEmailSha256", "d".repeat(64)],
    ["sourceRevision", "0".repeat(40)], ["backupSha256", "c".repeat(64)],
    ["credentialKeyVersion", 3]
  ]) {
    const f = fixture();
    assert.throws(() => f.verify({ expected: { ...expected, [key]: value } }), `must reject ${key}`);
  }
});

test("rejects forged signatures, unknown keys, missing approvals and unexpected fields", () => {
  const scenarios = [
    (f) => { f.bundle.approvals[0].signature = "A".repeat(86); },
    (f) => { f.bundle.approvals[0].keyId = "unregistered"; },
    (f) => { f.bundle.approvals.pop(); },
    (f) => { f.bundle.approvals.push(f.bundle.approvals[0]); },
    (f) => { f.bundle.request.extra = "anything"; },
    (f) => { f.bundle.extra = "anything"; },
    (f) => { f.bundle.approvals[0].extra = "anything"; }
  ];
  for (const change of scenarios) { const f = fixture(); change(f); assert.throws(() => f.verify()); }
});

test("rejects expired, not-yet-issued, malformed or too-long approval windows", () => {
  const f = fixture();
  assert.throws(() => f.verify({ now: new Date("2026-11-06T18:30:00.000Z") }));
  assert.throws(() => f.verify({ now: new Date("2026-11-06T17:59:59.000Z") }));
  for (const [key, value] of [["issuedAt", "bad"], ["expiresAt", "2026-11-08T18:30:00.000Z"]]) {
    const g = fixture(); g.bundle.request[key] = value; assert.throws(() => g.verify());
  }
});

test("fails for malformed registry, invalid Ed25519 keys and unexpected trust entries", () => {
  for (const change of [
    (r) => { r.schema = "unrecognized"; },
    (r) => { r.approvers[0].publicKeyPem = "not-a-key"; },
    (r) => { r.approvers[0].extra = "anything"; },
    (r) => { r.approvers.push(r.approvers[0]); }
  ]) {
    const f = fixture(); change(f.registry);
    const registryBytes = Buffer.from(JSON.stringify(f.registry));
    assert.throws(() => f.verify({ registryBytes, expectedRegistrySha256: createHash("sha256").update(registryBytes).digest("hex") }));
  }
});

test("offline CLI validates a signed bundle but never authorizes mutation or discloses identities", () => {
  const f = fixture();
  const current = Date.now();
  f.request.issuedAt = new Date(current - 60_000).toISOString();
  f.request.expiresAt = new Date(current + 20 * 60_000).toISOString();
  f.bundle.approvals = [f.approval("owner-2026", f.owner.privateKey), f.approval("reviewer-2026", f.reviewer.privateKey)];
  const directory = mkdtempSync(join(tmpdir(), "virki-sole-admin-review-test-"));
  try {
    const bundleFile = join(directory, "bundle.json");
    const registryFile = join(directory, "registry.json");
    const expectedFile = join(directory, "expected.json");
    writeFileSync(bundleFile, JSON.stringify(f.bundle));
    writeFileSync(registryFile, f.registryBytes);
    writeFileSync(expectedFile, JSON.stringify(expected));
    const argv = ["scripts/sole-admin-approval-verify.mjs", "--bundle", bundleFile, "--registry", registryFile, "--registry-sha256", f.expectedRegistrySha256, "--expected", expectedFile];
    const good = spawnSync(process.execPath, argv, { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /REVIEW_SIGNATURES_VALID request_sha256=[a-f0-9]{64}/);
    assert.match(good.stdout, /NO_CREDENTIAL_MUTATION_AUTHORIZED/);
    assert.doesNotMatch(good.stdout + good.stderr, /cstagingsoleadmin123|owner-2026|reviewer-2026/);
    const rejected = spawnSync(process.execPath, argv.filter((_, i) => i !== 5 && i !== 6), { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /REVIEW_SIGNATURES_REJECTED/);
    assert.doesNotMatch(rejected.stderr, /cstagingsoleadmin123|owner-2026|reviewer-2026/);

    // A JSON parser accepting duplicate keys could present a different target
    // than a human saw in the evidence. Refuse ambiguous representations.
    writeFileSync(bundleFile, JSON.stringify(f.bundle).replace('{"request":', '{"request":null,"request":'));
    const ambiguousBundle = spawnSync(process.execPath, argv, { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    assert.notEqual(ambiguousBundle.status, 0, "must reject a duplicated JSON request key");
    const duplicatedTarget = JSON.stringify(f.bundle).replace('"targetUserId":"cstagingsoleadmin123",', '"targetUserId":"cwrongvisibleaccount","targetUserId":"cstagingsoleadmin123",');
    assert.notEqual(duplicatedTarget, JSON.stringify(f.bundle), "the adversarial fixture must include duplicate target fields");
    writeFileSync(bundleFile, duplicatedTarget);
    const ambiguousTarget = spawnSync(process.execPath, argv, { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    assert.notEqual(ambiguousTarget.status, 0, "must reject a duplicated JSON targetUserId field");
    writeFileSync(bundleFile, JSON.stringify(f.bundle));
    writeFileSync(expectedFile, JSON.stringify(expected).replace('{"environment":', '{"environment":"production","environment":'));
    const ambiguousExpected = spawnSync(process.execPath, argv, { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8" });
    assert.notEqual(ambiguousExpected.status, 0, "must reject a duplicated JSON environment key");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("review-only implementation has no database, secret-reading, auth or network imports", () => {
  const p = fileURLToPath(new URL("./lib/sole-admin-approval.mjs", import.meta.url));
  const source = readFileSync(p, "utf8");
  assert.doesNotMatch(source, /@virki\/database|prisma|\.\$transaction|https?:|fetch\(|exec\(|spawn\(/);
});
