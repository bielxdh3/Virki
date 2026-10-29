import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  AUDITED_VERIFIER_FILES,
  assertIndependentVerifierRoots,
  inspectAuditedVerifierFiles,
  prepareTrustedVerifierPinSet,
  previewTrustedHostVerifierProvisioning,
} from "./trusted-host-installer.mjs";
import { TRUSTED_OFFLINE_STAGING_PATH } from "./trusted-image-loader.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const sha = (char) => char.repeat(40);
const digest = (char) => char.repeat(64);

function publicEntry(keyId) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  return {
    keyId, publicKeyPem,
    pinSha256: hash(publicKey.export({ type: "spki", format: "der" })),
  };
}

function setup(t) {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-verifier-preview-"));
  const sourceDirectory = path.join(base, "source");
  const operatorDirectory = path.join(base, "operator");
  mkdirSync(sourceDirectory, { mode: 0o700 });
  mkdirSync(operatorDirectory, { mode: 0o700 });
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const files = AUDITED_VERIFIER_FILES.map((relativePath, index) => {
    const pathname = path.join(sourceDirectory, ...relativePath.split("/"));
    mkdirSync(path.dirname(pathname), { recursive: true, mode: 0o700 });
    const bytes = Buffer.from(`// audited fixture ${index}\n`);
    writeFileSync(pathname, bytes, { mode: 0o600 });
    return { path: relativePath, sha256: hash(bytes) };
  });
  const hostIdentity = digest("a");
  const policy = {
    version: 2, mode: "offline-signed-v1", enabled: true,
    ownerAssuranceAccepted: true, hostIdentitySha256: hostIdentity,
    ledgerAnchorSha: sha("1"), platform: "linux/amd64",
    builder: publicEntry("builder-1"), owner: publicEntry("owner-1"),
    revokedKeyIds: [], revokedPinsSha256: [],
  };
  const ledger = { version: 1, anchorSha: sha("1"), entries: [] };
  const policyBytes = Buffer.from(JSON.stringify(policy));
  const ledgerBytes = Buffer.from(JSON.stringify(ledger));
  const pins = {
    version: 1, mode: "independent-native-verifier-pins-v1",
    files, trustPolicySha256: hash(policyBytes), ledgerSha256: hash(ledgerBytes),
  };
  const pinsBytes = Buffer.from(JSON.stringify(pins));
  for (const [name, bytes] of [
    ["verifier-pins.json", pinsBytes],
    ["trust-policy.json", policyBytes],
    ["ledger.json", ledgerBytes],
  ]) writeFileSync(path.join(operatorDirectory, name), bytes, { mode: 0o600 });
  return {
    base, sourceDirectory, operatorDirectory, files, hostIdentity,
    pins, pinsBytes, policyBytes, ledgerBytes,
  };
}

test("a complete external audit pin set accepts distinct v2 owner/builder keys and exact protected policy/ledger bytes", (t) => {
  const f = setup(t);
  const result = prepareTrustedVerifierPinSet({
    pinsBytes: f.pinsBytes, policyBytes: f.policyBytes,
    ledgerBytes: f.ledgerBytes, measuredHostIdentitySha256: f.hostIdentity,
  });
  assert.equal(result.status, "INDEPENDENT_PINS_PARSED_ONLY");
  assert.deepEqual(result.files, f.files);
  assert.equal(result.hostIdentitySha256, f.hostIdentity);
  assert.equal(Object.hasOwn(result, "deployAuthorized"), false);
  assert.equal(Object.hasOwn(result, "installAuthorized"), false);
});

test("operator-protected pin bytes cannot omit, duplicate, reorder or replace an audited verifier dependency", (t) => {
  const f = setup(t);
  const previousInventory = f.files.filter((entry) => ![
    "infra/offline/trusted-image-import.mjs",
    "infra/offline/trusted-manual-source.mjs",
    "infra/offline/trusted-release-coordinator.mjs",
    "scripts/lib/offline-ci-evidence.mjs",
    "scripts/lib/offline-release-ledger.mjs",
  ].includes(entry.path));
  assert.equal(previousInventory.length, 8,
    "the predecessor pin inventory was exactly eight audited modules");
  const bad = [
    // Reject valid old-format pin sets after expanding the authority graph.
    { ...f.pins, files: previousInventory },
    { ...f.pins, files: f.files.filter((entry) => entry.path !== "infra/offline/trusted-image-import.mjs") },
    { ...f.pins, files: f.files.slice(1) },
    { ...f.pins, files: [...f.files.slice(0, -1), f.files[0]] },
    { ...f.pins, files: [...f.files].reverse() },
    { ...f.pins, files: f.files.map((v, i) => i === 0 ? { path: "../malicious.mjs", sha256: v.sha256 } : v) },
    { ...f.pins, files: f.files.map((v, i) => i === 0 ? { ...v, sha256: digest("f") } : v),
      trustPolicySha256: digest("f") },
    { ...f.pins, extra: "allow-install" },
    { ...f.pins, version: 0 },
  ];
  for (const pins of bad) {
    assert.throws(() => prepareTrustedVerifierPinSet({
      pinsBytes: Buffer.from(JSON.stringify(pins)),
      policyBytes: f.policyBytes, ledgerBytes: f.ledgerBytes,
      measuredHostIdentitySha256: f.hostIdentity,
    }));
  }
});

test("policy trust cannot be asserted by an unreviewed or revoked owner, mismatched host, or altered ledger", (t) => {
  const f = setup(t);
  const policy = JSON.parse(f.policyBytes);
  for (const change of [
    { ownerAssuranceAccepted: false },
    { hostIdentitySha256: digest("b") },
    { revokedKeyIds: [policy.owner.keyId] },
    { revokedPinsSha256: [policy.builder.pinSha256] },
    { owner: policy.builder },
    { version: 1 },
  ]) {
    const raw = Buffer.from(JSON.stringify({ ...policy, ...change }));
    const pins = { ...f.pins, trustPolicySha256: hash(raw) };
    assert.throws(() => prepareTrustedVerifierPinSet({
      pinsBytes: Buffer.from(JSON.stringify(pins)), policyBytes: raw,
      ledgerBytes: f.ledgerBytes, measuredHostIdentitySha256: f.hostIdentity,
    }));
  }
  const modifiedLedger = Buffer.from(JSON.stringify({ version: 1, anchorSha: sha("2"), entries: [] }));
  assert.throws(() => prepareTrustedVerifierPinSet({
    pinsBytes: Buffer.from(JSON.stringify({ ...f.pins, ledgerSha256: hash(modifiedLedger) })),
    policyBytes: f.policyBytes, ledgerBytes: modifiedLedger,
    measuredHostIdentitySha256: f.hostIdentity,
  }));
});

test("strict JSON refuses duplicate keys, noncanonical encoding and self-asserted installation overrides", (t) => {
  const f = setup(t);
  for (const pinsBytes of [
    Buffer.from('{"version":1,"version":1}'),
    Buffer.from(" " + f.pinsBytes.toString("utf8")),
    Buffer.from([0xc3, 0x28]),
    Buffer.alloc(100000, 0x20),
    Buffer.from(JSON.stringify({ ...f.pins, deployAuthorized: true })),
  ]) assert.throws(() => prepareTrustedVerifierPinSet({
    pinsBytes, policyBytes: f.policyBytes, ledgerBytes: f.ledgerBytes,
    measuredHostIdentitySha256: f.hostIdentity,
  }));
});

test("source inspector measures every separately pinned verifier file without execution", (t) => {
  const f = setup(t);
  const result = inspectAuditedVerifierFiles({ sourceDirectory: f.sourceDirectory, files: f.files });
  assert.equal(result.status, "AUDITED_SOURCE_BYTES_MATCH_ONLY");
  assert.deepEqual(result.files, f.files);
  assert.equal(result.files.length, AUDITED_VERIFIER_FILES.length);
  assert.equal(Object.hasOwn(result, "installAuthorized"), false);
  assert.equal(Object.hasOwn(result, "deployAuthorized"), false);
});

test("source inspector refuses symlink, hardlink, missing file, bad digest and changed content", (t) => {
  const f = setup(t);
  const target = path.join(f.sourceDirectory, ...f.files[0].path.split("/"));
  const bytes = readFileSync(target);
  writeFileSync(target, "modified source");
  assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: f.sourceDirectory, files: f.files }));
  writeFileSync(target, bytes);
  const alias = path.join(f.base, "alias-source");
  try {
    symlinkSync(f.sourceDirectory, alias, "dir");
    assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: alias, files: f.files }));
  } catch (error) {
    if (error.code !== "EPERM" || process.platform !== "win32") throw error;
  }
  rmSync(target);
  try {
    symlinkSync(path.join(f.sourceDirectory, ...f.files[1].path.split("/")), target);
    assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: f.sourceDirectory, files: f.files }));
    rmSync(target);
  } catch (error) {
    if (error.code !== "EPERM" || process.platform !== "win32") throw error;
  }
  writeFileSync(target, bytes, { mode: 0o600 });
  const hardlink = path.join(f.base, "hardlink");
  linkSync(target, hardlink);
  assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: f.sourceDirectory, files: f.files }));
  rmSync(hardlink);
  rmSync(target);
  assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: f.sourceDirectory, files: f.files }));
  assert.throws(() => inspectAuditedVerifierFiles({ sourceDirectory: "../relative", files: f.files }));
});

test("host provisioning path requires actual native Linux root and cannot be activated by caller claims", (t) => {
  const f = setup(t);
  if (process.platform !== "linux" || process.getuid?.() !== 0 || /wsl|microsoft/iu.test(os.release())) {
    assert.throws(() => previewTrustedHostVerifierProvisioning({
      sourceDirectory: f.sourceDirectory, operatorDirectory: f.operatorDirectory,
    }), /native Linux\/amd64 root/iu);
  } else {
    t.skip("Native root installation preflight requires the real independently provisioned host, not a synthetic fixture");
  }
  assert.throws(() => previewTrustedHostVerifierProvisioning({
    sourceDirectory: f.sourceDirectory, operatorDirectory: f.operatorDirectory,
    policyAccepted: true,
  }));
  assert.deepEqual(readdirSync(f.operatorDirectory).sort(), ["ledger.json", "trust-policy.json", "verifier-pins.json"]);
});

test("direct script invocation never installs or signals successful activation", () => {
  const script = new URL("./trusted-host-installer.mjs", import.meta.url);
  const response = spawnSync(process.execPath, [fileURLToPath(script), "--install"], {
    encoding: "utf8", timeout: 5000,
  });
  assert.notEqual(response.status, 0);
  assert.match(response.stderr, /refused|blocked/iu);
  assert.equal(response.stdout, "");
});

test("independent verifier and operator origins refuse old and current candidate staging roots", () => {
  assert.equal(TRUSTED_OFFLINE_STAGING_PATH, "/var/lib/virki/offline-staging");
  for (const root of ["/var/lib/virki/offline-release/staging", TRUSTED_OFFLINE_STAGING_PATH]) {
    for (const candidate of [root, root + "/nested/private-source"]) {
      assert.throws(() => assertIndependentVerifierRoots({
        sourceDirectory: candidate, operatorDirectory: "/etc/virki/offline-release",
      }), /untrusted staging/u);
      assert.throws(() => assertIndependentVerifierRoots({
        sourceDirectory: "/usr/local/lib/virki/offline-release",
        operatorDirectory: candidate,
      }), /untrusted staging/u);
    }
  }
  assert.doesNotThrow(() => assertIndependentVerifierRoots({
    sourceDirectory: "/var/lib/virki/offline-staging-reviewed",
    operatorDirectory: "/etc/virki/offline-release",
  }));
});
