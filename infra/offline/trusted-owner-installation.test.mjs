import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  renameSync, rmSync, statfsSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AUDITED_VERIFIER_FILES } from "./trusted-host-installer.mjs";
import {
  installOwnerApprovedVerifier, measureInstalledTrustedVerifierAtUseTime,
} from "./trusted-owner-installation.mjs";

const enabled = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 && process.env.VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE === "1" &&
  existsSync("/.dockerenv") && statfsSync(os.tmpdir()).type === 0x01021994;
const fixtureOnly = { skip: enabled ? false : "Disposable Linux root Docker tmpfs fixture required" };
const sha = (data) => createHash("sha256").update(data).digest("hex");
const SHA = (char) => char.repeat(64);
const domain = Buffer.from("Virki/offline-verifier/owner-install/v1\0");
const moduleFile = fileURLToPath(new URL("./trusted-owner-installation.mjs", import.meta.url));
const pinnedImportFixture = fileURLToPath(
  new URL("./trusted-owner-esm-usepoint-fixture.mjs", import.meta.url));
const canonical = (data) => Buffer.from(JSON.stringify(data));
const interpreterPin = enabled ? sha(readFileSync(process.execPath)) : null;
const nativeGitPin = enabled ? sha(readFileSync("/usr/bin/git")) : null;

function ownerKey(keyId) {
  const pair = generateKeyPairSync("ed25519");
  return {
    keyId, privateKey: pair.privateKey,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: sha(pair.publicKey.export({ type: "spki", format: "der" })),
  };
}
function file(directory, name, data) {
  writeFileSync(path.join(directory, name), data, { mode: 0o600 });
}
function setup(t, { realSource = false } = {}) {
  const fixtureRoot = mkdtempSync(path.join(os.tmpdir(), "virki-owner-install-fixture-"));
  t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const source = path.join(fixtureRoot, "source");
  const operator = path.join(fixtureRoot, "operator");
  const bootstrap = path.join(fixtureRoot, "bootstrap");
  const code = path.join(fixtureRoot, "installed-code", "offline-release");
  const policy = path.join(fixtureRoot, "installed-policy", "offline-release");
  const ledger = path.join(fixtureRoot, "installed-ledger", "offline-release");
  for (const dir of [source, operator, bootstrap, path.dirname(code),
    path.dirname(policy), path.dirname(ledger)]) mkdirSync(dir, { mode: 0o700 });
  const sourceBytes = AUDITED_VERIFIER_FILES.map((relative, i) => {
    const target = path.join(source, ...relative.split("/"));
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const bytes = realSource ?
      readFileSync(fileURLToPath(new URL(`../../${relative}`, import.meta.url))) :
      Buffer.from(`// independent reviewer pinned mock executable ${i}\n`);
    writeFileSync(target, bytes, { mode: 0o600 });
    return bytes;
  });
  const files = AUDITED_VERIFIER_FILES.map((relative, i) => ({
    path: relative, sha256: sha(sourceBytes[i]),
  }));
  const host = SHA("a");
  const builder = ownerKey("release-builder");
  const owner = ownerKey("release-owner");
  const releasePolicy = canonical({
    version: 2, mode: "offline-signed-v1", enabled: true,
    ownerAssuranceAccepted: true, hostIdentitySha256: host,
    ledgerAnchorSha: "1".repeat(40), platform: "linux/amd64",
    builder: { keyId: builder.keyId, publicKeyPem: builder.publicKeyPem,
      pinSha256: builder.pinSha256 },
    owner: { keyId: owner.keyId, publicKeyPem: owner.publicKeyPem,
      pinSha256: owner.pinSha256 },
    revokedKeyIds: [], revokedPinsSha256: [],
  });
  const releaseLedger = canonical({ version: 1, anchorSha: "1".repeat(40), entries: [] });
  const operatorPins = canonical({
    version: 1, mode: "independent-native-verifier-pins-v1", files,
    trustPolicySha256: sha(releasePolicy), ledgerSha256: sha(releaseLedger),
  });
  file(operator, "trust-policy.json", releasePolicy);
  file(operator, "ledger.json", releaseLedger);
  file(operator, "verifier-pins.json", operatorPins);
  const bootstrapSigner = ownerKey("offline-install-owner");
  const bootstrapPolicy = canonical({
    version: 1, mode: "virki-owner-bootstrap-v1", hostIdentitySha256: host,
    signerKeyId: bootstrapSigner.keyId,
    ownerPublicKeySha256: bootstrapSigner.pinSha256,
    installerSha256: sha(readFileSync(moduleFile)),
    nodeExecutablePath: process.execPath, nodeExecutableSha256: interpreterPin,
    gitExecutableSha256: nativeGitPin,
    maxValiditySeconds: 3600,
    revokedKeyIds: [], revokedApprovalIds: [],
  });
  file(bootstrap, "bootstrap-policy.json", bootstrapPolicy);
  file(bootstrap, "owner-key.pem", bootstrapSigner.publicKeyPem);
  file(bootstrap, "installation-state.json", canonical({
    version: 1, lastSequence: 0, status: "ready", approvalDigest: null,
  }));
  const now = Math.floor(Date.now() / 1000);
  const approval = {
    version: 1, mode: "virki-native-verifier-install-v1", approvalId: SHA("b"),
    sequence: 1, signerKeyId: bootstrapSigner.keyId,
    hostIdentitySha256: host, bootstrapPolicySha256: sha(bootstrapPolicy),
    verifierPinsSha256: sha(operatorPins), trustPolicySha256: sha(releasePolicy),
    ledgerSha256: sha(releaseLedger), verifierDirectory: code,
    policyDirectory: policy, ledgerDirectory: ledger,
    issuedAt: now - 10, expiresAt: now + 600,
  };
  const signApproval = () => {
    const signature = sign(null, Buffer.concat([domain, canonical(approval)]),
      bootstrapSigner.privateKey).toString("base64");
    file(bootstrap, "installation-approval.json", canonical({ approval, signature }));
  };
  signApproval();
  const request = { fixtureRoot, measuredHostIdentitySha256: host };
  const locations = { code, policy, ledger, bootstrap, source, operator };
  const resignOperator = ({ releasePolicyMutation, releaseLedgerMutation }) => {
    const updatedPolicy = JSON.parse(readFileSync(path.join(operator, "trust-policy.json")));
    const updatedLedger = JSON.parse(readFileSync(path.join(operator, "ledger.json")));
    releasePolicyMutation?.(updatedPolicy);
    releaseLedgerMutation?.(updatedLedger);
    const policyBytes = canonical(updatedPolicy);
    const ledgerBytes = canonical(updatedLedger);
    const pinRecord = JSON.parse(readFileSync(path.join(operator, "verifier-pins.json")));
    pinRecord.trustPolicySha256 = sha(policyBytes);
    pinRecord.ledgerSha256 = sha(ledgerBytes);
    const newPins = canonical(pinRecord);
    file(operator, "trust-policy.json", policyBytes);
    file(operator, "ledger.json", ledgerBytes);
    file(operator, "verifier-pins.json", newPins);
    approval.verifierPinsSha256 = sha(newPins);
    approval.trustPolicySha256 = sha(policyBytes);
    approval.ledgerSha256 = sha(ledgerBytes);
    signApproval();
  };
  return { request, locations, files, approval, signApproval, resignOperator,
    sourceFile: (i) => path.join(source, ...files[i].path.split("/")),
    bootstrapPolicy, bootstrapSigner };
}
function noPublish(f) {
  assert.throws(() => installOwnerApprovedVerifier(f.request));
  for (const dest of [f.locations.code, f.locations.policy, f.locations.ledger]) {
    assert.equal(existsSync(dest), false);
  }
  assert.equal(existsSync(path.join(f.locations.bootstrap, ".installation-lock")), false);
  assert.equal(existsSync(path.join(f.locations.bootstrap, ".installation-state.json.partial")), false);
  assert.equal(JSON.parse(readFileSync(path.join(f.locations.bootstrap,
    "installation-state.json"))).status, "ready");
}

test("root bootstrap requires an actual independent Ed25519 approval and publishes the exact audited closure", fixtureOnly, (t) => {
  const f = setup(t);
  const result = installOwnerApprovedVerifier(f.request);
  assert.equal(result.status, "DISPOSABLE_OWNER_APPROVED_INSTALL_REHEARSAL");
  assert.equal(result.verifierFiles, 11);
  const state = JSON.parse(readFileSync(path.join(f.locations.bootstrap, "installation-state.json")));
  assert.equal(state.status, "installed");
  assert.equal(state.lastSequence, 1);
  assert.ok(existsSync(path.join(f.locations.bootstrap, ".installation-lock")));
  for (const { path: relative, sha256 } of f.files) {
    const target = path.join(f.locations.code, ...relative.split("/"));
    assert.equal(sha(readFileSync(target)), sha256);
    assert.equal(lstatSync(target).mode & 0o7777, 0o600);
    assert.equal(lstatSync(target).nlink, 1);
  }
  assert.throws(() => installOwnerApprovedVerifier(f.request), /installed|incomplete|already/u);
});

test("tamper, missing independent consent, invalid signature, revoked keys, bad host and expired approval all fail before mutation", fixtureOnly, (t) => {
  const attacks = [
    (f) => { f.approval.verifierPinsSha256 = SHA("e"); f.signApproval(); },
    (f) => { f.approval.ledgerSha256 = SHA("e"); f.signApproval(); },
    (f) => { f.approval.hostIdentitySha256 = SHA("e"); f.signApproval(); },
    (f) => { f.approval.sequence = 0; f.signApproval(); },
    (f) => { f.approval.expiresAt = Math.floor(Date.now() / 1000) - 1; f.signApproval(); },
    (f) => { f.approval.issuedAt = Math.floor(Date.now() / 1000) + 1000; f.signApproval(); },
    (f) => { f.approval.verifierDirectory += "-wrong"; f.signApproval(); },
    (f) => { const name = path.join(f.locations.bootstrap, "installation-approval.json");
      const signed = JSON.parse(readFileSync(name)); signed.approval.approvalId = SHA("c");
      file(f.locations.bootstrap, "installation-approval.json", canonical(signed)); },
    (f) => file(f.locations.bootstrap, "installation-approval.json", Buffer.from("{}")),
    (f) => { const policy = JSON.parse(f.bootstrapPolicy);
      policy.revokedKeyIds = [f.bootstrapSigner.keyId];
      file(f.locations.bootstrap, "bootstrap-policy.json", canonical(policy)); },
    (f) => { const policy = JSON.parse(f.bootstrapPolicy);
      policy.revokedApprovalIds = [f.approval.approvalId];
      file(f.locations.bootstrap, "bootstrap-policy.json", canonical(policy)); },
    (f) => { const policy = JSON.parse(f.bootstrapPolicy);
      policy.nodeExecutableSha256 = SHA("c");
      file(f.locations.bootstrap, "bootstrap-policy.json", canonical(policy)); },
    (f) => { const policy = JSON.parse(f.bootstrapPolicy);
      policy.gitExecutableSha256 = SHA("c");
      file(f.locations.bootstrap, "bootstrap-policy.json", canonical(policy)); },
    (f) => file(f.locations.operator, "trust-policy.json", Buffer.from("{}")),
    (f) => file(f.locations.operator, "ledger.json", Buffer.from("{}")),
    (f) => file(f.locations.operator, "verifier-pins.json", Buffer.from("{}")),
    (f) => writeFileSync(f.sourceFile(0), "tampered"),
    (f) => { const target = f.sourceFile(0);
      renameSync(target, target + ".saved"); symlinkSync(target + ".saved", target); },
    (f) => linkSync(f.sourceFile(1), f.sourceFile(1) + ".linked"),
    (f) => writeFileSync(path.join(f.locations.source, "extra.mjs"), "injected"),
    (f) => chmodSync(f.sourceFile(1), 0o666),
    (f) => chmodSync(f.locations.bootstrap, 0o777),
    (f) => symlinkSync(path.join(f.locations.source, "missing"), f.locations.code),
  ];
  for (const attack of attacks) {
    const f = setup(t);
    attack(f);
    noPublish(f);
  }
});

test("independent signature cannot authorize malformed policy or forged ledger even with updated hashes", fixtureOnly, (t) => {
  const corruptions = [
    { releasePolicyMutation: (policy) => { policy.ownerAssuranceAccepted = false; } },
    { releasePolicyMutation: (policy) => { policy.owner = policy.builder; } },
    { releasePolicyMutation: (policy) => { policy.revokedKeyIds = [policy.owner.keyId]; } },
    { releasePolicyMutation: (policy) => { policy.platform = "linux/arm64"; } },
    { releasePolicyMutation: (policy) => { policy.ledgerAnchorSha = "2".repeat(40); } },
    { releaseLedgerMutation: (ledger) => { ledger.entries.push({
      sequence: 1, priorSha: "9".repeat(40), nextSha: "2".repeat(40),
      manifestSha256: SHA("e"), nonce: "f".repeat(32), approvalDigest: SHA("a"),
    }); } },
  ];
  for (const corruption of corruptions) {
    const f = setup(t);
    f.resignOperator(corruption);
    noPublish(f);
  }
  const reused = setup(t);
  reused.resignOperator({ releasePolicyMutation(policy) {
    policy.owner = {
      keyId: reused.bootstrapSigner.keyId,
      publicKeyPem: reused.bootstrapSigner.publicKeyPem,
      pinSha256: reused.bootstrapSigner.pinSha256,
    };
  } });
  noPublish(reused);
});

test("duplicate JSON fields and symlinked or writable independently owned files are denied", fixtureOnly, (t) => {
  for (const attack of [
    (f) => { const filename = path.join(f.locations.bootstrap, "installation-approval.json");
      const bytes = readFileSync(filename, "utf8");
      file(f.locations.bootstrap, "installation-approval.json",
        bytes.replace('"signature":', '"signature":"junk","signature":')); },
    (f) => { const original = path.join(f.locations.bootstrap, "owner-key.pem");
      renameSync(original, original + ".backup"); symlinkSync(original + ".backup", original); },
    (f) => chmodSync(path.join(f.locations.bootstrap, "bootstrap-policy.json"), 0o666),
    (f) => { const original = path.join(f.locations.operator, "ledger.json");
      renameSync(original, original + ".backup"); symlinkSync(original + ".backup", original); },
  ]) {
    const f = setup(t);
    attack(f);
    noPublish(f);
  }
});

test("an interrupted write creates a durable failure latch; retry cannot finish a partial install", fixtureOnly, (t) => {
  for (const phase of ["pending", "policyPublished", "ledgerPublished", "codePublished"]) {
    const f = setup(t);
    assert.throws(() => installOwnerApprovedVerifier(f.request, {
      onPhase(current) { if (current === phase) throw new Error("injected power loss"); },
    }), /injected power loss/u);
    assert.ok(existsSync(path.join(f.locations.bootstrap, ".installation-lock")));
    const state = JSON.parse(readFileSync(path.join(f.locations.bootstrap, "installation-state.json")));
    assert.equal(state.status, "pending");
    assert.equal(state.lastSequence, 1);
    assert.throws(() => installOwnerApprovedVerifier(f.request));
  }
});

test("SIGKILL before first publication leaves a durable pending state and an exclusive lock", fixtureOnly, (t) => {
  const f = setup(t);
  const script = [
    "import { pathToFileURL } from 'node:url';",
    "const { installOwnerApprovedVerifier } = await import(pathToFileURL(process.env.OWNER_MODULE).href);",
    "installOwnerApprovedVerifier(JSON.parse(process.env.OWNER_REQUEST), {",
    "  onPhase(phase) { if (phase === 'pending') process.kill(process.pid, 'SIGKILL'); },",
    "});",
  ].join("\n");
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8", timeout: 10000,
    env: { ...process.env, OWNER_MODULE: moduleFile,
      OWNER_REQUEST: JSON.stringify(f.request) },
  });
  assert.equal(child.signal, "SIGKILL", child.stderr);
  const state = JSON.parse(readFileSync(path.join(f.locations.bootstrap, "installation-state.json")));
  assert.equal(state.status, "pending");
  assert.ok(existsSync(path.join(f.locations.bootstrap, ".installation-lock")));
  assert.throws(() => installOwnerApprovedVerifier(f.request));
});

test("production invocation cannot come from a source checkout, even with arbitrary caller flags", () => {
  assert.throws(() => installOwnerApprovedVerifier({}), /native Linux|bootstrap/u);
  const child = spawnSync(process.execPath, [moduleFile, "--install"], {
    encoding: "utf8", timeout: 5000,
  });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /independently installed/u);
});

test("use-time trust remeasures eleven genuine ESM modules after independently signed installation", fixtureOnly, (t) => {
  const f = setup(t, { realSource: true });
  for (const item of f.files) {
    const disk = readFileSync(path.join(f.locations.source, ...item.path.split("/")));
    assert.ok(disk.includes(Buffer.from("import ")), `${item.path} must contain real reviewed code`);
    assert.equal(sha(disk), item.sha256);
  }
  assert.equal(installOwnerApprovedVerifier(f.request).verifierFiles, 11);
  const measurement = measureInstalledTrustedVerifierAtUseTime(f.request);
  assert.equal(measurement.status, "INSTALLED_VERIFIER_BYTES_MEASURED_ONLY");
  assert.equal(measurement.installedModules, 11);
  assert.equal(measurement.liveLedgerSequence, 0);
  assert.equal(measurement.liveLedgerStatus, "INITIAL_LEDGER_INSPECTED_NOT_AUTHORIZED");
  assert.equal(Object.hasOwn(measurement, "releaseAuthorized"), false);
  assert.equal(Object.hasOwn(measurement, "deployAuthorized"), false);
  assert.equal(Object.hasOwn(measurement, "verifiedImageId"), false);
  assert.ok(Object.isFrozen(measurement));
});

test("use-time trust fails closed on tamper, swaps, symlinks and replayed owner state with real signed modules", fixtureOnly, (t) => {
  const attacks = [
    ...AUDITED_VERIFIER_FILES.map((relative) => (f) =>
      writeFileSync(path.join(f.locations.code, ...relative.split("/")), "injected")),
    (f) => { const src = path.join(f.locations.code, ...f.files[4].path.split("/"));
      renameSync(src, src + ".original"); symlinkSync(src + ".original", src); },
    (f) => { const dir = path.join(f.locations.code, "scripts", "lib");
      renameSync(dir, dir + "-old"); symlinkSync(dir + "-old", dir); },
    (f) => { const src = path.join(f.locations.code, ...f.files[2].path.split("/"));
      linkSync(src, src + ".hardlink"); },
    (f) => writeFileSync(path.join(f.locations.code, "infra", "offline", "extra.mjs"), "unexpected"),
    (f) => chmodSync(path.join(f.locations.code, "scripts"), 0o777),
    (f) => { const name = path.join(f.locations.bootstrap, "installation-state.json");
      const state = JSON.parse(readFileSync(name)); state.status = "pending";
      file(f.locations.bootstrap, "installation-state.json", canonical(state)); },
    (f) => { const name = path.join(f.locations.bootstrap, "installation-state.json");
      const state = JSON.parse(readFileSync(name)); state.lastSequence = 2;
      file(f.locations.bootstrap, "installation-state.json", canonical(state)); },
    (f) => { const name = path.join(f.locations.bootstrap, "installation-state.json");
      const state = JSON.parse(readFileSync(name)); state.approvalDigest = SHA("e");
      file(f.locations.bootstrap, "installation-state.json", canonical(state)); },
    (f) => { const name = path.join(f.locations.bootstrap, "installation-approval.json");
      const envelope = JSON.parse(readFileSync(name));
      envelope.approval.approvalId = SHA("d"); file(f.locations.bootstrap, "installation-approval.json", canonical(envelope)); },
    (f) => { const name = path.join(f.locations.operator, "verifier-pins.json");
      const pins = JSON.parse(readFileSync(name)); pins.files[1].sha256 = SHA("e");
      file(f.locations.operator, "verifier-pins.json", canonical(pins)); },
    (f) => file(f.locations.policy, "trust-policy.json", "{}"),
    (f) => { const name = path.join(f.locations.ledger, "ledger.json");
      renameSync(name, name + ".before"); symlinkSync(name + ".before", name); },
    (f) => { const lock = path.join(f.locations.bootstrap, ".installation-lock");
      renameSync(lock, lock + "-old"); symlinkSync(lock + "-old", lock); },
  ];
  for (const attack of attacks) {
    const f = setup(t, { realSource: true });
    installOwnerApprovedVerifier(f.request);
    attack(f);
    assert.throws(() => measureInstalledTrustedVerifierAtUseTime(f.request),
      /refused|unsafe|changed|malformed/u);
  }
});

test("use-time distinguishes an independently pinned initial ledger from a valid changing release ledger", fixtureOnly, (t) => {
  const f = setup(t, { realSource: true });
  installOwnerApprovedVerifier(f.request);
  const ledgerFile = path.join(f.locations.ledger, "ledger.json");
  const append = (entries) => file(f.locations.ledger, "ledger.json", canonical({
    version: 1, anchorSha: "1".repeat(40), entries,
  }));
  const first = {
    sequence: 1, priorSha: "1".repeat(40), nextSha: "2".repeat(40),
    manifestSha256: SHA("a"), nonce: "a".repeat(32), approvalDigest: SHA("b"),
  };
  const second = {
    sequence: 2, priorSha: "2".repeat(40), nextSha: "3".repeat(40),
    manifestSha256: SHA("c"), nonce: "c".repeat(32), approvalDigest: SHA("d"),
  };
  append([first, second]);
  const measured = measureInstalledTrustedVerifierAtUseTime(f.request);
  assert.equal(measured.liveLedgerSequence, 2);
  assert.equal(measured.liveLedgerStatus, "DYNAMIC_LEDGER_INSPECTED_NOT_AUTHORIZED");
  assert.equal(Object.hasOwn(measured, "releaseAuthorized"), false);
  second.nonce = first.nonce;
  append([first, second]);
  assert.throws(() => measureInstalledTrustedVerifierAtUseTime(f.request), /replay|ledger/u);
  second.nonce = "c".repeat(32);
  second.priorSha = "f".repeat(40);
  append([first, second]);
  assert.throws(() => measureInstalledTrustedVerifierAtUseTime(f.request), /predecessor|ledger/u);
  assert.ok(existsSync(ledgerFile));
});

function runPinnedImportFixture(f, { mutation = "none", envOverride = {}, nodeFlags = [] } = {}) {
  const environment = {
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: "/tmp",
    TMPDIR: "/tmp",
    VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE: "1",
    VIRKI_USEPOINT_REQUEST: JSON.stringify(f.request),
    VIRKI_USEPOINT_MUTATION: mutation,
    ...envOverride,
  };
  return spawnSync(process.execPath, [...nodeFlags, pinnedImportFixture], {
    encoding: "utf8", timeout: 12000, env: environment,
  });
}

test("native Node22 actually imports real owner-signed eleven-file ESM graph from measured in-memory snapshots", fixtureOnly, (t) => {
  for (const mutation of ["none", "swap-entry", "swap-dependency"]) {
    const f = setup(t, { realSource: true });
    installOwnerApprovedVerifier(f.request);
    const result = runPinnedImportFixture(f, { mutation });
    assert.equal(result.status, 0, `mutation=${mutation}: ${result.stderr}`);
    const loaded = JSON.parse(result.stdout.trim());
    assert.equal(loaded.status, "DISPOSABLE_NODE22_PINNED_ESM_IMPORT_PROVEN_ONLY");
    assert.equal(loaded.pinnedInventoryCount, 11);
    assert.ok(loaded.actualNodeEsmLoads >= 2 && loaded.actualNodeEsmLoads <= 11);
    assert.ok(loaded.loadedPaths.some((entry) =>
      entry.path === "infra/offline/trusted-host-entry.mjs"));
    assert.ok(loaded.loadedPaths.every((entry) =>
      f.files.some((pin) => pin.path === entry.path && pin.sha256 === entry.sha256)),
    "every byte string actually delivered to Node's loader must match the independently signed pins");
    assert.equal(Object.hasOwn(loaded, "deployAuthorized"), false);
  }
});

test("native fixture refuses preload, changed pin, revocation and before-launch ESM tampering", fixtureOnly, (t) => {
  for (const attack of [
    { nodeFlags: ["--trace-warnings"] },
    { envOverride: { NODE_OPTIONS: "--no-warnings" } },
    { envOverride: { LD_PRELOAD: "/tmp/not-a-library.so" } },
    { before(f) { writeFileSync(path.join(f.locations.code,
      "infra", "offline", "trusted-host-entry.mjs"), "// forged ESM\n"); } },
    { before(f) { const name = path.join(f.locations.bootstrap, "installation-state.json");
      const state = JSON.parse(readFileSync(name)); state.status = "pending";
      file(f.locations.bootstrap, "installation-state.json", canonical(state)); } },
    { before(f) { const name = path.join(f.locations.operator, "verifier-pins.json");
      const pins = JSON.parse(readFileSync(name)); pins.files[0].sha256 = SHA("f");
      file(f.locations.operator, "verifier-pins.json", canonical(pins)); } },
  ]) {
    const f = setup(t, { realSource: true });
    installOwnerApprovedVerifier(f.request);
    attack.before?.(f);
    const child = runPinnedImportFixture(f, attack);
    assert.notEqual(child.status, 0, `expected fail closed for ${JSON.stringify(Object.keys(attack))}`);
    assert.doesNotMatch(child.stdout, /DISPOSABLE_NODE22_PINNED_ESM_IMPORT_PROVEN_ONLY/u);
  }
});

test("Node loader fails closed when ESM pathname disappears or becomes a symlink after the signed snapshot", fixtureOnly, (t) => {
  for (const mutation of ["remove-entry", "symlink-entry"]) {
    const f = setup(t, { realSource: true });
    installOwnerApprovedVerifier(f.request);
    const result = runPinnedImportFixture(f, { mutation });
    assert.notEqual(result.status, 0, `expected fail closed after ${mutation}`);
    assert.doesNotMatch(result.stdout, /DISPOSABLE_NODE22_PINNED_ESM_IMPORT_PROVEN_ONLY/u);
  }
});

test("valid prior-ledger rollback stays explicitly unwitnessed and cannot become release authorization", fixtureOnly, (t) => {
  const f = setup(t, { realSource: true });
  installOwnerApprovedVerifier(f.request);
  const ledger = path.join(f.locations.ledger, "ledger.json");
  const initiallyApproved = readFileSync(ledger);
  file(f.locations.ledger, "ledger.json", canonical({
    version: 1, anchorSha: "1".repeat(40),
    entries: [{
      sequence: 1, priorSha: "1".repeat(40), nextSha: "2".repeat(40),
      manifestSha256: SHA("a"), nonce: "b".repeat(32),
      approvalDigest: SHA("c"),
    }],
  }));
  const appended = measureInstalledTrustedVerifierAtUseTime(f.request);
  assert.equal(appended.liveLedgerSequence, 1);
  assert.equal(appended.independentLedgerWitnessVerified, false);
  file(f.locations.ledger, "ledger.json", initiallyApproved);
  const rolledBack = measureInstalledTrustedVerifierAtUseTime(f.request);
  assert.equal(rolledBack.liveLedgerSequence, 0);
  assert.equal(rolledBack.independentLedgerWitnessVerified, false);
  assert.equal(Object.hasOwn(rolledBack, "releaseAuthorized"), false);
});
