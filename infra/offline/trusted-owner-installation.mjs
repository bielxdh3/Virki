import { createHash, createPublicKey, verify } from "node:crypto";
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, statfsSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// This module is a standalone BOOTSTRAP executable, provisioned by the owner
// separately from all uploaded source and release archives. Running a copy
// from a checkout cannot create trust. The approved entrypoint is the native
// root-owned file at BOOTSTRAP_ENTRY, with its SHA-256 in the already installed
// bootstrap policy. No release, Docker or process execution occurs here.
const BOOTSTRAP_ENTRY = "/usr/local/lib/virki/offline-bootstrap/trusted-owner-installation.mjs";
const BOOTSTRAP_ROOT = "/etc/virki/offline-bootstrap";
const SOURCE_ROOT = "/var/lib/virki/owner-reviewed-verifier";
const OPERATOR_ROOT = "/etc/virki/offline-verifier-operator";
const CODE_ROOT = "/usr/local/lib/virki/offline-release";
const POLICY_ROOT = "/etc/virki/offline-release";
const LEDGER_ROOT = "/var/lib/virki/offline-release";
const AUDITED_FILES = Object.freeze([
  "infra/offline/trusted-host-entry.mjs",
  "infra/offline/trusted-host-installer.mjs",
  "infra/offline/trusted-image-import.mjs",
  "infra/offline/trusted-image-loader.mjs",
  "infra/offline/trusted-release-coordinator.mjs",
  "infra/offline/trusted-source-git.mjs",
  "scripts/lib/offline-docker-tar-verifier.mjs",
  "scripts/lib/offline-release-attestation.mjs",
  "scripts/lib/offline-release-ledger.mjs",
  "scripts/lib/offline-source-tar-verifier.mjs",
  "scripts/lib/offline-trusted-release-policy.mjs",
]);
const DOMAIN = Buffer.from("Virki/offline-verifier/owner-install/v1\0", "utf8");
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const DIR_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const NEW_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const SHA = /^[0-9a-f]{64}$/u;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_CODE = 2 * 1024 * 1024;
const EXPECTED_BOOTSTRAP = ["bootstrap-policy.json", "installation-approval.json", "installation-state.json", "owner-key.pem"];
const EXPECTED_OPERATOR = ["ledger.json", "trust-policy.json", "verifier-pins.json"];

function reject(message) { throw new Error("Owner-approved verifier installation refused: " + message); }
function demand(ok, message) { if (!ok) reject(message); }
const hash = (data) => createHash("sha256").update(data).digest("hex");
function exact(record, names, label) {
  demand(record && typeof record === "object" && !Array.isArray(record) &&
    JSON.stringify(Object.keys(record)) === JSON.stringify(names), label + " schema invalid");
}
function json(bytes, names, label, max = 16384) {
  demand(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= max, label + " size invalid");
  let value;
  let raw;
  try {
    raw = new TextDecoder("utf8", { fatal: true }).decode(bytes);
    value = JSON.parse(raw);
  } catch { reject(label + " JSON invalid"); }
  exact(value, names, label);
  demand(JSON.stringify(value) === raw, label + " noncanonical/duplicate JSON");
  return value;
}
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function isPrivate(st, directory) {
  return st.uid === 0n && st.gid === 0n &&
    (st.mode & 0o7777n) === (directory ? 0o700n : 0o600n) &&
    (directory ? st.isDirectory() : st.isFile() && st.nlink === 1n);
}
function privateDir(dirname, fixture) {
  demand(typeof dirname === "string" && dirname.length > 1 && dirname.length < 4096 &&
    path.isAbsolute(dirname) && path.normalize(dirname) === dirname &&
    dirname !== path.parse(dirname).root && !dirname.includes("\0"),
  "noncanonical path");
  for (let segment = dirname; ; segment = path.dirname(segment)) {
    const meta = lstatSync(segment, { bigint: true });
    demand(meta.isDirectory() && !meta.isSymbolicLink() && meta.uid === 0n &&
      (fixture && segment === path.dirname(fixture) ?
        (meta.mode & 0o1000n) !== 0n :
        (meta.mode & 0o022n) === 0n), "unsafe directory ancestry: " + segment);
    if (path.dirname(segment) === segment) break;
  }
  demand(realpathSync.native(dirname) === dirname &&
    isPrivate(lstatSync(dirname, { bigint: true }), true),
  "root-owned private directory required: " + dirname);
  return lstatSync(dirname, { bigint: true });
}
function readPrivate(dirname, name, limit, fixture) {
  privateDir(dirname, fixture);
  const fdDir = openSync(dirname, DIR_FLAGS);
  try {
    const rootBefore = fstatSync(fdDir, { bigint: true });
    const filename = `/proc/self/fd/${fdDir}/${name}`;
    const before = lstatSync(filename, { bigint: true });
    demand(isPrivate(before, false) && before.size > 0n &&
      before.size <= BigInt(limit), "unsafe protected file: " + name);
    const fd = openSync(filename, READ_FLAGS);
    try {
      const opened = fstatSync(fd, { bigint: true });
      demand(same(before, opened), "protected file replaced before read: " + name);
      const bytes = readFileSync(fd);
      demand(bytes.length === Number(before.size) &&
        same(opened, fstatSync(fd, { bigint: true })) &&
        same(opened, lstatSync(filename, { bigint: true })),
      "protected file changed during read: " + name);
      demand(same(rootBefore, fstatSync(fdDir, { bigint: true })) &&
        same(rootBefore, lstatSync(dirname, { bigint: true })),
      "protected directory changed during read");
      return bytes;
    } finally { closeSync(fd); }
  } finally { closeSync(fdDir); }
}
function directoryEntries(dirname, expected, fixture) {
  privateDir(dirname, fixture);
  demand(JSON.stringify(readdirSync(dirname).sort()) === JSON.stringify([...expected].sort()),
    "unexpected/missing protected entries in " + dirname);
}
function readonlySource(source, relative, fixture) {
  const segments = relative.split("/");
  let parent = source;
  for (const segment of segments.slice(0, -1)) {
    parent = path.join(parent, segment);
    privateDir(parent, fixture);
  }
  return readPrivate(parent, segments.at(-1), MAX_CODE, fixture);
}
function exactModuleTree(root, fixture) {
  const expected = new Map([["", new Set()]]);
  for (const file of AUDITED_FILES) {
    const pieces = file.split("/");
    let prefix = "";
    for (let i = 0; i < pieces.length; i++) {
      expected.get(prefix).add(pieces[i]);
      if (i < pieces.length - 1) {
        prefix = prefix ? `${prefix}/${pieces[i]}` : pieces[i];
        if (!expected.has(prefix)) expected.set(prefix, new Set());
      }
    }
  }
  for (const [prefix, names] of expected) {
    const dir = path.join(root, prefix);
    privateDir(dir, fixture);
    demand(JSON.stringify(readdirSync(dir).sort()) === JSON.stringify([...names].sort()),
      "unexpected executable module or missing dependency");
  }
}
function checkPins(pins, policyBytes, ledgerBytes) {
  exact(pins, ["version", "mode", "files", "trustPolicySha256", "ledgerSha256"], "pin inventory");
  demand(pins.version === 1 && pins.mode === "independent-native-verifier-pins-v1" &&
    Array.isArray(pins.files) && pins.files.length === AUDITED_FILES.length &&
    pins.trustPolicySha256 === hash(policyBytes) && pins.ledgerSha256 === hash(ledgerBytes),
  "pinned policy/ledger or executable closure mismatch");
  pins.files.forEach((file, i) => {
    exact(file, ["path", "sha256"], "pin file");
    demand(file.path === AUDITED_FILES[i] && SHA.test(file.sha256),
      "unreviewed executable module");
  });
}
function checkOfflineHostPolicy(policyBytes, ledgerBytes, host, bootstrapSignerPin) {
  const policy = json(policyBytes, ["version", "mode", "enabled", "ownerAssuranceAccepted",
    "hostIdentitySha256", "ledgerAnchorSha", "platform", "builder", "owner",
    "revokedKeyIds", "revokedPinsSha256"], "independently reviewed host policy");
  demand(policy.version === 2 && policy.mode === "offline-signed-v1" &&
    policy.enabled === true && policy.ownerAssuranceAccepted === true &&
    policy.platform === "linux/amd64" && policy.hostIdentitySha256 === host &&
    /^[0-9a-f]{40}$/u.test(policy.ledgerAnchorSha),
  "offline host policy unaccepted or wrong host/architecture");
  const pins = [];
  for (const role of ["builder", "owner"]) {
    const signer = policy[role];
    exact(signer, ["keyId", "publicKeyPem", "pinSha256"], role + " policy key");
    demand(KEY_ID.test(signer.keyId) && SHA.test(signer.pinSha256) &&
      typeof signer.publicKeyPem === "string" && signer.publicKeyPem.length <= 2048,
    "malformed release signer key");
    let key;
    try { key = createPublicKey(signer.publicKeyPem); } catch { reject("release signer key invalid"); }
    demand(key.asymmetricKeyType === "ed25519" &&
      hash(key.export({ type: "spki", format: "der" })) === signer.pinSha256,
    "release signing key pin invalid");
    pins.push(signer);
  }
  demand(pins[0].keyId !== pins[1].keyId && pins[0].pinSha256 !== pins[1].pinSha256,
    "release builder and owner must be independent");
  demand(pins.every((entry) => entry.pinSha256 !== bootstrapSignerPin),
    "installation authority must use a separate Ed25519 key from release signers");
  for (const [array, pattern] of [[policy.revokedKeyIds, KEY_ID], [policy.revokedPinsSha256, SHA]]) {
    demand(Array.isArray(array) && array.length <= 128 &&
      array.every((entry) => typeof entry === "string" && pattern.test(entry)) &&
      new Set(array).size === array.length,
    "release revocations invalid");
  }
  demand(pins.every((entry) => !policy.revokedKeyIds.includes(entry.keyId) &&
    !policy.revokedPinsSha256.includes(entry.pinSha256)), "release signing key revoked");
  const ledger = json(ledgerBytes, ["version", "anchorSha", "entries"],
    "independent release ledger", 1024 * 1024);
  demand(ledger.version === 1 && ledger.anchorSha === policy.ledgerAnchorSha &&
    Array.isArray(ledger.entries) && ledger.entries.length <= 1024,
  "release ledger anchor/history invalid");
  let prior = ledger.anchorSha;
  const shas = new Set([prior]);
  const nonces = new Set();
  const manifests = new Set();
  const approvals = new Set();
  ledger.entries.forEach((entry, index) => {
    exact(entry, ["sequence", "priorSha", "nextSha", "manifestSha256", "nonce",
      "approvalDigest"], "release ledger entry");
    demand(entry.sequence === index + 1 && entry.priorSha === prior &&
      /^[0-9a-f]{40}$/u.test(entry.nextSha) && !shas.has(entry.nextSha) &&
      /^[0-9a-f]{32}$/u.test(entry.nonce) && !nonces.has(entry.nonce) &&
      SHA.test(entry.manifestSha256) && !manifests.has(entry.manifestSha256) &&
      SHA.test(entry.approvalDigest) && !approvals.has(entry.approvalDigest),
    "release ledger replay or inconsistent predecessor");
    prior = entry.nextSha;
    shas.add(prior);
    nonces.add(entry.nonce);
    manifests.add(entry.manifestSha256);
    approvals.add(entry.approvalDigest);
  });
  return Object.freeze({ policy, ledger, head: prior, sequence: ledger.entries.length });
}
function parseApproval(bytes, trust, state, pins, policyBytes, ledgerBytes, host, destinations, now,
  installed = false) {
  const wrapper = json(bytes, ["approval", "signature"], "owner approval");
  const approval = wrapper.approval;
  exact(approval, ["version", "mode", "approvalId", "sequence", "signerKeyId",
    "hostIdentitySha256", "bootstrapPolicySha256", "verifierPinsSha256",
    "trustPolicySha256", "ledgerSha256", "verifierDirectory", "policyDirectory",
    "ledgerDirectory", "issuedAt", "expiresAt"], "signed installation approval");
  demand(approval.version === 1 && approval.mode === "virki-native-verifier-install-v1" &&
    SHA.test(approval.approvalId) && KEY_ID.test(approval.signerKeyId) &&
    approval.signerKeyId === trust.signerKeyId &&
    !trust.revokedKeyIds.includes(approval.signerKeyId) &&
    !trust.revokedApprovalIds.includes(approval.approvalId),
  "approval signer revoked, malformed or unknown");
  demand(Number.isSafeInteger(approval.sequence) &&
    approval.sequence === (installed ? state.lastSequence : state.lastSequence + 1) &&
    Number.isSafeInteger(approval.issuedAt) && Number.isSafeInteger(approval.expiresAt) &&
    (installed || (approval.issuedAt <= now + 60 && now < approval.expiresAt)) &&
    approval.expiresAt > approval.issuedAt &&
    approval.expiresAt - approval.issuedAt <= trust.maxValiditySeconds,
  "approval expired, not yet valid or replayed");
  demand(approval.hostIdentitySha256 === host &&
    approval.bootstrapPolicySha256 === hash(trust.raw) &&
    approval.verifierPinsSha256 === hash(pins) &&
    approval.trustPolicySha256 === hash(policyBytes) &&
    approval.ledgerSha256 === hash(ledgerBytes) &&
    approval.verifierDirectory === destinations.code &&
    approval.policyDirectory === destinations.policy &&
    approval.ledgerDirectory === destinations.ledger,
  "approval scope differs from measured host, reviewed policy, ledger or destinations");
  demand(typeof wrapper.signature === "string" && SIGNATURE.test(wrapper.signature),
    "owner signature encoding invalid");
  const signed = Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(approval))]);
  demand(verify(null, signed, trust.key, Buffer.from(wrapper.signature, "base64")),
    "independent owner Ed25519 signature invalid");
  return { approval, digest: hash(bytes) };
}
function strictBootstrap(bytes, ownerPem) {
  const policy = json(bytes, ["version", "mode", "hostIdentitySha256", "signerKeyId",
    "ownerPublicKeySha256", "installerSha256", "nodeExecutablePath",
    "nodeExecutableSha256", "maxValiditySeconds", "revokedKeyIds", "revokedApprovalIds"],
  "independent bootstrap policy");
  demand(policy.version === 1 && policy.mode === "virki-owner-bootstrap-v1" &&
    SHA.test(policy.hostIdentitySha256) && SHA.test(policy.installerSha256) &&
    SHA.test(policy.ownerPublicKeySha256) && SHA.test(policy.nodeExecutableSha256) &&
    typeof policy.nodeExecutablePath === "string" && KEY_ID.test(policy.signerKeyId) &&
    Number.isSafeInteger(policy.maxValiditySeconds) &&
    policy.maxValiditySeconds > 0 && policy.maxValiditySeconds <= 86400 &&
    Array.isArray(policy.revokedKeyIds) && policy.revokedKeyIds.length <= 128 &&
    policy.revokedKeyIds.every((id) => KEY_ID.test(id)) &&
    new Set(policy.revokedKeyIds).size === policy.revokedKeyIds.length &&
    Array.isArray(policy.revokedApprovalIds) && policy.revokedApprovalIds.length <= 128 &&
    policy.revokedApprovalIds.every((id) => SHA.test(id)) &&
    new Set(policy.revokedApprovalIds).size === policy.revokedApprovalIds.length,
  "bootstrap trust and revocations invalid");
  let key;
  try { key = createPublicKey(ownerPem); } catch { reject("bootstrap owner key invalid"); }
  demand(key.asymmetricKeyType === "ed25519" &&
    hash(key.export({ type: "spki", format: "der" })) === policy.ownerPublicKeySha256,
  "independent owner signing key pin mismatch");
  return { ...policy, key, raw: bytes };
}
function verifyNativeInterpreter(trust) {
  const executable = process.execPath;
  demand(process.versions.node.split(".")[0] === "22" &&
    executable === trust.nodeExecutablePath && path.isAbsolute(executable) &&
    path.normalize(executable) === executable &&
    realpathSync.native(executable) === executable,
  "native Node 22 executable does not match independently installed interpreter path");
  for (let dir = path.dirname(executable); ; dir = path.dirname(dir)) {
    const st = lstatSync(dir, { bigint: true });
    demand(st.isDirectory() && !st.isSymbolicLink() && st.uid === 0n &&
      st.gid === 0n && (st.mode & 0o022n) === 0n,
    "unsafe native interpreter path owner or permissions");
    if (path.dirname(dir) === dir) break;
  }
  const before = lstatSync(executable, { bigint: true });
  demand(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.uid === 0n && before.gid === 0n &&
    (before.mode & 0o022n) === 0n && (before.mode & 0o111n) !== 0n &&
    before.size > 0n && before.size <= 256n * 1024n * 1024n,
  "unsafe native interpreter executable metadata");
  const fd = openSync(executable, READ_FLAGS);
  try {
    const opened = fstatSync(fd, { bigint: true });
    demand(same(before, opened), "native interpreter inode changed at opening");
    const digest = createHash("sha256");
    const block = Buffer.allocUnsafe(64 * 1024);
    let cursor = 0;
    while (cursor < Number(opened.size)) {
      const count = readSync(fd, block, 0,
        Math.min(block.length, Number(opened.size) - cursor), cursor);
      demand(count > 0, "native interpreter binary truncated while reading");
      digest.update(block.subarray(0, count));
      cursor += count;
    }
    demand(same(opened, fstatSync(fd, { bigint: true })) &&
      same(opened, lstatSync(executable, { bigint: true })) &&
      digest.digest("hex") === trust.nodeExecutableSha256,
    "native interpreter binary differs from independently pinned SHA-256");
  } finally { closeSync(fd); }
}
function identityDigest() {
  const filename = "/etc/machine-id";
  const st = lstatSync(filename, { bigint: true });
  demand(st.isFile() && st.uid === 0n && st.nlink === 1n &&
    (st.mode & 0o022n) === 0n && realpathSync.native(filename) === filename,
  "native host machine-id is untrusted");
  const id = readFileSync(filename, "utf8").trim();
  demand(/^[0-9a-f]{32}$/u.test(id) && !/^0+$/u.test(id), "machine-id malformed");
  return hash("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0" + id);
}
function nativeMode(request) {
  const fixture = request?.fixtureRoot;
  demand(process.platform === "linux" && process.arch === "x64" && process.getuid?.() === 0 &&
    constants.O_NOFOLLOW && constants.O_EXCL && constants.O_DIRECTORY &&
    (!/microsoft|wsl/iu.test(os.release()) ||
      (fixture !== undefined && existsSync("/.dockerenv"))),
  "native Linux/amd64 root required");
  if (fixture !== undefined) {
    demand(process.env.VIRKI_OWNER_INSTALL_DISPOSABLE_FIXTURE === "1" &&
      existsSync("/.dockerenv") && statfsSync(os.tmpdir()).type === 0x01021994 &&
      path.dirname(fixture) === realpathSync.native(os.tmpdir()) &&
      /^virki-owner-install-fixture-[a-zA-Z0-9]{6}$/u.test(path.basename(fixture)),
    "disposable root tmpfs fixture required");
    privateDir(fixture, fixture);
    exact(request, ["fixtureRoot", "measuredHostIdentitySha256"], "fixture request");
    demand(SHA.test(request.measuredHostIdentitySha256), "fixture host hash invalid");
    return {
      fixture,
      bootstrap: path.join(fixture, "bootstrap"),
      source: path.join(fixture, "source"),
      operator: path.join(fixture, "operator"),
      destinations: { code: path.join(fixture, "installed-code", "offline-release"),
        policy: path.join(fixture, "installed-policy", "offline-release"),
        ledger: path.join(fixture, "installed-ledger", "offline-release") },
      host: request.measuredHostIdentitySha256,
    };
  }
  exact(request, [], "native installation request");
  demand(fileURLToPath(import.meta.url) === BOOTSTRAP_ENTRY,
    "installer must execute from independently provisioned bootstrap, never a source checkout");
  return {
    fixture: undefined, bootstrap: BOOTSTRAP_ROOT, source: SOURCE_ROOT,
    operator: OPERATOR_ROOT,
    destinations: { code: CODE_ROOT, policy: POLICY_ROOT, ledger: LEDGER_ROOT },
    host: identityDigest(),
  };
}
function fsyncDir(dirname) {
  const fd = openSync(dirname, DIR_FLAGS);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function lexicalEntryExists(filename) {
  try { lstatSync(filename); return true; } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}
function writeNew(filename, bytes) {
  const fd = openSync(filename, NEW_FLAGS, 0o600);
  try {
    let pos = 0;
    while (pos < bytes.length) {
      const written = writeSync(fd, bytes, pos, bytes.length - pos, pos);
      demand(written > 0, "short staging write");
      pos += written;
    }
    fsyncSync(fd);
    demand(isPrivate(fstatSync(fd, { bigint: true }), false), "staging file permissions unsafe");
  } finally { closeSync(fd); }
}
function durableReplace(directory, name, bytes) {
  const temporary = `.${name}.partial`;
  writeNew(path.join(directory, temporary), bytes);
  fsyncDir(directory);
  renameSync(path.join(directory, temporary), path.join(directory, name));
  fsyncDir(directory);
}
function writeTree(root, bytes, fixture) {
  mkdirSync(root, { mode: 0o700 });
  for (let index = 0; index < AUDITED_FILES.length; index++) {
    const segments = AUDITED_FILES[index].split("/");
    let dir = root;
    for (const segment of segments.slice(0, -1)) {
      dir = path.join(dir, segment);
      if (!existsSync(dir)) mkdirSync(dir, { mode: 0o700 });
      privateDir(dir, fixture);
    }
    writeNew(path.join(dir, segments.at(-1)), bytes[index]);
  }
  exactModuleTree(root, fixture);
  for (let i = 0; i < bytes.length; i++) {
    demand(readonlySource(root, AUDITED_FILES[i], fixture).equals(bytes[i]),
      "installed executable bytes mismatch");
  }
  const flush = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) flush(path.join(dir, entry.name));
    }
    fsyncDir(dir);
  };
  flush(root);
}
function publish(parent, basename, payload, fixture) {
  privateDir(parent, fixture);
  const temp = path.join(parent, ".verifier-install-pending");
  const target = path.join(parent, basename);
  demand(!lexicalEntryExists(temp) && !lexicalEntryExists(target),
    "existing, linked or interrupted installation");
  if (Array.isArray(payload)) writeTree(temp, payload, fixture);
  else {
    mkdirSync(temp, { mode: 0o700 });
    writeNew(path.join(temp, payload.name), payload.bytes);
    fsyncDir(temp);
  }
  fsyncDir(parent);
  demand(!lexicalEntryExists(target), "installation destination appeared during staging");
  renameSync(temp, target);
  fsyncDir(parent);
  privateDir(target, fixture);
}

/**
 * Re-measures an independently installed verifier from the pinned bootstrap
 * authority on every invocation. Caller-provided image IDs, release bundles,
 * ledger head claims and source checkouts cannot act as trust anchors.
 *
 * This is deliberately only a read-only integrity measurement, NOT permission
 * to load Docker images, authorize a release, or import these paths later.
 * The dynamic ledger requires its own protected CAS/witness before admission.
 */
export function measureInstalledTrustedVerifierAtUseTime(request = {}) {
  const { fixture, bootstrap, operator, destinations, host } = nativeMode(request);
  const bootstrapEntry = fileURLToPath(import.meta.url);
  if (!fixture) {
    demand(bootstrapEntry === BOOTSTRAP_ENTRY &&
      isPrivate(lstatSync(bootstrapEntry, { bigint: true }), false),
    "use-time authority must execute from independently installed root bootstrap");
    privateDir(path.dirname(bootstrapEntry));
  }
  directoryEntries(bootstrap, [...EXPECTED_BOOTSTRAP, ".installation-lock"], fixture);
  const lock = path.join(bootstrap, ".installation-lock");
  privateDir(lock, fixture);
  demand(readdirSync(lock).length === 0, "installation lock contains unexpected entries");
  directoryEntries(operator, EXPECTED_OPERATOR, fixture);
  const bootstrapPolicyBytes = readPrivate(bootstrap, "bootstrap-policy.json", 16384, fixture);
  const ownerKeyBytes = readPrivate(bootstrap, "owner-key.pem", 4096, fixture);
  const trust = strictBootstrap(bootstrapPolicyBytes, ownerKeyBytes);
  demand(trust.hostIdentitySha256 === host, "use-time host differs from installed bootstrap");
  verifyNativeInterpreter(trust);
  const bootstrapCode = fixture ? readFileSync(bootstrapEntry) :
    readPrivate(path.dirname(bootstrapEntry), path.basename(bootstrapEntry), MAX_CODE);
  demand(hash(bootstrapCode) === trust.installerSha256,
    "use-time bootstrap executable differs from independently pinned installer");
  const state = json(readPrivate(bootstrap, "installation-state.json", 4096, fixture),
    ["version", "lastSequence", "status", "approvalDigest"], "installed bootstrap state", 4096);
  demand(state.version === 1 && state.status === "installed" &&
    Number.isSafeInteger(state.lastSequence) && state.lastSequence > 0 &&
    typeof state.approvalDigest === "string" && SHA.test(state.approvalDigest),
  "incomplete, replayed or unaccepted bootstrap installation state");

  const pinsBytes = readPrivate(operator, "verifier-pins.json", 16384, fixture);
  const policyBytes = readPrivate(operator, "trust-policy.json", 16384, fixture);
  const initialLedgerBytes = readPrivate(operator, "ledger.json", 1024 * 1024, fixture);
  const pins = json(pinsBytes, ["version", "mode", "files", "trustPolicySha256", "ledgerSha256"],
    "independent verifier inventory");
  checkPins(pins, policyBytes, initialLedgerBytes);
  demand(pins.files.length === 11, "the complete eleven-file reviewed closure is mandatory");
  const baseline = checkOfflineHostPolicy(policyBytes, initialLedgerBytes,
    host, trust.ownerPublicKeySha256);
  const approvalBytes = readPrivate(bootstrap, "installation-approval.json", 16384, fixture);
  const { approval, digest } = parseApproval(approvalBytes, trust, state, pinsBytes,
    policyBytes, initialLedgerBytes, host, destinations, Math.floor(Date.now() / 1000), true);
  demand(state.approvalDigest === digest && approval.sequence === state.lastSequence,
    "accepted installation state and signed approval digest or sequence mismatch");

  directoryEntries(destinations.policy, ["trust-policy.json"], fixture);
  demand(hash(readPrivate(destinations.policy, "trust-policy.json", 16384, fixture)) ===
    pins.trustPolicySha256, "installed release trust policy changed since owner approval");
  exactModuleTree(destinations.code, fixture);
  for (const file of pins.files) {
    demand(hash(readonlySource(destinations.code, file.path, fixture)) === file.sha256,
      "use-time verifier executable altered: " + file.path);
  }
  // A release legitimately appends to the installed ledger. The installation
  // signature pins the *initial* state, not a permanently frozen mutable head.
  // Only the initial prefix and structural validity are checked here. A signed
  // release decision and atomic monotonic witness remain separate obligations.
  const liveLedgerBytes = readPrivate(destinations.ledger, "ledger.json", 1024 * 1024, fixture);
  const live = checkOfflineHostPolicy(policyBytes, liveLedgerBytes,
    host, trust.ownerPublicKeySha256);
  demand(live.sequence >= baseline.sequence && baseline.ledger.entries.every((entry, i) =>
    JSON.stringify(entry) === JSON.stringify(live.ledger.entries[i])),
  "installed ledger lost or changed approved initial history");
  // Catch late replacement of protected approval/pins without ever trusting the
  // live ledger as authority over the verifier pin inventory.
  demand(hash(readPrivate(bootstrap, "installation-approval.json", 16384, fixture)) === digest &&
    hash(readPrivate(operator, "verifier-pins.json", 16384, fixture)) === hash(pinsBytes) &&
    hash(readPrivate(bootstrap, "installation-state.json", 4096, fixture)) ===
      hash(Buffer.from(JSON.stringify(state))),
  "protected trust material changed during use-time measurement");
  return Object.freeze({
    status: "INSTALLED_VERIFIER_BYTES_MEASURED_ONLY",
    installedModules: pins.files.length,
    pinsetSha256: hash(pinsBytes),
    ownerInstallationApprovalDigest: digest,
    ownerInstallationSequence: state.lastSequence,
    liveLedgerSha256: hash(liveLedgerBytes),
    liveLedgerSequence: live.sequence,
    liveLedgerStatus: liveLedgerBytes.equals(initialLedgerBytes) ?
      "INITIAL_LEDGER_INSPECTED_NOT_AUTHORIZED" : "DYNAMIC_LEDGER_INSPECTED_NOT_AUTHORIZED",
    restriction: "No release, ledger CAS, Docker image, execution or deployment authority is granted.",
  });
}

/**
 * One-time installation of independently owner-approved verifier bytes.
 * All three destinations must be initially absent. An O_EXCL lock and a
 * durable PENDING record are permanent failure latches if anything interrupts
 * the transaction. This deliberately cannot upgrade or repair a prior install.
 * In fixture mode only an isolated root tmpfs directory can be modified.
 */
export function installOwnerApprovedVerifier(request = {}, { onPhase } = {}) {
  const mode = nativeMode(request);
  const { fixture, bootstrap, source, operator, destinations, host } = mode;
  for (const d of [bootstrap, source, operator]) privateDir(d, fixture);
  for (const dest of Object.values(destinations)) {
    privateDir(path.dirname(dest), fixture);
    demand(!lexicalEntryExists(dest), "destination already installed or linked");
  }
  directoryEntries(bootstrap, EXPECTED_BOOTSTRAP, fixture);
  directoryEntries(operator, EXPECTED_OPERATOR, fixture);
  const policyBytes = readPrivate(bootstrap, "bootstrap-policy.json", 16384, fixture);
  const keyBytes = readPrivate(bootstrap, "owner-key.pem", 4096, fixture);
  const trust = strictBootstrap(policyBytes, keyBytes);
  demand(trust.hostIdentitySha256 === host, "independent bootstrap host binding invalid");
  verifyNativeInterpreter(trust);
  const ownBytes = readFileSync(fileURLToPath(import.meta.url));
  demand(hash(ownBytes) === trust.installerSha256, "bootstrap executable is not independently pinned");
  if (!fixture) {
    demand(isPrivate(lstatSync(BOOTSTRAP_ENTRY, { bigint: true }), false),
      "installer executable must be root-owned 0600");
    privateDir(path.dirname(BOOTSTRAP_ENTRY));
  }
  const state = json(readPrivate(bootstrap, "installation-state.json", 4096, fixture),
    ["version", "lastSequence", "status", "approvalDigest"], "installation state", 4096);
  demand(state.version === 1 && state.status === "ready" && state.approvalDigest === null &&
    Number.isSafeInteger(state.lastSequence) && state.lastSequence >= 0,
  "prior installation incomplete or already accepted");
  const pinsBytes = readPrivate(operator, "verifier-pins.json", 16384, fixture);
  const trustPolicyBytes = readPrivate(operator, "trust-policy.json", 16384, fixture);
  const ledgerBytes = readPrivate(operator, "ledger.json", 1024 * 1024, fixture);
  const pins = json(pinsBytes, ["version", "mode", "files", "trustPolicySha256", "ledgerSha256"],
    "operator pin inventory");
  checkPins(pins, trustPolicyBytes, ledgerBytes);
  checkOfflineHostPolicy(trustPolicyBytes, ledgerBytes, host, trust.ownerPublicKeySha256);
  const sourceBytes = pins.files.map((entry) => {
    const bytes = readonlySource(source, entry.path, fixture);
    demand(hash(bytes) === entry.sha256, "source file differs from independently pinned digest");
    return bytes;
  });
  exactModuleTree(source, fixture);
  const { approval, digest } = parseApproval(
    readPrivate(bootstrap, "installation-approval.json", 16384, fixture),
    trust, state, pinsBytes, trustPolicyBytes, ledgerBytes, host, destinations,
    Math.floor(Date.now() / 1000));
  demand(readdirSync(bootstrap).length === EXPECTED_BOOTSTRAP.length,
    "unexpected bootstrap content before acceptance");

  // No mutation is possible until all independent proofs have passed.
  // mkdir is an exclusive cross-process lock, intentionally never unlinked:
  // after SIGKILL the attempt cannot silently continue or replay.
  const lock = path.join(bootstrap, ".installation-lock");
  mkdirSync(lock, { mode: 0o700 });
  fsyncDir(bootstrap);
  durableReplace(bootstrap, "installation-state.json", Buffer.from(JSON.stringify({
    version: 1, lastSequence: approval.sequence, status: "pending", approvalDigest: digest,
  })));
  onPhase?.("pending");
  publish(path.dirname(destinations.policy), path.basename(destinations.policy),
    { name: "trust-policy.json", bytes: trustPolicyBytes }, fixture);
  onPhase?.("policyPublished");
  publish(path.dirname(destinations.ledger), path.basename(destinations.ledger),
    { name: "ledger.json", bytes: ledgerBytes }, fixture);
  onPhase?.("ledgerPublished");
  publish(path.dirname(destinations.code), path.basename(destinations.code), sourceBytes, fixture);
  onPhase?.("codePublished");
  exactModuleTree(destinations.code, fixture);
  pins.files.forEach((entry, i) => demand(
    hash(readonlySource(destinations.code, entry.path, fixture)) === entry.sha256 &&
    readonlySource(destinations.code, entry.path, fixture).equals(sourceBytes[i]),
  "installed verifier changed after publication"));
  demand(hash(readPrivate(destinations.policy, "trust-policy.json", 16384, fixture)) ===
    pins.trustPolicySha256 &&
    hash(readPrivate(destinations.ledger, "ledger.json", 1024 * 1024, fixture)) ===
    pins.ledgerSha256, "installed host policy or ledger mismatch");
  durableReplace(bootstrap, "installation-state.json", Buffer.from(JSON.stringify({
    version: 1, lastSequence: approval.sequence, status: "installed", approvalDigest: digest,
  })));
  onPhase?.("installed");
  return Object.freeze({
    status: fixture ? "DISPOSABLE_OWNER_APPROVED_INSTALL_REHEARSAL" : "OWNER_APPROVED_NATIVE_VERIFIER_INSTALLED",
    verifierFiles: pins.files.length, approvalDigest: digest, ownerSequence: approval.sequence,
  });
}

// A checkout cannot serve as a root installer through a forged --install CLI.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write("Trusted bootstrap must be independently installed and invoked by reviewed operator code.\n");
  process.exitCode = 2;
}
