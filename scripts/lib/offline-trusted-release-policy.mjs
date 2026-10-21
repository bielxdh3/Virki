import { createHash, createPublicKey } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyOfflineReleaseAttestation } from "./offline-release-attestation.mjs";

// The fixed roots are provisioned by an independent trusted operator. Neither
// the bundle, candidate manifest, environment nor request may select them.
// This foundation only reads trusted public keys and ledger. No activation.
const POLICY_DIRECTORY = "/etc/virki/offline-release";
const LEDGER_DIRECTORY = "/var/lib/virki/offline-release";
const POLICY_FILE = "trust-policy.json";
const LEDGER_FILE = "ledger.json";
const POLICY_LIMIT = 16 * 1024;
const LEDGER_LIMIT = 1024 * 1024;
const SHA = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const POLICY_FIELDS = ["version", "mode", "enabled", "ownerAssuranceAccepted", "hostIdentitySha256", "ledgerAnchorSha", "platform", "builder", "owner", "revokedPins"];
const ENTRY_FIELDS = ["sequence", "priorSha", "nextSha", "manifestSha256", "nonce", "approvalDigest"];
const FILE_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW;
const DIRECTORY_FLAGS = FILE_FLAGS | constants.O_DIRECTORY;

function refuse(message) {
  throw new Error("Trusted offline release policy refused: " + message);
}
function expect(holds, message) {
  if (!holds) refuse(message);
}
function exactRecord(value, fields, message) {
  expect(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((key, i) => Object.keys(value)[i] === key), message);
}
function parseCanonicalJson(bytes, max, fields, label) {
  expect(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= max,
    label + " bytes missing or oversized");
  let raw;
  let parsed;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(raw);
  } catch {
    refuse(label + " must be valid UTF-8 JSON");
  }
  exactRecord(parsed, fields, label + " schema invalid");
  expect(JSON.stringify(parsed) === raw, label + " is not canonical");
  return parsed;
}
function pinnedPublicKey(entry, role) {
  exactRecord(entry, ["publicKeyPem", "pinSha256"], role + " public-key schema invalid");
  expect(typeof entry.publicKeyPem === "string" && entry.publicKeyPem.length <= 2048 &&
    DIGEST.test(entry.pinSha256), role + " key material invalid");
  let key;
  try {
    key = createPublicKey(entry.publicKeyPem);
  } catch {
    refuse(role + " key cannot be decoded");
  }
  expect(key.asymmetricKeyType === "ed25519", role + " key must be Ed25519");
  const pin = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
  expect(pin === entry.pinSha256, role + " public key mismatches owner-pinned hash");
  return Object.freeze({ publicKeyPem: entry.publicKeyPem, pinSha256: pin });
}
function checkLedger(ledger) {
  expect(ledger.version === 1 && SHA.test(ledger.anchorSha) &&
    Array.isArray(ledger.entries) && ledger.entries.length <= 1024,
  "ledger version, anchor or history invalid");
  const shaSeen = new Set([ledger.anchorSha]);
  const nonceSeen = new Set();
  const manifestSeen = new Set();
  const approvalSeen = new Set();
  let head = ledger.anchorSha;
  for (const [i, entry] of ledger.entries.entries()) {
    exactRecord(entry, ENTRY_FIELDS, "ledger history entry schema invalid");
    expect(entry.sequence === i + 1 && entry.priorSha === head &&
      SHA.test(entry.nextSha) && !shaSeen.has(entry.nextSha) &&
      NONCE.test(entry.nonce) && !nonceSeen.has(entry.nonce) &&
      DIGEST.test(entry.manifestSha256) && !manifestSeen.has(entry.manifestSha256) &&
      DIGEST.test(entry.approvalDigest) && !approvalSeen.has(entry.approvalDigest),
    "ledger forged predecessor or replay");
    shaSeen.add(entry.nextSha);
    nonceSeen.add(entry.nonce);
    manifestSeen.add(entry.manifestSha256);
    approvalSeen.add(entry.approvalDigest);
    head = entry.nextSha;
  }
  return { predecessorSha: head, lastSequence: ledger.entries.length };
}

// Pure parser for unit tests. Bytes must originate from independently
// protected files: caller-supplied bytes alone NEVER establish trusted roots.
export function prepareOfflineTrustedReleasePolicy({
  policyBytes, ledgerBytes, measuredHostIdentitySha256,
} = {}) {
  expect(typeof measuredHostIdentitySha256 === "string" && DIGEST.test(measuredHostIdentitySha256),
    "independently measured host identity required");
  const policy = parseCanonicalJson(policyBytes, POLICY_LIMIT, POLICY_FIELDS, "trust policy");
  expect(policy.version === 1 && policy.mode === "offline-signed-v1" &&
    policy.enabled === true && policy.ownerAssuranceAccepted === true &&
    policy.platform === "linux/amd64", "offline policy not explicitly accepted");
  expect(policy.hostIdentitySha256 === measuredHostIdentitySha256, "trusted host marker mismatch");
  expect(SHA.test(policy.ledgerAnchorSha), "protected ledger anchor pin invalid");
  const builder = pinnedPublicKey(policy.builder, "builder");
  const owner = pinnedPublicKey(policy.owner, "owner");
  expect(builder.pinSha256 !== owner.pinSha256, "builder and owner keys must differ");
  expect(Array.isArray(policy.revokedPins) && policy.revokedPins.length <= 128 &&
    policy.revokedPins.every((pin) => typeof pin === "string" && DIGEST.test(pin)) &&
    new Set(policy.revokedPins).size === policy.revokedPins.length,
  "revocation list malformed or duplicated");
  expect(!policy.revokedPins.includes(builder.pinSha256) &&
    !policy.revokedPins.includes(owner.pinSha256), "pinned signing key is revoked");
  const ledger = parseCanonicalJson(ledgerBytes, LEDGER_LIMIT,
    ["version", "anchorSha", "entries"], "protected ledger");
  expect(ledger.anchorSha === policy.ledgerAnchorSha, "ledger does not match independently pinned anchor");
  const { predecessorSha, lastSequence } = checkLedger(ledger);
  return Object.freeze({
    trustedKeys: Object.freeze({ builder, owner }),
    hostIdentitySha256: measuredHostIdentitySha256,
    predecessorSha,
    lastSequence,
  });
}
function requireNativeTrustedHost() {
  expect(process.platform === "linux" && process.arch === "x64" &&
    typeof process.getuid === "function" && process.getuid() === 0 &&
    !/microsoft|wsl/iu.test(os.release()) &&
    constants.O_NOFOLLOW && constants.O_DIRECTORY,
  "native Linux/amd64 root-owned verifier required; WSL forbidden");
}
function trustedDirectoryBytes(directory, file, limit) {
  expect(realpathSync.native(directory) === directory, "protected path has symlinked ancestor");
  const directoryFd = openSync(directory, DIRECTORY_FLAGS);
  try {
    const directoryStat = fstatSync(directoryFd);
    expect(directoryStat.isDirectory() && directoryStat.uid === 0 &&
      (directoryStat.mode & 0o7777) === 0o700, "trusted directory must be root-owned 0700");
    const dirPath = "/proc/self/fd/" + directoryFd;
    const filenames = readdirSync(dirPath);
    expect(filenames.length === 1 && filenames[0] === file,
      "protected directory has extra, missing or interrupted files");
    const target = path.join(dirPath, file);
    const fileFd = openSync(target, FILE_FLAGS);
    try {
      const before = fstatSync(fileFd);
      const lexical = lstatSync(target);
      expect(before.isFile() && before.uid === 0 && (before.mode & 0o7777) === 0o600 &&
        before.nlink === 1 && !lexical.isSymbolicLink() &&
        lexical.dev === before.dev && lexical.ino === before.ino &&
        before.size > 0 && before.size <= limit,
      "trusted file has unsafe owner, link, mode or size");
      const bytes = readFileSync(fileFd);
      const after = fstatSync(fileFd);
      expect(bytes.length === before.size && after.dev === before.dev &&
        after.ino === before.ino && after.mtimeMs === before.mtimeMs &&
        after.size === before.size && after.mode === before.mode,
      "trusted file changed during verification");
      return bytes;
    } finally {
      closeSync(fileFd);
    }
  } finally {
    closeSync(directoryFd);
  }
}

// Installed READ-ONLY entrypoint. The candidate cannot supply trust paths.
// Both signatures are checked against independently protected owner pins.
// Return value does not authorize deployment, ledger writes or release.
export function verifyInstalledOfflineRelease({
  manifestBytes, signatures, expected, measuredHostIdentitySha256, nowSeconds,
} = {}) {
  requireNativeTrustedHost();
  const policy = trustedDirectoryBytes(POLICY_DIRECTORY, POLICY_FILE, POLICY_LIMIT);
  const ledger = trustedDirectoryBytes(LEDGER_DIRECTORY, LEDGER_FILE, LEDGER_LIMIT);
  const trust = prepareOfflineTrustedReleasePolicy({
    policyBytes: policy, ledgerBytes: ledger, measuredHostIdentitySha256,
  });
  expect(expected && typeof expected === "object" && !Array.isArray(expected) &&
    expected.hostIdentitySha256 === trust.hostIdentitySha256 &&
    expected.predecessorSha === trust.predecessorSha &&
    expected.lastSequence === trust.lastSequence,
  "independent measurements disagree with protected ledger or host");
  const attestation = verifyOfflineReleaseAttestation({
    manifestBytes,
    signatures,
    trustedKeys: trust.trustedKeys,
    expected: { ...expected,
      hostIdentitySha256: trust.hostIdentitySha256,
      predecessorSha: trust.predecessorSha,
      lastSequence: trust.lastSequence,
    },
    ...(nowSeconds === undefined ? {} : { nowSeconds }),
  });
  return Object.freeze({
    verifiedManifestSha256: attestation.manifestSha256,
    sourceSha: attestation.sourceSha,
    predecessorSha: attestation.predecessorSha,
    sequence: attestation.sequence,
    expiresAt: attestation.expiresAt,
    limitation: "Signatures only: provenance, atomic ledger acceptance and activation remain separate.",
  });
}
