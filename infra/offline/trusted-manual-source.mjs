import { createHash, createPublicKey, verify } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateOfflineCiEvidence } from "../../scripts/lib/offline-ci-evidence.mjs";
import { inspectUntrustedOfflineCandidate, verifyTrustedHostOfflineCandidate } from "./trusted-host-entry.mjs";
import { inspectManualGitSourceForPreview } from "./trusted-source-git.mjs";

// This is a DIFFERENT, manual-only trust root. No hosted CI, main, origin/main,
// manifest, upload or CLI may provision these files. The native host operator
// must independently audit and install the entire transitive verifier closure.
const INSTALLED_ENTRY = "/usr/local/lib/virki/offline-release/infra/offline/trusted-manual-source.mjs";
const TRUST_ROOT = "/etc/virki/manual-source";
const OWNER_SPKI_PIN = "/etc/virki/manual-source-owner.spki.sha256";
const COMMIT_PIN = "/etc/virki/manual-source-commit.sha";
const TRUSTED_GIT = "/var/lib/virki/offline-source/trusted.git";
const FILES = ["approval.json", "counter.json", "owner-key.json"];
const DOMAIN = Buffer.from("VIRKI_MANUAL_ROOT_SOURCE_APPROVAL_V1\0");
const REPO = "https://github.com/bielxdh3/Virki.git";
const MODE = "owner-manual-source-sha-v1";
const DOCUMENT = ["version", "mode", "repository", "sourceSha", "ciSourceBranch",
  "sourceArchiveSha256", "ciReportSha256", "runtimeImageId", "migratorImageId",
  "hostIdentitySha256", "sequence", "validFromSeconds", "validUntilSeconds"];
const OWNER = ["version", "keyId", "publicKeyPem"];
const COUNTER = ["version", "lastAcceptedSequence", "approvedSequence",
  "revokedKeyIds", "revokedPinsSha256"];
const SHA = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const IMAGE = /^sha256:[a-f0-9]{64}$/u;
const KEY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const SIG = /^[A-Za-z0-9+/]{86}==$/u;
const BRANCH = /^(?!\/)(?!.*(?:\/\/|\.\.))[A-Za-z0-9._/-]{1,200}$/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function refuse(reason) { throw new Error("Manual root source trust refused: " + reason); }
function check(value, reason) { if (!value) refuse(reason); }
function exact(value, fields, label) {
  check(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((key, i) => Object.keys(value)[i] === key), label + " has invalid fields");
}
function canonicalJson(bytes, fields, label, maxSize = 8192) {
  check(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= maxSize,
    label + " bytes invalid");
  let decoded, object;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    object = JSON.parse(decoded);
  } catch { refuse(label + " is not UTF-8 JSON"); }
  exact(object, fields, label);
  check(JSON.stringify(object) === decoded, label + " is not canonical JSON");
  return object;
}
function metadataEqual(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function absolute(location) {
  check(typeof location === "string" && location.length > 1 && location.length <= 4096 &&
    path.isAbsolute(location) && path.normalize(location) === location &&
    location !== path.parse(location).root && !location.includes("\0"),
  "noncanonical protected path");
}
function rootAncestors(location) {
  absolute(location);
  check(realpathSync.native(location) === location, "protected ancestor symlink");
  let cursor = location;
  for (;;) {
    const stat = lstatSync(cursor, { bigint: true });
    check(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0n &&
      (stat.mode & 0o022n) === 0n, "protected ancestor not root-owned or is writable");
    const parent = path.dirname(cursor);
    if (cursor === parent) break;
    cursor = parent;
  }
}
function privateRoot(location) {
  rootAncestors(location);
  const stat = lstatSync(location, { bigint: true });
  check((stat.mode & 0o7777n) === 0o700n, "root trust directory must be 0700");
  return stat;
}
function rootFile(location, maxBytes) {
  absolute(location);
  rootAncestors(path.dirname(location));
  const stat = lstatSync(location, { bigint: true });
  check(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0n &&
    stat.nlink === 1n && [0o400n, 0o600n].includes(stat.mode & 0o7777n) &&
    stat.size > 0n && stat.size <= BigInt(maxBytes), "unsafe protected file metadata");
  const fd = openSync(location, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check(metadataEqual(stat, fstatSync(fd, { bigint: true })), "protected file changed at open");
    const bytes = readFileSync(fd);
    check(bytes.length === Number(stat.size) &&
      metadataEqual(stat, fstatSync(fd, { bigint: true })) &&
      metadataEqual(stat, lstatSync(location, { bigint: true })),
    "protected file changed while reading");
    return bytes;
  } finally { closeSync(fd); }
}
function pinnedDirectoryFile(rootFd, name, maxBytes) {
  // /proc/self/fd/N is intentionally a kernel-backed symlink to the already
  // verified root directory inode, NOT an untrusted path ancestor.
  check(FILES.includes(name), "unexpected root trust filename");
  const location = "/proc/self/fd/" + rootFd + "/" + name;
  const stat = lstatSync(location, { bigint: true });
  check(stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0n &&
    stat.nlink === 1n && (stat.mode & 0o7777n) === 0o600n &&
    stat.size > 0n && stat.size <= BigInt(maxBytes), "unsafe pinned trust file");
  const fd = openSync(location, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check(metadataEqual(stat, fstatSync(fd, { bigint: true })), "pinned file swapped at open");
    const bytes = readFileSync(fd);
    check(bytes.length === Number(stat.size) &&
      metadataEqual(stat, fstatSync(fd, { bigint: true })) &&
      metadataEqual(stat, lstatSync(location, { bigint: true })),
    "pinned file mutated during read");
    return bytes;
  } finally { closeSync(fd); }
}
function pinnedText(location, regex) {
  const bytes = rootFile(location, 128);
  const text = bytes.toString("ascii");
  check(Buffer.from(text, "ascii").equals(bytes) && text.endsWith("\n") &&
    regex.test(text.slice(0, -1)), "invalid independent pin syntax");
  return text.slice(0, -1);
}
function readRootTrust(paths) {
  const rootBefore = privateRoot(paths.trustDirectory);
  check(JSON.stringify(readdirSync(paths.trustDirectory).sort()) ===
    JSON.stringify([...FILES].sort()), "missing or extra root trust files");
  const directory = openSync(paths.trustDirectory, constants.O_RDONLY |
    constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    check(metadataEqual(rootBefore, fstatSync(directory, { bigint: true })),
      "root trust changed during open");
    const pinned = "/proc/self/fd/" + directory;
    const bytes = Object.fromEntries(FILES.map((file) =>
      [file, pinnedDirectoryFile(directory, file, 8192)]));
    check(metadataEqual(rootBefore, fstatSync(directory, { bigint: true })) &&
      metadataEqual(rootBefore, lstatSync(paths.trustDirectory, { bigint: true })) &&
      JSON.stringify(readdirSync(pinned).sort()) === JSON.stringify([...FILES].sort()),
    "root trust changed during verification");
    return bytes;
  } finally { closeSync(directory); }
}
function revocations(items, regex) {
  check(Array.isArray(items) && items.length <= 128 &&
    items.every((value) => typeof value === "string" && regex.test(value)) &&
    new Set(items).size === items.length, "invalid root-installed revocation list");
}

/** Exact signed-authorization parser. This is a PURE verification primitive,
 * not an authority source: only the native installed entry below chooses roots.
 */
export function inspectManualOwnerApproval({ ownerBytes, approvalBytes, counterBytes,
  independentlyPinnedOwnerSpkiSha256, independentlyPinnedCommitSha, candidate, nowSeconds,
} = {}) {
  const owner = canonicalJson(ownerBytes, OWNER, "owner key");
  const counter = canonicalJson(counterBytes, COUNTER, "independent approval counter");
  const approval = canonicalJson(approvalBytes, ["document", "signatureBase64"], "owner approval");
  exact(approval.document, DOCUMENT, "signed owner document");
  check(owner.version === 1 && KEY.test(owner.keyId) &&
    typeof owner.publicKeyPem === "string" && owner.publicKeyPem.length <= 2048 &&
    HASH.test(independentlyPinnedOwnerSpkiSha256) &&
    SHA.test(independentlyPinnedCommitSha), "owner key or independent source pins missing");
  let key;
  try { key = createPublicKey(owner.publicKeyPem); }
  catch { refuse("invalid independently installed owner key"); }
  const spki = sha256(key.export({ format: "der", type: "spki" }));
  check(key.asymmetricKeyType === "ed25519" &&
    spki === independentlyPinnedOwnerSpkiSha256, "owner identity differs from external pin");
  revocations(counter.revokedKeyIds, KEY);
  revocations(counter.revokedPinsSha256, HASH);
  check(counter.version === 1 &&
    Number.isSafeInteger(counter.lastAcceptedSequence) && counter.lastAcceptedSequence >= 0 &&
    Number.isSafeInteger(counter.approvedSequence) &&
    counter.approvedSequence === counter.lastAcceptedSequence + 1 &&
    !counter.revokedKeyIds.includes(owner.keyId) &&
    !counter.revokedPinsSha256.includes(spki),
  "owner key revoked or independent approval counter invalid");
  const doc = approval.document;
  check(doc.version === 1 && doc.mode === MODE && doc.repository === REPO &&
    SHA.test(doc.sourceSha) && doc.sourceSha === independentlyPinnedCommitSha &&
    BRANCH.test(doc.ciSourceBranch) && doc.ciSourceBranch !== "main" &&
    HASH.test(doc.sourceArchiveSha256) &&
    HASH.test(doc.ciReportSha256) && IMAGE.test(doc.runtimeImageId) &&
    IMAGE.test(doc.migratorImageId) && doc.runtimeImageId !== doc.migratorImageId &&
    HASH.test(doc.hostIdentitySha256) && doc.sequence === counter.approvedSequence &&
    Number.isSafeInteger(doc.validFromSeconds) && doc.validFromSeconds > 0 &&
    Number.isSafeInteger(doc.validUntilSeconds) &&
    doc.validUntilSeconds > doc.validFromSeconds &&
    doc.validUntilSeconds - doc.validFromSeconds <= 86400 &&
    Number.isSafeInteger(nowSeconds) &&
    nowSeconds >= doc.validFromSeconds && nowSeconds < doc.validUntilSeconds,
  "signed owner approval expired, out of sequence or malformed");
  check(SIG.test(approval.signatureBase64) &&
    Buffer.from(approval.signatureBase64, "base64").toString("base64") === approval.signatureBase64 &&
    verify(null, Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(doc))]), key,
      Buffer.from(approval.signatureBase64, "base64")),
  "owner Ed25519 signature is invalid");
  exact(candidate, ["sourceSha", "sourceArchiveSha256", "ciReportSha256",
    "runtimeImageId", "migratorImageId", "hostIdentitySha256"], "candidate claims");
  check(doc.sourceSha === candidate.sourceSha &&
    doc.sourceArchiveSha256 === candidate.sourceArchiveSha256 &&
    doc.ciReportSha256 === candidate.ciReportSha256 &&
    doc.runtimeImageId === candidate.runtimeImageId &&
    doc.migratorImageId === candidate.migratorImageId &&
    doc.hostIdentitySha256 === candidate.hostIdentitySha256,
  "candidate source, images, CI digest or host mismatch signed owner approval");
  return Object.freeze({ sourceSha: doc.sourceSha, ciSourceBranch: doc.ciSourceBranch,
    ciReportSha256: doc.ciReportSha256, sequence: doc.sequence,
    expiresAt: doc.validUntilSeconds, deployAuthorized: false });
}

/** ROOT-owned rehearsal with explicit paths; NEVER usable to authorize release.
 * A native verifier must provide fixed, owner-installed paths and has no
 * caller-specified key, approval, counter, Git root or SHA pin.
 */
export async function inspectManualRootSourceForPreview({ trustDirectory, ownerPinPath,
  commitPinPath, trustedGitDirectory, archivePath, archiveSha256, archiveSizeBytes,
  candidate, nowSeconds,
} = {}) {
  check(process.platform === "linux" && process.getuid?.() === 0,
    "Linux root is required for preview");
  check(typeof trustDirectory === "string" && typeof ownerPinPath === "string" &&
    typeof commitPinPath === "string" && typeof trustedGitDirectory === "string" &&
    typeof archivePath === "string", "manual trust paths missing");
  check(candidate && archiveSha256 === candidate.sourceArchiveSha256 &&
    candidate.sourceSha && Number.isSafeInteger(archiveSizeBytes),
  "source archive claims differ from owner-approved manifest");
  const trusted = readRootTrust({ trustDirectory });
  const ownerPin = pinnedText(ownerPinPath, HASH);
  const sourcePin = pinnedText(commitPinPath, SHA);
  const approved = inspectManualOwnerApproval({
    ownerBytes: trusted["owner-key.json"], approvalBytes: trusted["approval.json"],
    counterBytes: trusted["counter.json"], independentlyPinnedOwnerSpkiSha256: ownerPin,
    independentlyPinnedCommitSha: sourcePin, candidate, nowSeconds,
  });
  // Verify the entire root-owned source TAR against exact Git commit objects.
  // Crucially this does NOT read or change the hosted main symbolic ref.
  const source = await inspectManualGitSourceForPreview({
    sourceArchivePath: archivePath, candidateSourceSha: approved.sourceSha,
    candidateArchiveSha256: archiveSha256, candidateArchiveSizeBytes: archiveSizeBytes,
    trustedGitDirectory, trustedShaPinPath: commitPinPath,
  });
  check(source.sourceSha === approved.sourceSha &&
    source.archiveSha256 === archiveSha256,
  "verified Git archive differs from owner-approved source");
  return Object.freeze({ status: "OWNER_MANUAL_SOURCE_PREVIEW_ONLY",
    deployAuthorized: false, sourceSha: source.sourceSha,
    archiveSha256: source.archiveSha256, ciSourceBranch: approved.ciSourceBranch,
    sequence: approved.sequence });
}

function requireNativeInstalled() {
  check(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release()) &&
    fileURLToPath(import.meta.url) === INSTALLED_ENTRY &&
    realpathSync.native(INSTALLED_ENTRY) === INSTALLED_ENTRY,
  "audited owner-installed native Linux root verifier required");
  rootAncestors(path.dirname(INSTALLED_ENTRY));
  const stat = lstatSync(INSTALLED_ENTRY, { bigint: true });
  check(stat.isFile() && stat.uid === 0n && stat.nlink === 1n &&
    (stat.mode & 0o022n) === 0n, "installed verifier file not root protected");
}
function safeCiReport(filename, digest, sha, branch) {
  const before = lstatSync(filename, { bigint: true });
  check(before.isFile() && before.uid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o600n &&
    before.size > 0n && before.size <= 65536n, "unsafe candidate CI report");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check(metadataEqual(before, fstatSync(fd, { bigint: true })), "CI report swapped");
    const bytes = readFileSync(fd);
    check(sha256(bytes) === digest &&
      metadataEqual(before, fstatSync(fd, { bigint: true })) &&
      metadataEqual(before, lstatSync(filename, { bigint: true })),
    "CI report differs from signed owner digest");
    validateOfflineCiEvidence(bytes, sha, branch, { requireOfflineFixture: true });
  } finally { closeSync(fd); }
}
/** Installed native, READ-ONLY source verification, not release coordination.
 * Output does NOT bypass independent manifest signatures, runner provenance,
 * acceptance ledger, remote monotonic witness or production safety checks.
 */
export async function verifyInstalledManualRootSource(request = {}) {
  requireNativeInstalled();
  exact(request, ["candidateDirectory"], "installed manual request");
  const first = await inspectUntrustedOfflineCandidate(request);
  const expected = first.expected;
  // The source permit is not a substitute for the OTHER owner/builder-signed
  // release manifest, independently measured machine identity or OCI image
  // revisions. Reuse the installed native host verifier for all three.
  const signed = await verifyTrustedHostOfflineCandidate(request);
  check(signed.status === "INSPECTED_ONLY_RELEASE_BLOCKED" &&
    signed.deployAuthorized === false &&
    signed.sourceSha === expected.sourceSha &&
    signed.verifiedManifestSha256 === first.manifestDigest &&
    signed.checkedImageRoles.length === 2 &&
    signed.checkedImageRoles.includes("runtime") &&
    signed.checkedImageRoles.includes("migrator"),
  "independent signed manifest, machine identity or image validation failed");
  const preview = await inspectManualRootSourceForPreview({
    trustDirectory: TRUST_ROOT, ownerPinPath: OWNER_SPKI_PIN, commitPinPath: COMMIT_PIN,
    trustedGitDirectory: TRUSTED_GIT, archivePath: first.archivePaths.source,
    archiveSha256: expected.sourceArchiveSha256,
    archiveSizeBytes: expected.sourceArchiveSizeBytes,
    candidate: { sourceSha: expected.sourceSha,
      sourceArchiveSha256: expected.sourceArchiveSha256,
      ciReportSha256: expected.ciReportSha256,
      runtimeImageId: expected.runtimeImage.imageId,
      migratorImageId: expected.migratorImage.imageId,
      hostIdentitySha256: expected.hostIdentitySha256 },
    nowSeconds: Math.floor(Date.now() / 1000),
  });
  safeCiReport(path.join(request.candidateDirectory, "ci-report.json"),
    expected.ciReportSha256, expected.sourceSha, preview.ciSourceBranch);
  const again = await inspectUntrustedOfflineCandidate(request);
  check(first.manifestDigest === again.manifestDigest &&
    first.manifestBytes.equals(again.manifestBytes) &&
    JSON.stringify(first.expected) === JSON.stringify(again.expected) &&
    first.signatures.owner === again.signatures.owner &&
    first.signatures.builder === again.signatures.builder,
  "candidate changed across inspections");
  return Object.freeze({ ...preview, status: "OWNER_MANUAL_SOURCE_INSPECTED_RELEASE_BLOCKED",
    deployAuthorized: false });
}
