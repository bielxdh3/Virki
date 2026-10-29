import { createHash, createPublicKey, verify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";

// Independently owner-installed, never copied from the signed candidate.
const AUTHORITY_ROOT = "/etc/virki/offline-transfer";
const AUTHORITY_FILES = Object.freeze(["permit.json", "permit.sig", "ssh-identity"]);
const FIELDS = Object.freeze([
  "version", "mode", "sourceSha", "manifestSha256", "envelopeSha256", "sshAlias",
  "host", "port", "sshUser", "knownHostsSha256", "clientSshKeyPinSha256",
  "receiverPath", "stageRoot", "nonce", "expiresAt",
]);
const DOMAIN = Buffer.from("VIRKI_OFFLINE_SSH_TRANSFER_PERMIT_V1\0");
const HEX = /^[a-f0-9]{64}$/u;
const SOURCE = /^[a-f0-9]{40}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
export const OFFLINE_SSH_LOGIN = "virki-offline";
function need(value, reason) {
  if (!value) throw new Error("Offline SSH permit refused: " + reason);
}
function same(a, b) {
  return ["dev", "ino", "uid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((name) => a[name] === b[name]);
}
function readRootAuthority() {
  need(process.platform === "linux" && process.getuid?.() === 0 &&
    constants.O_DIRECTORY && constants.O_NOFOLLOW && constants.O_NONBLOCK,
  "root Linux operator required");
  need(realpathSync.native(AUTHORITY_ROOT) === AUTHORITY_ROOT, "authority symlinked ancestor");
  const dirBefore = lstatSync(AUTHORITY_ROOT, { bigint: true });
  need(dirBefore.isDirectory() && dirBefore.uid === 0n &&
    (dirBefore.mode & 0o7777n) === 0o700n, "owner-protected 0700 authority root absent");
  const dirfd = openSync(AUTHORITY_ROOT, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const dirSt = fstatSync(dirfd, { bigint: true });
    need(dirSt.ino === dirBefore.ino && dirSt.dev === dirBefore.dev &&
      dirSt.mode === dirBefore.mode && dirSt.uid === dirBefore.uid,
    "authority directory changed during open");
    const dirPath = "/proc/self/fd/" + dirfd;
    need(JSON.stringify(readdirSync(dirPath).sort()) === JSON.stringify([...AUTHORITY_FILES].sort()),
      "authority root has missing or foreign files");
    const files = {};
    for (const filename of AUTHORITY_FILES) {
      const pathname = path.join(dirPath, filename);
      const before = lstatSync(pathname, { bigint: true });
      need(before.isFile() && before.uid === 0n && before.nlink === 1n &&
        (before.mode & 0o7777n) === 0o600n && before.size > 0n &&
        before.size <= 16384n, "authority file not root-owned private: " + filename);
      const fd = openSync(pathname, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        need(same(before, fstatSync(fd, { bigint: true })), "authority inode changed before read");
        // Do not materialize the SSH private identity in JavaScript memory.
        // The protected ssh-keygen executable derives only its public key.
        if (filename !== "ssh-identity") files[filename] = readFileSync(fd);
        need(same(before, fstatSync(fd, { bigint: true })) &&
          same(before, lstatSync(pathname, { bigint: true })),
        "authority inode changed during read");
      } finally { closeSync(fd); }
    }
    need(dirSt.ino === fstatSync(dirfd, { bigint: true }).ino &&
      dirSt.dev === lstatSync(AUTHORITY_ROOT, { bigint: true }).dev,
    "authority root replaced during read");
    return Object.freeze(files);
  } finally { closeSync(dirfd); }
}
export function parsePinnedOpenSshEd25519PublicKey(output) {
  need(typeof output === "string" && output.length <= 1024, "SSH public output malformed");
  const parts = output.trim().split(/\s+/u);
  need(parts.length >= 2 && parts[0] === "ssh-ed25519" &&
    /^[A-Za-z0-9+/]+={0,2}$/u.test(parts[1]), "SSH identity must be Ed25519");
  const blob = Buffer.from(parts[1], "base64");
  const type = Buffer.from("ssh-ed25519");
  need(blob.length === 4 + type.length + 4 + 32 &&
    blob.readUInt32BE(0) === type.length &&
    blob.subarray(4, 4 + type.length).equals(type) &&
    blob.readUInt32BE(4 + type.length) === 32,
  "malformed Ed25519 OpenSSH public key");
  const publicDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    blob.subarray(4 + type.length + 4),
  ]);
  return createHash("sha256").update(publicDer).digest("hex");
}
export function deriveOpenSshPrivateIdentityPin(identityPath) {
  // Node's createPrivateKey does not accept the normal OPENSSH PRIVATE KEY
  // Ed25519 format. Ask the independently installed root-owned ssh-keygen
  // to derive the public key without reading the private bytes into JS.
  need(typeof identityPath === "string" && path.isAbsolute(identityPath) &&
    path.normalize(identityPath) === identityPath && identityPath.length <= 4096 &&
    realpathSync.native(identityPath) === identityPath,
  "noncanonical or aliased SSH private identity");
  const original = lstatSync(identityPath, { bigint: true });
  need(original.isFile() && original.uid === BigInt(process.getuid?.() ?? -1) &&
    original.nlink === 1n && (original.mode & 0o7777n) === 0o600n &&
    original.size > 0n && original.size <= 16384n,
  "unsafe SSH private identity inode");
  const binary = "/usr/bin/ssh-keygen";
  const stat = lstatSync(binary);
  need(stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0,
  "protected system SSH key reader unavailable");
  const result = spawnSync(binary, ["-y", "-P", "", "-f", identityPath], {
    shell: false, input: "", encoding: "utf8", maxBuffer: 1024,
    timeout: 10_000, stdio: ["pipe", "pipe", "ignore"],
  });
  need(result.status === 0 && !result.error && !result.signal,
  "root SSH identity cannot derive public key");
  need(same(original, lstatSync(identityPath, { bigint: true })),
  "SSH identity changed while deriving public key");
  return parsePinnedOpenSshEd25519PublicKey(result.stdout);
}

/** Pure signature verifier for adversarial tests; caller bytes are never independent trust. */
export function verifyOwnerSignedOfflineSshPermit({
  permitBytes, signatureBytes, ownerPublicKeyPem, clientSshKeyPinSha256, plan,
  config, knownHostsSha256, now = Math.floor(Date.now() / 1000),
} = {}) {
  need(Buffer.isBuffer(permitBytes) && permitBytes.length > 0 && permitBytes.length <= 4096,
    "permit length invalid");
  need(Buffer.isBuffer(signatureBytes) && /^[A-Za-z0-9+/]{86}==$/u.test(signatureBytes.toString("ascii")),
    "permit signature envelope invalid");
  let parsed;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(permitBytes)); }
  catch { need(false, "malformed permit JSON"); }
  need(parsed && typeof parsed === "object" && !Array.isArray(parsed) &&
    Object.keys(parsed).length === FIELDS.length &&
    FIELDS.every((key, index) => Object.keys(parsed)[index] === key) &&
    Buffer.from(JSON.stringify(parsed)).equals(permitBytes), "noncanonical permit fields");
  need(parsed.version === 1 && parsed.mode === "owner-signed-ssh-stage-v1" &&
    SOURCE.test(parsed.sourceSha) && HEX.test(parsed.manifestSha256) &&
    HEX.test(parsed.envelopeSha256) && HEX.test(parsed.knownHostsSha256) &&
    HEX.test(parsed.clientSshKeyPinSha256) && NONCE.test(parsed.nonce) &&
    Number.isSafeInteger(parsed.expiresAt) && parsed.expiresAt > now &&
    parsed.expiresAt <= now + 600, "permit expired or invalid");
  need(plan && plan.status === "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED" &&
    plan.deployAuthorized === false && plan.transferAuthorized === false &&
    parsed.sourceSha === plan.revision &&
    parsed.manifestSha256 === plan.signedManifestSha256 &&
    parsed.envelopeSha256 === plan.signedEnvelopeSha256,
  "permit does not bind exact signed candidate and prior read-only preflight");
  need(config && config.sshUser === OFFLINE_SSH_LOGIN &&
    parsed.host === config.host && parsed.port === Number(config.port) &&
    parsed.sshAlias === config.sshAlias && parsed.sshUser === config.sshUser &&
    parsed.knownHostsSha256 === knownHostsSha256 &&
    parsed.clientSshKeyPinSha256 === clientSshKeyPinSha256 &&
    parsed.receiverPath === "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs" &&
    parsed.stageRoot === "/var/lib/virki/offline-staging",
  "permit differs from owner-pinned SSH host, fixed receiver account or private stage");
  need(typeof ownerPublicKeyPem === "string", "owner public-key pin absent");
  const owner = createPublicKey(ownerPublicKeyPem);
  need(owner.asymmetricKeyType === "ed25519", "owner signing key not Ed25519");
  const signature = Buffer.from(signatureBytes.toString("ascii"), "base64");
  need(signature.length === 64 &&
    verify(null, Buffer.concat([DOMAIN, permitBytes]), owner, signature),
  "owner Ed25519 transfer permission invalid");
  return Object.freeze({
    status: "OWNER_APPROVED_EXACT_SSH_TRANSFER",
    manifestSha256: parsed.manifestSha256,
    transferAuthorized: true, deployAuthorized: false,
  });
}

/** Native root verification against independently installed, owner-protected host pins. */
export function verifyRemoteOfflineTransferPermit({
  permitBytes, signatureBytes, hostPolicy, manifestSha256, envelopeSha256,
  now = Math.floor(Date.now() / 1000),
}) {
  need(hostPolicy && typeof hostPolicy === "object" &&
    hostPolicy.version === 1 && hostPolicy.mode === "offline-host-transfer-v1" &&
    SOURCE.test(hostPolicy.expectedSourceSha) &&
    HEX.test(hostPolicy.knownHostsSha256) &&
    HEX.test(hostPolicy.clientSshKeyPinSha256) &&
    typeof hostPolicy.ownerPublicKeyPem === "string" &&
    hostPolicy.sshUser === OFFLINE_SSH_LOGIN &&
    HEX.test(manifestSha256) && HEX.test(envelopeSha256),
  "independently installed remote approval policy missing");
  verifyOwnerSignedOfflineSshPermit({
    permitBytes, signatureBytes, ownerPublicKeyPem: hostPolicy.ownerPublicKeyPem,
    clientSshKeyPinSha256: hostPolicy.clientSshKeyPinSha256,
    knownHostsSha256: hostPolicy.knownHostsSha256, now,
    config: {
      sshAlias: hostPolicy.sshAlias, host: hostPolicy.host,
      port: hostPolicy.port, sshUser: hostPolicy.sshUser,
    },
    plan: {
      status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED",
      revision: hostPolicy.expectedSourceSha,
      signedManifestSha256: manifestSha256, signedEnvelopeSha256: envelopeSha256,
      transferAuthorized: false, deployAuthorized: false,
    },
  });
  return Object.freeze({
    nonce: JSON.parse(permitBytes.toString("utf8")).nonce,
    manifestSha256, envelopeSha256,
  });
}

/** Root trust roots are read afresh immediately before the SSH process starts. */
export function requireIndependentlySignedOfflineSshTransfer({ authority, plan }) {
  need(authority && authority.owner && authority.config && authority.policy &&
    authority.knownHostsSha256 === authority.policy.knownHostsSha256,
  "operator trust root incomplete");
  const bytes = readRootAuthority();
  const permit = verifyOwnerSignedOfflineSshPermit({
    permitBytes: bytes["permit.json"], signatureBytes: bytes["permit.sig"],
    ownerPublicKeyPem: authority.owner.publicKeyPem,
    clientSshKeyPinSha256: deriveOpenSshPrivateIdentityPin(
      path.join(AUTHORITY_ROOT, "ssh-identity")),
    plan, config: authority.config, knownHostsSha256: authority.knownHostsSha256,
  });
  return Object.freeze({
    ...permit, permitBytes: bytes["permit.json"], signatureBytes: bytes["permit.sig"],
  });
}
