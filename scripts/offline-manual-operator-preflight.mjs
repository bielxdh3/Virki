import { createHash, createPublicKey, verify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectOfflineHostReadiness, OFFLINE_COMPONENTS } from "./offline-host-readiness.mjs";

// Manual operator preflight is a NON-AUTHORIZING, READ-ONLY preparation check.
// No installer, generated signer, generic command, SSH host override or secret
// reader is exposed. An owner must independently establish and protect the
// files, key custody and remote native host before invoking this inspection.
const DOMAIN = "VIRKI_MANUAL_OFFLINE_PROVISION_CHECKLIST_V1\0";
const FILES = Object.freeze([
  "checklist-signature.json", "checklist.json", "identity.json", "known_hosts",
  "owner-pin.json", "owner-public.pem", "ssh-identity",
]);
const BLOCKED = Object.freeze({ status: "MANUAL_OPERATOR_PREFLIGHT_BLOCKED",
  transferAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false });
const SHA40 = /^[0-9a-f]{40}$/u;
const SHA64 = /^[0-9a-f]{64}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const safeHost = (v) => typeof v === "string" && /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u.test(v) &&
  !v.includes("..") && !v.startsWith("-");
const safeUser = (v) => typeof v === "string" && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u.test(v);
const sha = (data) => createHash("sha256").update(data).digest("hex");
function check(value) { if (!value) throw new Error("manual operator preflight refused"); }
function exact(value, fields) {
  check(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(fields));
}
function regularPrivate(st) {
  check(st.isFile() && !st.isSymbolicLink() && st.nlink === 1n &&
    st.uid === BigInt(process.getuid()) && (st.mode & 0o7777n) === 0o600n);
}
function same(a, b) {
  return ["dev", "ino", "mode", "uid", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((field) => a[field] === b[field]);
}
function checkedDirectory(dir) {
  check(process.platform === "linux" && typeof process.getuid === "function" &&
    typeof dir === "string" && path.isAbsolute(dir) && path.normalize(dir) === dir &&
    realpathSync.native(dir) === dir);
  const st = lstatSync(dir, { bigint: true });
  check(st.isDirectory() && !st.isSymbolicLink() && st.uid === BigInt(process.getuid()) &&
    (st.mode & 0o7777n) === 0o700n);
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  check(same(st, fstatSync(fd, { bigint: true })));
  return fd;
}
function readOwnerFile(dirfd, filename, max = 8192) {
  const anchored = `/proc/self/fd/${dirfd}/${filename}`;
  const before = lstatSync(anchored, { bigint: true });
  regularPrivate(before);
  check(before.size > 0n && before.size <= BigInt(max));
  const fd = openSync(anchored, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    check(same(before, fstatSync(fd, { bigint: true })));
    const bytes = readFileSync(fd);
    check(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(anchored, { bigint: true })));
    return bytes;
  } finally { closeSync(fd); }
}
function canonicalJson(bytes, fields) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const object = JSON.parse(text);
  exact(object, fields);
  check(JSON.stringify(object) === text);
  return object;
}
function validateHostKey(value) {
  check(typeof value === "string" && /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/u.test(value));
  const raw = value.split(" ")[1];
  const blob = Buffer.from(raw, "base64");
  check(blob.toString("base64") === raw && blob.length === 51 &&
    blob.readUInt32BE(0) === 11 && blob.toString("ascii", 4, 15) === "ssh-ed25519" &&
    blob.readUInt32BE(15) === 32);
}
function inspectOperatorAssets(operatorDirectory, now) {
  const fd = checkedDirectory(operatorDirectory);
  try {
    const anchored = `/proc/self/fd/${fd}`;
    check(JSON.stringify(readdirSync(anchored).sort()) === JSON.stringify(FILES));
    const bytes = new Map(FILES.filter((name) => name !== "ssh-identity")
      .map((name) => [name, readOwnerFile(fd, name)]));
    const sshKey = lstatSync(`${anchored}/ssh-identity`, { bigint: true });
    regularPrivate(sshKey);
    check(sshKey.size > 0n && sshKey.size <= 16384n);
    const identity = canonicalJson(bytes.get("identity.json"), [
      "version", "mode", "host", "port", "sshUser", "hostKeyAlias", "sshHostPublicKey", "expectedSourceSha",
    ]);
    check(identity.version === 1 && identity.mode === "virki-manual-operator-identity-v1" &&
      safeHost(identity.host) && Number.isSafeInteger(identity.port) && identity.port >= 1 &&
      identity.port <= 65535 && safeUser(identity.sshUser) && safeHost(identity.hostKeyAlias) &&
      SHA40.test(identity.expectedSourceSha));
    validateHostKey(identity.sshHostPublicKey);
    check(bytes.get("known_hosts").equals(Buffer.from(`${identity.hostKeyAlias} ${identity.sshHostPublicKey}\n`)));
    const pin = canonicalJson(bytes.get("owner-pin.json"), ["version", "mode", "ownerSignerSpkiSha256"]);
    check(pin.version === 1 && pin.mode === "separately-provisioned-owner-pin-v1" &&
      SHA64.test(pin.ownerSignerSpkiSha256));
    const key = createPublicKey(bytes.get("owner-public.pem"));
    check(key.asymmetricKeyType === "ed25519" &&
      sha(key.export({ format: "der", type: "spki" })) === pin.ownerSignerSpkiSha256);
    const checklist = canonicalJson(bytes.get("checklist.json"), [
      "version", "mode", "checklistId", "identitySha256", "sourceSha", "issuedAt", "expiresAt", "components",
    ]);
    check(checklist.version === 1 && checklist.mode === "virki-manual-provision-checklist-v1" &&
      SHA64.test(checklist.checklistId) && SHA64.test(checklist.identitySha256) &&
      checklist.identitySha256 === sha(bytes.get("identity.json")) &&
      checklist.sourceSha === identity.expectedSourceSha &&
      Number.isSafeInteger(checklist.issuedAt) && Number.isSafeInteger(checklist.expiresAt) &&
      checklist.issuedAt <= now && now < checklist.expiresAt &&
      checklist.expiresAt - checklist.issuedAt <= 300 &&
      JSON.stringify(checklist.components) === JSON.stringify(OFFLINE_COMPONENTS));
    const signature = canonicalJson(bytes.get("checklist-signature.json"), ["version", "signature"]);
    check(signature.version === 1 && B64.test(signature.signature) &&
      Buffer.from(signature.signature, "base64").toString("base64") === signature.signature &&
      verify(null, Buffer.concat([Buffer.from(DOMAIN), bytes.get("checklist.json")]), key,
        Buffer.from(signature.signature, "base64")));
    // Two independent syntactic checks: the signer binds the exact identity
    // and the SSH host-key file contains that exact approved Ed25519 key.
    check(same(sshKey, lstatSync(`${anchored}/ssh-identity`, { bigint: true })));
    const immutableDigest = sha(Buffer.concat(FILES.filter((name) => name !== "ssh-identity")
      .map((name) => Buffer.concat([Buffer.from(name + "\0"), bytes.get(name)]))));
    check(same(fstatSync(fd, { bigint: true }), lstatSync(operatorDirectory, { bigint: true })));
    return { identity, immutableDigest, checklistId: checklist.checklistId };
  } finally { closeSync(fd); }
}
function trustedSystemSsh() {
  const file = "/usr/bin/ssh";
  const st = lstatSync(file, { bigint: true });
  check(st.isFile() && !st.isSymbolicLink() && st.uid === 0n && st.nlink === 1n &&
    (st.mode & 0o022n) === 0n && realpathSync.native(file) === file);
  const parent = lstatSync("/usr/bin", { bigint: true });
  check(parent.isDirectory() && parent.uid === 0n && (parent.mode & 0o022n) === 0n);
}

/** No install or mutation. Mockable only for isolated tests, not release authority. */
export async function inspectManualOfflineOperatorPreflight({
  operatorDirectory = path.join(homedir(), ".virki", "offline-manual-operator"),
  execute,
  now = Math.floor(Date.now() / 1000),
} = {}) {
  try {
    check(Number.isSafeInteger(now));
    trustedSystemSsh();
    const initial = inspectOperatorAssets(operatorDirectory, now);
    const config = {
      sshAlias: initial.identity.hostKeyAlias, host: initial.identity.host,
      port: initial.identity.port, root: "/var/lib/virki/offline-release",
      sshUser: initial.identity.sshUser,
    };
    const profile = {
      knownHostsFile: path.join(operatorDirectory, "known_hosts"),
      identityFile: path.join(operatorDirectory, "ssh-identity"),
      environment: Object.freeze({ PATH: "/usr/bin:/bin", HOME: homedir(), LC_ALL: "C", LANG: "C" }),
    };
    // Revalidation before egress and after return catches a changed signer,
    // destination or known_hosts file during a long-running remote query.
    const recheck = () => check(inspectOperatorAssets(operatorDirectory, Math.floor(Date.now() / 1000))
      .immutableDigest === initial.immutableDigest);
    const invoke = (command, args, options) => {
      recheck();
      if (execute) return execute(command, args, options);
      trustedSystemSsh();
      const result = spawnSync(command, args, {
        shell: false, windowsHide: true, encoding: "utf8", input: options?.input,
        timeout: 15_000, maxBuffer: 4096, env: options?.env,
        stdio: options?.input === undefined ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
      });
      return { status: result.error || result.signal ? 1 : result.status,
        stdout: result.stdout ?? "" };
    };
    const result = await inspectOfflineHostReadiness({
      config, sshUser: initial.identity.sshUser,
      pinnedProfile: profile, sshCommand: "/usr/bin/ssh", execute: invoke,
    });
    // Never report success when signed inputs rotate during the operation.
    check(inspectOperatorAssets(operatorDirectory, Math.floor(Date.now() / 1000))
      .immutableDigest === initial.immutableDigest);
    check(result.status === "HOST_COMPONENTS_INSPECTED_ONLY" && Array.isArray(result.unverified));
    return Object.freeze({
      status: result.unverified.length === 0
        ? "SIGNED_PROVISION_CHECKLIST_AND_HOST_METADATA_INSPECTED_ONLY"
        : "MANUAL_OPERATOR_PROVISIONING_INCOMPLETE",
      checklistId: initial.checklistId,
      metadataObserved: result.metadataObserved, unverified: result.unverified,
      ownerTrustInstalledVerified: false, witnessCasAuthorized: false,
      transferAuthorized: false, dockerLoadAuthorized: false, deployAuthorized: false,
    });
  } catch {
    // Never echo private identity, keys, SSH stderr or host details.
    return BLOCKED;
  }
}

const entry = fileURLToPath(import.meta.url);
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
let executable = false;
try { executable = invoked && realpathSync.native(invoked) === realpathSync.native(entry); }
catch { /* refuse missing/aliased entry */ }
if (executable) {
  const canonical = invoked === entry && realpathSync.native(invoked) === invoked;
  const result = canonical && process.argv.length === 2
    ? await inspectManualOfflineOperatorPreflight() : BLOCKED;
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.status === "SIGNED_PROVISION_CHECKLIST_AND_HOST_METADATA_INSPECTED_ONLY" ? 0 : 1;
}
