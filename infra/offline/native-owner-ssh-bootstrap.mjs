import { createHash, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Standalone offline-transfer sshd instance. Never append a Match block to the
// production sshd_config, whose Include ordering could change hosted logins.
// Listener is LOOPBACK ONLY: operator must separately attest network transport.
const SSHD = [
  "Port 2223",
  "ListenAddress 127.0.0.1",
  "AddressFamily inet",
  "HostKey /etc/virki/offline-transfer-ssh/ssh_host_ed25519_key",
  "PidFile /run/virki-offline-sshd.pid",
  "AllowUsers virki-offline",
  "PermitRootLogin no",
  "PubkeyAuthentication yes",
  "AuthenticationMethods publickey",
  "PasswordAuthentication no",
  "KbdInteractiveAuthentication no",
  "PermitEmptyPasswords no",
  "PermitUserEnvironment no",
  "PermitUserRC no",
  "StrictModes yes",
  "HostKeyAlgorithms ssh-ed25519",
  "PubkeyAcceptedAlgorithms ssh-ed25519",
  "AllowTcpForwarding no",
  "AllowAgentForwarding no",
  "AllowStreamLocalForwarding no",
  "X11Forwarding no",
  "PermitTTY no",
  "PermitTunnel no",
  "GatewayPorts no",
  "PermitOpen none",
  "PermitListen none",
  "DisableForwarding yes",
  "MaxSessions 1",
  "MaxStartups 2:30:4",
  "LogLevel VERBOSE",
  "AuthorizedKeysFile /etc/virki/offline-transfer-ssh/authorized_keys",
  "AuthorizedKeysCommand none",
  "Match User virki-offline",
  "  ForceCommand /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate",
].join("\n") + "\n";

const RECEIVER = "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs";
const INSTALLED_INSPECTOR = "/usr/local/lib/virki/offline-release/infra/offline/native-owner-ssh-bootstrap.mjs";
const GATE = "/usr/bin/node " + RECEIVER + " --gate";
const SUDO = [
  "Defaults:virki-offline env_reset, !setenv",
  "Cmnd_Alias VIRKI_OFFLINE_TRANSFER = /usr/bin/node " + RECEIVER + ", \\",
  "    /usr/bin/node " + RECEIVER + " --read-probe, \\",
  "    /usr/bin/node " + RECEIVER + " --read-docker, \\",
  "    /usr/bin/node " + RECEIVER + " --read-identity",
  "virki-offline ALL=(root) NOPASSWD: VIRKI_OFFLINE_TRANSFER",
].join("\n") + "\n";

const FIXED = Object.freeze({
  sshd: "/etc/virki/offline-transfer-ssh/sshd_config",
  sudoers: "/etc/sudoers.d/virki-offline-transfer",
  authorized: "/etc/virki/offline-transfer-ssh/authorized_keys",
  receiver: RECEIVER,
  protocol: "/usr/local/lib/virki/offline-transfer/lib/offline-ssh-stage-protocol.mjs",
  permit: "/usr/local/lib/virki/offline-transfer/lib/offline-ssh-transfer-permit.mjs",
  hostPolicy: "/etc/virki/offline-transfer-host/host-policy.json",
  releasePolicy: "/etc/virki/offline-release/trust-policy.json",
  machineId: "/etc/machine-id",
});
const SHA = /^[0-9a-f]{64}$/u;
const hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
function demand(ok, what) {
  if (!ok) throw new Error("Native owner SSH bootstrap refused: " + what);
}
export function renderNativeOwnerSshdMatch() { return SSHD; }
export function renderNativeOwnerSudoers() { return SUDO; }
export function validateOwnerSshBlueprint({ sshd, sudoers } = {}) {
  demand(sshd === SSHD && sudoers === SUDO,
    "SSH and sudoer commands must match the exact owner-reviewed template");
  return true;
}

function safeParents(location) {
  demand(typeof location === "string" && location.startsWith("/") &&
    path.normalize(location) === location && !location.includes("\0"),
  "noncanonical host path");
  let parent = path.dirname(location);
  demand(realpathSync.native(parent) === parent, "aliased root ancestors");
  while (true) {
    const st = lstatSync(parent, { bigint: true });
    // Root-owned sticky 01777 parents are safe against unprivileged renames
    // of root-owned entries. Ordinary group/world writable parents are not.
    const writable = (st.mode & 0o022n) !== 0n;
    const stickySafe = (st.mode & 0o1000n) !== 0n &&
      st.uid === 0n && (st.mode & 0o2000n) === 0n;
    demand(st.isDirectory() && !st.isSymbolicLink() && st.uid === 0n &&
      (!writable || stickySafe), "mutable ancestor of root-owned SSH authority");
    if (parent === "/") break;
    parent = path.dirname(parent);
  }
}
function requirePublicReadTraversal(location) {
  // OpenSSH auth_openkeyfile() temporarily uses the target account UID, and
  // the ForceCommand Node process runs unprivileged BEFORE its exact sudo
  // elevation. Root-owned 0600 bytes or 0700 parents break BOTH boundaries.
  // These artifacts hold public key/code only, never owner signing secrets.
  safeParents(location);
  let current = path.dirname(location);
  while (true) {
    const st = lstatSync(current);
    demand(st.isDirectory() && st.uid === 0 &&
      (st.mode & 0o001) !== 0, "unprivileged SSH account cannot traverse root path");
    if (current === "/") break;
    current = path.dirname(current);
  }
}
function protectedBytes(filename, mode, max = 16384) {
  safeParents(filename);
  const before = lstatSync(filename, { bigint: true });
  const permittedModes = Array.isArray(mode) ? mode : [mode];
  demand(before.isFile() && !before.isSymbolicLink() && before.uid === 0n &&
    before.nlink === 1n && permittedModes.some((m) => (before.mode & 0o7777n) === BigInt(m)) &&
    before.size > 0n && before.size <= BigInt(max), "untrusted installed file");
  const fd = openSync(filename,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_CLOEXEC);
  try {
    const same = (a, b) => ["dev", "ino", "mode", "uid", "gid", "nlink",
      "size", "ctimeNs", "mtimeNs"].every((k) => a[k] === b[k]);
    demand(same(before, fstatSync(fd, { bigint: true })), "changed at open");
    const bytes = readFileSync(fd);
    demand(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(filename, { bigint: true })),
    "changed during read");
    return bytes;
  } finally { closeSync(fd); }
}
function canonical(bytes, max = 16384) {
  demand(bytes.length > 0 && bytes.length <= max, "oversized policy");
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value = JSON.parse(raw);
  demand(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(value) === raw, "noncanonical installed policy");
  return value;
}
function clientKeyDigest(authorized) {
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(authorized);
  const match = /^restrict,command="([^"\r\n]+)" ssh-ed25519 ([A-Za-z0-9+/]+={0,2})\n$/u.exec(raw);
  demand(match?.[1] === GATE, "unrestricted or noncanonical authorized_keys");
  const bin = Buffer.from(match[2], "base64");
  demand(bin.toString("base64") === match[2] && bin.length === 51,
    "unsupported client key encoding");
  let pos = 0;
  const readString = () => {
    demand(pos + 4 <= bin.length, "truncated SSH client key");
    const length = bin.readUInt32BE(pos); pos += 4;
    demand(length > 0 && length <= 32 && pos + length <= bin.length,
      "overlong SSH client key field");
    const value = bin.subarray(pos, pos + length); pos += length; return value;
  };
  demand(readString().equals(Buffer.from("ssh-ed25519")), "wrong SSH algorithm");
  const pub = readString();
  demand(pub.length === 32 && pos === bin.length, "invalid SSH public key");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]);
  return hex(spki);
}
const EXPECTED_HOST_KEYS = [
  "version", "mode", "expectedSourceSha", "host", "port", "sshAlias", "sshUser",
  "knownHostsSha256", "clientSshKeyPinSha256", "ownerPublicKeyPem",
];
function exactFields(obj, fields) {
  demand(JSON.stringify(Object.keys(obj)) === JSON.stringify(fields), "wrong policy fields");
}

/**
 * TEST FIXTURE / NONAUTHORIZING INSPECTION ONLY. Accepts filesystem paths to
 * make attacks testable. A caller-provided directory/key can NEVER become the
 * independently installed trust root or authorize an SSH listener/deployment.
 */
export function inspectOwnerSshBootstrapFixture(places) {
  demand(process.platform === "linux" && process.getuid?.() === 0,
    "Linux root required for protected-file inspection");
  exactFields(places, Object.keys(FIXED));
  validateOwnerSshBlueprint({
    sshd: protectedBytes(places.sshd, 0o600).toString("utf8"),
    sudoers: protectedBytes(places.sudoers, 0o440).toString("utf8"),
  });
  requirePublicReadTraversal(places.authorized);
  requirePublicReadTraversal(places.receiver);
  requirePublicReadTraversal(places.protocol);
  requirePublicReadTraversal(places.permit);
  const keyPin = clientKeyDigest(protectedBytes(places.authorized, 0o644, 512));
  protectedBytes(places.receiver, 0o644, 2 * 1024 * 1024);
  protectedBytes(places.protocol, 0o644, 2 * 1024 * 1024);
  protectedBytes(places.permit, 0o644, 2 * 1024 * 1024);
  const host = canonical(protectedBytes(places.hostPolicy, 0o600, 8192));
  exactFields(host, EXPECTED_HOST_KEYS);
  const owner = createPublicKey(host.ownerPublicKeyPem);
  const ownerPin = hex(owner.export({ type: "spki", format: "der" }));
  demand(host.version === 1 && host.mode === "offline-host-transfer-v1" &&
    host.sshUser === "virki-offline" && host.port === 2223 &&
    SHA.test(host.clientSshKeyPinSha256) && host.clientSshKeyPinSha256 === keyPin &&
    SHA.test(host.knownHostsSha256) &&
    /^[a-f0-9]{40}$/u.test(host.expectedSourceSha) &&
    typeof host.ownerPublicKeyPem === "string" &&
    owner.asymmetricKeyType === "ed25519" && ownerPin !== keyPin,
  "SSH owner identity, account, or pinned key mismatched");
  const machine = protectedBytes(places.machineId, [0o644, 0o444], 256).toString("ascii");
  demand(/^[a-f0-9]{32}\n$/u.test(machine) && !/^0{32}\n$/u.test(machine),
    "native host identity malformed");
  const identity = hex(Buffer.concat([Buffer.from("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0"),
    Buffer.from(machine.slice(0, -1))]));
  const release = canonical(protectedBytes(places.releasePolicy, 0o600, 65536));
  demand(release.version === 2 && release.hostIdentitySha256 === identity &&
    release.owner?.pinSha256 === ownerPin &&
    release.owner.publicKeyPem === host.ownerPublicKeyPem &&
    typeof release.owner.keyId === "string" && release.owner.keyId.length > 0 &&
    Array.isArray(release.revokedKeyIds) &&
    Array.isArray(release.revokedPinsSha256) &&
    !release.revokedKeyIds.includes(release.owner.keyId) &&
    !release.revokedPinsSha256.includes(ownerPin),
  "independent release host/owner/revocation pin differs from SSH trust");
  return Object.freeze({ status: "FIXTURE_PROTECTED_SSH_BLUEPRINT_ONLY",
    hostIdentitySha256: identity, deployAuthorized: false, sshEnabled: false });
}

function nativeOnly() {
  return process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && !/microsoft|wsl/iu.test(os.release());
}
function requireProtectedExecutable(filename) {
  safeParents(filename);
  demand(realpathSync.native(filename) === filename,
    "installed binary is an alias");
  const st = lstatSync(filename, { bigint: true });
  demand(st.isFile() && !st.isSymbolicLink() && st.uid === 0n &&
    st.nlink === 1n && (st.mode & 0o022n) === 0n &&
    (st.mode & 0o111n) !== 0n, "installed native executable is not owner protected");
}
export function inspectInstalledOwnerSshBootstrap(...args) {
  demand(args.length === 0, "caller cannot provide owner identity or paths");
  if (!nativeOnly()) return Object.freeze({
    status: "OWNER_SSH_BOOTSTRAP_NOT_INSTALLED", deployAuthorized: false,
  });
  try {
    demand(fileURLToPath(import.meta.url) === INSTALLED_INSPECTOR &&
      /^v22\./u.test(process.version) &&
      ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"].every(
        (key) => !Object.hasOwn(process.env, key)),
    "installed Node 22 inspector/runtime context is not independently protected");
    protectedBytes(INSTALLED_INSPECTOR, 0o600, 2 * 1024 * 1024);
    const preview = inspectOwnerSshBootstrapFixture(FIXED);
    for (const executable of ["/usr/bin/node", "/usr/bin/sudo",
      "/usr/sbin/sshd", "/usr/sbin/visudo"]) requireProtectedExecutable(executable);
    // Real sshd/sudoers are necessary even though this read-only inspector
    // cannot attest root-installed signer, running daemon or network policy.
    const sshdSyntax = spawnSync("/usr/sbin/sshd", ["-t", "-f", FIXED.sshd], {
      stdio: ["ignore", "pipe", "pipe"], timeout: 8000, encoding: "utf8",
    });
    if (sshdSyntax.status !== 0 || sshdSyntax.error || sshdSyntax.signal)
      throw new Error("sshd native configuration is not runnable");
    const sshd = spawnSync("/usr/sbin/sshd",
      ["-T", "-f", FIXED.sshd,
        "-C", "user=virki-offline,host=localhost,addr=127.0.0.1"], {
        stdio: ["ignore", "pipe", "pipe"], timeout: 8000, encoding: "utf8",
      });
    const sudoers = spawnSync("/usr/sbin/visudo", ["-cf", FIXED.sudoers], {
      stdio: ["ignore", "pipe", "pipe"], timeout: 8000, encoding: "utf8",
    });
    if (sshd.status !== 0 || sshd.error || sshd.signal ||
        sudoers.status !== 0 || sudoers.error || sudoers.signal) throw new Error("native parser refused");
    const options = new Map(sshd.stdout.trim().split("\n").map((line) => {
      const sep = line.indexOf(" ");
      return [line.slice(0, sep).toLowerCase(), line.slice(sep + 1).toLowerCase()];
    }));
    for (const [key, expected] of [
      ["forcecommand", GATE.toLowerCase()], ["permitrootlogin", "no"],
      ["passwordauthentication", "no"], ["kbdinteractiveauthentication", "no"],
      ["disableforwarding", "yes"], ["permittty", "no"],
      ["allowtcpforwarding", "no"], ["authenticationmethods", "publickey"],
      ["authorizedkeysfile", FIXED.authorized], ["allowusers", "virki-offline"],
      ["port", "2223"], ["hostkey", "/etc/virki/offline-transfer-ssh/ssh_host_ed25519_key"],
    ]) demand(options.get(key) === expected, "effective sshd policy differs");
    return Object.freeze({ status: "OWNER_SSH_NATIVE_PARSERS_VERIFIED_LOCAL_ONLY",
      hostIdentitySha256: preview.hostIdentitySha256,
      sshEnabled: false, deployAuthorized: false });
  } catch {
    return Object.freeze({ status: "OWNER_SSH_BOOTSTRAP_NOT_INSTALLED",
      deployAuthorized: false });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== "--inspect") {
    process.stderr.write("Native owner SSH inspector: no arbitrary arguments accepted.\n");
    process.exitCode = 2;
  } else {
    const status = inspectInstalledOwnerSshBootstrap();
    process.stdout.write(JSON.stringify(status) + "\n");
    process.exitCode = 2; // inspection is never an activation/approval token
  }
}
