import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, realpathSync, statfsSync,
  writeSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import os from "node:os";
import { parsePinnedOpenSshEd25519PublicKey } from "../../scripts/lib/offline-ssh-transfer-permit.mjs";

// This generator is DATA ONLY. Its caller supplies independently reviewed SHA
// pins, which remain claims until an external owner separately authenticates
// them. It never runs sshd, sudo, writes /etc, or authorizes installation.
const SHA = /^[0-9a-f]{64}$/u;
const ROOT = "/usr/local/lib/virki/offline-transfer";
const RECEIVER = ROOT + "/offline-host-transfer-receiver.mjs";
const NODE = "/usr/bin/node";
const LOGIN = "virki-offline";
const FORCED = NODE + " " + RECEIVER + " --gate";
const AUTHORIZED = "/etc/ssh/virki-offline/authorized_keys";
const HOST_PRIVATE = "/etc/ssh/ssh_host_ed25519_key";
const PINS_ROOT = "/etc/virki/offline-ssh-bootstrap";
const PINS_FILE = PINS_ROOT + "/owner-pins.json";
const SHARED_BASELINE_FILE = PINS_ROOT + "/shared-sshd-baseline.json";
const SSHPUB = HOST_PRIVATE + ".pub";
const VISUDO = "/usr/sbin/visudo";
const SSHD = "/usr/sbin/sshd";
const SSH_KEYGEN = "/usr/bin/ssh-keygen";
const EXPECTED_RECEIVER = Object.freeze([
  "offline-host-transfer-receiver.mjs",
  "lib/offline-ssh-stage-protocol.mjs",
  "lib/offline-ssh-transfer-permit.mjs",
]);
const EXPECTED_FIELDS = Object.freeze([
  "clientPublicKey", "independentlyPinnedClientSpkiSha256",
  "hostPublicKey", "independentlyPinnedHostSpkiSha256",
  "reviewedReceiverFiles", "reviewedNode22ExecutableSha256",
  "unrelatedSshdBaselineSha256",
]);
// Full outputs captured BEFORE installation of the proposed Include, pinned
// by an independent owner. Fixed user/address/port matrix, never caller-supplied.
export const SHARED_SSHD_BASELINE_CONTEXTS = Object.freeze(
  ["root", "nobody", "unrelated-admin"].flatMap((user) =>
    [
      `user=${user},host=localhost,addr=127.0.0.1,lport=22`,
      `user=${user},host=remote.example,addr=192.0.2.54,lport=22`,
      `user=${user},host=remote.example,addr=2001:db8::54,lport=22222`,
    ]));

function requireThat(value, reason) {
  if (!value) throw new Error("Owner offline SSH bootstrap refused: " + reason);
}
function exact(value, keys) {
  requireThat(value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key, index) => Object.keys(value)[index] === key), "unexpected bootstrap fields");
}
function ed25519(publicText, pinned, label) {
  requireThat(typeof publicText === "string" && publicText.length <= 512 &&
    SHA.test(pinned), label + " key or pin missing");
  const elements = publicText.trim().split(/\s+/u);
  requireThat(elements.length >= 2 && elements.length <= 3 &&
    elements[0] === "ssh-ed25519" &&
    /^[A-Za-z0-9+/]+={0,2}$/u.test(elements[1]) &&
    (elements.length === 2 || /^[A-Za-z0-9_.@-]{1,80}$/u.test(elements[2])),
  label + " invalid OpenSSH public key");
  requireThat(parsePinnedOpenSshEd25519PublicKey(
    elements.slice(0, 2).join(" ")) === pinned,
  label + " independently pinned SPKI mismatch");
  return elements.slice(0, 2).join(" ");
}

function sudoers() {
  // Sudoers argument matching must remain EXACT (no wildcard, shell,
  // SETENV, runas other than root, or general Node interpreter permission).
  const entries = ["", " --read-probe", " --read-docker", " --read-identity"];
  return "Defaults:virki-offline env_reset,!setenv\n" +
    "Cmnd_Alias VIRKI_OFFLINE_TRANSFER = " +
    entries.map((args) => NODE + " " + RECEIVER + args).join(", \\\n    ") +
    "\nvirki-offline ALL=(root) NOPASSWD: VIRKI_OFFLINE_TRANSFER\n";
}
function sshd() {
  return [
    "# Restricted per-user Match: no changes to global sshd defaults or other logins",
    "Match User virki-offline",
    "    AuthorizedKeysFile " + AUTHORIZED,
    "    AuthorizedKeysCommand none",
    "    TrustedUserCAKeys none",
    "    AuthorizedPrincipalsCommand none",
    "    AuthorizedPrincipalsFile none",
    "    PubkeyAcceptedAlgorithms ssh-ed25519",
    "    HostbasedAuthentication no",
    "    GSSAPIAuthentication no",
    "    ForceCommand " + FORCED,
    "    PubkeyAuthentication yes",
    "    AuthenticationMethods publickey",
    "    PasswordAuthentication no",
    "    KbdInteractiveAuthentication no",
    "    PermitTTY no",
    "    AllowTcpForwarding no",
    "    AllowAgentForwarding no",
    "    X11Forwarding no",
    "    PermitTunnel no",
    "    PermitUserRC no",
    "    PermitOpen none",
    "    PermitListen none",
    "    GatewayPorts no",
    "    MaxSessions 1",
    "",
  ].join("\n");
}

/** Strictly bounded NONAUTHORIZING owner-installation blueprint. */
export function renderOwnerPinnedOfflineSshBootstrap(request = {}) {
  exact(request, EXPECTED_FIELDS);
  const client = ed25519(request.clientPublicKey,
    request.independentlyPinnedClientSpkiSha256, "client");
  ed25519(request.hostPublicKey, request.independentlyPinnedHostSpkiSha256, "host");
  requireThat(SHA.test(request.reviewedNode22ExecutableSha256), "Node22 pin missing");
  requireThat(SHA.test(request.unrelatedSshdBaselineSha256),
    "independently reviewed pre-install SSH baseline digest missing");
  requireThat(Array.isArray(request.reviewedReceiverFiles) &&
    request.reviewedReceiverFiles.length === EXPECTED_RECEIVER.length &&
    request.reviewedReceiverFiles.every((file, i) =>
      file && typeof file === "object" && !Array.isArray(file) &&
      Object.keys(file).length === 2 &&
      Object.keys(file)[0] === "path" && Object.keys(file)[1] === "sha256" &&
      file.path === EXPECTED_RECEIVER[i] && SHA.test(file.sha256)),
  "incomplete or unsafe reviewed receiver dependency inventory");

  const files = Object.freeze({
    authorized_keys: Object.freeze({ path: AUTHORIZED, mode: 0o644,
      contents: `restrict,command="${FORCED}" ${client}\n` }),
    sudoers: Object.freeze({ path: "/etc/sudoers.d/virki-offline", mode: 0o440,
      contents: sudoers() }),
    sshd_config: Object.freeze({ path: "/etc/ssh/sshd_config.d/90-virki-offline.conf",
      mode: 0o644, contents: sshd() }),
  });
  return Object.freeze({
    status: "OWNER_SSH_BOOTSTRAP_REVIEW_ONLY",
    installAuthorized: false, deployAuthorized: false,
    sshLogin: LOGIN,
    clientSpkiSha256: request.independentlyPinnedClientSpkiSha256,
    hostSpkiSha256: request.independentlyPinnedHostSpkiSha256,
    node22Sha256: request.reviewedNode22ExecutableSha256,
    unrelatedSshdBaselineSha256: request.unrelatedSshdBaselineSha256,
    receiverFiles: Object.freeze(request.reviewedReceiverFiles.map((file) =>
      Object.freeze({ path: file.path, sha256: file.sha256 }))),
    files,
  });
}

/** Confirms ONLY contents of a ROOT-OWNED disposable fixture on isolated
 * tmpfs. Never interprets fixture files as installed production authority.
 */
export function attestDisposableOfflineSshBootstrap({ directory, independentlyReviewed } = {}) {
  requireThat(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 &&
    typeof directory === "string" &&
    /^\/tmp\/virki-offline-ssh-bootstrap-test-[A-Za-z0-9]{6}\/reviewed$/u.test(directory) &&
    path.normalize(directory) === directory && realpathSync.native(directory) === directory &&
    statfsSync(directory).type === 0x01021994,
  "root-only disposable Linux tmpfs fixture required");
  const dir = lstatSync(directory, { bigint: true });
  requireThat(dir.isDirectory() && dir.uid === 0n &&
    (dir.mode & 0o7777n) === 0o700n &&
    readdirSync(directory).sort().join("\0") ===
      ["authorized_keys", "sshd_config", "sudoers"].sort().join("\0"),
  "unexpected fixture files or permissions");
  const rendered = renderOwnerPinnedOfflineSshBootstrap(independentlyReviewed);
  for (const [name, expected] of Object.entries(rendered.files)) {
    const namePath = path.join(directory, name);
    const before = lstatSync(namePath, { bigint: true });
    requireThat(before.isFile() && before.uid === 0n && before.nlink === 1n &&
      (before.mode & 0o7777n) === BigInt(expected.mode) &&
      before.size === BigInt(Buffer.byteLength(expected.contents)),
    "unsafe reviewed fixture file " + name);
    const fd = openSync(namePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const a = fstatSync(fd, { bigint: true });
      const contents = readFileSync(fd);
      const b = fstatSync(fd, { bigint: true });
      const after = lstatSync(namePath, { bigint: true });
      requireThat(["dev", "ino", "uid", "mode", "size", "mtimeNs", "ctimeNs"]
        .every((field) => before[field] === a[field] && a[field] === b[field] &&
          b[field] === after[field]) &&
        contents.equals(Buffer.from(expected.contents)),
      "reviewed fixture bytes or identity changed " + name);
    } finally { closeSync(fd); }
  }
  return Object.freeze({
    status: "SSH_BOOTSTRAP_FILES_INSPECTED_NOT_INSTALLED",
    installAuthorized: false, deployAuthorized: false,
    inventoryDigest: createHash("sha256").update(Object.values(rendered.files)
      .map((f) => f.path + "\0" + f.mode + "\0" + f.contents).join("\0")).digest("hex"),
  });
}

/** Root-only disposable MATERIALIZATION of the three inert owner-reviewed
 * configuration recipes. This is NOT installation: it can write ONLY a new
 * empty /tmp/virki-offline-ssh-bootstrap-test-XXXXXX/reviewed tmpfs directory,
 * never /etc, actual authorized_keys or host sudoers. Interrupted state is
 * preserved for the test owner to reconcile, not retried or overwritten.
 */
export function writeDisposableOwnerSshBootstrapReviewBundle({
  directory, independentlyReviewed,
} = {}) {
  requireThat(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 &&
    typeof directory === "string" &&
    /^\/tmp\/virki-offline-ssh-bootstrap-test-[A-Za-z0-9]{6}\/reviewed$/u.test(directory) &&
    path.normalize(directory) === directory,
  "root-only review-bundle tmpfs required");
  const parent = path.dirname(directory);
  requireThat(realpathSync.native(parent) === parent &&
    statfsSync(parent).type === 0x01021994,
  "review bundle parent is not private tmpfs");
  const original = lstatSync(parent);
  requireThat(original.isDirectory() && original.uid === 0 &&
    (original.mode & 0o7777) === 0o700, "unsafe review-bundle parent");
  const expected = renderOwnerPinnedOfflineSshBootstrap(independentlyReviewed);
  try {
    mkdirSync(directory, { mode: 0o700, recursive: false });
  } catch {
    throw new Error("Owner offline SSH bootstrap refused: review bundle is not new and empty");
  }
  for (const [name, definition] of Object.entries(expected.files)) {
    const bytes = Buffer.from(definition.contents);
    const fd = openSync(path.join(directory, name),
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      definition.mode);
    try {
      fchmodSync(fd, definition.mode);
      let offset = 0;
      while (offset < bytes.byteLength) {
        const size = writeSync(fd, bytes, offset, bytes.byteLength - offset);
        requireThat(size > 0, "incomplete reviewed recipe write");
        offset += size;
      }
      fsyncSync(fd);
    } finally { closeSync(fd); }
  }
  const dirfd = openSync(directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(dirfd); } finally { closeSync(dirfd); }
  return attestDisposableOfflineSshBootstrap({ directory, independentlyReviewed });
}

function hashProtectedFile(filename, mode, maxBytes) {
  requireThat(realpathSync.native(filename) === filename, "protected file path aliased");
  const original = lstatSync(filename, { bigint: true });
  requireThat(original.isFile() && original.nlink === 1n && original.uid === 0n &&
    (original.mode & 0o7777n) === BigInt(mode) &&
    original.size > 0n && original.size <= BigInt(maxBytes),
  "unsafe root-owned executable/dependency");
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const same = (v) => ["dev", "ino", "mode", "uid", "gid", "nlink", "size",
      "mtimeNs", "ctimeNs"].every((k) => v[k] === original[k]);
    requireThat(same(fstatSync(fd, { bigint: true })), "protected source swapped before read");
    const bytes = readFileSync(fd);
    requireThat(bytes.length === Number(original.size) &&
      same(fstatSync(fd, { bigint: true })) &&
      same(lstatSync(filename, { bigint: true })),
    "protected source changed during read");
    return createHash("sha256").update(bytes).digest("hex");
  } finally { closeSync(fd); }
}

/** Read-only, root-only runtime inspection of three exact review-pinned ESM
 * modules and the protected OS Node22 executable. The source directory is
 * arbitrary for tests: this report is NEVER production trust or permission.
 */
export function inspectOwnerPinnedOfflineSshRuntime({
  receiverDirectory, nodeExecutable, independentlyReviewed,
} = {}) {
  requireThat(process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 &&
    nodeExecutable === NODE && typeof receiverDirectory === "string" &&
    path.isAbsolute(receiverDirectory) &&
    path.normalize(receiverDirectory) === receiverDirectory &&
    realpathSync.native(receiverDirectory) === receiverDirectory,
  "root Linux offline SSH inspection required");
  const pins = renderOwnerPinnedOfflineSshBootstrap(independentlyReviewed);
  const dir = lstatSync(receiverDirectory, { bigint: true });
  requireThat(dir.isDirectory() && dir.uid === 0n &&
    (dir.mode & 0o022n) === 0n, "receiver directory not root-protected");
  const lib = lstatSync(path.join(receiverDirectory, "lib"), { bigint: true });
  requireThat(lib.isDirectory() && lib.uid === 0n &&
    (lib.mode & 0o022n) === 0n, "receiver library directory not root-protected");
  const node = hashProtectedFile(NODE, 0o755, 128 * 1024 * 1024);
  requireThat(node === pins.node22Sha256, "Node22 executable pin mismatch");
  const version = spawnSync(NODE, ["--version"], {
    shell: false, encoding: "utf8", timeout: 3000, maxBuffer: 80,
    env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent" },
  });
  requireThat(version.status === 0 && !version.error && !version.signal &&
    /^v22\.[0-9]+\.[0-9]+\n?$/u.test(version.stdout), "runtime is not pinned Node22");
  for (const entry of pins.receiverFiles) {
    requireThat(hashProtectedFile(path.join(receiverDirectory, entry.path),
      0o644, 2 * 1024 * 1024) === entry.sha256,
    "receiver module does not match owner-reviewed SHA256");
  }
  return Object.freeze({ status: "NATIVE_SSH_CODE_PINNED_NOT_INSTALLED",
    installAuthorized: false, deployAuthorized: false,
    node22Sha256: node, receiverFiles: pins.receiverFiles.length });
}

// Read-only inspection. The trusted pins are installed by a separate owner
// under a FIXED native /etc path, not read from candidate bytes or SSH input.
// This is not the installer and never authorizes deployment, release or SSH.
const NOT_READY = Object.freeze({
  status: "blocked", installAuthorized: false, deployAuthorized: false,
});
function rootProtectedAncestors(file) {
  requireThat(realpathSync.native(file) === file, "native installed path is aliased");
  let name = path.dirname(file);
  while (true) {
    const stat = lstatSync(name);
    requireThat(stat.isDirectory() && !stat.isSymbolicLink() &&
      stat.uid === 0 && (stat.mode & 0o022) === 0,
    "native installed ancestor not protected");
    const parent = path.dirname(name);
    if (parent === name) break;
    name = parent;
  }
}
function readInstalledText(file, mode, maxBytes) {
  rootProtectedAncestors(file);
  const original = lstatSync(file, { bigint: true });
  requireThat(original.isFile() && original.uid === 0n && original.nlink === 1n &&
    (original.mode & 0o7777n) === BigInt(mode) &&
    original.size > 0n && original.size <= BigInt(maxBytes),
  "native installed file mode/size/owner rejected");
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const same = (now) => ["dev", "ino", "mode", "uid", "gid", "nlink", "size",
      "mtimeNs", "ctimeNs"].every((key) => now[key] === original[key]);
    requireThat(same(fstatSync(fd, { bigint: true })), "native installed file changed");
    const bytes = readFileSync(fd);
    requireThat(bytes.byteLength === Number(original.size) &&
      same(fstatSync(fd, { bigint: true })) &&
      same(lstatSync(file, { bigint: true })),
    "native installed file altered during read");
    return bytes.toString("utf8");
  } finally { closeSync(fd); }
}
function assertNativeCommand(binary, args) {
  rootProtectedAncestors(binary);
  const stat = lstatSync(binary);
  requireThat(stat.isFile() && stat.uid === 0 &&
    (stat.mode & 0o022) === 0, "native validator executable not protected");
  const result = spawnSync(binary, args, {
    shell: false, encoding: "utf8", timeout: 5000, maxBuffer: 128 * 1024,
    env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent" },
  });
  requireThat(result.status === 0 && !result.error && !result.signal,
    "native validator command did not pass");
  return result.stdout;
}
/** Match the real daemon's PRIVATE host key against the independently
 * owner-reviewed Ed25519 public SPKI. The caller pin alone grants no authority. */
export function inspectOwnerPinnedSshHostKey(approvedPublicKey, approvedSpkiSha256) {
  const pinned = ed25519(approvedPublicKey, approvedSpkiSha256, "owner host");
  requireThat(ed25519(readInstalledText(SSHPUB, 0o644, 512),
    approvedSpkiSha256, "installed host") === pinned, "dedicated host .pub differs");
  rootProtectedAncestors(HOST_PRIVATE);
  const hostKey = lstatSync(HOST_PRIVATE);
  requireThat(hostKey.isFile() && hostKey.nlink === 1 &&
    hostKey.uid === 0 && hostKey.gid === 0 &&
    (hostKey.mode & 0o7777) === 0o600,
  "dedicated SSH host private key not protected");
  const actualHostKey = assertNativeCommand(SSH_KEYGEN, [
    "-y", "-P", "", "-f", HOST_PRIVATE,
  ]);
  requireThat(ed25519(actualHostKey, approvedSpkiSha256,
    "actual private-key-derived SSH host") === pinned,
  "dedicated sshd host private key differs from owner pin");
  return Object.freeze({ status: "DEDICATED_HOST_KEY_MATCHED_NONAUTHORIZING",
    installAuthorized: false, deployAuthorized: false });
}
/** Pure structural verification of the effective RESTRICTED sshd -T output.
 * This never treats string output as trust or a live daemon measurement. */
export function verifyRestrictedOfflineSshdEffectiveConfiguration(meaning) {
  requireThat(typeof meaning === "string" && meaning.length > 0 && meaning.length < 131072,
    "dedicated sshd effective policy unavailable");
  const lines = meaning.split("\n");
  const collected = new Map();
  for (const line of lines) {
    const space = line.indexOf(" ");
    if (space > 0) {
      const key = line.slice(0, space).toLowerCase();
      if (key === "hostkey") {
        collected.set(key, [...(collected.get(key) ?? []), line.slice(space + 1)]);
      } else {
        requireThat(!collected.has(key), "duplicate effective sshd directive");
        collected.set(key, line.slice(space + 1));
      }
    }
  }
  requireThat(Array.isArray(collected.get("hostkey")) &&
    collected.get("hostkey").includes(HOST_PRIVATE),
  "root owner-pinned ssh-ed25519 server host identity not configured");
  for (const [key, expected] of [
    ["authorizedkeysfile", AUTHORIZED],
    ["authorizedkeyscommand", "none"],
    ["trustedusercakeys", "none"],
    ["authorizedprincipalscommand", "none"],
    ["authorizedprincipalsfile", "none"],
    ["pubkeyacceptedalgorithms", "ssh-ed25519"],
    ["hostbasedauthentication", "no"],
    ["gssapiauthentication", "no"],
    ["forcecommand", FORCED],
    ["authenticationmethods", "publickey"],
    ["pubkeyauthentication", "yes"],
    ["passwordauthentication", "no"],
    ["kbdinteractiveauthentication", "no"],
    ["strictmodes", "yes"],
    ["permittty", "no"],
    ["allowtcpforwarding", "no"],
    ["allowagentforwarding", "no"],
    ["x11forwarding", "no"],
    ["permittunnel", "no"],
    ["permituserrc", "no"],
    ["permituserenvironment", "no"],
    ["permitopen", "none"],
    ["permitlisten", "none"],
    ["maxsessions", "1"],
  ]) requireThat(collected.get(key) === expected,
    "native effective sshd policy is not isolated forced-command-only");
  return true;
}

/** Verify root-pinned preinstall SSH baselines for unrelated users against
 * actual sshd -T -C outputs. This is evidence for the fixed matrix only,
 * not proof for every unmeasured connection or the running daemon. */
export function verifyUnrelatedSshdEffectiveBaselines(baselines, observed) {
  exact(baselines, ["version", "snapshots"]);
  requireThat(baselines.version === 1 && Array.isArray(baselines.snapshots) &&
    baselines.snapshots.length === SHARED_SSHD_BASELINE_CONTEXTS.length &&
    Array.isArray(observed) && observed.length === SHARED_SSHD_BASELINE_CONTEXTS.length,
  "missing complete independent SSH comparison baselines");
  for (let i = 0; i < SHARED_SSHD_BASELINE_CONTEXTS.length; i++) {
    const expected = baselines.snapshots[i];
    exact(expected, ["context", "effective"]);
    requireThat(expected.context === SHARED_SSHD_BASELINE_CONTEXTS[i] &&
      typeof expected.effective === "string" &&
      expected.effective.length > 0 && expected.effective.length <= 16384 &&
      typeof observed[i] === "string" && observed[i] === expected.effective,
    "unrelated SSH policy drift detected at owner-pinned context");
  }
  return true;
}

/** Actual native-host READINESS INSPECTION only. Takes NO arguments and
 * refuses non-native/WSL. The read-only checks run installed visudo and sshd
 * validators; they do not reconfigure or restart the running SSH service.
 */
export function inspectInstalledOwnerSshBootstrapReadiness(request) {
  try {
    requireThat(request === undefined && process.platform === "linux" &&
      process.arch === "x64" && process.getuid?.() === 0 &&
      !/microsoft|wsl/iu.test(os.release()),
    "native owner-only readiness required");
    rootProtectedAncestors(PINS_FILE);
    const dir = lstatSync(PINS_ROOT);
    requireThat(dir.isDirectory() && dir.uid === 0 &&
      (dir.mode & 0o7777) === 0o700 &&
      readdirSync(PINS_ROOT).sort().join("\0") ===
        "owner-pins.json\0shared-sshd-baseline.json",
    "native independent owner pin directory missing/ambiguous");
    const pinsText = readInstalledText(PINS_FILE, 0o600, 4096);
    const pins = JSON.parse(pinsText);
    exact(pins, EXPECTED_FIELDS);
    requireThat(JSON.stringify(pins) === pinsText, "owner pin JSON not canonical");
    const review = renderOwnerPinnedOfflineSshBootstrap(pins);
    const baselinesText = readInstalledText(SHARED_BASELINE_FILE, 0o600, 131072);
    requireThat(createHash("sha256").update(baselinesText).digest("hex") ===
      review.unrelatedSshdBaselineSha256,
    "pre-install SSH baseline differs from owner-pinned digest");
    const baselines = JSON.parse(baselinesText);
    requireThat(JSON.stringify(baselines) === baselinesText,
      "pre-install SSH baseline JSON is noncanonical");
    for (const file of Object.values(review.files)) {
      requireThat(readInstalledText(file.path, file.mode, 4096) === file.contents,
      "native deployed SSH/authorized_keys/sudoers content differs from owner blueprint");
    }
    inspectOwnerPinnedSshHostKey(pins.hostPublicKey, review.hostSpkiSha256);
    rootProtectedAncestors(RECEIVER);
    const releaseDir = lstatSync(ROOT);
    requireThat(releaseDir.uid === 0 && releaseDir.isDirectory() &&
      (releaseDir.mode & 0o7777) === 0o755,
    "native installed receiver directory must be root-owned 0755");
    const libDir = lstatSync(ROOT + "/lib");
    requireThat(libDir.uid === 0 && libDir.isDirectory() &&
      (libDir.mode & 0o7777) === 0o755,
    "native receiver dependency directory must be root-owned 0755");
    inspectOwnerPinnedOfflineSshRuntime({
      receiverDirectory: ROOT, nodeExecutable: NODE, independentlyReviewed: pins,
    });
    assertNativeCommand(VISUDO, ["-c", "-f", review.files.sudoers.path]);
    assertNativeCommand(SSHD, ["-t"]);
    verifyRestrictedOfflineSshdEffectiveConfiguration(assertNativeCommand(SSHD, [
      "-T", "-C", "user=virki-offline,host=localhost,addr=127.0.0.1",
    ]));
    verifyUnrelatedSshdEffectiveBaselines(baselines,
      SHARED_SSHD_BASELINE_CONTEXTS.map((context) =>
        assertNativeCommand(SSHD, ["-T", "-C", context])));
    requireThat(readInstalledText(SHARED_BASELINE_FILE, 0o600, 131072) === baselinesText,
      "SSH baseline changed during native readiness");
    for (const file of Object.values(review.files)) {
      requireThat(readInstalledText(file.path, file.mode, 4096) === file.contents,
        "installed SSH file changed during readiness");
    }
    return Object.freeze({
      status: "OWNER_PINNED_SSH_BOOTSTRAP_INSPECTED_ONLY",
      installAuthorized: false, deployAuthorized: false,
    });
  } catch {
    return NOT_READY;
  }
}
