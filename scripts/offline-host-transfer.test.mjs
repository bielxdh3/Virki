import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync, linkSync, lstatSync, mkdtempSync, mkdirSync,
  readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable, PassThrough } from "node:stream";
import { test } from "node:test";
import {
  OFFLINE_WIRE_FILES, streamOfflineStageToWritable,
  receiveOfflineWireToQuarantine, publishVerifiedOfflineQuarantine,
} from "./lib/offline-ssh-stage-protocol.mjs";
import { buildPinnedOfflineReceiverSshArgs, transferOfflineSignedCandidate } from "./offline-host-transfer-client.mjs";
import { rewriteOfflineProbeRequest } from "./offline-production-transport.mjs";
import { SSH_OPTIONS } from "./production-preflight.mjs";
import {
  restrictedOfflineSshGateSelector, buildExactRestrictedOfflineSudoArgs,
  consumeOfflineSignedTransferNonce,
} from "./offline-host-transfer-receiver.mjs";
import {
  verifyOwnerSignedOfflineSshPermit, parsePinnedOpenSshEd25519PublicKey,
  deriveOpenSshPrivateIdentityPin, verifyRemoteOfflineTransferPermit,
} from "./lib/offline-ssh-transfer-permit.mjs";

const linux = { skip: process.platform !== "linux" ? "Linux O_NOFOLLOW is required" : false };
// The on-disk receiver lock may be tested as root under WSL or Docker. The
// actual native host *publication* gate must still reject the WSL kernel.
const linuxRootFixture = { skip: process.platform !== "linux" || process.getuid?.() !== 0 ?
  "Linux root fixture required" : false };
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function privateFixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-ssh-wire-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source");
  const stage = path.join(root, "stage");
  mkdirSync(source, { mode: 0o700 });
  mkdirSync(stage, { mode: 0o700 });
  const expected = new Map();
  for (const [index, name] of OFFLINE_WIRE_FILES.entries()) {
    const data = name === "source.tar" ? Buffer.alloc(2 * 1024 * 1024 + 77, index + 1)
      : Buffer.from("signed-fixture-" + name + "-v1");
    writeFileSync(path.join(source, name), data, { mode: 0o600 });
    expected.set(name, data);
  }
  return { root, source, stage, expected };
}
async function captureWire(source, signedPermit) {
  const wire = new PassThrough();
  const chunks = [];
  const reading = (async () => {
    for await (const chunk of wire) chunks.push(Buffer.from(chunk));
  })();
  const result = await streamOfflineStageToWritable({
    candidateDirectory: source, writable: wire, signedPermit,
  });
  await reading;
  assert.equal(result.status, "UNTRUSTED_WIRE_SENT");
  return Buffer.concat(chunks);
}
function readWire(bytes) {
  // Deliberately use tiny fragmented packets; headers and file boundaries
  // have no guaranteed alignment in real SSH pipes.
  return Readable.from((function* () {
    for (let i = 0; i < bytes.length; i += 7999) yield bytes.subarray(i, i + 7999);
  })());
}

test("private SSH data pipe transfers eleven exact bytes with second-pass independent readback", linux, async (t) => {
  const f = privateFixture(t);
  const wire = await captureWire(f.source);
  const stage = await receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: false,
  });
  assert.equal(stage.status, "UNTRUSTED_QUARANTINED");
  assert.equal(stage.fileCount, 11);
  assert.equal(stage.manifestSha256, digest(f.expected.get("manifest.json")));
  assert.equal(stage.transferAuthorized, false);
  assert.equal(stage.deployAuthorized, false);
  assert.match(path.basename(stage.pendingDirectory), /^\.incoming-[a-f0-9]{32}$/u);
  assert.equal(lstatSync(stage.pendingDirectory).mode & 0o777, 0o700);
  for (const name of OFFLINE_WIRE_FILES) {
    assert.deepEqual(readFileSync(path.join(stage.pendingDirectory, name)), f.expected.get(name));
    assert.equal(lstatSync(path.join(stage.pendingDirectory, name)).mode & 0o777, 0o600);
  }
  // Quarantine must not be published on WSL even with all transferred hashes.
  await assert.rejects(publishVerifiedOfflineQuarantine({
    pendingDirectory: stage.pendingDirectory, stagingParent: f.stage,
    manifestSha256: stage.manifestSha256,
  }));
});

test("altered data, truncation and trailing bytes refuse and clean only new quarantine", linux, async (t) => {
  const f = privateFixture(t);
  const wire = await captureWire(f.source);
  for (const bad of [
    Buffer.concat([wire.subarray(0, 8000), Buffer.from([wire[8000] ^ 1]), wire.subarray(8001)]),
    wire.subarray(0, wire.length - 1),
    Buffer.concat([wire, Buffer.from("smuggling")]),
  ]) {
    await assert.rejects(receiveOfflineWireToQuarantine({
      readable: readWire(bad), stagingParent: f.stage, requireRoot: false,
    }), /refused|truncated|hash|trailing/u);
    assert.deepEqual(readdirSync(f.stage), []);
  }
});

test("root receiver requires an exclusive root-owned lock and refuses overlapping stage", linuxRootFixture, async (t) => {
  const f = privateFixture(t);
  const unsigned = await captureWire(f.source);
  const wire = await captureWire(f.source, {
    permitBytes: Buffer.from('{"requires":"owner-validation-before-native-data"}'),
    signatureBytes: Buffer.from("A".repeat(86) + "=="),
  });
  await assert.rejects(receiveOfflineWireToQuarantine({
    readable: readWire(unsigned), stagingParent: f.stage, requireRoot: true,
    authorizeTransfer: () => { throw new Error("Must not accept V1"); },
  }), /signed one-use transfer permit/u);
  await assert.rejects(receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: true,
  }), /signed one-use transfer permit/u);
  writeFileSync(path.join(f.stage, ".receiver-lock"), "", { mode: 0o600, flag: "wx" });
  let authorizations = 0;
  const authorizeTransfer = ({ permitBytes, signatureBytes }) => {
    assert.match(permitBytes.toString(), /owner-validation/u);
    assert.equal(signatureBytes.length, 88);
    authorizations += 1;
  };
  const pending = await receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: true,
    authorizeTransfer,
  });
  assert.equal(pending.status, "UNTRUSTED_QUARANTINED");
  assert.equal(pending.fileCount, 11);
  await assert.rejects(receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: true,
    authorizeTransfer,
  }), /exclusive receiver lock/u);
  assert.equal(authorizations, 2);
  assert.deepEqual(readdirSync(f.stage).sort(),
    [".receiver-lock", path.basename(pending.pendingDirectory)].sort());
});

test("owner-signed native transfer V2 binds exact bytes, consumes nonce durably, and refuses direct SSH replay", linuxRootFixture, async (t) => {
  const f = privateFixture(t);
  const nonceJournal = path.join(f.root, "nonce-journal");
  mkdirSync(nonceJournal, { mode: 0o700 });
  const owner = generateKeyPairSync("ed25519");
  const now = Math.floor(Date.now() / 1000);
  const manifestSha256 = digest(f.expected.get("manifest.json"));
  const envelopeSha256 = digest(f.expected.get("signatures.json"));
  const hostPolicy = {
    version: 1, mode: "offline-host-transfer-v1",
    expectedSourceSha: "a".repeat(40),
    host: "host.example.test", port: 2222, sshAlias: "virki-prod",
    sshUser: "virki-offline", knownHostsSha256: "b".repeat(64),
    clientSshKeyPinSha256: "c".repeat(64),
    ownerPublicKeyPem: owner.publicKey.export({ type: "spki", format: "pem" }),
  };
  const permit = {
    version: 1, mode: "owner-signed-ssh-stage-v1",
    sourceSha: hostPolicy.expectedSourceSha, manifestSha256, envelopeSha256,
    sshAlias: hostPolicy.sshAlias, host: hostPolicy.host, port: hostPolicy.port,
    sshUser: hostPolicy.sshUser, knownHostsSha256: hostPolicy.knownHostsSha256,
    clientSshKeyPinSha256: hostPolicy.clientSshKeyPinSha256,
    receiverPath: "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs",
    stageRoot: "/var/lib/virki/offline-staging", nonce: "e".repeat(32),
    expiresAt: now + 300,
  };
  const permitBytes = Buffer.from(JSON.stringify(permit));
  const signatureBytes = Buffer.from(sign(null,
    Buffer.concat([Buffer.from("VIRKI_OFFLINE_SSH_TRANSFER_PERMIT_V1\0"), permitBytes]),
    owner.privateKey).toString("base64"));
  const wire = await captureWire(f.source, { permitBytes, signatureBytes });
  writeFileSync(path.join(f.stage, ".receiver-lock"), "", { mode: 0o600, flag: "wx" });
  const authorizeTransfer = (payload) => {
    const authorization = verifyRemoteOfflineTransferPermit({ ...payload, hostPolicy, now });
    consumeOfflineSignedTransferNonce(nonceJournal, authorization.nonce, authorization.manifestSha256);
  };
  const forgedWire = await captureWire(f.source, {
    permitBytes, signatureBytes: Buffer.from("A".repeat(86) + "=="),
  });
  await assert.rejects(receiveOfflineWireToQuarantine({
    readable: readWire(forgedWire), stagingParent: f.stage, requireRoot: true, authorizeTransfer,
  }), /owner Ed25519 transfer permission invalid/u);
  assert.deepEqual(readdirSync(nonceJournal), []);
  assert.deepEqual(readdirSync(f.stage), [".receiver-lock"]);
  const stage = await receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: true, authorizeTransfer,
  });
  assert.equal(stage.manifestSha256, manifestSha256);
  assert.equal(readFileSync(path.join(nonceJournal, permit.nonce), "utf8"),
    "VIRKI_SIGNED_TRANSFER_NONCE_V1 " + manifestSha256 + "\n");
  rmSync(stage.pendingDirectory, { recursive: true, force: true });
  await assert.rejects(receiveOfflineWireToQuarantine({
    readable: readWire(wire), stagingParent: f.stage, requireRoot: true, authorizeTransfer,
  }), /EEXIST/u);
  assert.deepEqual(readdirSync(f.stage), [".receiver-lock"]);
  for (const override of [
    { signatureBytes: Buffer.from("A".repeat(86) + "==") },
    { manifestSha256: "0".repeat(64) },
    { envelopeSha256: "0".repeat(64) },
  ]) assert.throws(() => verifyRemoteOfflineTransferPermit({
    permitBytes, signatureBytes, hostPolicy, manifestSha256, envelopeSha256,
    ...override, now,
  }));
  assert.throws(() => verifyRemoteOfflineTransferPermit({
    permitBytes, signatureBytes, hostPolicy: { ...hostPolicy,
      clientSshKeyPinSha256: "0".repeat(64) }, manifestSha256, envelopeSha256, now,
  }));
  assert.throws(() => verifyRemoteOfflineTransferPermit({
    permitBytes, signatureBytes, hostPolicy, manifestSha256, envelopeSha256, now: now + 301,
  }));
});

test("rejects forged header/path/malformed inventory before any file creation", linux, async (t) => {
  const f = privateFixture(t);
  const wire = await captureWire(f.source);
  const len = wire.readUInt32BE(0);
  const original = JSON.parse(wire.subarray(4, 4 + len).toString("utf8"));
  const invalid = [
    { ...original, files: [{ ...original.files[0], name: "../escape" }, ...original.files.slice(1)] },
    { ...original, files: original.files.slice(0, 10) },
    { ...original, files: [{ ...original.files[0], size: 9e15 }, ...original.files.slice(1)] },
    { ...original, files: [{ ...original.files[0], sha256: "0".repeat(64) }, ...original.files.slice(1)] },
  ];
  for (const obj of invalid) {
    const metadata = Buffer.from(JSON.stringify(obj));
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(metadata.length);
    const corrupt = Buffer.concat([prefix, metadata, wire.subarray(4 + len)]);
    await assert.rejects(receiveOfflineWireToQuarantine({
      readable: readWire(corrupt), stagingParent: f.stage, requireRoot: false,
    }));
    assert.deepEqual(readdirSync(f.stage), []);
  }
});

test("source path symlink, hardlink, foreign file and public directory are refused", linux, async (t) => {
  const f = privateFixture(t);
  const sourceFile = path.join(f.source, "manifest.json");
  const target = path.join(f.root, "linked");
  linkSync(sourceFile, target);
  await assert.rejects(captureWire(f.source), /unsafe file inode/u);
  rmSync(target);
  rmSync(sourceFile);
  symlinkSync(path.join(f.source, "signatures.json"), sourceFile);
  await assert.rejects(captureWire(f.source), /unsafe file inode/u);
  rmSync(sourceFile);
  writeFileSync(sourceFile, "new manifest", { mode: 0o600 });
  writeFileSync(path.join(f.source, "extra"), "no", { mode: 0o600 });
  await assert.rejects(captureWire(f.source), /foreign or missing/u);
  rmSync(path.join(f.source, "extra"));
  chmodSync(f.source, 0o755);
  await assert.rejects(captureWire(f.source), /owner-private 0700/u);
});

test("host receiver SSH argv pins exact peer, user, key, identity and fixed forced command", () => {
  const args = buildPinnedOfflineReceiverSshArgs({
    trustedDirectory: "/etc/virki/offline-client-trust",
    config: { sshAlias: "virki-prod", host: "host.example.test", port: 2222,
      root: "/srv/virki", sshUser: "virki-offline" },
  });
  assert.deepEqual(args.slice(0, 2), ["-F", "none"]);
  assert.ok(args.includes("HostName=host.example.test"));
  assert.ok(args.includes("Port=2222"));
  assert.ok(args.includes("User=virki-offline"));
  assert.ok(args.includes("RequestTTY=no"));
  assert.ok(args.includes("StrictHostKeyChecking=yes"));
  assert.ok(args.includes("HostKeyAlgorithms=ssh-ed25519"));
  assert.ok(args.includes("IdentityAgent=none"));
  assert.ok(args.includes("PasswordAuthentication=no"));
  assert.equal(args.at(-1), "offline-receive-v1");
  assert.equal(args.at(-2), "virki-prod");
  assert.throws(() => buildPinnedOfflineReceiverSshArgs({
    trustedDirectory: "/etc/virki/offline-client-trust",
    config: { sshAlias: "virki-prod", host: "host.example.test", port: 2222,
      root: "/srv/virki", sshUser: "root" },
  }), /fixed|untrusted/u);
  for (const sshUser of ["-o ProxyCommand=evil", "root; true", "../../root", ""]) {
    assert.throws(() => buildPinnedOfflineReceiverSshArgs({
      trustedDirectory: "/etc/virki/offline-client-trust",
      config: { sshAlias: "virki-prod", host: "host.example.test", port: 2222,
        root: "/srv/virki", sshUser },
    }));
  }
});

test("the production entrypoint refuses fabricated permission before SSH writes", async () => {
  await assert.rejects(transferOfflineSignedCandidate({}), /exact three path inputs required/u);
  await assert.rejects(transferOfflineSignedCandidate({
    candidateDirectory: "/missing", trustedDirectory: "/missing", repositoryRoot: "/missing",
  }));
});

test("offline-only preflight rewrites eight probes, docker and identity into fixed forced-command selectors", () => {
  const config = { sshAlias: "virki-prod", host: "host.example.test", port: 2222,
    root: "/srv/virki", sshUser: "virki-offline" };
  for (const [remote, expected] of [
    ["bash -s -- probe /srv/virki", "offline-probe-v1"],
    ["bash -s -- docker /srv/virki", "offline-docker-v1"],
    ["bash -s -- identity /srv/virki", "offline-identity-v1"],
  ]) {
    assert.deepEqual(rewriteOfflineProbeRequest([...SSH_OPTIONS, config.sshAlias, remote],
      "test-local-script-discarded", config), [...SSH_OPTIONS, config.sshAlias, expected]);
  }
  for (const bad of [
    "bash -s -- deploy /srv/virki", "bash -s -- probe /tmp/evil",
    "bash -s -- docker /srv/virki; id", "bash -s --",
    "offline-receive-v1", "offline-identity-v1",
  ]) assert.throws(() => rewriteOfflineProbeRequest([...SSH_OPTIONS, config.sshAlias, bad],
    "script", config));
  assert.throws(() => rewriteOfflineProbeRequest([...SSH_OPTIONS, "attacker", "bash -s -- probe /srv/virki"],
    "script", config));
  assert.throws(() => rewriteOfflineProbeRequest([...SSH_OPTIONS, config.sshAlias, "bash -s -- probe /srv/virki"],
    "script", { ...config, root: "/tmp/evil" }));
});

test("forced command gate accepts only fixed receive/probe/docker/identity selectors", () => {
  assert.equal(restrictedOfflineSshGateSelector("offline-receive-v1"), null);
  for (const [command, selector] of [
    ["offline-probe-v1", "--read-probe"],
    ["offline-docker-v1", "--read-docker"],
    ["offline-identity-v1", "--read-identity"],
  ]) assert.equal(restrictedOfflineSshGateSelector(command), selector);
  for (const input of [
    "", undefined, null, "bash -s --", "bash -s -- probe /srv/virki",
    "offline-probe-v1; /bin/sh", "offline-probe-v1\n", "offline-docker-v1 /tmp",
    "offline-receive-v1; id", "/bin/sh", "scp -t /etc",
  ]) assert.throws(() => restrictedOfflineSshGateSelector(input));
});

test("sudo privilege boundary pins only four exact executable+argv combinations", () => {
  const prefix = ["-n", "-u", "root", "--", "/usr/bin/node",
    "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs"];
  for (const [original, suffix] of [
    ["offline-receive-v1", []], ["offline-probe-v1", ["--read-probe"]],
    ["offline-docker-v1", ["--read-docker"]],
    ["offline-identity-v1", ["--read-identity"]],
  ]) {
    assert.deepEqual(buildExactRestrictedOfflineSudoArgs(original), [...prefix, ...suffix]);
  }
  for (const bad of [undefined, "", "sudo -s", "offline-probe-v1 --extra",
    "bash -s --", "offline-receive-v1; id"]) {
    assert.throws(() => buildExactRestrictedOfflineSudoArgs(bad));
  }
});

test("restricted SSH gate and privileged receiver cannot execute from the local checkout", () => {
  const script = path.join(import.meta.dirname, "offline-host-transfer-receiver.mjs");
  for (const args of [[], ["--gate"], ["--gate", "extra"], ["--untrusted"],
    ["--read-probe"], ["--read-docker"], ["--read-identity"],
  ]) {
    const attempt = spawnSync(process.execPath, [script, ...args], {
      encoding: "utf8", timeout: 10000,
      env: {
        ...process.env, SSH_ORIGINAL_COMMAND: "offline-receive-v1",
        SUDO_USER: "virki-offline", SUDO_UID: "1000",
        SUDO_COMMAND: "/usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs",
      },
    });
    assert.equal(attempt.status, 2);
    assert.ok(attempt.stderr.length < 300);
  }
});

test("normal OpenSSH Ed25519 public key maps to precisely the owner's SPKI pin", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const type = Buffer.from("ssh-ed25519");
  const length = (size) => {
    const output = Buffer.alloc(4);
    output.writeUInt32BE(size);
    return output;
  };
  const wire = Buffer.concat([length(type.length), type, length(32), spki.subarray(-32)]);
  const openSsh = "ssh-ed25519 " + wire.toString("base64") + " ephemeral-test@localhost\n";
  assert.equal(parsePinnedOpenSshEd25519PublicKey(openSsh), digest(spki));
  for (const bad of [
    "ssh-rsa " + wire.toString("base64"),
    "ssh-ed25519 " + wire.subarray(0, -1).toString("base64"),
    "ssh-ed25519 " + Buffer.alloc(51).toString("base64"),
    "ssh-ed25519 bad!base64",
  ]) assert.throws(() => parsePinnedOpenSshEd25519PublicKey(bad));
});

test("genuine ssh-keygen OpenSSH Ed25519 private key yields its exact public SPKI pin", linux, (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-openssh-real-key-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const key = path.join(root, "id_ed25519");
  const made = spawnSync("/usr/bin/ssh-keygen",
    ["-q", "-t", "ed25519", "-N", "", "-f", key], { encoding: "utf8", timeout: 10000 });
  assert.equal(made.status, 0, "genuine OpenSSH private key generation must succeed");
  assert.match(readFileSync(key, "utf8"), /BEGIN OPENSSH PRIVATE KEY/u);
  const actual = deriveOpenSshPrivateIdentityPin(key);
  const ownerPublic = readFileSync(key + ".pub", "utf8");
  assert.equal(actual, parsePinnedOpenSshEd25519PublicKey(ownerPublic));
  const other = path.join(root, "other_ed25519");
  assert.equal(spawnSync("/usr/bin/ssh-keygen",
    ["-q", "-t", "ed25519", "-N", "", "-f", other], { timeout: 10000 }).status, 0);
  assert.notEqual(actual, deriveOpenSshPrivateIdentityPin(other));
  assert.throws(() => deriveOpenSshPrivateIdentityPin(key + ".pub"));
});

test("real Ed25519 owner permit binds manifest, envelope, SSH destination, key, receiver and expiry", () => {
  const owner = generateKeyPairSync("ed25519");
  const now = 1800000000;
  const config = { sshAlias: "virki-prod", host: "host.example.test",
    port: 2222, root: "/srv/virki", sshUser: "virki-offline" };
  const plan = {
    status: "PRETRANSFER_INSPECTED_DEPLOY_BLOCKED", revision: "a".repeat(40),
    signedManifestSha256: "b".repeat(64), signedEnvelopeSha256: "c".repeat(64),
    transferAuthorized: false, deployAuthorized: false,
  };
  const permit = {
    version: 1, mode: "owner-signed-ssh-stage-v1",
    sourceSha: plan.revision, manifestSha256: plan.signedManifestSha256,
    envelopeSha256: plan.signedEnvelopeSha256, sshAlias: config.sshAlias,
    host: config.host, port: config.port, sshUser: config.sshUser,
    knownHostsSha256: "d".repeat(64), clientSshKeyPinSha256: "e".repeat(64),
    receiverPath: "/usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs",
    stageRoot: "/var/lib/virki/offline-staging", nonce: "f".repeat(32),
    expiresAt: now + 300,
  };
  const ownerPublicKeyPem = owner.publicKey.export({ type: "spki", format: "pem" });
  const signed = (value) => {
    const permitBytes = Buffer.from(JSON.stringify(value));
    const signatureBytes = Buffer.from(sign(null,
      Buffer.concat([Buffer.from("VIRKI_OFFLINE_SSH_TRANSFER_PERMIT_V1\0"), permitBytes]),
      owner.privateKey).toString("base64"));
    return {
      permitBytes, signatureBytes, ownerPublicKeyPem,
      clientSshKeyPinSha256: "e".repeat(64), plan,
      config, knownHostsSha256: "d".repeat(64), now,
    };
  };
  const authorized = verifyOwnerSignedOfflineSshPermit(signed(permit));
  assert.equal(authorized.status, "OWNER_APPROVED_EXACT_SSH_TRANSFER");
  assert.equal(authorized.transferAuthorized, true);
  assert.equal(authorized.deployAuthorized, false);
  for (const modified of [
    { ...permit, manifestSha256: "9".repeat(64) },
    { ...permit, envelopeSha256: "9".repeat(64) },
    { ...permit, sourceSha: "9".repeat(40) },
    { ...permit, knownHostsSha256: "9".repeat(64) },
    { ...permit, clientSshKeyPinSha256: "9".repeat(64) },
    { ...permit, sshUser: "nobody" },
    { ...permit, sshUser: "root" },
    { ...permit, host: "attacker.example.test" },
    { ...permit, receiverPath: "/tmp/evil" },
    { ...permit, stageRoot: "/srv/demanage" },
    { ...permit, expiresAt: now - 1 },
    { ...permit, expiresAt: now + 3600 },
    { ...permit, nonce: "bad" },
  ]) assert.throws(() => verifyOwnerSignedOfflineSshPermit(signed(modified)));
  const incorrectOwner = generateKeyPairSync("ed25519");
  assert.throws(() => verifyOwnerSignedOfflineSshPermit({
    ...signed(permit),
    ownerPublicKeyPem: incorrectOwner.publicKey.export({ type: "spki", format: "pem" }),
  }), /owner Ed25519 transfer permission invalid/u);
  assert.throws(() => verifyOwnerSignedOfflineSshPermit({
    ...signed(permit), signatureBytes: Buffer.from("A".repeat(86) + "=="),
  }), /owner Ed25519 transfer permission invalid/u);
  assert.throws(() => verifyOwnerSignedOfflineSshPermit({
    ...signed(permit), clientSshKeyPinSha256: "0".repeat(64),
  }), /permit differs/u);
  assert.throws(() => verifyOwnerSignedOfflineSshPermit({
    ...signed(permit), plan: { ...plan, transferAuthorized: true },
  }), /permit does not bind/u);
});
