import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, chownSync, linkSync, mkdtempSync, mkdirSync, readFileSync,
  renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  renderNativeOwnerSshdMatch, renderNativeOwnerSudoers,
  validateOwnerSshBlueprint, inspectOwnerSshBootstrapFixture,
  inspectInstalledOwnerSshBootstrap,
} from "./native-owner-ssh-bootstrap.mjs";

const expectedGate = "/usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const eligible = process.platform === "linux" && process.getuid?.() === 0;
function wireKey(publicKey) {
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const str = (bytes) => {
    const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length);
    return Buffer.concat([size, bytes]);
  };
  return "ssh-ed25519 " + Buffer.concat([str(Buffer.from("ssh-ed25519")), str(raw)]).toString("base64");
}
function fixture(t) {
  const root = mkdtempSync("/dev/shm/virki-ssh-bootstrap-");
  chmodSync(root, 0o755); // only public paths; signer/policy roots remain 0700
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const places = {
    sshd: path.join(root, "etc/virki/offline-transfer-ssh/sshd_config"),
    sudoers: path.join(root, "etc/sudoers.d/virki-offline-transfer"),
    authorized: path.join(root, "etc/virki/offline-transfer-ssh/authorized_keys"),
    receiver: path.join(root, "usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs"),
    protocol: path.join(root, "usr/local/lib/virki/offline-transfer/lib/offline-ssh-stage-protocol.mjs"),
    permit: path.join(root, "usr/local/lib/virki/offline-transfer/lib/offline-ssh-transfer-permit.mjs"),
    hostPolicy: path.join(root, "etc/virki/offline-transfer-host/host-policy.json"),
    releasePolicy: path.join(root, "etc/virki/offline-release/trust-policy.json"),
    machineId: path.join(root, "etc/machine-id"),
  };
  for (const file of Object.values(places)) mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  for (const leaf of [places.authorized, places.receiver, places.protocol, places.permit]) {
    let ancestor = path.dirname(leaf);
    while (ancestor !== root) {
      chmodSync(ancestor, 0o755);
      ancestor = path.dirname(ancestor);
    }
  }
  const key = generateKeyPairSync("ed25519").publicKey;
  const owner = generateKeyPairSync("ed25519").publicKey;
  const pub = wireKey(key);
  const authorized = 'restrict,command="' + expectedGate + '" ' + pub + "\n";
  const policy = {
    version: 1, mode: "offline-host-transfer-v1", expectedSourceSha: "a".repeat(40),
    host: "fixture.example.invalid", port: 2223, sshAlias: "fixture",
    sshUser: "virki-offline", knownHostsSha256: "b".repeat(64),
    clientSshKeyPinSha256: sha(key.export({ type: "spki", format: "der" })),
    ownerPublicKeyPem: owner.export({ type: "spki", format: "pem" }),
  };
  for (const [file, contents, mode] of [
    [places.sshd, renderNativeOwnerSshdMatch(), 0o600],
    [places.sudoers, renderNativeOwnerSudoers(), 0o440],
    [places.authorized, authorized, 0o644],
    [places.receiver, "// disposable installed fixture\n", 0o644],
    [places.protocol, "// public pinned protocol dependency\n", 0o644],
    [places.permit, "// public pinned permit dependency\n", 0o644],
    [places.hostPolicy, JSON.stringify(policy), 0o600],
    [places.releasePolicy, JSON.stringify({
      version: 2, hostIdentitySha256: sha(Buffer.concat([
        Buffer.from("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0"), Buffer.from("a".repeat(32)),
      ])),
      owner: { keyId: "release-owner", publicKeyPem: policy.ownerPublicKeyPem,
        pinSha256: sha(owner.export({ type: "spki", format: "der" })) },
      revokedKeyIds: [], revokedPinsSha256: [],
    }), 0o600],
    [places.machineId, "a".repeat(32) + "\n", 0o644],
  ]) {
    writeFileSync(file, contents, { mode }); chmodSync(file, mode); chownSync(file, 0, 0);
  }
  return { root, places, authorized, policy };
}

test("owner SSH blueprint has exact Match account, forced command, and four non-wildcard sudo rules", () => {
  const sshd = renderNativeOwnerSshdMatch(), sudoers = renderNativeOwnerSudoers();
  assert.match(sshd, /\nMatch User virki-offline\n/u);
  assert.match(sshd, /ForceCommand \/usr\/bin\/node .* --gate/u);
  assert.match(sshd, /AuthenticationMethods publickey/u);
  assert.match(sshd, /PasswordAuthentication no/u);
  assert.match(sshd, /DisableForwarding yes/u);
  assert.match(sshd, /PermitTTY no/u);
  assert.doesNotMatch(sshd + sudoers, /\*|\/bin\/(?:sh|bash)|SETENV:|\/usr\/bin\/env/u);
  assert.match(sudoers, /Cmnd_Alias VIRKI_OFFLINE_TRANSFER/u);
  assert.equal((sudoers.match(/\/usr\/bin\/node \/usr\/local\/lib\/virki\/offline-transfer\/offline-host-transfer-receiver\.mjs/g) ?? []).length, 4);
  assert.equal(validateOwnerSshBlueprint({ sshd, sudoers }), true);
  for (const [sshdBad, sudoBad] of [
    [sshd.replace("ForceCommand ", "#ForceCommand "), sudoers],
    [sshd.replace("PasswordAuthentication no", "PasswordAuthentication yes"), sudoers],
    [sshd.replace("Match User virki-offline", "Match User *"), sudoers],
    [sshd, sudoers.replace(" --read-probe", " *")],
    [sshd, sudoers + "virki-offline ALL=(ALL) NOPASSWD: ALL\n"],
  ]) assert.throws(() => validateOwnerSshBlueprint({ sshd: sshdBad, sudoers: sudoBad }));
});

test("only installed fixed-root gate may report readiness; uninstalled checkout always blocks", () => {
  assert.deepEqual(inspectInstalledOwnerSshBootstrap(), {
    status: "OWNER_SSH_BOOTSTRAP_NOT_INSTALLED", deployAuthorized: false,
  });
  assert.throws(() => inspectInstalledOwnerSshBootstrap({ root: "/tmp", ownerKeyPem: "attacker" }));
});

test("real unprivileged SSH key reader and forced-command Node can traverse and read only public root-owned files", {
  skip: !eligible,
}, (t) => {
  const f = fixture(t);
  const reader = spawnSync(process.execPath, ["-e", `
    const fs = require("node:fs");
    for (const pathname of process.argv.slice(1)) {
      const data = fs.readFileSync(pathname);
      if (!data.length) process.exit(13);
      try { fs.openSync(pathname, "a"); process.exit(14); }
      catch (e) { if (e.code !== "EACCES") process.exit(15); }
    }
    process.stdout.write("UNPRIVILEGED_CAN_READ_NO_WRITE");
  `, f.places.authorized, f.places.receiver, f.places.protocol, f.places.permit], {
    uid: 65534, gid: 65534, shell: false, encoding: "utf8", timeout: 5000,
  });
  assert.equal(reader.error, undefined, String(reader.error));
  assert.equal(reader.status, 0, reader.stderr);
  assert.equal(reader.stdout, "UNPRIVILEGED_CAN_READ_NO_WRITE");
  const privateRead = spawnSync(process.execPath, ["-e", `
    try { require("node:fs").readFileSync(process.argv[1]); process.exit(13); }
    catch (e) { process.exit(e.code === "EACCES" ? 0 : 14); }
  `, f.places.hostPolicy], {
    uid: 65534, gid: 65534, shell: false, encoding: "utf8", timeout: 5000,
  });
  assert.equal(privateRead.status, 0, privateRead.stderr);
});

test("root-only read-only fixture validates actual pinned SSH public key and resists file and policy attacks", {
  skip: !eligible,
}, (t) => {
  const good = fixture(t);
  assert.equal(inspectOwnerSshBootstrapFixture(good.places).status, "FIXTURE_PROTECTED_SSH_BLUEPRINT_ONLY");
  const changes = [
    (f) => { writeFileSync(f.places.authorized, f.authorized.replace("restrict,", "")); },
    (f) => { writeFileSync(f.places.authorized, f.authorized.replace(" --gate", " --read-probe")); },
    (f) => { writeFileSync(f.places.authorized, f.authorized + f.authorized); },
    (f) => { chmodSync(f.places.authorized, 0o666); },
    (f) => { writeFileSync(f.places.hostPolicy, JSON.stringify({ ...f.policy, clientSshKeyPinSha256: "f".repeat(64) })); },
    (f) => { writeFileSync(f.places.sudoers, renderNativeOwnerSudoers() + "virki-offline ALL=(ALL) NOPASSWD: ALL\n"); },
    (f) => { chmodSync(path.dirname(f.places.sudoers), 0o777); },
    (f) => { writeFileSync(f.places.machineId, "0".repeat(32) + "\n"); },
    (f) => { writeFileSync(f.places.releasePolicy, '{"version":2,"hostIdentitySha256":"' + "f".repeat(64) + '"}'); },
    (f) => { const p = JSON.parse(readFileSync(f.places.releasePolicy, "utf8")); p.revokedKeyIds.push("release-owner"); writeFileSync(f.places.releasePolicy, JSON.stringify(p)); },
    (f) => { const p = JSON.parse(readFileSync(f.places.releasePolicy, "utf8")); p.owner.pinSha256 = "f".repeat(64); writeFileSync(f.places.releasePolicy, JSON.stringify(p)); },
    (f) => { renameSync(f.places.authorized, f.places.authorized + ".original"); symlinkSync(f.places.authorized + ".original", f.places.authorized); },
    (f) => { linkSync(f.places.authorized, path.join(f.root, "untrusted-second-link")); },
    (f) => { chmodSync(path.dirname(f.places.hostPolicy), 0o777); },
    (f) => { chmodSync(f.places.authorized, 0o600); },
    (f) => { chmodSync(f.places.receiver, 0o600); },
    (f) => { chmodSync(f.places.protocol, 0o600); },
    (f) => { chmodSync(f.places.permit, 0o600); },
    (f) => { chmodSync(path.dirname(f.places.authorized), 0o700); },
    (f) => { chmodSync(path.dirname(f.places.receiver), 0o700); },
    (f) => { chmodSync(path.dirname(f.places.protocol), 0o700); },
  ];
  for (const change of changes) {
    const f = fixture(t);
    change(f);
    assert.throws(() => inspectOwnerSshBootstrapFixture(f.places));
  }
});

test("real visudo parses the exact static sudoers without trusting a candidate", {
  skip: process.platform !== "linux",
}, (t) => {
  const candidate = "/usr/sbin/visudo";
  const check = spawnSync(candidate, ["-V"], { encoding: "utf8", timeout: 5000 });
  if (check.error) return t.skip("visudo not installed in disposable Linux runtime");
  const dir = mkdtempSync("/dev/shm/virki-ssh-sudoers-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, "virki-offline-transfer");
  writeFileSync(filename, renderNativeOwnerSudoers());
  const run = spawnSync(candidate, ["-cf", filename], { encoding: "utf8", timeout: 5000 });
  assert.equal(run.status, 0, run.stderr);
});
