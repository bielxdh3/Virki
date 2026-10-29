import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, chownSync, copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  renderOwnerPinnedOfflineSshBootstrap,
  attestDisposableOfflineSshBootstrap,
  inspectOwnerPinnedOfflineSshRuntime,
  inspectInstalledOwnerSshBootstrapReadiness,
  writeDisposableOwnerSshBootstrapReviewBundle,
  verifyRestrictedOfflineSshdEffectiveConfiguration,
  verifyUnrelatedSshdEffectiveBaselines,
  SHARED_SSHD_BASELINE_CONTEXTS,
} from "./owner-ssh-bootstrap.mjs";

const digest = (data) => createHash("sha256").update(data).digest("hex");
function sshKey() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  const alg = Buffer.from("ssh-ed25519");
  const field = (part) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(part.length);
    return Buffer.concat([len, part]);
  };
  return { key: `ssh-ed25519 ${Buffer.concat([field(alg), field(der.subarray(-32))]).toString("base64")}`,
    pin: digest(der) };
}
const FIXED = Object.freeze([
  "offline-host-transfer-receiver.mjs",
  "lib/offline-ssh-stage-protocol.mjs",
  "lib/offline-ssh-transfer-permit.mjs",
]);
const claimed = () => {
  const client = sshKey(); const host = sshKey();
  return { clientPublicKey: client.key + " test@local",
    independentlyPinnedClientSpkiSha256: client.pin,
    hostPublicKey: host.key + " test-host@local",
    independentlyPinnedHostSpkiSha256: host.pin,
    reviewedReceiverFiles: FIXED.map((name, i) => ({
      path: name, sha256: String.fromCharCode(97 + i).repeat(64),
    })),
    reviewedNode22ExecutableSha256: "d".repeat(64),
    unrelatedSshdBaselineSha256: "e".repeat(64) };
};
test("native readiness requires complete preapproved unrelated-principal SSH baselines", () => {
  assert.equal(SHARED_SSHD_BASELINE_CONTEXTS.length, 9);
  assert.equal(new Set(SHARED_SSHD_BASELINE_CONTEXTS).size, 9);
  assert.ok(SHARED_SSHD_BASELINE_CONTEXTS.every((context) =>
    /user=(?:root|nobody|unrelated-admin),/u.test(context)));
  const baseline = { version: 1, snapshots: SHARED_SSHD_BASELINE_CONTEXTS.map(
    (context, index) => ({ context, effective: `port 22\npermittty yes\nprofile ${index}\n` })) };
  const current = baseline.snapshots.map((snapshot) => snapshot.effective);
  assert.equal(verifyUnrelatedSshdEffectiveBaselines(baseline, current), true);
  assert.throws(() => verifyUnrelatedSshdEffectiveBaselines(baseline,
    current.map((v, index) => index === 4 ? v.replace("yes", "no") : v)), /refused/u);
  assert.throws(() => verifyUnrelatedSshdEffectiveBaselines({
    ...baseline, snapshots: baseline.snapshots.slice(1),
  }, current), /refused/u);
  assert.throws(() => verifyUnrelatedSshdEffectiveBaselines({
    ...baseline, snapshots: baseline.snapshots.map((s, i) =>
      i === 0 ? { context: "user=virki-offline,host=localhost,addr=127.0.0.1,lport=22",
        effective: s.effective } : s),
  }, current), /refused/u);
  assert.throws(() => verifyUnrelatedSshdEffectiveBaselines(baseline,
    current.slice(1)), /refused/u);
});
test("produces exact four command sudoers, doubly forced authorized_keys and no interactive SSH", () => {
  const source = claimed();
  const result = renderOwnerPinnedOfflineSshBootstrap(source);
  assert.equal(result.status, "OWNER_SSH_BOOTSTRAP_REVIEW_ONLY");
  assert.equal(result.installAuthorized, false);
  assert.equal(result.deployAuthorized, false);
  assert.deepEqual(Object.keys(result.files), ["authorized_keys", "sudoers", "sshd_config"]);
  const entry = " /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs";
  assert.equal(result.files.authorized_keys.mode, 0o644);
  assert.equal(result.files.sudoers.mode, 0o440);
  assert.match(result.files.authorized_keys.contents,
    /^restrict,command="\/usr\/bin\/node \/usr\/local\/lib\/virki\/offline-transfer\/offline-host-transfer-receiver\.mjs --gate" ssh-ed25519 [A-Za-z0-9+/]+={0,2}\n$/u);
  assert.match(result.files.sudoers.contents, /Defaults:virki-offline env_reset,!setenv\n/u);
  assert.match(result.files.sudoers.contents, /NOPASSWD: VIRKI_OFFLINE_TRANSFER/u);
  assert.equal((result.files.sudoers.contents.match(/\/usr\/bin\/node/g) ?? []).length, 4);
  assert.equal((result.files.sudoers.contents.match(/--read-/g) ?? []).length, 3);
  assert.ok(result.files.sudoers.contents.includes(entry));
  assert.equal(result.files.sshd_config.path, "/etc/ssh/sshd_config.d/90-virki-offline.conf");
  assert.match(result.files.sshd_config.contents, /^#.*restricted.*\nMatch User virki-offline\n/iu);
  for (const requirement of [
    "ForceCommand /usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate",
    "AuthenticationMethods publickey", "PasswordAuthentication no",
    "KbdInteractiveAuthentication no", "PermitTTY no", "AllowTcpForwarding no",
    "X11Forwarding no", "AllowAgentForwarding no", "PermitUserRC no",
    "AuthorizedKeysFile /etc/ssh/virki-offline/authorized_keys",
    "AuthorizedKeysCommand none", "TrustedUserCAKeys none",
    "AuthorizedPrincipalsCommand none", "AuthorizedPrincipalsFile none",
    "PubkeyAcceptedAlgorithms ssh-ed25519",
    "HostbasedAuthentication no", "GSSAPIAuthentication no",
  ]) assert.ok(result.files.sshd_config.contents.includes(requirement + "\n"), requirement);
  assert.deepEqual(result.receiverFiles, source.reviewedReceiverFiles);
  assert.equal(result.node22Sha256, source.reviewedNode22ExecutableSha256);
});

test("restricted account effective policy rejects ambient alternate pubkey and cert authentication", () => {
  const expected = [
    ["hostkey", "/etc/ssh/ssh_host_ed25519_key"],
    ["authorizedkeysfile", "/etc/ssh/virki-offline/authorized_keys"],
    ["authorizedkeyscommand", "none"], ["trustedusercakeys", "none"],
    ["authorizedprincipalscommand", "none"],
    ["authorizedprincipalsfile", "none"], ["hostbasedauthentication", "no"],
    ["gssapiauthentication", "no"],
    ["pubkeyacceptedalgorithms", "ssh-ed25519"],
    ["forcecommand", "/usr/bin/node /usr/local/lib/virki/offline-transfer/offline-host-transfer-receiver.mjs --gate"],
    ["authenticationmethods", "publickey"], ["pubkeyauthentication", "yes"],
    ["passwordauthentication", "no"], ["kbdinteractiveauthentication", "no"],
    ["permittty", "no"], ["allowtcpforwarding", "no"],
    ["allowagentforwarding", "no"], ["x11forwarding", "no"],
    ["permittunnel", "no"], ["permituserrc", "no"],
    ["permituserenvironment", "no"], ["permitopen", "none"],
    ["permitlisten", "none"], ["maxsessions", "1"], ["strictmodes", "yes"],
  ];
  const make = (list) => list.map(([name, value]) => name + " " + value).join("\n") + "\n";
  const actual = make(expected);
  assert.equal(verifyRestrictedOfflineSshdEffectiveConfiguration(actual), true);
  for (const [key, altered] of [
    ["authorizedkeyscommand", "/usr/local/bin/alternate-keys %u"],
    ["trustedusercakeys", "/etc/ssh/trusted_ca"],
    ["authorizedprincipalscommand", "/usr/bin/true"],
    ["authorizedprincipalsfile", "/tmp/other"],
    ["authorizedkeysfile", "/home/virki-offline/.ssh/authorized_keys"],
    ["hostkey", "/etc/ssh/evil_host_key"],
    ["forcecommand", "none"],
    ["hostbasedauthentication", "yes"],
    ["pubkeyacceptedalgorithms", "ssh-ed25519,ssh-rsa"],
    ["gssapiauthentication", "yes"],
  ]) {
    assert.throws(() => verifyRestrictedOfflineSshdEffectiveConfiguration(
      make(expected.map((entry) => entry[0] === key ? [key, altered] : entry))),
    /refused/u, key);
  }
  assert.throws(() => verifyRestrictedOfflineSshdEffectiveConfiguration(
    actual + "authorizedkeyscommand /usr/bin/true\n"), /refused/u);
  assert.throws(() => verifyRestrictedOfflineSshdEffectiveConfiguration(
    actual.replace("authorizedkeyscommand none\n", "")), /refused/u);
});

test("native host readiness has no request/fixture authority and always blocks off-host", () => {
  assert.deepEqual(inspectInstalledOwnerSshBootstrapReadiness(), {
    status: "blocked", installAuthorized: false, deployAuthorized: false,
  });
  assert.deepEqual(inspectInstalledOwnerSshBootstrapReadiness({
    sshdConfig: "/tmp/inject", ownerPins: claimed(), allowShell: true,
  }), { status: "blocked", installAuthorized: false, deployAuthorized: false });
});

test("owner-reviewed installable three-file recipe is materialized exclusively in empty root tmpfs",
  { skip: process.platform !== "linux" || process.getuid?.() !== 0 ?
    "Root Linux disposable tmpfs required" : false }, (t) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-offline-ssh-bootstrap-test-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const folder = path.join(root, "reviewed");
    const approved = claimed();
    const result = writeDisposableOwnerSshBootstrapReviewBundle({
      directory: folder, independentlyReviewed: approved,
    });
    assert.equal(result.status, "SSH_BOOTSTRAP_FILES_INSPECTED_NOT_INSTALLED");
    assert.equal(result.installAuthorized, false);
    assert.equal(result.deployAuthorized, false);
    assert.equal(readFileSync(path.join(folder, "sudoers"), "utf8"),
      renderOwnerPinnedOfflineSshBootstrap(approved).files.sudoers.contents);
    assert.throws(() => writeDisposableOwnerSshBootstrapReviewBundle({
      directory: folder, independentlyReviewed: approved,
    }), /refused/u, "cannot overwrite a previously materialized bundle");
    assert.throws(() => writeDisposableOwnerSshBootstrapReviewBundle({
      directory: "/etc/sudoers.d", independentlyReviewed: approved,
    }), /refused/u, "must not write actual owner host paths");
  });

test("actual visudo parses generated exact four-command rule on disposable Linux",
  { skip: process.platform !== "linux" ? "Native visudo unavailable" : false }, (t) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "virki-ssh-visudo-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const file = path.join(dir, "virki-offline");
    writeFileSync(file, renderOwnerPinnedOfflineSshBootstrap(claimed()).files.sudoers.contents,
      { mode: 0o440 });
    const checked = spawnSync("/usr/sbin/visudo", ["-c", "-f", file], {
      encoding: "utf8", timeout: 5000, maxBuffer: 1024, shell: false,
    });
    assert.equal(checked.status, 0, checked.stderr);
  });

test("native owner-pinned Node22 and all three receiver modules require actual unchanged root files",
  { skip: process.platform !== "linux" || process.getuid?.() !== 0 ?
    "Linux root readonly file attestation required" : false }, (t) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-ssh-code-pin-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    mkdirSync(path.join(root, "lib"), { mode: 0o700 });
    const review = claimed();
    review.reviewedReceiverFiles = FIXED.map((name) => {
      const bytes = readFileSync(path.join(import.meta.dirname, "../../scripts", name));
      const destination = path.join(root, name);
      copyFileSync(path.join(import.meta.dirname, "../../scripts", name), destination);
      chmodSync(destination, 0o644);
      chownSync(destination, 0, 0);
      return { path: name, sha256: digest(bytes) };
    });
    review.reviewedNode22ExecutableSha256 = digest(readFileSync("/usr/bin/node"));
    const valid = inspectOwnerPinnedOfflineSshRuntime({
      receiverDirectory: root, nodeExecutable: "/usr/bin/node",
      independentlyReviewed: review,
    });
    assert.equal(valid.status, "NATIVE_SSH_CODE_PINNED_NOT_INSTALLED");
    assert.equal(valid.deployAuthorized, false);
    const child = path.join(root, FIXED[0]);
    writeFileSync(child, "// attacker rewritten root module");
    assert.throws(() => inspectOwnerPinnedOfflineSshRuntime({
      receiverDirectory: root, nodeExecutable: "/usr/bin/node",
      independentlyReviewed: review,
    }), /refused/u);
    copyFileSync(path.join(import.meta.dirname, "../../scripts", FIXED[0]), child);
    chmodSync(child, 0o666);
    assert.throws(() => inspectOwnerPinnedOfflineSshRuntime({
      receiverDirectory: root, nodeExecutable: "/usr/bin/node",
      independentlyReviewed: review,
    }), /refused/u);
    chmodSync(child, 0o644);
    assert.throws(() => inspectOwnerPinnedOfflineSshRuntime({
      receiverDirectory: root, nodeExecutable: "/usr/bin/node",
      independentlyReviewed: { ...review,
        reviewedNode22ExecutableSha256: "f".repeat(64) },
    }), /refused/u);
  });

test("real non-root process reads owner-installed 0644 SSH key and receiver but not 0600 owner pins",
  { skip: process.platform !== "linux" || process.getuid?.() !== 0 ?
    "Native Linux root fixture needed for actual unprivileged probe" : false }, (t) => {
    const root = mkdtempSync(path.join(os.tmpdir(), "virki-ssh-nonroot-read-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    chmodSync(root, 0o755);
    const source = claimed();
    const files = renderOwnerPinnedOfflineSshBootstrap(source).files;
    const readable = ["authorized_keys", "offline-host-transfer-receiver.mjs"];
    writeFileSync(path.join(root, readable[0]), files.authorized_keys.contents, { mode: 0o644 });
    const original = path.join(import.meta.dirname, "../../scripts/offline-host-transfer-receiver.mjs");
    copyFileSync(original, path.join(root, readable[1]));
    chmodSync(path.join(root, readable[1]), 0o644);
    writeFileSync(path.join(root, "owner-pins.json"),
      JSON.stringify(source), { mode: 0o600 });
    const result = spawnSync("/usr/bin/setpriv",
      ["--reuid", "65534", "--regid", "65534", "--clear-groups",
        "/usr/bin/node", "--input-type=module", "-e",
        'import { readFileSync } from "node:fs"; for (const file of ["authorized_keys", "offline-host-transfer-receiver.mjs"]) { if (!readFileSync(file).length) process.exit(2); } try { readFileSync("owner-pins.json"); process.exit(3); } catch (e) { if (e?.code !== "EACCES") process.exit(4); }',
      ], { cwd: root, encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 0, result.stderr + " " + result.error?.message);
  });

test("refuses substituted client or host SPKI and arbitrary installation authority", () => {
  const original = claimed();
  const mutations = [
    { independentlyPinnedClientSpkiSha256: "f".repeat(64) },
    { independentlyPinnedHostSpkiSha256: "e".repeat(64) },
    { clientPublicKey: "ssh-rsa XXX" },
    { hostPublicKey: "ssh-ed25519 ../../../etc/passwd" },
    { reviewedNode22ExecutableSha256: "wrong" },
    { unrelatedSshdBaselineSha256: "wrong" },
    { reviewedReceiverFiles: original.reviewedReceiverFiles.slice(1) },
    { reviewedReceiverFiles: original.reviewedReceiverFiles.map((f) => ({
      ...f, path: "../" + f.path,
    })) },
    { authorizedKeysPath: "/tmp/attacker" }, { allowShell: true },
  ];
  for (const mutation of mutations) {
    assert.throws(() => renderOwnerPinnedOfflineSshBootstrap({
      ...original, ...mutation,
    }), undefined, JSON.stringify(mutation));
  }
});

test("disposable root-owned bundle attestation rejects mutation and unsafe modes",
  { skip: process.platform !== "linux" || process.getuid?.() !== 0 ?
    "Native Linux root tmpfs fixture required" : false }, (t) => {
  const fixture = mkdtempSync(path.join(os.tmpdir(), "virki-offline-ssh-bootstrap-test-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const reviewed = claimed();
  const rendered = renderOwnerPinnedOfflineSshBootstrap(reviewed);
  const dir = path.join(fixture, "reviewed");
  mkdirSync(dir, { mode: 0o700 });
  for (const [name, file] of Object.entries(rendered.files)) {
    writeFileSync(path.join(dir, name), file.contents, { mode: 0o600 });
    chmodSync(path.join(dir, name), file.mode);
  }
  const attestation = attestDisposableOfflineSshBootstrap({
    directory: dir, independentlyReviewed: reviewed,
  });
  assert.equal(attestation.status, "SSH_BOOTSTRAP_FILES_INSPECTED_NOT_INSTALLED");
  assert.equal(attestation.installAuthorized, false);
  const original = readFileSync(path.join(dir, "sudoers"));
  writeFileSync(path.join(dir, "sudoers"), Buffer.concat([original, Buffer.from("virki-offline ALL=(ALL) NOPASSWD: ALL\n")]));
  assert.throws(() => attestDisposableOfflineSshBootstrap({
    directory: dir, independentlyReviewed: reviewed,
  }));
  writeFileSync(path.join(dir, "sudoers"), original);
  chmodSync(path.join(dir, "sudoers"), 0o666);
  assert.throws(() => attestDisposableOfflineSshBootstrap({
    directory: dir, independentlyReviewed: reviewed,
  }));
});
