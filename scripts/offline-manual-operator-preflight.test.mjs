import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { inspectManualOfflineOperatorPreflight } from "./offline-manual-operator-preflight.mjs";

const SHA = (x) => createHash("sha256").update(x).digest("hex");
const DOMAIN = "VIRKI_MANUAL_OFFLINE_PROVISION_CHECKLIST_V1\0";
const now = Math.floor(Date.now() / 1000);
const fakeHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHWfEGVfBCGEiwmo+mo5xd9QkTCv39RbYxjO60V72ec";
const components = ["TRUST_POLICY", "VERIFIER_MODULE", "LEDGER", "ISOLATED_DOCKER_SOCKET", "OWNER_BOOTSTRAP"];
const json = (file, object) => writeFileSync(file, JSON.stringify(object), { mode: 0o600 });

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-manual-operator-test-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const operatorDirectory = path.join(root, "operator");
  mkdirSync(operatorDirectory, { mode: 0o700 });
  const signer = generateKeyPairSync("ed25519");
  const ownerPublicPem = signer.publicKey.export({ type: "spki", format: "pem" });
  const signerSha = SHA(signer.publicKey.export({ type: "spki", format: "der" }));
  const identity = {
    version: 1, mode: "virki-manual-operator-identity-v1", host: "production.example.invalid",
    port: 2222, sshUser: "deploy", hostKeyAlias: "virki-prod",
    sshHostPublicKey: fakeHostKey, expectedSourceSha: "a".repeat(40),
  };
  const checklist = {
    version: 1, mode: "virki-manual-provision-checklist-v1", checklistId: "b".repeat(64),
    identitySha256: SHA(JSON.stringify(identity)), sourceSha: identity.expectedSourceSha,
    issuedAt: now - 1, expiresAt: now + 30, components,
  };
  const writeAll = () => {
    json(path.join(operatorDirectory, "identity.json"), identity);
    json(path.join(operatorDirectory, "owner-pin.json"), {
      version: 1, mode: "separately-provisioned-owner-pin-v1", ownerSignerSpkiSha256: signerSha,
    });
    writeFileSync(path.join(operatorDirectory, "owner-public.pem"), ownerPublicPem, { mode: 0o600 });
    json(path.join(operatorDirectory, "checklist.json"), checklist);
    json(path.join(operatorDirectory, "checklist-signature.json"), {
      version: 1, signature: sign(null, Buffer.from(DOMAIN + JSON.stringify(checklist)), signer.privateKey).toString("base64"),
    });
    writeFileSync(path.join(operatorDirectory, "known_hosts"), `${identity.hostKeyAlias} ${identity.sshHostPublicKey}\n`, { mode: 0o600 });
    writeFileSync(path.join(operatorDirectory, "ssh-identity"), "TEST-NOT-A-REAL-KEY", { mode: 0o600 });
  };
  writeAll();
  return { operatorDirectory, identity, checklist, writeAll };
}

function fakeSsh({ badConfig = false, fail = false, labels = components } = {}) {
  const calls = [];
  const execute = (cmd, args, options) => {
    calls.push({ cmd, args, options });
    assert.equal(cmd, "/usr/bin/ssh");
    if (args.includes("-G")) return { status: 0, stdout: `hostname ${badConfig ? "other.example.invalid" : "production.example.invalid"}\nport 2222\nuser deploy\nstricthostkeychecking true\npermitlocalcommand false\nclearallforwardings true\nidentitiesonly true\nidentityagent none\nupdatehostkeys false\nhostkeyalgorithms ssh-ed25519\n` };
    return fail ? { status: 255, stdout: "", stderr: "password/private failure" } : {
      status: 0, stdout: labels.map((key) => `VIRKI_OFFLINE_COMPONENT_${key}=METADATA_OBSERVED`).join("\n") + "\n",
    };
  };
  return { calls, execute };
}

const POSIX = { skip: process.platform !== "linux" && process.platform !== "darwin" };

test("RED: owner signed independent fixed identity + explicit host key and key file permit read-only SSH metadata only", POSIX, async (t) => {
  const f = fixture(t), ssh = fakeSsh();
  const result = await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: ssh.execute, now });
  assert.equal(result.status, "SIGNED_PROVISION_CHECKLIST_AND_HOST_METADATA_INSPECTED_ONLY");
  assert.deepEqual(result.unverified, []);
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.transferAuthorized, false);
  assert.equal(ssh.calls.length, 2);
  for (const call of ssh.calls) {
    assert.equal(call.args[call.args.indexOf("-F") + 1], "none");
    for (const s of ["StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none", "UpdateHostKeys=no", "IdentitiesOnly=yes", "IdentityAgent=none", "ProxyCommand=none", "ProxyJump=none", "BatchMode=yes"]) assert.ok(call.args.includes(s));
    assert.ok(call.args.includes(`UserKnownHostsFile=${path.join(f.operatorDirectory, "known_hosts")}`));
    assert.ok(call.args.includes(path.join(f.operatorDirectory, "ssh-identity")));
  }
  assert.doesNotMatch(JSON.stringify(result), /production\.example|PRIVATE KEY|BEGIN/u);
});

test("RED: wrong signature, signer pin, host, key, expiry or missing operator identity refuses before SSH", POSIX, async (t) => {
  const cases = [
    (f) => { f.checklist.sourceSha = "c".repeat(40); json(path.join(f.operatorDirectory, "checklist.json"), f.checklist); },
    (f) => { f.identity.host = "other.example.invalid"; json(path.join(f.operatorDirectory, "identity.json"), f.identity); },
    (f) => { f.identity.sshHostPublicKey = fakeHostKey.replace(/.$/u, "A"); json(path.join(f.operatorDirectory, "identity.json"), f.identity); },
    (f) => { json(path.join(f.operatorDirectory, "owner-pin.json"), { version: 1, mode: "separately-provisioned-owner-pin-v1", ownerSignerSpkiSha256: "0".repeat(64) }); },
    (f) => { f.checklist.expiresAt = now - 1; f.writeAll(); },
    (f) => { rmSync(path.join(f.operatorDirectory, "ssh-identity")); },
    (f) => { writeFileSync(path.join(f.operatorDirectory, "known_hosts"), `other ${fakeHostKey}\n`); },
  ];
  for (const attack of cases) {
    const f = fixture(t), ssh = fakeSsh(); attack(f);
    const result = await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: ssh.execute, now });
    assert.equal(result.status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
    assert.equal(ssh.calls.length, 0);
  }
});

test("RED: symlinks, untrusted permissions, wrong server ssh -G and failed remote probe refuse", POSIX, async (t) => {
  const f = fixture(t);
  const bad = fakeSsh({ badConfig: true });
  assert.equal((await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: bad.execute, now })).status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
  assert.equal(bad.calls.length, 1);
  const down = fakeSsh({ fail: true });
  assert.equal((await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: down.execute, now })).status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
  assert.equal(down.calls.length, 2);
  chmodSync(path.join(f.operatorDirectory, "identity.json"), 0o666);
  const unsafe = fakeSsh();
  assert.equal((await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: unsafe.execute, now })).status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
  assert.equal(unsafe.calls.length, 0);
  chmodSync(path.join(f.operatorDirectory, "identity.json"), 0o600);
  const original = path.join(f.operatorDirectory, "identity.json");
  rmSync(original);
  symlinkSync(path.join(f.operatorDirectory, "checklist.json"), original);
  assert.equal((await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: unsafe.execute, now })).status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
  assert.equal(unsafe.calls.length, 0);
});

test("five UNVERIFIED host components are not a ready or successful manual preflight", POSIX, async (t) => {
  const f = fixture(t), ssh = fakeSsh();
  const original = ssh.execute;
  ssh.execute = (cmd, args, options) => args.includes("-G") ? original(cmd, args, options)
    : { status: 0, stdout: components.map((c) => `VIRKI_OFFLINE_COMPONENT_${c}=UNVERIFIED`).join("\n") + "\n" };
  const result = await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute: ssh.execute, now });
  assert.equal(result.status, "MANUAL_OPERATOR_PROVISIONING_INCOMPLETE");
  assert.deepEqual(result.unverified, components);
  assert.equal(result.deployAuthorized, false);
});

test("owner identity replaced after SSH -G blocks before remote command", POSIX, async (t) => {
  const f = fixture(t);
  const ssh = fakeSsh();
  const original = ssh.execute;
  const execute = (cmd, args, options) => {
    const result = original(cmd, args, options);
    if (args.includes("-G")) writeFileSync(path.join(f.operatorDirectory, "known_hosts"), "tampered\n");
    return result;
  };
  const result = await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute, now });
  assert.equal(result.status, "MANUAL_OPERATOR_PREFLIGHT_BLOCKED");
  assert.equal(ssh.calls.length, 1);
});

test("real /usr/bin/ssh -G verifies pinned no-config identity without opening a connection", POSIX, async (t) => {
  const f = fixture(t);
  let calls = 0;
  const execute = (cmd, args, options) => {
    calls += 1;
    if (args.includes("-G")) {
      const p = spawnSync(cmd, args, { env: options.env, encoding: "utf8", timeout: 5000 });
      return { status: p.status, stdout: p.stdout ?? "" };
    }
    return { status: 0, stdout: components.map((c) => `VIRKI_OFFLINE_COMPONENT_${c}=UNVERIFIED`).join("\n") + "\n" };
  };
  const result = await inspectManualOfflineOperatorPreflight({ operatorDirectory: f.operatorDirectory, execute, now });
  assert.equal(result.status, "MANUAL_OPERATOR_PROVISIONING_INCOMPLETE");
  assert.equal(calls, 2);
});

test("CLI with no operator-provisioned files is nonauthorizing and never prints source secrets", () => {
  const child = spawnSync(process.execPath, ["scripts/offline-manual-operator-preflight.mjs"], {
    encoding: "utf8", env: { PATH: process.env.PATH ?? "" }, timeout: 10000,
  });
  assert.equal(child.status, 1);
  assert.match(child.stdout, /MANUAL_OPERATOR_PREFLIGHT_BLOCKED/u);
  assert.doesNotMatch(child.stdout, /BEGIN|PRIVATE KEY|password|identityFile|\.production\.operator/u);
});
