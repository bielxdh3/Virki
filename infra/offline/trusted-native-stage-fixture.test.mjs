import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, renameSync, rmSync, statfsSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { AUDITED_VERIFIER_FILES } from "./trusted-host-installer.mjs";
import { rehearseTrustedNativeVerifierStaging } from "./trusted-native-stage-fixture.mjs";

const native = process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 && statfsSync(os.tmpdir()).type === 0x01021994 &&
  process.env.VIRKI_DISPOSABLE_STAGE_REHEARSAL === "1" && existsSync("/.dockerenv");
const onlyNative = { skip: native ? false : "Disposable native Linux/amd64 root fixture required" };
const digest = (value) => createHash("sha256").update(value).digest("hex");
const sh = (char) => char.repeat(40);
const SHA = (char) => char.repeat(64);

function key(keyId) {
  const { publicKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    pinSha256: digest(publicKey.export({ type: "spki", format: "der" })),
  };
}

function setup(t) {
  const fixtureRoot = mkdtempSync(path.join(os.tmpdir(), "virki-native-stage-fixture-"));
  const sourceDirectory = path.join(fixtureRoot, "source");
  const operatorDirectory = path.join(fixtureRoot, "operator");
  const stagingDirectory = path.join(fixtureRoot, "staging");
  for (const dir of [sourceDirectory, operatorDirectory, stagingDirectory]) {
    mkdirSync(dir, { mode: 0o700 });
  }
  t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const files = AUDITED_VERIFIER_FILES.map((relativePath, index) => {
    const target = path.join(sourceDirectory, ...relativePath.split("/"));
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const bytes = Buffer.from(`// vetted fixture ${index}: distinct pinned module bytes\n`);
    writeFileSync(target, bytes, { mode: 0o600 });
    return { path: relativePath, sha256: digest(bytes) };
  });
  const measuredHostIdentitySha256 = SHA("a");
  const policy = {
    version: 2, mode: "offline-signed-v1", enabled: true,
    ownerAssuranceAccepted: true, hostIdentitySha256: measuredHostIdentitySha256,
    ledgerAnchorSha: sh("1"), platform: "linux/amd64",
    builder: key("fixture-builder"), owner: key("fixture-owner"),
    revokedKeyIds: [], revokedPinsSha256: [],
  };
  const ledger = { version: 1, anchorSha: sh("1"), entries: [] };
  const policyBytes = Buffer.from(JSON.stringify(policy));
  const ledgerBytes = Buffer.from(JSON.stringify(ledger));
  const pinsBytes = Buffer.from(JSON.stringify({
    version: 1, mode: "independent-native-verifier-pins-v1",
    files, trustPolicySha256: digest(policyBytes), ledgerSha256: digest(ledgerBytes),
  }));
  for (const [name, bytes] of [
    ["verifier-pins.json", pinsBytes], ["trust-policy.json", policyBytes],
    ["ledger.json", ledgerBytes],
  ]) writeFileSync(path.join(operatorDirectory, name), bytes, { mode: 0o600 });
  const request = {
    fixtureRoot, sourceDirectory, operatorDirectory, stagingDirectory,
    measuredHostIdentitySha256,
  };
  const sourcePath = (index) => path.join(sourceDirectory, ...files[index].path.split("/"));
  return { ...request, request, files, sourcePath, pinsBytes, policyBytes, ledgerBytes };
}

function assertPublished(f) {
  const published = path.join(f.stagingDirectory, "published");
  assert.equal(lstatSync(published).mode & 0o7777, 0o700);
  for (const entry of f.files) {
    const src = path.join(f.sourceDirectory, ...entry.path.split("/"));
    const dst = path.join(published, ...entry.path.split("/"));
    const stat = lstatSync(dst);
    assert.equal(stat.isFile(), true);
    assert.equal(stat.uid, 0);
    assert.equal(stat.nlink, 1);
    assert.equal(stat.mode & 0o7777, 0o600);
    assert.equal(digest(readFileSync(dst)), entry.sha256);
    assert.deepEqual(readFileSync(dst), readFileSync(src));
  }
}

function deniedUnpublished(f) {
  assert.throws(() => rehearseTrustedNativeVerifierStaging(f.request));
  assert.deepEqual(readdirSync(f.stagingDirectory), []);
}

test("native root fixture publishes exactly ten operator-pinned private modules in one directory rename", onlyNative, (t) => {
  const f = setup(t);
  const result = rehearseTrustedNativeVerifierStaging(f.request);
  assert.equal(result.status, "DISPOSABLE_NATIVE_LINUX_STAGING_REHEARSAL_ONLY");
  assert.equal(result.auditedSourceCount, 10);
  assert.equal(result.operatorPinsSha256, digest(f.pinsBytes));
  assert.equal(Object.hasOwn(result, "installAuthorized"), false);
  assert.equal(Object.hasOwn(result, "deployAuthorized"), false);
  assert.deepEqual(readdirSync(f.stagingDirectory), ["published"]);
  assertPublished(f);
  assert.throws(() => rehearseTrustedNativeVerifierStaging(f.request), /refused|invalid|blocked/iu);
  assertPublished(f);
});

test("pinned ten-file inventory refuses altered bytes, missing dependencies and operator digest edits", onlyNative, (t) => {
  for (const mutate of [
    (f) => writeFileSync(f.sourcePath(3), "different module bytes"),
    (f) => rmSync(f.sourcePath(5)),
    (f) => writeFileSync(path.join(f.operatorDirectory, "verifier-pins.json"), "{}"),
    (f) => writeFileSync(path.join(f.operatorDirectory, "trust-policy.json"), "{}"),
    (f) => writeFileSync(path.join(f.operatorDirectory, "ledger.json"), "{}"),
    (f) => writeFileSync(path.join(f.operatorDirectory, "unexpected-policy.json"), "{}"),
  ]) {
    const f = setup(t);
    mutate(f);
    deniedUnpublished(f);
  }
});

test("explicit owner-provisioned trust policy and binding to measured fixture identity are mandatory", onlyNative, (t) => {
  for (const mutate of [
    (policy) => { policy.ownerAssuranceAccepted = false; },
    (policy) => { policy.owner = policy.builder; },
    (policy) => { policy.revokedKeyIds = [policy.owner.keyId]; },
    (policy) => { policy.hostIdentitySha256 = SHA("b"); },
  ]) {
    const f = setup(t);
    const policy = JSON.parse(f.policyBytes);
    mutate(policy);
    const bytes = Buffer.from(JSON.stringify(policy));
    const pins = JSON.parse(f.pinsBytes);
    pins.trustPolicySha256 = digest(bytes);
    writeFileSync(path.join(f.operatorDirectory, "trust-policy.json"), bytes);
    writeFileSync(path.join(f.operatorDirectory, "verifier-pins.json"), JSON.stringify(pins));
    deniedUnpublished(f);
  }
});

test("fixture refuses overlapping trust roots and any untrusted staging as its source or operator", onlyNative, (t) => {
  const f = setup(t);
  for (const override of [
    { sourceDirectory: f.operatorDirectory },
    { operatorDirectory: f.sourceDirectory },
    { sourceDirectory: f.stagingDirectory },
    { operatorDirectory: f.stagingDirectory },
    { stagingDirectory: f.sourceDirectory },
    { stagingDirectory: f.operatorDirectory },
    { fixtureRoot: "/etc/virki" },
    { fixtureRoot: path.dirname(f.fixtureRoot) },
    { stagingDirectory: "/usr/local/lib/virki/offline-release" },
  ]) {
    assert.throws(() => rehearseTrustedNativeVerifierStaging({ ...f.request, ...override }));
  }
  assert.deepEqual(readdirSync(f.stagingDirectory), []);
});

test("source and independent operator deny symlinks, hardlinks and writable or public modes", onlyNative, (t) => {
  for (const mutate of [
    (f) => chmodSync(f.sourcePath(0), 0o644),
    (f) => chmodSync(f.operatorDirectory, 0o755),
    (f) => chmodSync(path.join(f.operatorDirectory, "ledger.json"), 0o666),
    (f) => { const file = f.sourcePath(1); const tmp = file + ".original";
      renameSync(file, tmp); symlinkSync(tmp, file); },
    (f) => linkSync(f.sourcePath(2), f.sourcePath(2) + ".linked"),
    (f) => { const file = path.join(f.operatorDirectory, "verifier-pins.json");
      const tmp = file + ".original"; renameSync(file, tmp); symlinkSync(tmp, file); },
    (f) => linkSync(path.join(f.operatorDirectory, "ledger.json"),
      path.join(f.operatorDirectory, "other")),
    (f) => { const nested = path.join(f.sourceDirectory, "infra");
      renameSync(nested, nested + "-real"); symlinkSync(nested + "-real", nested); },
  ]) {
    const f = setup(t);
    mutate(f);
    deniedUnpublished(f);
  }
});

test("staging requires an empty real private root directory and never follows an alias", onlyNative, (t) => {
  for (const mutate of [
    (f) => chmodSync(f.stagingDirectory, 0o777),
    (f) => writeFileSync(path.join(f.stagingDirectory, "occupied"), "junk"),
    (f) => { renameSync(f.stagingDirectory, f.stagingDirectory + "-real");
      symlinkSync(f.stagingDirectory + "-real", f.stagingDirectory); },
  ]) {
    const f = setup(t);
    mutate(f);
    assert.throws(() => rehearseTrustedNativeVerifierStaging(f.request));
  }
});

test("candidate cannot publish unexpected modules, late modified bytes or a link inserted before rename", onlyNative, (t) => {
  for (const mutate of [
    (candidate) => writeFileSync(path.join(candidate, "unexpected.js"), "unreviewed"),
    (candidate, f) => writeFileSync(path.join(candidate, ...f.files[0].path.split("/")), "tampered"),
    (candidate, f) => {
      const target = path.join(candidate, ...f.files[1].path.split("/"));
      const original = target + ".backup";
      renameSync(target, original);
      symlinkSync(original, target);
    },
  ]) {
    const f = setup(t);
    assert.throws(() => rehearseTrustedNativeVerifierStaging(f.request, {
      onPhase(phase) {
        if (phase === "beforePublish") {
          mutate(path.join(f.stagingDirectory, ".candidate-partial"), f);
        }
      },
    }));
    assert.equal(readdirSync(f.stagingDirectory).includes("published"), false);
  }
});

test("SIGKILL before and after fsynced directory rename leaves no partially published ten-file set", onlyNative, (t) => {
  const fixtureModule = fileURLToPath(new URL("./trusted-native-stage-fixture.mjs", import.meta.url));
  for (const phase of ["beforePublish", "afterPublish"]) {
    const f = setup(t);
    const code = [
      "import { pathToFileURL } from 'node:url';",
      "const { rehearseTrustedNativeVerifierStaging } = await import(pathToFileURL(process.env.FIXTURE_MODULE).href);",
      "const request = JSON.parse(process.env.FIXTURE_REQUEST);",
      "rehearseTrustedNativeVerifierStaging(request, {",
      "  onPhase(phase) { if (phase === process.env.FIXTURE_CRASH_AT) process.kill(process.pid, 'SIGKILL'); },",
      "});",
    ].join("\n");
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
      encoding: "utf8", timeout: 10000,
      env: { ...process.env, FIXTURE_MODULE: fixtureModule,
        FIXTURE_REQUEST: JSON.stringify(f.request), FIXTURE_CRASH_AT: phase },
    });
    assert.equal(child.signal, "SIGKILL", `${phase}: ${child.stderr}`);
    const present = readdirSync(f.stagingDirectory);
    if (phase === "beforePublish") {
      assert.equal(present.some((name) => name === "published"), false);
      assert.equal(present.some((name) => name.startsWith(".candidate-")), true);
      assert.throws(() => rehearseTrustedNativeVerifierStaging(f.request));
    } else {
      assert.deepEqual(present, ["published"]);
      assertPublished(f);
    }
  }
});
