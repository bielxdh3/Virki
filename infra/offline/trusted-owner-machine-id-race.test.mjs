import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync, linkSync, mkdtempSync, readFileSync, renameSync, rmSync,
  symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const nativeRoot = process.platform === "linux" && process.getuid?.() === 0;
const legitimate = "0123456789abcdef0123456789abcdef\n";
const substitute = "fedcba9876543210fedcba9876543210\n";
const domainDigest = (id) => createHash("sha256")
  .update("VIRKI_OFFLINE_HOST_MACHINE_ID_V1\0" + id.trim()).digest("hex");

// No production entrypoint or release admission is invoked. Only this test
// creates a fresh disposable source copy and inserts a deterministic callback
// in the real metadata-to-open gap. The checked-in production code keeps the
// fixed /etc/machine-id pathname and never accepts a fixtureRoot override.
test("native owner bootstrap pins the machine-id inode across adversarial swaps", {
  skip: nativeRoot ? false : "native Linux root filesystem fixture required",
}, async (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-machine-id-race-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, "machine-id");
  const source = readFileSync(fileURLToPath(
    new URL("./trusted-owner-installation.mjs", import.meta.url)), "utf8");
  const sourceFilename = 'const filename = "/etc/machine-id";';
  const checkedMetadata = '  "native host machine-id is untrusted");';
  const readFinished = /([ \t]+offset \+= count;\r?\n[ \t]+\}\r?\n)([ \t]+demand\(same\(opened)/u;
  assert.ok(source.includes(sourceFilename), "production must have a fixed host path");
  assert.ok(source.includes(checkedMetadata), "race hook requires the actual guarded read");
  assert.match(source, readFinished, "post-read hook requires pinned FD verification");
  const fixtureSource = source
    .replace(sourceFilename, `const filename = ${JSON.stringify(target)};`)
    .replace(checkedMetadata, checkedMetadata +
      "\n  globalThis.__virkiMachineIdRace?.();")
    .replace(readFinished, (_whole, bytesRead, check) =>
      bytesRead + "    globalThis.__virkiMachineIdPostReadRace?.();\n" + check) +
      "\nexport { identityDigest as disposableIdentityDigest };\n";
  const isolatedModule = path.join(root, "measured-bootstrap-copy.mjs");
  writeFileSync(isolatedModule, fixtureSource, { mode: 0o600 });
  const { disposableIdentityDigest: digest } = await import(pathToFileURL(isolatedModule).href);
  const reset = () => {
    rmSync(target, { force: true });
    rmSync(target + ".old", { force: true });
    rmSync(target + ".other", { force: true });
    writeFileSync(target, legitimate, { mode: 0o600 });
    chmodSync(target, 0o600);
  };
  const runWithRace = (mutation, postReadMutation) => {
    reset();
    globalThis.__virkiMachineIdRace = mutation;
    globalThis.__virkiMachineIdPostReadRace = postReadMutation;
    try { return digest(); }
    finally {
      delete globalThis.__virkiMachineIdRace;
      delete globalThis.__virkiMachineIdPostReadRace;
    }
  };

  await t.test("unmodified root-owned regular file produces only a domain-separated digest", () => {
    assert.equal(runWithRace(() => {}), domainDigest(legitimate));
  });
  await t.test("atomic rename with different content between metadata and open refuses", () => {
    assert.throws(() => runWithRace(() => {
      renameSync(target, target + ".old");
      writeFileSync(target, substitute, { mode: 0o600 });
    }), /machine-id|changed|untrusted/u);
  });
  await t.test("swapped inode with identical content cannot reuse its predecessor's trust", () => {
    assert.throws(() => runWithRace(() => {
      renameSync(target, target + ".old");
      writeFileSync(target, legitimate, { mode: 0o600 });
    }), /machine-id|changed|untrusted/u);
  });
  await t.test("late symlink to a valid root-owned ID is never followed", () => {
    assert.throws(() => runWithRace(() => {
      renameSync(target, target + ".old");
      writeFileSync(target + ".other", substitute, { mode: 0o600 });
      symlinkSync(target + ".other", target);
    }), /machine-id|changed|untrusted|ELOOP/u);
  });
  await t.test("pathname swapped after pinned FD read is detected before identity publication", () => {
    assert.throws(() => runWithRace(() => {}, () => {
      renameSync(target, target + ".old");
      writeFileSync(target, legitimate, { mode: 0o600 });
    }), /machine-id|changed|untrusted/u);
  });
  await t.test("in-place rewrite after pinned FD read invalidates metadata snapshot", () => {
    assert.throws(() => runWithRace(() => {}, () => {
      writeFileSync(target, substitute);
    }), /machine-id|changed|untrusted/u);
  });
  await t.test("oversized identity, hardlink and writable file fail closed", () => {
    reset();
    writeFileSync(target, "a".repeat(8192));
    assert.throws(() => digest(), /machine-id|untrusted/u);
    reset();
    linkSync(target, target + ".other");
    assert.throws(() => digest(), /machine-id|untrusted/u);
    reset();
    chmodSync(target, 0o666);
    assert.throws(() => digest(), /machine-id|untrusted/u);
  });
});
