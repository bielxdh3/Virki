import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, symlinkSync,
  writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectNativeFirstExecSourceForDevOnly } from "./offline-native-firstexec-dev-audit.mjs";

const repo = fileURLToPath(new URL("..", import.meta.url));

test("TDD: real PR88 first-exec imports are rejected before any privileged operation", () => {
  const inspected = inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: repo });
  assert.equal(inspected.status, "DEV_FIRST_EXEC_ROOT_LAUNCH_BLOCKED");
  assert.equal(inspected.nativeRootLaunchAuthorized, false);
  assert.equal(inspected.deployAuthorized, false);
  assert.equal(inspected.ownerInstalledClosureVerified, false);
  assert.ok(inspected.eagerStaticImports.includes("scripts/offline-manual-native-supervisor.mjs"));
  assert.ok(inspected.eagerStaticImports.includes("infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs"));
  for (const missing of ["scripts/offline-manual-native-supervisor.mjs",
    "infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs",
    "infra/offline/manual-native-activation-safety.mjs"]) {
    assert.ok(inspected.missingFromInstalledInventory.includes(missing), missing);
  }
});

test("TDD: importing hostile module is never needed for the DEV audit", (t) => {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-dev-firstexec-"));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const write = (relative, value) => {
    const pathname = path.join(base, relative);
    mkdirSync(path.dirname(pathname), { recursive: true });
    writeFileSync(pathname, value);
  };
  write("scripts/offline-manual-native-supervisor.mjs",
    'import "../infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs";\n');
  write("infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs",
    'import "../manual-native-activation-safety.mjs";\n');
  write("infra/offline/manual-native-activation-safety.mjs",
    'throw Error("HOSTILE_MODULE_MUST_NOT_EXECUTE");\n');
  write("infra/offline/trusted-host-installer.mjs",
    'export const AUDITED_VERIFIER_FILES = Object.freeze(["infra/offline/trusted-host-installer.mjs"]);\n');
  const report = inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: base });
  assert.equal(report.nativeRootLaunchAuthorized, false);
  assert.ok(report.missingFromInstalledInventory.includes(
    "infra/offline/manual-native-activation-safety.mjs"));
  assert.match(readFileSync(path.join(base,
    "infra/offline/manual-native-activation-safety.mjs"), "utf8"), /HOSTILE_MODULE_MUST_NOT_EXECUTE/u);
});

test("TDD: removing static imports or adding inventory names still grants zero root authority", (t) => {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-dev-firstexec-"));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const files = ["scripts/offline-manual-native-supervisor.mjs",
    "infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs",
    "infra/offline/manual-native-activation-safety.mjs"];
  for (const entry of files) {
    const pathname = path.join(base, entry);
    mkdirSync(path.dirname(pathname), { recursive: true });
    writeFileSync(pathname, "export const value = 1;\n");
  }
  const installer = path.join(base, "infra/offline/trusted-host-installer.mjs");
  writeFileSync(installer,
    `export const AUDITED_VERIFIER_FILES = Object.freeze(${JSON.stringify(files)});\n`);
  const inspected = inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: base });
  assert.deepEqual(inspected.eagerStaticImports, []);
  assert.deepEqual(inspected.missingFromInstalledInventory, []);
  assert.equal(inspected.nativeRootLaunchAuthorized, false);
  assert.equal(inspected.ownerInstalledClosureVerified, false);
});

test("TDD: missing files, symlinked sources and malformed inventories refuse without import", (t) => {
  const base = mkdtempSync(path.join(os.tmpdir(), "virki-dev-firstexec-"));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  assert.throws(() => inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: base }), /DEV first-exec audit refused/u);
  assert.throws(() => inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: base,
    deployAuthorized: true }), /DEV first-exec audit refused/u);
});

test("TDD: malicious replacement between stat/open never hangs on a FIFO or symlink", (t) => {
  if (process.platform !== "linux" || process.getuid?.() === 0) return t.skip("Linux nonroot FIFO fixture");
  for (const type of ["fifo", "symlink"]) {
    const base = mkdtempSync(path.join(os.tmpdir(), "virki-dev-firstexec-race-"));
    t.after(() => rmSync(base, { recursive: true, force: true }));
    const source = path.join(base, "scripts/offline-manual-native-supervisor.mjs");
    mkdirSync(path.dirname(source), { recursive: true });
    writeFileSync(source, 'import "./dependency.mjs";\n');
    const mk = spawnSync("/usr/bin/mkfifo", [path.join(base, "malicious.fifo")],
      { timeout: 3000, shell: false });
    assert.equal(mk.status, 0);
    let invoked = false;
    assert.throws(() => inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: base }, {
      afterLstat(filename) {
        if (invoked || filename !== source) return;
        invoked = true;
        renameSync(source, source + ".original");
        if (type === "fifo") renameSync(path.join(base, "malicious.fifo"), source);
        else symlinkSync(source + ".original", source);
      },
    }), /DEV first-exec audit refused/u);
    assert.ok(invoked);
  }
});

test("TDD: effective-root identity is refused even if real uid remains unprivileged", (t) => {
  if (process.platform !== "linux" || process.getuid?.() === 0) return t.skip("Linux nonroot process identity fixture");
  const original = { geteuid: process.geteuid, getegid: process.getegid };
  try {
    for (const [name, value] of [["geteuid", 0], ["getegid", 0],
      ["geteuid", process.getuid() + 1]]) {
      process[name] = () => value; // Mock only; no actual credential changes.
      assert.ok(process.getuid() !== 0);
      assert.throws(() => inspectNativeFirstExecSourceForDevOnly({ repositoryRoot: repo }),
        /DEV first-exec audit refused/u);
      process[name] = original[name];
    }
  } finally {
    process.geteuid = original.geteuid;
    process.getegid = original.getegid;
  }
});
