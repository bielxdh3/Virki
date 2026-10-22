import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, rmSync, statfsSync, symlinkSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { rehearseProtectedNativeOfflineRecovery } from "./trusted-native-recovery-fixture.mjs";

// Can create and remove only dedicated tmpfs fixture paths. No Docker socket
// or installed policy directory is mounted in this container.
const NATIVE = process.env.VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST === "1" &&
  process.platform === "linux" && process.arch === "x64" &&
  process.getuid?.() === 0 && existsSync("/.dockerenv") &&
  statfsSync(os.tmpdir()).type === 0x01021994;
const nativeOnly = { skip: NATIVE ? false : "requires dedicated no-network Linux tmpfs container" };
if (NATIVE && /microsoft|wsl/iu.test(os.release())) {
  // Docker Desktop's disposable root container shares a WSL kernel. Mimic
  // native kernel detection ONLY to exercise the existing trusted ledger's
  // file-system O_EXCL/fsync behavior, never as a host admission proof.
  os.release = () => "6.12.0-disposable-atomicity-test";
}
const OLD = "a".repeat(40);
const NEW = "b".repeat(40);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
const pad = (size) => (512 - size % 512) % 512;

function tar(entries) {
  const parts = [];
  for (const { name, bytes } of entries) {
    const data = Buffer.from(bytes);
    const h = Buffer.alloc(512);
    h.write(name, 0, "ascii");
    const oct = (at, size, number) => h.write(number.toString(8).padStart(size - 1, "0") + "\0", at, "ascii");
    oct(100, 8, 0o644);
    oct(108, 8, 0);
    oct(116, 8, 0);
    oct(124, 12, data.length);
    oct(136, 12, 0);
    h.fill(32, 148, 156);
    h.write("0", 156, "ascii");
    h.write("ustar", 257, "ascii");
    h.write("00", 263, "ascii");
    oct(148, 8, h.reduce((sum, value) => sum + value, 0));
    parts.push(h, data, Buffer.alloc(pad(data.length)));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}
function fakeDockerArchive(role) {
  const layer = tar([{ name: "payload.txt", bytes: "protected " + role }]);
  const config = Buffer.from(JSON.stringify({
    os: "linux", architecture: "amd64", config: {
      User: "node:node",
      Labels: {
        "org.opencontainers.image.revision": NEW,
        "org.opencontainers.image.source": "https://github.com/bielxdh3/Virki",
      },
    },
    rootfs: { type: "layers", diff_ids: [`sha256:${hash(layer)}`] },
  }));
  const id = hash(config);
  const layerPath = `${"a".repeat(64)}/layer.tar`;
  const bytes = tar([
    { name: `${id}.json`, bytes: config },
    { name: layerPath, bytes: layer },
    { name: "manifest.json", bytes: JSON.stringify([
      { Config: `${id}.json`, RepoTags: null, Layers: [layerPath] },
    ]) },
  ]);
  return { bytes, descriptor: {
    imageId: `sha256:${id}`, archiveSha256: hash(bytes), archiveSizeBytes: bytes.length,
  } };
}
function fixture(t, candidateHealth = "ok") {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-native-recovery-fixture-"));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const folder of ["operator", "operator/ledger", "candidate", "sealed", "state",
    "releases", "database", "backups", "restores", "fake-docker"]) {
    mkdirSync(path.join(root, folder), { recursive: true, mode: 0o700 });
    chmodSync(path.join(root, folder), 0o700);
  }
  const put = (relative, value) => {
    const name = path.join(root, relative);
    writeFileSync(name, Buffer.isBuffer(value) ? value : JSON.stringify(value), { mode: 0o600 });
    chmodSync(name, 0o600);
  };
  const oldData = {
    schemaVersion: 1,
    accounts: [{ id: "admin", passwordHash: "argon2-fixture", mfa: "encrypted-seed" },
      { id: "user", email: "masked-fixture" }],
    secrets: { oidc: "ciphertext", sessionKey: "encrypted", backupFactors: ["ciphertext-1"] },
    audit: [{ id: "audit-1", action: "LOGIN", digest: "hash" }],
    outbox: [{ type: "ACCOUNT_RECOVERY", encryptedPayload: "ciphertext", attempt: 3 }],
    sessions: [{ id: "cookie-1", expires: 1234567890 }],
    extra: { untouched: ["nested", { metadata: true }] },
  };
  const runtime = fakeDockerArchive("runtime");
  const migrator = fakeDockerArchive("migrator");
  put("operator/fixture.json", {
    version: 1, kind: "isolated-native-recovery", identity: randomBytes(16).toString("hex"),
  });
  put("operator/ledger/ledger.json", { version: 1, anchorSha: OLD, entries: [] });
  put("operator/accepted-plan.json", {
    version: 1, previousSha: OLD, nextSha: NEW,
    manifestSha256: "c".repeat(64), nonce: "d".repeat(32),
    sequence: 1, approvalDigest: "e".repeat(64),
    runtime: runtime.descriptor, migrator: migrator.descriptor,
  });
  put("candidate/runtime.tar", runtime.bytes);
  put("candidate/migrator.tar", migrator.bytes);
  put(`releases/${OLD}.json`, { revision: OLD, schemaVersion: 1, health: "ok" });
  put(`releases/${NEW}.json`, { revision: NEW, schemaVersion: 2, health: candidateHealth });
  put("state/active.json", { revision: OLD });
  put("state/routing.json", { maintenance: false, runningSha: OLD });
  put("state/journal.json", { version: 1, steps: [] });
  put("database/live.json", oldData);
  put("fake-docker/images.json", { images: [] });
  const read = (name) => readJson(path.join(root, name));
  const run = (callback = undefined) => rehearseProtectedNativeOfflineRecovery({ fixtureRoot: root },
    callback ? { afterPhase: callback } : {});
  return {
    root, put, read, run, oldData, runtime, migrator,
    status: () => ({
      active: read("state/active.json"), route: read("state/routing.json"),
      entries: read("operator/ledger/ledger.json").entries,
      locked: existsSync(path.join(root, "operator/ledger/.offline-release.lock")),
    }),
  };
}
function retainedPredecessor(f, lock = true) {
  assert.equal(f.read("database/live.json").schemaVersion, 1);
  assert.deepEqual(f.read("database/live.json"), f.oldData);
  assert.deepEqual(f.read("state/active.json"), { revision: OLD });
  assert.deepEqual(f.read("state/routing.json"), { maintenance: false, runningSha: OLD });
  assert.equal(f.status().locked, lock);
  assert.deepEqual(f.read(`releases/${OLD}.json`),
    { revision: OLD, schemaVersion: 1, health: "ok" });
}
function childScript() {
  return `import os from "node:os";
  if (/microsoft|wsl/iu.test(os.release())) os.release = () => "6.12.0-disposable-atomicity-test";
  const { rehearseProtectedNativeOfflineRecovery } = await import(
    ${JSON.stringify(new URL("./trusted-native-recovery-fixture.mjs", import.meta.url).href)});
  try {
    await rehearseProtectedNativeOfflineRecovery({fixtureRoot:process.argv[1]}, {
      afterPhase(phase) {
        if (process.argv[2] === "crash" && phase === "live-migrated") process.kill(process.pid, "SIGKILL");
        if (process.argv[2] === "hold" && phase === "attempted") {
          const end = Date.now() + 300;
          while (Date.now() < end) {}
        }
      },
    });
    process.stdout.write("success");
  } catch (e) {
    process.stderr.write(String(e.message));
    process.exitCode = 2;
  }`;
}
function runChild(root, action = "none") {
  return spawnSync(process.execPath, ["--input-type=module", "--eval", childScript(), root, action],
    { encoding: "utf8", timeout: 20000,
      env: { ...process.env, VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST: "1" } });
}
function parallelChild(root) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath,
      ["--input-type=module", "--eval", childScript(), root, "hold"],
      { env: { ...process.env, VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST: "1" } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("native recovery rehearsal reserves one ledger attempt for two distinct pinned images then completes after full verified restore", nativeOnly, async (t) => {
  const f = fixture(t);
  const before = readFileSync(path.join(f.root, "database/live.json"));
  const result = await f.run();
  assert.equal(result.status, "NATIVE_DISPOSABLE_RECOVERY_REHEARSAL_ONLY");
  assert.equal(result.deployAuthorized, false);
  assert.equal(result.twoPinnedImagesVerified, true);
  assert.equal(result.originalBackupSha256, hash(before));
  assert.equal(f.status().locked, false);
  assert.deepEqual(f.status().entries.map((entry) => entry.nextSha), [NEW]);
  assert.deepEqual(f.read("state/active.json"), { revision: NEW });
  assert.deepEqual(f.read("state/routing.json"), { maintenance: false, runningSha: NEW });
  const migrated = f.read("database/live.json");
  assert.deepEqual(migrated, { ...f.oldData, schemaVersion: 2 });
  assert.deepEqual(f.read("restores/1.json"), migrated);
  assert.deepEqual(readFileSync(path.join(f.root, "backups/1.dump")), before);
  const imgs = f.read("fake-docker/images.json").images;
  assert.deepEqual(imgs.map((item) => item.role), ["runtime", "migrator"]);
  assert.deepEqual(imgs.map((item) => item.imageId),
    [f.runtime.descriptor.imageId, f.migrator.descriptor.imageId]);
  assert.deepEqual(readdirSync(path.join(f.root, "sealed")), []);
  assert.deepEqual(f.read("state/journal.json").steps, [
    "attempted", "loaded-runtime", "loaded-migrator", "maintenance",
    "backup-verified", "restore-verified", "restore-migrated", "live-migrated",
    "candidate-healthy", "activated-under-maintenance", "completed",
  ]);
  assert.deepEqual(f.read(`releases/${OLD}.json`),
    { revision: OLD, schemaVersion: 1, health: "ok" });
});

test("each after-admission phase failure preserves attempted ledger lock and restores old data when maintenance began", nativeOnly, async (t) => {
  for (const phase of [
    "attempted", "loaded-runtime", "loaded-migrator", "maintenance",
    "backup-verified", "restore-verified", "restore-migrated",
    "live-migrated", "candidate-healthy", "activated-under-maintenance",
  ]) await t.test(phase, async (subtest) => {
    const f = fixture(subtest);
    await assert.rejects(f.run((step) => {
      if (step === phase) throw new Error("injected " + phase);
    }), new RegExp("injected " + phase));
    retainedPredecessor(f);
    assert.deepEqual(f.status().entries, []);
    await assert.rejects(f.run(), /initial active state not safe|prior pending attempt/u);
    assert.equal(f.status().locked, true);
    if (["live-migrated", "candidate-healthy", "activated-under-maintenance"].includes(phase)) {
      assert.deepEqual(f.read("backups/1.dump"), f.oldData);
    }
  });
});

test("candidate health failure restores old DB with all security metadata and leaves ledger blocked", nativeOnly, async (t) => {
  const f = fixture(t, "fail");
  await assert.rejects(f.run(), /candidate health refused/u);
  retainedPredecessor(f);
  assert.deepEqual(f.read("backups/1.dump"), f.oldData);
});

test("mutated second archive after first protected load refuses role 2 without fallback", nativeOnly, async (t) => {
  const f = fixture(t);
  await assert.rejects(f.run((phase) => {
    if (phase === "loaded-runtime") {
      const bytes = Buffer.from(f.migrator.bytes);
      bytes[1000] ^= 1;
      f.put("candidate/migrator.tar", bytes);
    }
  }), /digest changed during detachment|archive parser|Offline Docker TAR/u);
  retainedPredecessor(f);
  assert.deepEqual(f.read("fake-docker/images.json").images.map((i) => i.role), ["runtime"]);
});

test("postcheck rejects unexpected second image tag and refuses activation", nativeOnly, async (t) => {
  const f = fixture(t);
  await assert.rejects(f.run((phase) => {
    if (phase === "loaded-migrator") {
      const state = f.read("fake-docker/images.json");
      state.images[1].tags = ["forbidden:latest"];
      f.put("fake-docker/images.json", state);
    }
  }), /loaded image identity, role or untagged policy mismatch/u);
  retainedPredecessor(f);
});

test("altering backup after live migration blocks rollback and retains maintenance and attempted state", nativeOnly, async (t) => {
  const f = fixture(t);
  await assert.rejects(f.run((phase) => {
    if (phase === "live-migrated") {
      f.put("backups/1.dump", { corrupted: true });
      throw new Error("injected post-migration failure");
    }
  }), /verified rollback is blocked/u);
  assert.equal(f.status().locked, true);
  assert.equal(f.status().active.revision, OLD);
  assert.equal(f.status().route.maintenance, true);
  assert.equal(f.read("database/live.json").schemaVersion, 2);
  assert.deepEqual(f.read("state/journal.json").steps.at(-1), "rollback-blocked");
});

test("crash between live migration and health retains maintenance, old activation and attempted ledger lock", nativeOnly, (t) => {
  const f = fixture(t);
  const child = runChild(f.root, "crash");
  assert.equal(child.signal, "SIGKILL", child.stderr);
  assert.equal(f.status().locked, true);
  assert.equal(f.status().route.maintenance, true);
  assert.equal(f.status().active.revision, OLD);
  assert.equal(f.read("database/live.json").schemaVersion, 2);
  assert.deepEqual(f.status().entries, []);
  assert.equal(f.read("state/journal.json").steps.at(-1), "live-migrated");
});

test("two competing processes share one real O_EXCL ledger reservation", nativeOnly, async (t) => {
  const f = fixture(t);
  const results = await Promise.all([parallelChild(f.root), parallelChild(f.root)]);
  assert.deepEqual(results.map((r) => r.code).sort(), [0, 2], JSON.stringify(results));
  assert.equal(results.filter((r) => r.stdout === "success").length, 1);
  assert.equal(f.status().entries.length, 1);
  assert.equal(f.read("fake-docker/images.json").images.length, 2);
});

test("forged staged result, caller image IDs and operator override rejected before ledger mutation", nativeOnly, async (t) => {
  const f = fixture(t);
  for (const extra of [
    { status: "staged" }, { imageId: f.runtime.descriptor.imageId },
    { ledgerSequence: 1 }, { dockerSocket: "/var/run/docker.sock" },
    { trustedApproval: true },
  ]) await assert.rejects(rehearseProtectedNativeOfflineRecovery(
    { fixtureRoot: f.root, ...extra }), /fixture request fields invalid/u);
  assert.equal(f.status().locked, false);
  assert.deepEqual(f.status().entries, []);
});

test("rejects symlinked candidate and hard-linked operator trust bytes", nativeOnly, async (t) => {
  await t.test("candidate symlink", async (subtest) => {
    const f = fixture(subtest);
    rmSync(path.join(f.root, "candidate/runtime.tar"));
    symlinkSync(path.join(f.root, "candidate/migrator.tar"), path.join(f.root, "candidate/runtime.tar"));
    await assert.rejects(f.run(), /unsafe fixture private file/u);
    assert.equal(f.status().locked, true);
  });
  await t.test("operator hardlink", async (subtest) => {
    const f = fixture(subtest);
    linkSync(path.join(f.root, "operator/accepted-plan.json"),
      path.join(f.root, "operator/linked-plan.json"));
    await assert.rejects(f.run(), /unsafe fixture private file/u);
    assert.equal(f.status().locked, false);
  });
});
