import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, openSync,
  readFileSync, realpathSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// All effects are confined to a specially provisioned, disposable local fixture.
// This does not call Docker, SSH, the hosted deploy flow, or an installed host
// verifier. Fixture state, including its "success" result, is NEVER authority
// to activate a real Virki release.
const SHA = /^[a-f0-9]{40}$/u;
const ID = /^[a-f0-9]{32}$/u;
const PHASES = new Set([
  "attempted", "maintenance", "backup-verified", "restore-verified",
  "restore-migrated", "live-migrated", "candidate-running", "health-passed",
  "committed", "rollback-started", "rolled-back", "rollback-blocked",
]);
const MAX_BYTES = 1024 * 1024;
const MARKER = ".virki-disposable-recovery.json";
const LOCK = ".recovery-attempt.lock";
const OPEN_NEW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
  (constants.O_NOFOLLOW ?? 0);

function check(value, message) {
  if (!value) throw new Error("Disposable recovery refused: " + message);
}
function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function exact(value, fields, message) {
  check(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field)), message);
}
function syncParent(filename) {
  // Windows cannot fsync directory handles; these are cross-platform local
  // regression fixtures. A native Linux operational port must use fsync.
  if (process.platform === "win32") return;
  const fd = openSync(path.dirname(filename), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function assertPrivateDirectory(directory) {
  const stat = lstatSync(directory);
  check(stat.isDirectory() && !stat.isSymbolicLink(), "unsafe fixture directory");
  if (process.platform !== "win32") {
    check(stat.uid === process.getuid() && (stat.mode & 0o077) === 0,
      "fixture directory must be private to its owner");
  }
}
function fixtureRoot(root) {
  check(process.env.VIRKI_DISPOSABLE_RECOVERY_TEST === "1",
    "explicit disposable test opt-in required");
  check(typeof root === "string" && path.isAbsolute(root) &&
    path.normalize(root) === root && !root.includes("\0") &&
    path.dirname(root) === path.resolve(os.tmpdir()) &&
    /^virki-offline-recovery-fixture-[a-zA-Z0-9]{6}$/u.test(path.basename(root)),
  "root must be an OS-temp disposable fixture");
  assertPrivateDirectory(root);
  check(realpathSync.native(root) === root, "fixture path changed or is an alias");
  const marker = readJson(root, MARKER);
  exact(marker, ["version", "disposable", "id"], "invalid fixture marker");
  check(marker.version === 1 && marker.disposable === true && ID.test(marker.id),
    "missing independent disposable fixture identity");
  for (const name of ["state", "releases", "database", "backups", "restores"]) {
    assertPrivateDirectory(path.join(root, name));
  }
  return root;
}
function checkedPath(root, relative, allowAbsent = false) {
  check(typeof relative === "string" && relative.length < 255 &&
    !relative.includes("..") && !path.isAbsolute(relative), "unsafe fixture relative path");
  const filename = path.join(root, relative);
  const directory = path.dirname(filename);
  check(directory === root || directory.startsWith(root + path.sep),
    "path escaped disposable fixture");
  // Every parent must remain a real directory, including the revision folder.
  for (let current = directory; current !== root; current = path.dirname(current)) {
    assertPrivateDirectory(current);
  }
  if (existsSync(filename)) {
    const stat = lstatSync(filename);
    check(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
      stat.size > 0 && stat.size <= MAX_BYTES, "unsafe fixture file");
  } else if (!allowAbsent) {
    throw new Error("Disposable recovery refused: missing fixture file");
  } else {
    // existsSync follows dangling symlinks, so check lstat separately.
    try { lstatSync(filename); check(false, "dangling fixture link"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  return filename;
}
function readBytes(root, relative) {
  const file = checkedPath(root, relative);
  const before = lstatSync(file, { bigint: true });
  const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const unchanged = (stat) => [
    "dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs",
  ].every((key) => stat[key] === before[key]);
  try {
    check(unchanged(fstatSync(fd, { bigint: true })), "fixture file changed before reading");
    const bytes = readFileSync(fd);
    check(bytes.length > 0 && bytes.length <= MAX_BYTES &&
      BigInt(bytes.length) === before.size &&
      unchanged(fstatSync(fd, { bigint: true })) &&
      unchanged(lstatSync(file, { bigint: true })),
    "fixture file changed during reading");
    return bytes;
  } finally { closeSync(fd); }
}
function readJson(root, relative) {
  const bytes = readBytes(root, relative);
  let data;
  try { data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch (error) { throw new Error("Disposable recovery refused: invalid fixture JSON", { cause: error }); }
  return data;
}
function writeNew(root, relative, bytes) {
  check(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_BYTES,
    "invalid write size");
  const file = checkedPath(root, relative, true);
  check(!existsSync(file), "fixture output already exists");
  const fd = openSync(file, OPEN_NEW, 0o600);
  try {
    let written = 0;
    while (written < bytes.length) {
      const n = writeSync(fd, bytes, written, bytes.length - written, written);
      check(n > 0, "short fixture write");
      written += n;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  syncParent(file);
}
function replace(root, relative, bytes) {
  const file = checkedPath(root, relative, true);
  const temp = relative + "." + randomBytes(12).toString("hex") + ".tmp";
  writeNew(root, temp, bytes);
  try {
    checkedPath(root, relative, true);
    renameSync(path.join(root, temp), file);
    syncParent(file);
  } catch (error) {
    try { unlinkSync(path.join(root, temp)); } catch { /* leave evidence if cleanup fails */ }
    throw error;
  }
}
function replaceJson(root, relative, value) {
  replace(root, relative, Buffer.from(JSON.stringify(value)));
}
function revision(root, sha) {
  check(SHA.test(sha), "invalid release revision");
  const data = readJson(root, `releases/${sha}/release.json`);
  exact(data, ["revision", "schemaVersion", "health"], "invalid fixture release descriptor");
  check(data.revision === sha && Number.isSafeInteger(data.schemaVersion) &&
    data.schemaVersion > 0 && ["ok", "fail"].includes(data.health),
  "fixture release identity or health descriptor mismatch");
  return data;
}
function database(root) {
  const data = readJson(root, "database/database.json");
  exact(data, ["schemaVersion", "accounts"], "invalid fixture database");
  check(Number.isSafeInteger(data.schemaVersion) && data.schemaVersion > 0 &&
    Array.isArray(data.accounts) && data.accounts.length > 0 &&
    data.accounts.length < 1000 && data.accounts.every((value) =>
      typeof value === "string" && value.length > 0 && value.length < 128),
  "invalid fixture database schema or accounts");
  return data;
}
function control(root) {
  const active = readJson(root, "state/active.json");
  const route = readJson(root, "state/routing.json");
  exact(active, ["revision"], "invalid active release marker");
  exact(route, ["maintenance", "runningSha"], "invalid routing marker");
  check(SHA.test(active.revision) && typeof route.maintenance === "boolean" &&
    (route.runningSha === null || SHA.test(route.runningSha)),
  "invalid fixture routing state");
  return { active, route };
}
function events(root) {
  const journal = readJson(root, "state/journal.json");
  exact(journal, ["version", "events"], "invalid recovery journal");
  check(journal.version === 1 && Array.isArray(journal.events) &&
    journal.events.length < 512 && journal.events.every((entry) =>
      entry && typeof entry === "object" && ID.test(entry.id) &&
      PHASES.has(entry.phase) && SHA.test(entry.previousSha) && SHA.test(entry.nextSha)),
  "invalid recovery journal entries");
  return journal;
}
function record(root, id, phase, previousSha, nextSha) {
  const journal = events(root);
  journal.events.push({ id, phase, previousSha, nextSha });
  replaceJson(root, "state/journal.json", journal);
}
function healthy(root, sha, route) {
  const app = revision(root, sha);
  const db = database(root);
  check(app.health === "ok" && db.schemaVersion === app.schemaVersion &&
    route.runningSha === sha, "application health or database schema mismatch");
}
function preflight(root, request) {
  const { expectedPreviousSha, candidateSha } = request;
  check(SHA.test(expectedPreviousSha) && SHA.test(candidateSha) &&
    expectedPreviousSha !== candidateSha, "invalid release transition");
  const { active, route } = control(root);
  const existing = events(root);
  check(active.revision === expectedPreviousSha && !route.maintenance &&
    route.runningSha === expectedPreviousSha, "predecessor is not active and healthy");
  check(existing.events.length === 0 ||
    ["committed", "rolled-back"].includes(existing.events.at(-1).phase),
  "unresolved attempted operation");
  const predecessor = revision(root, expectedPreviousSha);
  const candidate = revision(root, candidateSha);
  check(candidate.schemaVersion >= predecessor.schemaVersion,
    "downgrade would require an independently reviewed restore plan");
  healthy(root, expectedPreviousSha, route);
  check(!existsSync(path.join(root, LOCK)), "another operation or crash is unresolved");
  return digest(readBytes(root, "database/database.json"));
}
function lock(root, attempt) {
  writeNew(root, LOCK, Buffer.from(JSON.stringify(attempt)));
}
function unlock(root, id) {
  const recorded = readJson(root, LOCK);
  check(recorded.id === id, "attempt lock was replaced");
  unlinkSync(checkedPath(root, LOCK));
  syncParent(path.join(root, LOCK));
}

/**
 * Executes a real (but entirely disposable) data file transition. A verified
 * clone receives the schema change before the live fixture database; the
 * original backup and both release descriptors are retained permanently.
 * Failures restore the exact pre-attempt database bytes before reopening the
 * predecessor. Crashes retain an exclusive attempted marker and block retries.
 */
export function rehearseDisposableOfflineRecovery(request, options = {}) {
  exact(request, ["fixtureRoot", "expectedPreviousSha", "candidateSha"], "invalid request");
  check(options && typeof options === "object" && !Array.isArray(options) &&
    Object.keys(options).every((key) => key === "onPhase") &&
    (options.onPhase === undefined || typeof options.onPhase === "function"),
  "invalid disposable test instrumentation");
  const root = fixtureRoot(request.fixtureRoot);
  const { expectedPreviousSha: oldSha, candidateSha: newSha } = request;
  const initialDigest = preflight(root, request);
  const id = randomBytes(16).toString("hex");
  lock(root, { id, previousSha: oldSha, nextSha: newSha });
  let backupRelative = null;
  let attempted = false;
  const checkpoint = (phase) => {
    record(root, id, phase, oldSha, newSha);
    options.onPhase?.(phase);
  };
  try {
    // Recheck AFTER the exclusive reservation to reject preflight races.
    const { active, route } = control(root);
    check(active.revision === oldSha && !route.maintenance &&
      route.runningSha === oldSha &&
      digest(readBytes(root, "database/database.json")) === initialDigest,
    "fixture changed between preflight and reservation");
    record(root, id, "attempted", oldSha, newSha);
    attempted = true;
    options.onPhase?.("attempted");
    replaceJson(root, "state/routing.json", { maintenance: true, runningSha: null });
    checkpoint("maintenance");

    const originalBytes = readBytes(root, "database/database.json");
    check(digest(originalBytes) === initialDigest, "database changed before backup");
    const newBackup = `backups/${id}.dump`;
    writeNew(root, newBackup, originalBytes);
    backupRelative = newBackup;
    check(digest(readBytes(root, backupRelative)) === initialDigest,
      "persisted backup does not match live data");
    checkpoint("backup-verified");

    const cloneRelative = `restores/${id}.dump`;
    writeNew(root, cloneRelative, readBytes(root, backupRelative));
    check(digest(readBytes(root, cloneRelative)) === initialDigest &&
      digest(readBytes(root, backupRelative)) === initialDigest,
    "disposable restore differs from verified backup");
    checkpoint("restore-verified");

    const target = revision(root, newSha);
    const restoredData = JSON.parse(readBytes(root, cloneRelative).toString("utf8"));
    restoredData.schemaVersion = target.schemaVersion;
    replaceJson(root, cloneRelative, restoredData);
    check(readJson(root, cloneRelative).schemaVersion === target.schemaVersion &&
      JSON.stringify(readJson(root, cloneRelative).accounts) ===
        JSON.stringify(JSON.parse(originalBytes.toString("utf8")).accounts),
    "migration changed account data on disposable restore");
    checkpoint("restore-migrated");

    check(digest(readBytes(root, backupRelative)) === initialDigest,
      "verified backup was modified before live migration");
    replaceJson(root, "database/database.json", restoredData);
    checkpoint("live-migrated");
    replaceJson(root, "state/routing.json", { maintenance: true, runningSha: newSha });
    checkpoint("candidate-running");
    healthy(root, newSha, control(root).route);
    checkpoint("health-passed");

    // An application process could mutate protected account state while it is
    // warming up. Re-verify both copies and the original snapshot immediately
    // before recording completion, including after test fault hooks.
    check(digest(readBytes(root, backupRelative)) === initialDigest,
      "verified rollback backup changed before activation");
    check(revision(root, oldSha).schemaVersion === JSON.parse(originalBytes.toString("utf8")).schemaVersion,
      "predecessor no longer matches the rollback snapshot");
    const live = database(root);
    const clone = readJson(root, cloneRelative);
    check(JSON.stringify(live) === JSON.stringify(clone) &&
      JSON.stringify(live.accounts) ===
        JSON.stringify(JSON.parse(originalBytes.toString("utf8")).accounts),
    "live identity state differs from verified migrated restore");
    const finalRoute = control(root).route;
    check(finalRoute.maintenance === true && finalRoute.runningSha === newSha,
      "candidate became routed before durable completion");
    healthy(root, newSha, finalRoute);

    // Publish completion BEFORE reopening the route. An interrupted publish
    // cannot serve an unrecorded candidate; an orphan lock still blocks retry.
    replaceJson(root, "state/active.json", { revision: newSha });
    record(root, id, "committed", oldSha, newSha);
    replaceJson(root, "state/routing.json", { maintenance: false, runningSha: newSha });
    unlock(root, id);
    return Object.freeze({
      status: "DISPOSABLE_RECOVERY_REHEARSAL_PASSED", deployAuthorized: false,
      previousSha: oldSha, candidateSha: newSha,
      backupSha256: initialDigest, attemptId: id,
    });
  } catch (error) {
    if (!attempted) {
      // Lock exists but attempted state could not be durably recorded:
      // preserve it for manual inspection rather than silently retrying.
      throw error;
    }
    try {
      record(root, id, "rollback-started", oldSha, newSha);
      replaceJson(root, "state/routing.json", { maintenance: true, runningSha: null });
      if (backupRelative) {
        const original = readBytes(root, backupRelative);
        check(digest(original) === initialDigest, "backup identity changed");
        replace(root, "database/database.json", original);
      } else {
        check(digest(readBytes(root, "database/database.json")) === initialDigest,
          "database changed before verified backup");
      }
      replaceJson(root, "state/active.json", { revision: oldSha });
      replaceJson(root, "state/routing.json", { maintenance: true, runningSha: oldSha });
      healthy(root, oldSha, control(root).route);
      record(root, id, "rolled-back", oldSha, newSha);
      replaceJson(root, "state/routing.json", { maintenance: false, runningSha: oldSha });
      unlock(root, id);
    } catch (rollbackFailure) {
      try { record(root, id, "rollback-blocked", oldSha, newSha); } catch { /* retain attempted lock */ }
      throw new AggregateError([error, rollbackFailure],
        "Disposable recovery failed and safe rollback is blocked; attempted lock retained",
        { cause: rollbackFailure });
    }
    throw error;
  }
}

// Read-only status for a crashed fixture. No silent unlock, automatic retry,
// production recovery or authority inference from locally created evidence.
export function inspectDisposableOfflineRecovery(fixtureDirectory) {
  const root = fixtureRoot(fixtureDirectory);
  const { active, route } = control(root);
  const journal = events(root);
  const last = journal.events.at(-1)?.phase ?? "none";
  const hasLock = existsSync(path.join(root, LOCK));
  return Object.freeze({
    status: hasLock ? "DISPOSABLE_ATTEMPT_REQUIRES_MANUAL_RECONCILIATION" :
      "DISPOSABLE_REHEARSAL_IDLE",
    deployAuthorized: false, lastPhase: last,
    activeSha: active.revision, maintenance: route.maintenance,
    attemptedLock: hasLock,
  });
}
