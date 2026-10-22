import { createHash, randomBytes } from "node:crypto";
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  openSync, readFileSync, readdirSync, readSync, realpathSync, renameSync, statfsSync,
  unlinkSync, writeSync,
} from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { recordOfflineReleaseAcceptance, completeOfflineReleaseAcceptance } from
  "../../scripts/lib/offline-release-ledger.mjs";
import { verifyOfflineDockerSaveTarFromHandle } from
  "../../scripts/lib/offline-docker-tar-verifier.mjs";
import { compareUntrustedLoadedImageForPreview } from "./trusted-image-loader.mjs";

// This is an isolated Linux root regression CONTROLLER, not the production
// operator or a way to claim that an uploaded bundle was approved. Only a
// disposable, no-network, root-owned tmpfs fixture can pass the runtime gate.
// No Docker socket, executable, PostgreSQL connection, SSH, or host root is used.
const REV = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const IMAGE = /^sha256:[a-f0-9]{64}$/u;
const NONCE = /^[a-f0-9]{32}$/u;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const CREATE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const MAX_JSON = 1024 * 1024;
const MAX_IMAGE = 256 * 1024 * 1024; // Fixture cap; real image loader has a separate bound.
const SHA_SOURCE = "https://github.com/bielxdh3/Virki";
const ROLES = Object.freeze(["runtime", "migrator"]);
const FINISHED_PHASES = Object.freeze([
  "attempted", "loaded-runtime", "loaded-migrator", "maintenance",
  "backup-verified", "restore-verified", "restore-migrated", "live-migrated",
  "candidate-healthy", "activated-under-maintenance", "finalizing-ledger", "completed",
]);

function refuse(message) { throw new Error("Native recovery fixture refused: " + message); }
function requireIt(value, message) { if (!value) refuse(message); }
function strictKeys(object, keys, label) {
  requireIt(object && typeof object === "object" && !Array.isArray(object) &&
    Object.keys(object).length === keys.length && keys.every((key) => Object.hasOwn(object, key)),
  label + " fields invalid");
}
function sha(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
    .every((key) => a[key] === b[key]);
}
function dir(dirname) {
  const meta = lstatSync(dirname, { bigint: true });
  requireIt(meta.isDirectory() && !meta.isSymbolicLink() &&
    meta.uid === 0n && meta.gid === 0n && (meta.mode & 0o7777n) === 0o700n,
  "fixture directory must be root:root 0700");
}
function rootGate(root) {
  requireIt(process.env.VIRKI_NATIVE_RECOVERY_DISPOSABLE_TEST === "1" &&
    process.platform === "linux" && process.arch === "x64" &&
    process.getuid?.() === 0 && existsSync("/.dockerenv") &&
    statfsSync(os.tmpdir()).type === 0x01021994 && constants.O_NOFOLLOW &&
    constants.O_DIRECTORY, "isolated Linux root tmpfs container required");
  requireIt(typeof root === "string" && !root.includes("\0") &&
    path.isAbsolute(root) && path.normalize(root) === root &&
    path.dirname(root) === realpathSync.native(os.tmpdir()) &&
    /^virki-native-recovery-fixture-[a-zA-Z0-9]{6}$/u.test(path.basename(root)) &&
    realpathSync.native(root) === root, "fixture root must be direct OS tmpfs child");
  dir(root);
  for (const folder of ["operator", "operator/ledger", "candidate", "sealed", "state",
    "releases", "database", "backups", "restores", "fake-docker"]) {
    const segments = folder.split("/");
    let current = root;
    for (const segment of segments) {
      current = path.join(current, segment);
      dir(current);
    }
  }
  const identity = readJson(root, "operator/fixture.json");
  strictKeys(identity, ["version", "kind", "identity"], "independent fixture marker");
  requireIt(identity.version === 1 && identity.kind === "isolated-native-recovery" &&
    NONCE.test(identity.identity), "fixture independent marker invalid");
  return root;
}
function pathname(root, relative) {
  requireIt(typeof relative === "string" && /^[a-zA-Z0-9./_-]+$/u.test(relative) &&
    !relative.startsWith("/") &&
    relative.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== ".."),
  "unsafe fixture relative path");
  const result = path.join(root, ...relative.split("/"));
  let parent = path.dirname(result);
  while (parent !== root) {
    dir(parent);
    parent = path.dirname(parent);
  }
  return result;
}
function checkFile(root, relative, sizeLimit = MAX_JSON) {
  const file = pathname(root, relative);
  const meta = lstatSync(file, { bigint: true });
  requireIt(meta.isFile() && !meta.isSymbolicLink() && meta.nlink === 1n &&
    meta.uid === 0n && meta.gid === 0n && (meta.mode & 0o7777n) === 0o600n &&
    meta.size > 0n && meta.size <= BigInt(sizeLimit), "unsafe fixture private file");
  return { file, meta };
}
function readPrivate(root, relative, limit = MAX_JSON) {
  const { file, meta } = checkFile(root, relative, limit);
  const fd = openSync(file, READ_FLAGS);
  try {
    requireIt(same(meta, fstatSync(fd, { bigint: true })), "file swapped before reading");
    const bytes = readFileSync(fd);
    requireIt(bytes.length === Number(meta.size) &&
      same(meta, fstatSync(fd, { bigint: true })) &&
      same(meta, lstatSync(file, { bigint: true })), "file changed while reading");
    return bytes;
  } finally { closeSync(fd); }
}
function readJson(root, relative) {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(readPrivate(root, relative)));
}
function syncDir(dirname) {
  const fd = openSync(dirname, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function create(root, relative, bytes) {
  requireIt(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_IMAGE,
    "invalid fixture write");
  const file = pathname(root, relative);
  const fd = openSync(file, CREATE_FLAGS, 0o600);
  try {
    for (let at = 0; at < bytes.length;) {
      const size = writeSync(fd, bytes, at, bytes.length - at, at);
      requireIt(size > 0, "short fixture write");
      at += size;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  syncDir(path.dirname(file));
}
function atomic(root, relative, bytes) {
  requireIt(bytes.length <= MAX_JSON, "state too large");
  const target = pathname(root, relative);
  checkFile(root, relative);
  const temporary = relative + "." + randomBytes(12).toString("hex");
  create(root, temporary, bytes);
  renameSync(pathname(root, temporary), target);
  syncDir(path.dirname(target));
}
function putJson(root, relative, value) { atomic(root, relative, Buffer.from(JSON.stringify(value))); }
function operatorPlan(root) {
  const plan = readJson(root, "operator/accepted-plan.json");
  strictKeys(plan, ["version", "previousSha", "nextSha", "manifestSha256", "nonce",
    "sequence", "approvalDigest", "runtime", "migrator"], "protected fixture plan");
  requireIt(plan.version === 1 && REV.test(plan.previousSha) &&
    REV.test(plan.nextSha) && plan.previousSha !== plan.nextSha &&
    HASH.test(plan.manifestSha256) && HASH.test(plan.approvalDigest) &&
    NONCE.test(plan.nonce) && plan.sequence === 1,
  "protected fixture plan revision or approval invalid");
  for (const role of ROLES) {
    strictKeys(plan[role], ["imageId", "archiveSha256", "archiveSizeBytes"], role + " identity");
    requireIt(IMAGE.test(plan[role].imageId) && HASH.test(plan[role].archiveSha256) &&
      Number.isSafeInteger(plan[role].archiveSizeBytes) &&
      plan[role].archiveSizeBytes >= 2048 &&
      plan[role].archiveSizeBytes <= MAX_IMAGE &&
      plan[role].archiveSizeBytes % 512 === 0,
    "invalid pinned image");
  }
  requireIt(plan.runtime.imageId !== plan.migrator.imageId &&
    plan.runtime.archiveSha256 !== plan.migrator.archiveSha256,
  "runtime and migrator must be different pinned images");
  return plan;
}
function activeState(root, plan) {
  const active = readJson(root, "state/active.json");
  const route = readJson(root, "state/routing.json");
  const journal = readJson(root, "state/journal.json");
  strictKeys(active, ["revision"], "active state");
  strictKeys(route, ["maintenance", "runningSha"], "routing state");
  strictKeys(journal, ["version", "steps"], "journal");
  requireIt(active.revision === plan.previousSha && route.runningSha === plan.previousSha &&
    route.maintenance === false && journal.version === 1 &&
    Array.isArray(journal.steps) && journal.steps.length === 0,
  "initial active state not safe");
  const old = readJson(root, `releases/${plan.previousSha}.json`);
  const candidate = readJson(root, `releases/${plan.nextSha}.json`);
  strictKeys(old, ["revision", "schemaVersion", "health"], "predecessor release");
  strictKeys(candidate, ["revision", "schemaVersion", "health"], "candidate release");
  requireIt(old.revision === plan.previousSha && candidate.revision === plan.nextSha &&
    old.health === "ok" && Number.isSafeInteger(old.schemaVersion) &&
    Number.isSafeInteger(candidate.schemaVersion) &&
    old.schemaVersion > 0 && candidate.schemaVersion >= old.schemaVersion,
  "incompatible release descriptors");
  const data = readJson(root, "database/live.json");
  requireIt(data.schemaVersion === old.schemaVersion &&
    data.accounts && data.secrets && data.audit && data.outbox &&
    Array.isArray(data.accounts) && data.accounts.length > 0,
  "predecessor database not healthy or full data missing");
  requireIt(readJson(root, "fake-docker/images.json").images.length === 0 &&
    !existsSync(pathname(root, "state/transaction.json")) &&
    !existsSync(pathname(root, "operator/ledger/.offline-release.lock")),
  "prior pending attempt or unexpected daemon state");
  return { candidate, original: readPrivate(root, "database/live.json") };
}
async function borrowArchive(root, role, identity, revision) {
  const source = `candidate/${role}.tar`;
  const { file, meta } = checkFile(root, source, MAX_IMAGE);
  requireIt(meta.size === BigInt(identity.archiveSizeBytes), "candidate archive size mismatch");
  const src = await open(file, READ_FLAGS);
  let sealed;
  const temporary = `sealed/${role}.tar`;
  try {
    requireIt(same(meta, await src.stat({ bigint: true })), "candidate swapped before pinning");
    const out = openSync(pathname(root, temporary), CREATE_FLAGS, 0o600);
    try {
      const buffer = Buffer.allocUnsafe(64 * 1024);
      const hasher = createHash("sha256");
      let at = 0;
      while (at < identity.archiveSizeBytes) {
        const count = readSync(src.fd, buffer, 0,
          Math.min(buffer.length, identity.archiveSizeBytes - at), at);
        requireIt(count > 0, "short pinned candidate read");
        let done = 0;
        while (done < count) {
          const written = writeSync(out, buffer, done, count - done);
          requireIt(written > 0, "short detached archive write");
          done += written;
        }
        hasher.update(buffer.subarray(0, count));
        at += count;
      }
      requireIt(hasher.digest("hex") === identity.archiveSha256 &&
        same(meta, await src.stat({ bigint: true })) &&
        same(meta, lstatSync(file, { bigint: true })),
      "pinned source identity or digest changed during detachment");
      fsyncSync(out);
    } finally { closeSync(out); }
    syncDir(pathname(root, "sealed"));
    sealed = await open(pathname(root, temporary), READ_FLAGS);
    const sealedStat = await sealed.stat({ bigint: true });
    requireIt(sealedStat.uid === 0n && sealedStat.gid === 0n &&
      sealedStat.nlink === 1n && sealedStat.size === BigInt(identity.archiveSizeBytes) &&
      (sealedStat.mode & 0o7777n) === 0o600n, "detached archive metadata invalid");
    const proof = await verifyOfflineDockerSaveTarFromHandle({
      fileHandle: sealed, role, expectedImageId: identity.imageId,
      expectedRevision: revision, expectedArchiveSha256: identity.archiveSha256,
      expectedArchiveSizeBytes: identity.archiveSizeBytes,
    });
    requireIt(proof.imageId === identity.imageId && proof.archiveSha256 === identity.archiveSha256 &&
      same(sealedStat, await sealed.stat({ bigint: true })),
    "detached archive parser identity mismatch");
    // The fake Docker backend consumes the original sealed handle. No pathname
    // is given to the backend and a caller cannot specify the expected ID.
    unlinkSync(pathname(root, temporary));
    syncDir(pathname(root, "sealed"));
    await src.close();
    return sealed;
  } catch (error) {
    if (sealed) await sealed.close();
    throw error;
  } finally {
    if (src.fd !== -1) await src.close();
  }
}
function fakeLoad(root, handle, role, plan) {
  const bytes = readFileSync(handle.fd);
  requireIt(sha(bytes) === plan[role].archiveSha256 &&
    bytes.length === plan[role].archiveSizeBytes,
  "fake Docker consumed unauthenticated bytes");
  const daemon = readJson(root, "fake-docker/images.json");
  strictKeys(daemon, ["images"], "fake daemon");
  requireIt(daemon.images.every((item) => item.role !== role && item.imageId !== plan[role].imageId),
  "fake daemon image already loaded");
  daemon.images.push({
    role, imageId: plan[role].imageId, archiveSha256: sha(bytes),
    revision: plan.nextSha, source: SHA_SOURCE, platform: "linux/amd64",
    user: "node:node", tags: [],
  });
  putJson(root, "fake-docker/images.json", daemon);
}
function verifyDaemon(root, plan, complete = false) {
  const daemon = readJson(root, "fake-docker/images.json");
  strictKeys(daemon, ["images"], "fake daemon inventory");
  requireIt(Array.isArray(daemon.images) && daemon.images.length <= 2,
    "unexpected fake daemon image count");
  for (const image of daemon.images) {
    requireIt(ROLES.includes(image.role) && image.imageId === plan[image.role].imageId &&
      image.archiveSha256 === plan[image.role].archiveSha256 &&
      image.revision === plan.nextSha && image.source === SHA_SOURCE &&
      image.platform === "linux/amd64" && image.user === "node:node" &&
      Array.isArray(image.tags) && image.tags.length === 0,
    "loaded image identity, role or untagged policy mismatch");
    const inspection = compareUntrustedLoadedImageForPreview({
      imageInspect: [{
        Id: image.imageId, Os: "linux", Architecture: "amd64",
        Config: { User: image.user, Labels: {
          "org.opencontainers.image.revision": image.revision,
          "org.opencontainers.image.source": image.source,
        } },
        RepoTags: null, RepoDigests: null,
      }],
      verifiedImage: {
        imageId: plan[image.role].imageId, revision: plan.nextSha,
        source: SHA_SOURCE, platform: "linux/amd64", user: "node:node",
      },
    });
    requireIt(inspection.dockerTagAuthorized === false &&
      inspection.deployAuthorized === false, "fake loaded image admitted unexpected authority");
  }
  if (complete) requireIt(daemon.images.length === 2 &&
    daemon.images.every((item, index) => item.role === ROLES[index]),
  "both pinned roles must be present in fixed order");
}
function checkpoint(root, plan, phase, afterPhase) {
  const journal = readJson(root, "state/journal.json");
  journal.steps.push(phase);
  putJson(root, "state/journal.json", journal);
  afterPhase?.(phase);
}
function restoredIdentity(before, after, schema) {
  requireIt(after.schemaVersion === schema && before.schemaVersion <= schema,
    "migration schema mismatch");
  const expected = { ...before, schemaVersion: schema };
  requireIt(JSON.stringify(expected) === JSON.stringify(after),
    "migration changed protected user, security, audit or recovery data");
}
function preflight(root, plan) {
  const { candidate, original } = activeState(root, plan);
  return { candidate, original, originalDigest: sha(original) };
}
function rollback(root, plan, originalDigest, backupRelative) {
  // Failure after maintenance must preserve a verified snapshot before any
  // destructive restore. Unverifiable rollback holds maintenance and lock.
  putJson(root, "state/routing.json", { maintenance: true, runningSha: null });
  const restored = backupRelative
    ? readPrivate(root, backupRelative)
    : readPrivate(root, "database/live.json");
  requireIt(sha(restored) === originalDigest, "rollback proof missing or changed");
  atomic(root, "database/live.json", restored);
  const old = readJson(root, `releases/${plan.previousSha}.json`);
  requireIt(old.health === "ok" && readJson(root, "database/live.json").schemaVersion === old.schemaVersion,
    "predecessor health or schema invalid after restore");
  putJson(root, "state/active.json", { revision: plan.previousSha });
  // Keep maintenance active until the durable rollback checkpoint is stored.
  // The attempted ledger latch still requires operator reconciliation.
  checkpoint(root, plan, "rolled-back");
  putJson(root, "state/routing.json", { maintenance: false, runningSha: plan.previousSha });
}

/**
 * Test-only native Linux controller. External request contains ONLY a fixture
 * directory; release identity is obtained from protected operator bytes in
 * this same process. It NEVER accepts status='staged', image IDs, injected
 * Docker/PG handles, caller ledger flags or production root paths.
 *
 * The SAME root-pinned closure verifies both detached image descriptors,
 * reserves exactly one attempted ledger transition, checks both imported
 * images, validates backup and disposable restore, then exercises maintenance,
 * migrations, health and rollback. The existing ledger's lock persists after
 * failure/crash. Completed fixture ledger entries have NO release authority.
 */
export async function rehearseProtectedNativeOfflineRecovery(request = {}, options = {}) {
  strictKeys(request, ["fixtureRoot"], "fixture request");
  requireIt(options && typeof options === "object" && !Array.isArray(options) &&
    Object.keys(options).every((key) => key === "afterPhase") &&
    (options.afterPhase === undefined || typeof options.afterPhase === "function"),
  "invalid fixture fault instrumentation");
  const root = rootGate(request.fixtureRoot);
  const plan = operatorPlan(root);
  const { candidate, original, originalDigest } = preflight(root, plan);
  const ledgerRequest = {
    directory: pathname(root, "operator/ledger"),
    manifestSha256: plan.manifestSha256, priorSha: plan.previousSha,
    nextSha: plan.nextSha, nonce: plan.nonce, sequence: plan.sequence,
    approvalDigest: plan.approvalDigest,
  };
  // These are the only authenticated identities this function can use. The
  // fixture's private operator record is NOT a production owner-signature
  // verifier; integration with installed host trust remains intentionally off.
  const accepted = recordOfflineReleaseAcceptance(ledgerRequest);
  requireIt(accepted.status === "attempted" && accepted.pendingSha === plan.nextSha &&
    accepted.sequence === plan.sequence, "attempted reservation does not match protected context");
  let maintenance = false;
  let ledgerFinalizationStarted = false;
  let backupRelative;
  const step = (phase) => checkpoint(root, plan, phase, options.afterPhase);
  try {
    create(root, "state/transaction.json", Buffer.from(JSON.stringify({
      status: "attempted", predecessor: plan.previousSha, candidate: plan.nextSha,
      manifestSha256: plan.manifestSha256,
    })));
    step("attempted");
    for (const role of ROLES) {
      const handle = await borrowArchive(root, role, plan[role], plan.nextSha);
      try { fakeLoad(root, handle, role, plan); }
      finally { await handle.close(); }
      verifyDaemon(root, plan);
      step(`loaded-${role}`);
    }
    verifyDaemon(root, plan, true);
    putJson(root, "state/routing.json", { maintenance: true, runningSha: null });
    maintenance = true;
    step("maintenance");

    const now = readPrivate(root, "database/live.json");
    requireIt(sha(now) === originalDigest, "database changed before protected backup");
    backupRelative = `backups/${plan.sequence}.dump`;
    create(root, backupRelative, now);
    requireIt(sha(readPrivate(root, backupRelative)) === originalDigest,
      "backup digest mismatched snapshot");
    step("backup-verified");

    const cloneRelative = `restores/${plan.sequence}.json`;
    create(root, cloneRelative, readPrivate(root, backupRelative));
    requireIt(sha(readPrivate(root, cloneRelative)) === originalDigest,
      "disposable restore does not reproduce exact backup");
    step("restore-verified");

    const from = readJson(root, cloneRelative);
    const migrated = { ...from, schemaVersion: candidate.schemaVersion };
    putJson(root, cloneRelative, migrated);
    restoredIdentity(from, readJson(root, cloneRelative), candidate.schemaVersion);
    step("restore-migrated");

    requireIt(sha(readPrivate(root, backupRelative)) === originalDigest,
      "rollback backup changed before live migration");
    atomic(root, "database/live.json", Buffer.from(JSON.stringify(migrated)));
    restoredIdentity(JSON.parse(original.toString("utf8")),
      readJson(root, "database/live.json"), candidate.schemaVersion);
    step("live-migrated");
    putJson(root, "state/routing.json", { maintenance: true, runningSha: plan.nextSha });
    requireIt(candidate.health === "ok", "candidate health refused");
    step("candidate-healthy");

    // Any fake app mutation, archive role replacement, or failed migration
    // detected at this point keeps the real attempted ledger lock unresolved.
    verifyDaemon(root, plan, true);
    requireIt(sha(readPrivate(root, backupRelative)) === originalDigest,
      "rollback backup changed during health");
    const live = readJson(root, "database/live.json");
    restoredIdentity(JSON.parse(original.toString("utf8")), live, candidate.schemaVersion);
    requireIt(JSON.stringify(live) === JSON.stringify(readJson(root, cloneRelative)) &&
      readJson(root, "state/routing.json").maintenance === true,
    "live data differs from verified restored clone or maintenance escaped");
    putJson(root, "state/active.json", { revision: plan.nextSha });
    step("activated-under-maintenance");
    // Once finalization begins, the ledger can commit its head before its
    // caller receives a result. NEVER roll back a candidate after this point:
    // an interrupted ledger could already have committed the next SHA.
    ledgerFinalizationStarted = true;
    step("finalizing-ledger");
    // This is a FAKE fixture health report. The ledger persistence primitive
    // cannot establish real operational authority from its digest.
    const final = completeOfflineReleaseAcceptance({
      ...ledgerRequest, observedActiveSha: plan.nextSha,
      healthReportSha256: sha(Buffer.from(JSON.stringify({ fixture: true,
        revision: plan.nextSha, runtime: plan.runtime.imageId, migrator: plan.migrator.imageId }))),
    });
    requireIt(final.status === "completed" && final.headSha === plan.nextSha,
      "fixture ledger completion refused");
    // Publish the durable completed journal and terminal transaction marker
    // BEFORE reopening the route. A SIGKILL at either checkpoint therefore
    // leaves maintenance engaged and requires manual reconciliation.
    step("completed");
    putJson(root, "state/transaction.json", {
      status: "completed", predecessor: plan.previousSha,
      candidate: plan.nextSha, manifestSha256: plan.manifestSha256,
    });
    putJson(root, "state/routing.json", { maintenance: false, runningSha: plan.nextSha });
    return Object.freeze({
      status: "NATIVE_DISPOSABLE_RECOVERY_REHEARSAL_ONLY", deployAuthorized: false,
      twoPinnedImagesVerified: true, attemptSequence: accepted.sequence,
      originalBackupSha256: originalDigest,
    });
  } catch (error) {
    if (ledgerFinalizationStarted) {
      // Keep the current routing/maintenance evidence for manual reconciliation.
      // No automated rollback or lock removal can safely interpret a partial
      // success of the independent ledger finalization primitive.
      throw error;
    }
    if (maintenance) {
      try { rollback(root, plan, originalDigest, backupRelative); }
      catch (failure) {
        try { checkpoint(root, plan, "rollback-blocked"); } catch { /* preserve attempted lock */ }
        throw new AggregateError([error, failure],
          "Native recovery fixture failed and verified rollback is blocked", { cause: failure });
      }
    }
    // Before maintenance, old release/data are untouched. Never clear the
    // attempted ledger lock or accept the same nonce/sequence after a failure.
    throw error;
  }
}

/**
 * Read-only crash evidence. Even a completed fixture is non-authorizing.
 * Never removes a stale ledger lock or alters an interrupted transaction.
 */
export function inspectProtectedNativeOfflineRecoveryFixture(request = {}) {
  strictKeys(request, ["fixtureRoot"], "fixture request");
  const root = rootGate(request.fixtureRoot);
  const plan = operatorPlan(root);
  const active = readJson(root, "state/active.json");
  const route = readJson(root, "state/routing.json");
  const journal = readJson(root, "state/journal.json");
  const ledger = readJson(root, "operator/ledger/ledger.json");
  const pending = existsSync(pathname(root, "operator/ledger/.offline-release.lock"));
  const finalizing = existsSync(pathname(root, "operator/ledger/.offline-release.finalizing"));
  const hasTransaction = existsSync(pathname(root, "state/transaction.json"));
  const transaction = hasTransaction ? readJson(root, "state/transaction.json") : null;
  const checkpoint = Array.isArray(journal.steps) ? journal.steps.at(-1) ?? null : null;
  // A crash AFTER ledger commitment but BEFORE reopening the route can leave
  // no pending lock. Maintenance and an incomplete journal still require
  // manual reconciliation; absence of .lock alone is never a success proof.
  const structurallyValid = journal.version === 1 && Array.isArray(journal.steps) &&
    Array.isArray(ledger.entries) && ledger.version === 1 &&
    ledger.anchorSha === plan.previousSha &&
    Object.keys(ledger).length === 3 && typeof route.maintenance === "boolean";
  const expectedEntry = {
    sequence: plan.sequence, priorSha: plan.previousSha,
    nextSha: plan.nextSha, manifestSha256: plan.manifestSha256,
    nonce: plan.nonce, approvalDigest: plan.approvalDigest,
  };
  const pristine = structurallyValid && !hasTransaction && checkpoint === null &&
    active.revision === plan.previousSha && route.runningSha === plan.previousSha &&
    !route.maintenance && ledger.entries.length === 0;
  const completed = structurallyValid && transaction !== null &&
    transaction.status === "completed" && transaction.predecessor === plan.previousSha &&
    transaction.candidate === plan.nextSha && transaction.manifestSha256 === plan.manifestSha256 &&
    Object.keys(transaction).length === 4 &&
    JSON.stringify(journal.steps) === JSON.stringify(FINISHED_PHASES) &&
    !route.maintenance && route.runningSha === plan.nextSha &&
    active.revision === plan.nextSha && ledger.entries.length === 1 &&
    JSON.stringify(ledger.entries[0]) === JSON.stringify(expectedEntry);
  // The status is evidence, not an admission token. Still refuse to describe
  // a corrupted database, daemon image inventory or rollback snapshot as a
  // coherent idle/complete rehearsal merely because a journal says so.
  let coherentFixture = false;
  try {
    const liveData = readJson(root, "database/live.json");
    if (pristine) {
      const predecessor = readJson(root, `releases/${plan.previousSha}.json`);
      const docker = readJson(root, "fake-docker/images.json");
      coherentFixture = liveData.schemaVersion === predecessor.schemaVersion &&
        Array.isArray(liveData.accounts) && liveData.accounts.length > 0 &&
        liveData.secrets && Array.isArray(liveData.audit) &&
        Array.isArray(liveData.outbox) && Array.isArray(docker.images) &&
        docker.images.length === 0 &&
        readdirSync(pathname(root, "sealed")).length === 0 &&
        readdirSync(pathname(root, "backups")).length === 0 &&
        readdirSync(pathname(root, "restores")).length === 0;
    } else if (completed) {
      verifyDaemon(root, plan, true);
      const candidate = readJson(root, `releases/${plan.nextSha}.json`);
      const backup = readPrivate(root, `backups/${plan.sequence}.dump`);
      const original = JSON.parse(backup.toString("utf8"));
      restoredIdentity(original, liveData, candidate.schemaVersion);
      const clone = readJson(root, `restores/${plan.sequence}.json`);
      coherentFixture = candidate.health === "ok" &&
        JSON.stringify(clone) === JSON.stringify(liveData) &&
        readdirSync(pathname(root, "sealed")).length === 0;
    }
  } catch {
    coherentFixture = false;
  }
  const status = !pending && !finalizing && coherentFixture && (pristine || completed)
    ? "DISPOSABLE_REHEARSAL_INSPECTION_ONLY"
    : "DISPOSABLE_ATTEMPT_REQUIRES_MANUAL_RECONCILIATION";
  return Object.freeze({
    status, deployAuthorized: false,
    activeSha: active.revision,
    maintenance: route.maintenance,
    lastCheckpoint: checkpoint,
    pendingAttempt: pending, finalizing,
    acceptedEntries: ledger.entries.length,
  });
}
