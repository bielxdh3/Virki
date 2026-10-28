import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync,
  readdirSync, readlinkSync, realpathSync, renameSync, symlinkSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// DEVELOPMENT-ONLY native filesystem experiment. No Docker, service, SQL, or
// release-authority operation is exposed. All mutations stay beneath a single
// private OS-tmpdir fixture. Production code must never import this module.
// Signed health comes from a separate DEV assessor; caller cannot pass a
// boolean, report, key, process callback, or status to these operations.
const DOMAIN = "VIRKI_DISPOSABLE_ACTIVATION_HEALTH_V1";
const BLOCKED = "Disposable activation integrity blocked";
const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const B64 = /^[A-Za-z0-9+/]{86}==$/u;
const ROOT_NAME = /^virki-activation-integrity-[a-zA-Z0-9]{6}$/u;
const PLAN_FIELDS = [
  "version", "txId", "hostIdentitySha256", "previousSha", "nextSha",
  "expectedDataSha256", "expectedPreviousRuntimeSha256", "expectedRuntimeSha256",
  "healthPublicKeyPem", "healthPinSha256",
];
const HEALTH_FIELDS = [
  "version", "domain", "txId", "hostIdentitySha256", "previousSha", "nextSha",
  "route", "runtimeSha256", "dataSha256", "switchEventSha256", "healthy",
];
const EVENT_FIELDS = [
  "version", "sequence", "phase", "planSha256", "previousEventSha256", "eventNonce", "eventSha256",
];
const STATES = [
  [], ["intent"], ["intent", "switched"], ["intent", "switched", "health-confirmed"],
  ["intent", "switched", "rollback-intent"],
  ["intent", "switched", "rollback-intent", "rolled-back"],
];
const READ = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const WRITE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const digest = (value) => createHash("sha256").update(value).digest("hex");
const ensure = (value) => { if (!value) throw new Error(BLOCKED); };
const exact = (value, fields) => ensure(value !== null && typeof value === "object" &&
  !Array.isArray(value) && Object.keys(value).length === fields.length &&
  fields.every((key) => Object.hasOwn(value, key)));
const result = (status) => Object.freeze({
  status, deployAuthorized: false, witnessCasAuthorized: false,
  transferAuthorized: false, dockerLoadAuthorized: false,
});
const same = (a, b) => ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]
  .every((field) => a[field] === b[field]);

function privateDirectory(folder) {
  const st = lstatSync(folder, { bigint: true });
  ensure(st.isDirectory() && !st.isSymbolicLink() &&
    st.uid === BigInt(process.getuid()) && st.gid === BigInt(process.getgid()) &&
    (st.mode & 0o7777n) === 0o700n);
}

function verifyRoot(root, action) {
  ensure(process.platform === "linux" && process.env.VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY === "1" &&
    typeof process.getuid === "function" && constants.O_NOFOLLOW && constants.O_DIRECTORY);
  ensure(typeof root === "string" && path.isAbsolute(root) &&
    path.normalize(root) === root && ROOT_NAME.test(path.basename(root)) &&
    path.dirname(root) === realpathSync.native(os.tmpdir()) &&
    realpathSync.native(root) === root);
  privateDirectory(root);
  const before = lstatSync(root, { bigint: true });
  const fd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    ensure(same(before, fstatSync(fd, { bigint: true })));
    const anchor = `/proc/self/fd/${fd}`;
    for (const folder of ["operator", "state", "state/journal", "releases", "data", "evidence"]) {
      privateDirectory(path.join(anchor, folder));
    }
    const resultValue = action(anchor);
    // Creating the temporary route symlink legitimately changes directory
    // ctime/mtime; its identity, owner and mode must remain pinned.
    const still = lstatSync(root, { bigint: true });
    const opened = fstatSync(fd, { bigint: true });
    ensure(["dev", "ino", "uid", "gid", "mode", "nlink"].every((name) =>
      still[name] === before[name] && opened[name] === before[name]));
    return resultValue;
  } finally {
    closeSync(fd);
  }
}

function readPrivate(anchor, relative, max = 16384) {
  const file = path.join(anchor, relative);
  const before = lstatSync(file, { bigint: true });
  ensure(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n &&
    before.uid === BigInt(process.getuid()) && before.gid === BigInt(process.getgid()) &&
    (before.mode & 0o7777n) === 0o600n && before.size > 0n &&
    before.size <= BigInt(max));
  const fd = openSync(file, READ);
  try {
    ensure(same(before, fstatSync(fd, { bigint: true })));
    const bytes = readFileSync(fd);
    ensure(bytes.length === Number(before.size) &&
      same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(file, { bigint: true })));
    return bytes;
  } finally { closeSync(fd); }
}

function readJson(anchor, relative) {
  const bytes = readPrivate(anchor, relative);
  const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const object = JSON.parse(content);
  ensure(JSON.stringify(object) === content);
  return { bytes, object };
}

function syncDir(directory) {
  // /proc/self/fd/N itself is a kernel-created symlink to the already-pinned
  // open directory; O_NOFOLLOW would reject reopening it. Sync that FD itself.
  if (/^\/proc\/self\/fd\/[0-9]+$/u.test(directory)) {
    fsyncSync(Number(directory.slice("/proc/self/fd/".length)));
    return;
  }
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function createDurable(anchor, relative, bytes) {
  ensure(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 16384);
  const file = path.join(anchor, relative);
  const fd = openSync(file, WRITE, 0o600);
  try {
    for (let at = 0; at < bytes.length;) {
      const n = writeSync(fd, bytes, at, bytes.length - at);
      ensure(n > 0);
      at += n;
    }
    fsyncSync(fd);
  } finally { closeSync(fd); }
  syncDir(path.dirname(file));
}

function present(file) {
  try { lstatSync(file); return true; }
  catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function identity(anchor) {
  const { bytes, object: plan } = readJson(anchor, "operator/activation.json");
  exact(plan, PLAN_FIELDS);
  ensure(plan.version === 1 && HEX64.test(plan.txId) &&
    HEX64.test(plan.hostIdentitySha256) && HEX40.test(plan.previousSha) &&
    HEX40.test(plan.nextSha) && plan.previousSha !== plan.nextSha &&
    HEX64.test(plan.expectedDataSha256) &&
    HEX64.test(plan.expectedPreviousRuntimeSha256) &&
    HEX64.test(plan.expectedRuntimeSha256) &&
    HEX64.test(plan.healthPinSha256));
  const key = createPublicKey(plan.healthPublicKeyPem);
  ensure(key.asymmetricKeyType === "ed25519" &&
    digest(key.export({ format: "der", type: "spki" })) === plan.healthPinSha256);
  for (const revision of [plan.previousSha, plan.nextSha])
    privateDirectory(path.join(anchor, "releases", revision));
  ensure(digest(readPrivate(anchor, "data/live.bin")) === plan.expectedDataSha256 &&
    // The predecessor is an integrity-sensitive rollback target, not merely
    // an existing regular 0600 file. Recheck its exact protected bytes on
    // EVERY entry point, including inspect and rollback, before any mutation.
    digest(readPrivate(anchor, `releases/${plan.previousSha}/runtime.bin`)) ===
      plan.expectedPreviousRuntimeSha256 &&
    digest(readPrivate(anchor, `releases/${plan.nextSha}/runtime.bin`)) ===
      plan.expectedRuntimeSha256);
  return { plan, key, planSha256: digest(bytes) };
}

function current(anchor, plan) {
  const file = path.join(anchor, "current");
  const before = lstatSync(file, { bigint: true });
  ensure(before.isSymbolicLink() && before.uid === BigInt(process.getuid()) &&
    before.gid === BigInt(process.getgid()));
  const target = readlinkSync(file);
  ensure(target === `releases/${plan.previousSha}` ||
    target === `releases/${plan.nextSha}`);
  ensure(same(before, lstatSync(file, { bigint: true })));
  return { target, stat: before };
}

function journal(anchor, planSha256) {
  const directory = path.join(anchor, "state/journal");
  const names = readdirSync(directory);
  ensure(names.length <= 4 && names.every((name) => /^0{0,7}[1-4]\.json$/u.test(name)));
  names.sort();
  const phases = [];
  let last = "0".repeat(64);
  for (let index = 0; index < names.length; index++) {
    const name = `${String(index + 1).padStart(8, "0")}.json`;
    ensure(names[index] === name);
    const { object } = readJson(anchor, `state/journal/${name}`);
    exact(object, object.phase === "health-confirmed"
      ? [...EVENT_FIELDS, "evidenceSha256"] : EVENT_FIELDS);
    ensure(object.version === 1 && object.sequence === index + 1 &&
      object.planSha256 === planSha256 && object.previousEventSha256 === last &&
      typeof object.phase === "string" && HEX64.test(object.eventNonce) &&
      HEX64.test(object.eventSha256));
    if (object.phase === "health-confirmed") ensure(HEX64.test(object.evidenceSha256));
    const { eventSha256, ...body } = object;
    ensure(eventSha256 === digest(Buffer.from(JSON.stringify(body))));
    phases.push(object.phase);
    last = eventSha256;
  }
  ensure(STATES.some((state) => JSON.stringify(state) === JSON.stringify(phases)));
  return { phases, last };
}

function append(anchor, identityValue, entry, phase, evidenceSha256) {
  ensure(phase === "health-confirmed" ? HEX64.test(evidenceSha256) :
    evidenceSha256 === undefined);
  const body = {
    version: 1, sequence: entry.phases.length + 1, phase,
    planSha256: identityValue.planSha256, previousEventSha256: entry.last,
    // Fresh journal randomness prevents a signed "health" proof from being
    // precomputed before the actual candidate switch has been journaled.
    eventNonce: randomBytes(32).toString("hex"),
  };
  const bound = phase === "health-confirmed" ? { ...body, evidenceSha256 } : body;
  const item = { ...bound, eventSha256: digest(Buffer.from(JSON.stringify(bound))) };
  createDurable(anchor, `state/journal/${String(body.sequence).padStart(8, "0")}.json`,
    Buffer.from(JSON.stringify(item)));
  return item.eventSha256;
}

function flip(anchor, plan, oldTarget, newTarget) {
  const previous = current(anchor, plan);
  ensure(previous.target === oldTarget);
  const tmp = `.current-${randomBytes(16).toString("hex")}`;
  symlinkSync(newTarget, path.join(anchor, tmp));
  syncDir(anchor);
  ensure(same(previous.stat, lstatSync(path.join(anchor, "current"), { bigint: true })));
  renameSync(path.join(anchor, tmp), path.join(anchor, "current"));
  syncDir(anchor);
  ensure(current(anchor, plan).target === newTarget);
}

function maybeFault(stage) {
  if (process.env.VIRKI_DISPOSABLE_ACTIVATION_FAULT === stage) process.kill(process.pid, "SIGKILL");
}

function verifyHealth(anchor, proof, entry) {
  const { plan, key } = proof;
  const { object: health, bytes } = readJson(anchor, "evidence/health.json");
  exact(health, ["message", "signature"]);
  exact(health.message, HEALTH_FIELDS);
  const m = health.message;
  ensure(m.version === 1 && m.domain === DOMAIN &&
    m.txId === plan.txId && m.hostIdentitySha256 === plan.hostIdentitySha256 &&
    m.previousSha === plan.previousSha && m.nextSha === plan.nextSha &&
    m.route === `releases/${plan.nextSha}` &&
    m.runtimeSha256 === plan.expectedRuntimeSha256 &&
    m.dataSha256 === plan.expectedDataSha256 && m.switchEventSha256 === entry.last &&
    m.healthy === true && current(anchor, plan).target === m.route &&
    B64.test(health.signature) &&
    Buffer.from(health.signature, "base64").toString("base64") === health.signature &&
    verify(null, Buffer.from(`${DOMAIN}\0${JSON.stringify(m)}`), key,
      Buffer.from(health.signature, "base64")));
  // Re-read the native release and data after proof verification, not only a
  // caller's claimed digest. No opaque healthReportSha256 is accepted.
  ensure(digest(readPrivate(anchor, `releases/${plan.nextSha}/runtime.bin`)) === m.runtimeSha256 &&
    digest(readPrivate(anchor, "data/live.bin")) === m.dataSha256);
  return digest(bytes);
}

function observe(anchor, proof) {
  const entry = journal(anchor, proof.planSha256);
  const phases = entry.phases.join(",");
  const target = current(anchor, proof.plan).target;
  if (phases === "") {
    ensure(target === `releases/${proof.plan.previousSha}`);
    return { status: "idle-dev-only", entry };
  }
  if (phases === "intent" || phases === "intent,switched,rollback-intent")
    return { status: "blocked-ambiguous-dev-only", entry };
  if (phases === "intent,switched") {
    ensure(target === `releases/${proof.plan.nextSha}`);
    // A preexisting failed or forged assessor file is an unresolved attempt.
    // Reconciliation must not be achieved by deleting that evidence and retrying.
    if (present(path.join(anchor, "evidence/health.json")))
      verifyHealth(anchor, proof, entry);
    return { status: "pending-independent-health-dev-only", entry };
  }
  if (phases === "intent,switched,health-confirmed") {
    ensure(target === `releases/${proof.plan.nextSha}`);
    // The previously journaled switch digest is the second event SHA.
    const switchEntry = readJson(anchor, "state/journal/00000002.json").object;
    const proofDigest = verifyHealth(anchor, proof, { last: switchEntry.eventSha256 });
    const healthEvent = readJson(anchor, "state/journal/00000003.json").object;
    ensure(healthEvent.evidenceSha256 === proofDigest);
    return { status: "health-evidence-recorded-dev-only", entry };
  }
  if (phases === "intent,switched,rollback-intent,rolled-back") {
    ensure(target === `releases/${proof.plan.previousSha}`);
    return { status: "rolled-back-dev-only", entry };
  }
  throw new Error(BLOCKED);
}

function operate(input, action) {
  try {
    exact(input, ["fixtureRoot"]);
    return verifyRoot(input.fixtureRoot, (anchor) => action(anchor, identity(anchor)));
  } catch {
    throw new Error(BLOCKED);
  }
}

export function activateDisposableRevision(input) {
  return operate(input, (anchor, proof) => {
    const state = observe(anchor, proof);
    ensure(state.status === "idle-dev-only");
    append(anchor, proof, state.entry, "intent");
    maybeFault("after-intent");
    flip(anchor, proof.plan, `releases/${proof.plan.previousSha}`,
      `releases/${proof.plan.nextSha}`);
    maybeFault("after-rename");
    append(anchor, proof, journal(anchor, proof.planSha256), "switched");
    return result("pending-independent-health-dev-only");
  });
}

export function confirmDisposableRevisionHealth(input) {
  return operate(input, (anchor, proof) => {
    const state = observe(anchor, proof);
    ensure(state.status === "pending-independent-health-dev-only");
    const healthDigest = verifyHealth(anchor, proof, state.entry);
    append(anchor, proof, state.entry, "health-confirmed", healthDigest);
    return result("health-evidence-recorded-dev-only");
  });
}

export function rollbackDisposableRevision(input) {
  return operate(input, (anchor, proof) => {
    const state = observe(anchor, proof);
    ensure(state.status === "pending-independent-health-dev-only");
    ensure(!present(path.join(anchor, "evidence/health.json")));
    append(anchor, proof, state.entry, "rollback-intent");
    maybeFault("after-rollback-intent");
    flip(anchor, proof.plan, `releases/${proof.plan.nextSha}`,
      `releases/${proof.plan.previousSha}`);
    maybeFault("after-rollback-rename");
    append(anchor, proof, journal(anchor, proof.planSha256), "rolled-back");
    return result("rolled-back-dev-only");
  });
}

export function inspectDisposableActivation(input) {
  try {
    return operate(input, (anchor, proof) => result(observe(anchor, proof).status));
  } catch {
    return result("blocked-ambiguous-dev-only");
  }
}
