import { createHash } from "node:crypto";
import {
  closeSync, constants, fsyncSync, fstatSync, lstatSync, openSync,
  readFileSync, readdirSync, realpathSync, statfsSync, writeSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

// WSL-root tmpfs-only DEV rehearsal. This module does not run on a native Linux
// production host; the future independently installed root supervisor must
// implement the same durable state machine under an owner-controlled root,
// bound to real host, signed owner approval, witness CAS and an off-host floor.
// No Docker socket, production path or state-changing command is exposed here.
const PREFIX = "virki-manual-activation-fixture-";
const SHA = /^[0-9a-f]{64}$/u;
const ACTIONS = ["fence-writers", "verify-backup", "restore-clone", "migrate-clone",
  "migrate-live", "verify-private-health", "activate-runtime", "resume-writers"];
const READ = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const WRITE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const hash = (data) => createHash("sha256").update(data).digest("hex");
function demand(value) { if (!value) throw new Error("Disposable manual activation journal refused"); }
function same(a, b) {
  return ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeMs", "ctimeMs"]
    .every((name) => a[name] === b[name]);
}
function exact(value, names) {
  demand(value && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value)) === JSON.stringify(names));
}
function root(directory) {
  // Never take a caller-provided path on native Linux. WSL root in a fixed
  // ephemeral tmpfs is the only supported rehearsal environment here.
  demand(process.platform === "linux" && process.getuid?.() === 0 &&
    /microsoft|wsl/iu.test(os.release()) &&
    statfsSync("/dev/shm").type === 0x01021994 &&
    typeof directory === "string" &&
    path.isAbsolute(directory) && directory === path.normalize(directory));
  const base = "/dev/shm";
  demand(path.dirname(directory) === base &&
    new RegExp(`^${PREFIX}[a-zA-Z0-9_-]{6,64}$`, "u").test(path.basename(directory)) &&
    realpathSync.native(directory) === directory);
  const info = lstatSync(directory);
  demand(info.isDirectory() && !info.isSymbolicLink() && info.uid === 0 &&
    info.gid === 0 && (info.mode & 0o7777) === 0o700);
  return info;
}
function name(index, suffix) {
  demand(Number.isSafeInteger(index) && index >= 0 && index <= ACTIONS.length &&
    ["intent", "complete"].includes(suffix));
  return `${String(index).padStart(8, "0")}.${suffix}`;
}
function readPrivate(directory, filename) {
  const location = path.join(directory, filename);
  const before = lstatSync(location);
  demand(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 &&
    before.uid === 0 && before.gid === 0 && (before.mode & 0o7777) === 0o600 &&
    before.size > 0 && before.size <= 32768);
  const fd = openSync(location, READ);
  try {
    demand(same(before, fstatSync(fd)));
    const bytes = readFileSync(fd);
    demand(bytes.length === before.size && same(before, fstatSync(fd)) &&
      same(before, lstatSync(location)));
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    demand(JSON.stringify(value) === bytes.toString("utf8"));
    return { value, sha: hash(bytes) };
  } finally { closeSync(fd); }
}
function durable(directory, filename, object) {
  const bytes = Buffer.from(JSON.stringify(object));
  demand(bytes.length > 0 && bytes.length <= 32768);
  const before = root(directory);
  const fd = openSync(path.join(directory, filename), WRITE, 0o600);
  try {
    for (let at = 0; at < bytes.length;) {
      const wrote = writeSync(fd, bytes, at, bytes.length - at);
      demand(wrote > 0);
      at += wrote;
    }
    fsyncSync(fd);
    const observed = fstatSync(fd);
    demand(observed.isFile() && observed.nlink === 1 && observed.uid === 0 &&
      observed.gid === 0 && (observed.mode & 0o7777) === 0o600 &&
      observed.size === bytes.length);
  } finally { closeSync(fd); }
  const directoryFd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  const after = root(directory);
  demand(before.dev === after.dev && before.ino === after.ino &&
    readPrivate(directory, filename).sha === hash(bytes));
  return hash(bytes);
}
function validateCheckpoint(c) {
  exact(c, ["version", "attemptId", "hostIdentitySha256", "manifestSha256",
    "sequence", "receiptSha256", "completed", "pending", "previousDigest"]);
  demand(c.version === 1 && /^[a-f0-9]{32}$/u.test(c.attemptId) &&
    [c.hostIdentitySha256, c.manifestSha256, c.receiptSha256, c.previousDigest]
      .every((value) => SHA.test(value)) && Array.isArray(c.completed) &&
    c.sequence === c.completed.length && c.sequence >= 0 && c.sequence <= ACTIONS.length);
  c.completed.forEach((entry, i) => {
    exact(entry, ["stage", "result", "snapshotSha256"]);
    demand(entry.stage === ACTIONS[i] && entry.result === "completed" &&
      SHA.test(entry.snapshotSha256));
  });
  if (c.pending) {
    exact(c.pending, ["stage", "sequence", "ownerApprovalSha256",
      "witnessReceiptSha256", "previousDigest"]);
    demand(c.sequence < ACTIONS.length && c.pending.sequence === c.sequence + 1 &&
      c.pending.stage === ACTIONS[c.sequence] &&
      [c.pending.ownerApprovalSha256, c.pending.witnessReceiptSha256,
        c.pending.previousDigest].every((value) => SHA.test(value)) &&
      c.pending.previousDigest === c.previousDigest);
  } else { demand(c.pending === null); }
}
function inspect(directory) {
  root(directory);
  const files = readdirSync(directory).sort();
  demand(files.length > 0 && files.length <= 1 + ACTIONS.length * 2 &&
    files.every((entry) => /^\d{8}\.(?:intent|complete)$/u.test(entry)) &&
    files.includes(name(0, "complete")));
  let previous = readPrivate(directory, name(0, "complete"));
  exact(previous.value, ["checkpoint"]);
  validateCheckpoint(previous.value.checkpoint);
  const first = previous.value.checkpoint;
  demand(first.sequence === 0 && first.pending === null && first.completed.length === 0 &&
    first.previousDigest === "0".repeat(64));
  let latest = first;
  let found = 1;
  let pending = false;
  for (let index = 1; index <= ACTIONS.length; index++) {
    const intentName = name(index, "intent");
    const completeName = name(index, "complete");
    const hasIntent = files.includes(intentName);
    const hasComplete = files.includes(completeName);
    demand(!hasComplete || hasIntent);
    if (!hasIntent) {
      demand(!files.some((entry) => Number(entry.slice(0, 8)) >= index));
      break;
    }
    found++;
    const intent = readPrivate(directory, intentName);
    exact(intent.value, ["priorCommitSha256", "checkpoint"]);
    const state = intent.value.checkpoint;
    validateCheckpoint(state);
    demand(intent.value.priorCommitSha256 === previous.sha &&
      state.pending?.stage === ACTIONS[index - 1] &&
      state.sequence === latest.sequence &&
      state.previousDigest === hash(JSON.stringify(latest)) &&
      JSON.stringify(state.completed) === JSON.stringify(latest.completed));
    if (!hasComplete) {
      demand(!files.some((entry) => Number(entry.slice(0, 8)) > index));
      latest = state;
      pending = true;
      break;
    }
    const complete = readPrivate(directory, completeName);
    exact(complete.value, ["intentSha256", "checkpoint"]);
    const committed = complete.value.checkpoint;
    validateCheckpoint(committed);
    demand(complete.value.intentSha256 === intent.sha &&
      committed.pending === null && committed.sequence === index &&
      committed.previousDigest === hash(JSON.stringify(state)) &&
      committed.receiptSha256 === state.pending.witnessReceiptSha256 &&
      JSON.stringify(committed.completed.slice(0, -1)) === JSON.stringify(latest.completed) &&
      committed.completed.at(-1)?.stage === ACTIONS[index - 1]);
    latest = committed;
    previous = complete;
    found++;
  }
  demand(files.length === found);
  return { checkpoint: latest, pending, previousSha: previous.sha };
}

export function createDisposableManualActivationJournal({ directory, checkpoint } = {}) {
  root(directory);
  demand(readdirSync(directory).length === 0);
  validateCheckpoint(checkpoint);
  demand(checkpoint.sequence === 0 && checkpoint.pending === null &&
    checkpoint.previousDigest === "0".repeat(64));
  durable(directory, name(0, "complete"), { checkpoint });
  return Object.freeze({ status: "DISPOSABLE_JOURNAL_CREATED_NONAUTHORIZING",
    deployAuthorized: false });
}
export function inspectDisposableManualActivationJournal({ directory } = {}) {
  const latest = inspect(directory);
  return Object.freeze({ status: latest.pending ?
    "DISPOSABLE_PENDING_OPERATOR_RECONCILIATION" : "DISPOSABLE_COMMITTED_NONAUTHORIZING",
  sequence: latest.checkpoint.sequence, deployAuthorized: false });
}
export function persistDisposableManualActivationIntent({ directory, checkpoint } = {}) {
  const history = inspect(directory);
  demand(!history.pending && history.checkpoint.sequence < ACTIONS.length);
  validateCheckpoint(checkpoint);
  demand(checkpoint.pending && checkpoint.sequence === history.checkpoint.sequence &&
    checkpoint.pending.stage === ACTIONS[checkpoint.sequence] &&
    checkpoint.previousDigest === hash(JSON.stringify(history.checkpoint)) &&
    JSON.stringify(checkpoint.completed) === JSON.stringify(history.checkpoint.completed));
  durable(directory, name(checkpoint.sequence + 1, "intent"), {
    priorCommitSha256: history.previousSha, checkpoint,
  });
  demand(inspect(directory).pending);
  return Object.freeze({ status: "DISPOSABLE_INTENT_DURABLE_NONAUTHORIZING",
    deployAuthorized: false });
}
export function persistDisposableManualActivationCompletion({ directory, checkpoint } = {}) {
  const history = inspect(directory);
  demand(history.pending);
  const pending = history.checkpoint;
  validateCheckpoint(checkpoint);
  demand(checkpoint.pending === null && checkpoint.sequence === pending.sequence + 1 &&
    checkpoint.previousDigest === hash(JSON.stringify(pending)) &&
    checkpoint.receiptSha256 === pending.pending.witnessReceiptSha256 &&
    JSON.stringify(checkpoint.completed.slice(0, -1)) === JSON.stringify(pending.completed) &&
    checkpoint.completed.at(-1)?.stage === pending.pending.stage);
  const intent = readPrivate(directory, name(checkpoint.sequence, "intent"));
  durable(directory, name(checkpoint.sequence, "complete"), {
    intentSha256: intent.sha, checkpoint,
  });
  demand(!inspect(directory).pending);
  return Object.freeze({ status: "DISPOSABLE_COMMIT_DURABLE_NONAUTHORIZING",
    deployAuthorized: false });
}
