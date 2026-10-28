import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync, writeSync } from "node:fs";
import path from "node:path";

// NON-AUTHORIZING recovery protocol boundary. It does not run a DB, connect to
// Docker, accept a PostgreSQL URL, sign approvals or claim Prisma migrations
// ran. The owner must independently provision a native no-port executor that
// verifies real pg_dump/pg_restore AND Prisma migrate deploy in one namespace.
const PREFIX = "VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL_V1\0";
const FILE = ".offline-pg-prisma-attempt";
const SHA40 = /^[a-f0-9]{40}$/u;
const SHA64 = /^[a-f0-9]{64}$/u;
const MIGRATION = /^[0-9]{8,14}_[a-z0-9_]+$/u;
const MAX_SQL = 2 * 1024 * 1024;
const MAX_MIGRATIONS = 256;
function refuse() { throw new Error("Disposable PostgreSQL/Prisma protocol refused."); }
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
function requireIt(ok) { if (!ok) refuse(); }

function canonicalFolder(dir) {
  requireIt(process.platform === "linux" && typeof process.getuid === "function" &&
    typeof dir === "string" && path.isAbsolute(dir) && path.normalize(dir) === dir &&
    dir !== path.parse(dir).root && realpathSync.native(dir) === dir);
  const stat = lstatSync(dir);
  requireIt(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o7777) === 0o700);
  return stat;
}
function readPinnedFile(file, maxSize) {
  const before = lstatSync(file);
  requireIt(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 &&
    before.size > 0 && before.size <= maxSize);
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd);
    requireIt(opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    const current = lstatSync(file);
    requireIt(bytes.length === opened.size && [after, current].every((s) =>
      s.dev === opened.dev && s.ino === opened.ino && s.size === opened.size &&
      s.mtimeMs === opened.mtimeMs && s.ctimeMs === opened.ctimeMs));
    return bytes;
  } finally { closeSync(fd); }
}

/** Inspects actual checked-in Prisma SQL bytes, never claims they were run. */
export function digestDisposablePrismaMigrations(migrationDirectory) {
  requireIt(process.platform === "linux" && path.isAbsolute(migrationDirectory) &&
    path.normalize(migrationDirectory) === migrationDirectory &&
    realpathSync.native(migrationDirectory) === migrationDirectory);
  const entries = readdirSync(migrationDirectory).sort();
  const names = entries.filter((name) => name !== "migration_lock.toml");
  requireIt(names.length > 0 && names.length <= MAX_MIGRATIONS && names.every((name) =>
    name === "0_init" || MIGRATION.test(name)) &&
    entries.length === names.length + 1);
  const manifest = [];
  const files = [["migration_lock.toml", path.join(migrationDirectory, "migration_lock.toml")]];
  for (const name of names) {
    const directory = path.join(migrationDirectory, name);
    const dirStat = lstatSync(directory);
    requireIt(dirStat.isDirectory() && !dirStat.isSymbolicLink() &&
      realpathSync.native(directory) === directory &&
      JSON.stringify(readdirSync(directory)) === JSON.stringify(["migration.sql"]));
    files.push([`${name}/migration.sql`, path.join(directory, "migration.sql")]);
  }
  for (const [name, file] of files) {
    const bytes = readPinnedFile(file, MAX_SQL);
    manifest.push({ name, bytes: bytes.length, sha256: hash(bytes) });
  }
  const encoded = Buffer.from(`${PREFIX}${JSON.stringify(manifest)}`);
  return Object.freeze({ migrationPlanSha256: hash(encoded), migrationCount: names.length,
    productionProof: false, prismaEngineExecuted: false, deployAuthorized: false });
}

/**
 * Persistent one-shot DEV checkpoint, deliberately no reset/retry endpoint.
 * All mutation is limited to a user-owned 0700 disposable directory. The
 * O_EXCL latch is fsynced before its payload; an interrupted write permanently
 * blocks further attempts pending independent manual reconciliation.
 */
export function reserveDisposablePgPrismaCheckpoint(request) {
  requireIt(request && typeof request === "object" && !Array.isArray(request) &&
    Object.keys(request).length === 3 &&
    ["directory", "sourceSha", "migrationPlanSha256"].every((k) => Object.hasOwn(request, k)));
  const { directory, sourceSha, migrationPlanSha256 } = request;
  requireIt(process.env.VIRKI_DISPOSABLE_PG_PRISMA_PROTOCOL === "1" &&
    SHA40.test(sourceSha) && SHA64.test(migrationPlanSha256));
  const expected = canonicalFolder(directory);
  const dirfd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let fd;
  try {
    const pinned = fstatSync(dirfd);
    requireIt(expected.dev === pinned.dev && expected.ino === pinned.ino);
    // Refuse preexisting foreign files, pending receipts, or old attempts.
    requireIt(readdirSync(`/proc/self/fd/${dirfd}`).length === 0);
    const file = `/proc/self/fd/${dirfd}/${FILE}`;
    fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    fsyncSync(dirfd);
    const bytes = Buffer.from(JSON.stringify({ version: 1, status: "manual_provisioning_required",
      sourceSha, migrationPlanSha256, nonce: randomBytes(16).toString("hex") }));
    let written = 0;
    while (written < bytes.length) {
      const part = writeSync(fd, bytes, written, bytes.length - written);
      requireIt(part > 0);
      written += part;
    }
    fsyncSync(fd);
    fsyncSync(dirfd);
    const verified = readPinnedFile(file, 1024);
    requireIt(verified.equals(bytes));
    return Object.freeze({ status: "CHECKPOINTED_NEEDS_INDEPENDENT_EXECUTOR",
      checkpointSha256: hash(bytes), productionProof: false,
      backupVerified: false, restoreVerified: false, prismaMigrationVerified: false,
      healthVerified: false, rollbackVerified: false, transferAuthorized: false,
      dockerLoadAuthorized: false, deployAuthorized: false });
  } catch {
    // A partially written latch is never removed automatically.
    refuse();
  } finally {
    if (fd !== undefined) closeSync(fd);
    closeSync(dirfd);
  }
}

/** Safe read-only diagnostics: no data, credentials, or host details. */
export function inspectDisposablePgPrismaCheckpoint(directory) {
  canonicalFolder(directory);
  requireIt(JSON.stringify(readdirSync(directory)) === JSON.stringify([FILE]));
  const file = path.join(directory, FILE);
  const stat = lstatSync(file);
  requireIt(stat.uid === process.getuid() && (stat.mode & 0o7777) === 0o600);
  const bytes = readPinnedFile(file, 1024);
  const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  requireIt(Object.keys(parsed).join(",") === "version,status,sourceSha,migrationPlanSha256,nonce" &&
    parsed.version === 1 && parsed.status === "manual_provisioning_required" &&
    SHA40.test(parsed.sourceSha) && SHA64.test(parsed.migrationPlanSha256) &&
    /^[a-f0-9]{32}$/u.test(parsed.nonce) && JSON.stringify(parsed) === bytes.toString("utf8"));
  return Object.freeze({ status: "UNRECONCILED_DISPOSABLE_ATTEMPT", checkpointSha256: hash(bytes),
    productionProof: false, deployAuthorized: false, transferAuthorized: false });
}
