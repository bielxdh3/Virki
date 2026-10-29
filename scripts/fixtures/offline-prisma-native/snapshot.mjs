import { createHash } from "node:crypto";
import {
  chmodSync, constants, lstatSync, mkdirSync, openSync, readFileSync,
  writeFileSync, closeSync,
} from "node:fs";
import path from "node:path";
import { verifyCommittedStage2PrismaMigrations } from "../../lib/offline-prisma-native-source.mjs";

// Disposable pinned Node runner only; build a privately held snapshot of
// the EXACT stage2-authorized SQL bytes before invoking the real Prisma CLI.
// No mutable source-tree file can be swapped into the Prisma migration engine
// after this point. The snapshot resides solely in container-private tmpfs.
function refuse() { throw new Error("Disposable Prisma committed migration snapshot refused."); }
const sha = (b) => createHash("sha256").update(b).digest("hex");
const schemaSha = "370f3a62d7343c32906abfc301ae3358ba817d211425a786399184da1ac19b8f";
const source = "/workspace/packages/database/prisma";
const target = "/tmp/virki-prisma";
function copyPinned(from, to) {
  const stat = lstatSync(from);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 2 * 1024 * 1024) refuse();
  const bytes = readFileSync(from);
  if (bytes.length !== stat.size) refuse();
  const fd = openSync(to, constants.O_EXCL | constants.O_CREAT | constants.O_WRONLY, 0o600);
  try { writeFileSync(fd, bytes); } finally { closeSync(fd); }
  if (!readFileSync(to).equals(bytes)) refuse();
  chmodSync(to, 0o400);
  return bytes;
}
if (process.platform !== "linux" || process.env.VIRKI_PRISMA_NATIVE_DISPOSABLE !== "1" ||
    typeof process.getuid !== "function" || process.getuid() !== 1000 ||
    process.env.DATABASE_URL || process.env.PGHOST || process.env.PGHOSTADDR) refuse();
const sourcePlan = verifyCommittedStage2PrismaMigrations(path.join(source, "migrations"));
mkdirSync(target, { mode: 0o700 });
mkdirSync(path.join(target, "migrations"), { mode: 0o700 });
const snapshotSchema = copyPinned(path.join(source, "schema.prisma"), path.join(target, "schema.prisma"));
const norm = Buffer.from(snapshotSchema.toString("utf8").replace(/\r\n/gu, "\n"), "utf8");
if (sha(norm) !== schemaSha) refuse();
copyPinned(path.join(source, "migrations", "migration_lock.toml"),
  path.join(target, "migrations", "migration_lock.toml"));
for (const item of sourcePlan) {
  const dir = path.join(target, "migrations", item.name);
  mkdirSync(dir, { mode: 0o700 });
  const bytes = copyPinned(path.join(source, "migrations", item.name, "migration.sql"),
    path.join(dir, "migration.sql"));
  if (sha(bytes) !== item.checksum) refuse();
  chmodSync(dir, 0o500);
}
if (JSON.stringify(verifyCommittedStage2PrismaMigrations(path.join(target, "migrations"))) !==
    JSON.stringify(sourcePlan)) refuse();
chmodSync(path.join(target, "migrations"), 0o500);
chmodSync(target, 0o500);
process.stdout.write("SNAPSHOT_READY\n");
