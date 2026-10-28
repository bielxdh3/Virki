import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";

// Independent verifier of REAL committed Prisma migration.sql bytes. This is
// deliberately separate from Prisma CLI's _prisma_migrations implementation;
// both MUST agree before any developer fixture may claim migration health.
const NAME = /^(?:0_init|[0-9]{8,14}_[a-z0-9_]+)$/u;
const SHA = /^[a-f0-9]{64}$/u;
// Independent exact-owner-requested Git source anchor, derived via `git show`
// from immutable stage2 commit 16dd2a5e3c05924cb8e8d7158f2fb9ad00c97d1d
// (NOT from the mutable working tree). Digest values are not trust keys or
// deployment authority. This deliberately rejects all new/modified migrations
// until their hashes are reviewed at a separately authorized source SHA.
export const STAGE2_SOURCE_SHA = "16dd2a5e3c05924cb8e8d7158f2fb9ad00c97d1d";
const COMMITTED = Object.freeze({
  "0_init": "f25ea2e86139bc2937091bad59426e120d793a72b11929380deaadf67a372bf6",
  "20261001000000_security_polish": "a3af0aadc1e00effc7202583724b73f9958a73ec27126f9a82ddf46d06f23832",
  "20261006120000_audit_log_role_boundaries": "a76095e32948e25fe8cd8b15d9f79b43d04af8e6d402e73f17bdb6f1980a8804",
  "20261006130000_email_outbox_processing_lease": "18c4a3ff985df019a3ce3ca2dd07a161374a71e40e26b27fcda6feb0f029f87b",
  "20261014120000_account_invitation_email_kind": "817a67227a912b3edef0b2d26ba637f745a9b857dc4ac299c37fe6bc0cd309c7",
  "20261017120000_audit_actor_immutable": "7d79aa0a16cc78d2f3ed5b6250c11eabd6d6c12280231a510b1c30dcf083f350",
  "20261017150000_structured_audit_envelope": "72551d0d99bd68345e1cfebf5896eb2deed2d646622608f04028b6d190d765cb",
  "20261017160000_recovery_request_purpose": "71b0e4f3c32dfc7fecb67a5c940810dfd6ad656023dbb0f7a3f81ffc5ea0e3bb",
  "20261019120000_runtime_audit_write_boundary": "c3b2f068af0be8c8a32189ef825b43e250160092e6c50b1f138f6e94bc9f3392",
  "20261020120000_elevation_credential_key_version": "b7c835021c27ae64097959a8200e6027527c1572c8e650a16825525c965c386b",
  "20261025190000_user_passkeys": "bd989817794411877c789405d9ee4876b0e4722b2c49cc715427a2a07d720a34",
});
const COMMITTED_LOCK = "99836963713b4f5b269ad49af0ed3d7b0b2e336115c2f92dc9ac683d139d0900";
function refuse() { throw new Error("Disposable Prisma migration source/history proof refused."); }
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

function readPinned(file) {
  const entry = lstatSync(file);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 ||
      entry.size < 1 || entry.size > 2 * 1024 * 1024) refuse();
  const bytes = readFileSync(file);
  const after = lstatSync(file);
  if (bytes.length !== entry.size || entry.ino !== after.ino || entry.dev !== after.dev ||
      entry.mtimeMs !== after.mtimeMs || entry.ctimeMs !== after.ctimeMs) refuse();
  return bytes;
}

export function verifyDisposablePrismaMigrations(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory) ||
    realpathSync.native(directory) !== path.resolve(directory)) refuse();
  const base = lstatSync(directory);
  if (!base.isDirectory() || base.isSymbolicLink()) refuse();
  const entries = readdirSync(directory).sort();
  const names = entries.filter((v) => v !== "migration_lock.toml");
  if (names.length < 1 || names.length > 128 || names[0] !== "0_init" ||
      entries.length !== names.length + 1 || !names.every((v) => NAME.test(v))) refuse();
  const lock = readPinned(path.join(directory, "migration_lock.toml")).toString("utf8");
  const settings = lock.split(/\r?\n/u).map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  if (settings.length !== 1 || !/^provider\s*=\s*"postgresql"$/u.test(settings[0])) refuse();
  const proof = [];
  for (const name of names) {
    const folder = path.join(directory, name);
    const stat = lstatSync(folder);
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
      realpathSync.native(folder) !== folder ||
      JSON.stringify(readdirSync(folder)) !== '["migration.sql"]') refuse();
    proof.push(Object.freeze({ name, checksum: digest(readPinned(path.join(folder, "migration.sql"))) }));
  }
  return Object.freeze(proof);
}

export function verifyCommittedStage2PrismaMigrations(directory) {
  const verified = verifyDisposablePrismaMigrations(directory);
  // Git for Windows core.autocrlf may checkout CRLF while the immutable
  // stage2 Git blobs use LF. Anchor to exact committed LF bytes, then return
  // raw *checkout* hashes separately for Prisma's DB history checks.
  const commitDigest = (bytes) => {
    const value = bytes.toString("utf8");
    if (/\r(?!\n)/u.test(value)) refuse();
    return digest(Buffer.from(value.replace(/\r\n/gu, "\n"), "utf8"));
  };
  if (verified.length !== Object.keys(COMMITTED).length ||
      verified.some((item) => COMMITTED[item.name] !== commitDigest(readPinned(path.join(directory, item.name, "migration.sql")))) ||
      commitDigest(readPinned(path.join(directory, "migration_lock.toml"))) !== COMMITTED_LOCK) refuse();
  return verified;
}

export function verifyDisposablePrismaDatabaseHistory(proof, text) {
  if (!Array.isArray(proof) || proof.length < 1 || proof.length > 128 ||
      typeof text !== "string" || text.length > 8192) refuse();
  const lines = text.trim().split("\n");
  if (lines.length !== proof.length) refuse();
  for (let i = 0; i < proof.length; i++) {
    const row = proof[i];
    if (!NAME.test(row?.name ?? "") || !SHA.test(row?.checksum ?? "") ||
        lines[i] !== `${row.name}|${row.checksum}`) refuse();
  }
  return Object.freeze({ migrationCount: proof.length, migrationHistoryVerified: true,
    productionProof: false, deployAuthorized: false });
}
