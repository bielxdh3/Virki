// Diagnostic-only verification of the real Prisma CLI after exact schema-engine
// SIGKILL. Every predicate is fail closed; a CLI zero exit is NEVER recovery proof.
import { createHash } from "node:crypto";

function refuse() { throw new Error("Disposable Prisma postkill evidence refused."); }
const safeLine = /^(?:Prisma schema loaded from \/tmp\/virki-prisma\/schema\.prisma|Error: P[0-9]{4}|All migrations have been successfully applied\.|Applying migration `(?:0_init|[0-9]{14}_[a-z0-9_]+)`|[0-9]{1,3} migrations found in prisma\/migrations)$/u;

export function summarizePrismaPostkillOutput(output) {
  if (typeof output !== "string" || Buffer.byteLength(output) > 32768) refuse();
  const safeLines = output.split(/\r?\n/u).filter((line) => safeLine.test(line)).slice(0, 6);
  return Object.freeze({ byteLength: Buffer.byteLength(output),
    sha256: createHash("sha256").update(output).digest("hex"), safeLines });
}

export function classifyPrismaPostkillExit(marker) {
  if (!marker || typeof marker !== "object" || Array.isArray(marker) ||
      !["status", "signal", "error"].every((key) => Object.hasOwn(marker, key)) ||
      Object.keys(marker).some((key) => !["status", "signal", "error", "stdout", "stderr"].includes(key)) ||
      !Number.isSafeInteger(marker.status) || marker.status < 0 || marker.status > 255 ||
      marker.signal !== null || marker.error !== null) refuse();
  return Object.freeze({ zeroExitAnomaly: marker.status === 0, cliFailed: marker.status > 0 });
}

export function assertPrismaPostkillDatabaseState(state) {
  // Exact tuple: pending, finished, rolled_back, launchUrl column. Executed
  // on the disposable clone both before and after releasing the owned blocker.
  if (state !== "1|0|0|0") refuse();
  return true;
}
