// Only inside the owner-checked, networkless disposable Node22 runner.
// The Windows orchestrator waits for PostgreSQL to report a REAL blocked
// schema-engine DDL before invoking `kill`; a successful exit from `kill`
// proves the exact Prisma schema engine (not an unrelated test child) got SIGKILL.
import { spawnSync } from "node:child_process";
import {
  constants, existsSync, openSync, closeSync, readFileSync, readdirSync, writeFileSync,
} from "node:fs";
import { INTERRUPT_TIMING } from "../../lib/offline-prisma-native-ddl-observation.mjs";

const PRISMA = "/usr/local/lib/node_modules/prisma/build/index.js";
const ENGINE = "/usr/local/lib/node_modules/@prisma/engines/schema-engine-debian-openssl-3.0.x";
const SCHEMA = "/tmp/virki-prisma/schema.prisma";
const EXIT_MARKER = "/tmp/virki-prisma-engine-exit.json";
const DATABASE_URL = "postgresql://postgres@localhost:5432/virki_clone?host=/var/run/postgresql";
function refuse() { throw new Error("Disposable real Prisma engine interrupt refused."); }
function readProc(pid, filename) {
  try { return readFileSync(`/proc/${pid}/${filename}`, "utf8"); } catch { return ""; }
}
function cmd(pid) { return readProc(pid, "cmdline").split("\0").filter(Boolean); }
function expectedEngine(pid) {
  const argv = cmd(pid);
  if (argv[0] !== ENGINE) return false;
  const status = readProc(pid, "status");
  if (!/^Uid:\s+70\s+70\s+70\s+70\s*$/mu.test(status)) return false;
  const parent = /^PPid:\s+(\d+)\s*$/mu.exec(status)?.[1];
  if (!parent) return false;
  const parentArgs = cmd(parent);
  return parentArgs.includes(PRISMA) && parentArgs.includes("migrate") &&
    parentArgs.includes("deploy") && parentArgs.includes(SCHEMA);
}

const mode = process.argv[2];
if (process.platform !== "linux" || typeof process.getuid !== "function" ||
    process.getuid() !== 70 || !process.env.VIRKI_PRISMA_NATIVE_DISPOSABLE ||
    process.env.DATABASE_URL || process.env.PGHOSTADDR || process.env.PGHOST ||
    process.argv.length !== 3 || !["run", "kill", "result", "probe"].includes(mode)) refuse();
if (mode === "run") {
  const command = [PRISMA, "migrate", "deploy", "--schema", SCHEMA];
  const result = spawnSync(process.execPath, command, {
    shell: false, timeout: INTERRUPT_TIMING.engineTimeoutMs,
    maxBuffer: 32768, encoding: "utf8",
    env: { ...process.env, DATABASE_URL },
  });
  const evidence = { status: result.status, signal: result.signal,
    error: result.error?.code ?? null };
  const fd = openSync(EXIT_MARKER, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try { writeFileSync(fd, JSON.stringify(evidence), "utf8"); } finally { closeSync(fd); }
  if (result.error || result.status === 0) refuse();
  process.stdout.write("REAL_PRISMA_CLI_FAILED_AFTER_ENGINE_SIGKILL\n");
} else if (mode === "probe") {
  const found = readdirSync("/proc").filter((p) => /^\d+$/u.test(p) && expectedEngine(p));
  if (found.length > 1) refuse();
  if (found.length === 1) process.stdout.write("EXACT_SCHEMA_ENGINE_UID_PPID_VERIFIED\n");
  else if (existsSync(EXIT_MARKER)) process.stdout.write("PRISMA_CLI_EXITED_BEFORE_OBSERVATION\n");
  else process.stdout.write("ENGINE_NOT_YET_OBSERVED\n");
} else if (mode === "kill") {
  const found = readdirSync("/proc").filter((p) => /^\d+$/u.test(p) && expectedEngine(p));
  if (found.length !== 1) refuse();
  process.kill(Number(found[0]), "SIGKILL");
  process.stdout.write("EXACT_PRISMA_SCHEMA_ENGINE_SIGKILL_SENT\n");
} else {
  let evidence;
  try { evidence = JSON.parse(readFileSync(EXIT_MARKER, "utf8")); } catch { refuse(); }
  if (evidence.error !== null || !Number.isInteger(evidence.status) ||
      evidence.status === 0 || evidence.signal !== null) refuse();
  process.stdout.write("REAL_PRISMA_CLI_NONZERO_AFTER_SIGKILL\n");
}
