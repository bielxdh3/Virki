import { constants, lstatSync, openSync, closeSync, fstatSync, readFileSync,
  realpathSync } from "node:fs";
import path from "node:path";

// Unprivileged static DEV diagnostic only. NEVER run as root from a checkout.
// It neither imports target modules nor starts Node/Docker/SSH/PG or validates
// owner consent. In particular, this cannot substitute for a pre-Node OS gate.
const SURFACE = Object.freeze([
  "scripts/offline-manual-native-supervisor.mjs",
  "infra/offline/native-supervisor/owner-installed-manual-supervisor.mjs",
  "infra/offline/manual-native-activation-safety.mjs",
]);
const INVENTORY = "infra/offline/trusted-host-installer.mjs";
const fail = () => { throw new Error("DEV first-exec audit refused"); };
function inspectFile(repo, relative, afterLstat) {
  const filename = path.join(repo, ...relative.split("/"));
  let stat;
  try { stat = lstatSync(filename, { bigint: true }); }
  catch { fail(); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
      stat.size < 1n || stat.size > 2n * 1024n * 1024n) fail();
  // Only for adversarial, unprivileged tests. A real host authority must never
  // depend on this JS scanner or accept hooks from the candidate.
  afterLstat?.(filename);
  let fd;
  try {
    // NONBLOCK prevents a regular-file-to-FIFO rename race from hanging the
    // diagnostic. Verify the opened type again before reading any bytes.
    fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW |
      constants.O_NONBLOCK);
  } catch { fail(); }
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || stat.dev !== opened.dev || stat.ino !== opened.ino ||
        stat.size !== opened.size || stat.mtimeNs !== opened.mtimeNs ||
        stat.ctimeNs !== opened.ctimeNs) fail();
    const bytes = readFileSync(fd);
    const ended = fstatSync(fd, { bigint: true });
    const named = lstatSync(filename, { bigint: true });
    if (bytes.length !== Number(stat.size) ||
        [ended, named].some((s) => s.dev !== stat.dev || s.ino !== stat.ino ||
          s.size !== stat.size || s.mtimeNs !== stat.mtimeNs ||
          s.ctimeNs !== stat.ctimeNs)) fail();
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally { closeSync(fd); }
}

/**
 * Inspect the current *untrusted checkout* without loading its module graph.
 * `missingFromInstalledInventory` is a lower bound: the entire dynamic
 * transitive ESM closure, interpreter/loader/DSOs and host policy remain
 * unverified even when the returned arrays are empty.
 */
export function inspectNativeFirstExecSourceForDevOnly(request = {}, { afterLstat } = {}) {
  if (!request || Object.keys(request).length !== 1 ||
      typeof request.repositoryRoot !== "string" ||
      !path.isAbsolute(request.repositoryRoot) ||
      path.normalize(request.repositoryRoot) !== request.repositoryRoot ||
      (afterLstat !== undefined && typeof afterLstat !== "function")) fail();
  if (typeof process.getuid === "function") {
    if ([process.geteuid, process.getgid, process.getegid]
      .some((method) => typeof method !== "function")) fail();
    const [uid, euid, gid, egid] = [process.getuid(), process.geteuid(),
      process.getgid(), process.getegid()];
    // A real nonroot UID with an elevated effective identity is still an
    // attacker-controlled privileged process, and must never use this scanner.
    if (![uid, euid, gid, egid].every((id) => Number.isSafeInteger(id) && id > 0) ||
        uid !== euid || gid !== egid) fail();
  }
  const repo = path.resolve(request.repositoryRoot);
  if (realpathSync.native(repo) !== repo) fail();
  const files = SURFACE.map((name) => [name, inspectFile(repo, name, afterLstat)]);
  const source = inspectFile(repo, INVENTORY, afterLstat);
  const match = source.match(/AUDITED_VERIFIER_FILES\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/u);
  if (!match) fail();
  const list = [...match[1].matchAll(/"([a-zA-Z0-9_./-]+\.mjs)"/gu)]
    .map((item) => item[1]);
  if (list.length < 1 || list.length > 64 || new Set(list).size !== list.length ||
      list.some((name) => name.startsWith("/") || name.includes(".."))) fail();
  // Any static import initiates eager dependencies before the module's own
  // body can check its installed location and hashes. This diagnostic is not
  // a security-grade JS parser; it may conservatively report false positives.
  const eagerStaticImports = files.filter(([, text]) =>
    /^\s*import\s+(?!\()/mu.test(text)).map(([name]) => name);
  const missingFromInstalledInventory = SURFACE.filter((name) => !list.includes(name));
  return Object.freeze({
    status: "DEV_FIRST_EXEC_ROOT_LAUNCH_BLOCKED",
    eagerStaticImports: Object.freeze(eagerStaticImports),
    missingFromInstalledInventory: Object.freeze(missingFromInstalledInventory),
    nativeRootLaunchAuthorized: false, ownerInstalledClosureVerified: false,
    deployAuthorized: false,
  });
}
