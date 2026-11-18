import { spawnSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const STAGING_NODE_RANGE = Object.freeze({ minimum: "22.13.0", maximumExclusive: "23.0.0" });
export const STAGING_NPM_RANGE = Object.freeze({ minimum: "10.9.3", maximumExclusive: "11.0.0" });

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function parseVersion(value) {
  if (typeof value !== "string") return null;
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.exec(value.trim());
  return match ? match.slice(1).map(Number) : null;
}

function compareVersion(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function inRange(value, minimum, maximumExclusive) {
  const parsed = parseVersion(value);
  return parsed !== null &&
    compareVersion(parsed, parseVersion(minimum)) >= 0 &&
    compareVersion(parsed, parseVersion(maximumExclusive)) < 0;
}

function pinnedNpmCliPath() {
  const candidate = process.platform === "win32"
    ? path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")
    : realpathSync(path.join(path.dirname(process.execPath), "npm"));
  const stat = lstatSync(candidate, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) fail("NPM_VERSION_UNAVAILABLE");
  return candidate;
}

export function sanitizedNpmEnvironment(environment) {
  return Object.fromEntries(Object.entries(environment).filter(([name]) =>
    !/^(?:NODE_OPTIONS|NODE_PATH|npm_config_|PGSSLKEYLOGFILE$|SSLKEYLOGFILE$)/iu.test(name)));
}

export function verifyCleanNodeStartup({ execArgv, environment }) {
  if (execArgv.length !== 0 || Object.entries(environment).some(([name, value]) =>
    /^(?:NODE_OPTIONS|NODE_PATH)$/iu.test(name) && value)) {
    fail("UNTRUSTED_NODE_PRELOAD");
  }
  return true;
}

export function verifyStagingToolchain({ nodeVersion, npmVersion }) {
  if (!inRange(nodeVersion, STAGING_NODE_RANGE.minimum, STAGING_NODE_RANGE.maximumExclusive)) {
    fail("UNSUPPORTED_NODE_VERSION");
  }
  if (!inRange(npmVersion, STAGING_NPM_RANGE.minimum, STAGING_NPM_RANGE.maximumExclusive)) {
    fail("UNSUPPORTED_NPM_VERSION");
  }
  return true;
}

function runCli() {
  try {
    // A preload is already able to execute before this script starts. Fail
    // closed when one is present; the operator must start with a clean Node.
    verifyCleanNodeStartup({ execArgv: process.execArgv, environment: process.env });
    const npm = spawnSync(process.execPath, [pinnedNpmCliPath(), "--version"], {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 10_000,
      env: sanitizedNpmEnvironment(process.env),
      windowsHide: true
    });
    if (npm.error || npm.status !== 0 || typeof npm.stdout !== "string") fail("NPM_VERSION_UNAVAILABLE");
    verifyStagingToolchain({ nodeVersion: process.versions.node, npmVersion: npm.stdout.trim() });
    process.stdout.write("STAGING_TOOLCHAIN=PASS\n");
    return 0;
  } catch {
    process.stderr.write("BLOCK:STAGING_TOOLCHAIN\n");
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runCli();
}
