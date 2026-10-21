// Disposable regression harness for functions copied byte-for-byte from the
// checked-in production Bash runner. All Docker/Compose functions are stubs.
// It must never execute production-server.sh as a whole or use SSH.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const productionSource = readFileSync(fileURLToPath(new URL("../production-server.sh", import.meta.url)), "utf8");
const sha = /^[a-f0-9]{40}$/u;
const exposedFunctions = new Set([
  "cleanup_failed_backup_verification", "create_verified_backup", "cleanup_deploy_staging",
  "maintenance_on", "stop_routed_services", "apply_production_migrations",
  "resume_services", "activate_source",
]);

export function disposableReleaseFixture(t, predecessor, candidate) {
  assert.match(predecessor, sha);
  assert.match(candidate, sha);
  assert.notEqual(predecessor, candidate);
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-disposable-release-rehearsal-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const name of ["backups", ".deploy-tmp", "releases", `releases/${predecessor}`,
    `releases/${candidate}`, `releases/${candidate}/infra`,
    `releases/${candidate}/infra/postgres-init`]) {
    mkdirSync(path.join(root, name), { recursive: true, mode: 0o700 });
  }
  symlinkSync(`releases/${predecessor}`, path.join(root, "current"));
  writeFileSync(path.join(root, ".virki-deploy-revision"), `${predecessor}\n`, { mode: 0o600 });
  writeFileSync(path.join(root, "releases", predecessor, "identity.txt"), "original identity\n");
  writeFileSync(path.join(root, "backups", "prior.dump"), "original backup\n");
  writeFileSync(path.join(root, "releases", candidate, "infra", "postgres-init", "10-virki-database-roles.sh"), "# disposable role script\n");
  return { root, predecessor, candidate };
}

function functionFromProduction(name) {
  assert.ok(exposedFunctions.has(name), `Disallowed rehearsal function: ${name}`);
  const match = productionSource.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, "mu"));
  assert.ok(match, `Missing production function: ${name}`);
  return match[0];
}

const stubs = String.raw`
fail() { printf '%s\n' "$1" >&2; exit 1; }
compose() {
  printf 'compose %s\n' "$*" >> "$operations_log"
  if [[ "$1" == ps && "$2" == -q && "$3" == postgres ]]; then
    printf 'disposable-postgres\n'
    return 0
  fi
  if [[ "$1" == exec && "$2" == -T && "$3" == postgres && "$4" == sh && "$5" == -lc ]]; then
    printf 'disposable-pgdump-data\n'
    return 0
  fi
  if [[ "$failure" == production-migration && "$1" == --profile && "$2" == migration ]]; then
    printf 'simulated production migration failure\n' >&2
    return 71
  fi
  return 0
}
docker() {
  printf 'docker %s\n' "$*" >> "$operations_log"
  if [[ "$1" == exec && "$*" == *pg_restore* ]]; then cat >/dev/null; fi
  return 0
}
create_clone_storage() { :; }
wait_for_clone() { :; }
run_clone_migrations() {
  if [[ "$failure" == clone-migration ]]; then
    printf 'simulated clone migration failure\n' >&2
    return 72
  fi
}
cleanup_clone() { rm -f -- "$2"; }
verify_clone_cleanup() { [[ ! -e "$2" ]]; }
identity_snapshot() { printf 'same-identity\n'; }
recovery_snapshot() { printf 'same-recovery\n'; }
assert_backup_verified() { [[ -f "$verification_path" ]]; }
normalize_migration_history() { :; }
run_migration_status() {
  if [[ "$failure" == migration-status ]]; then
    printf 'simulated migration status failure\n' >&2
    return 73
  fi
}
verify_migration_schema() { :; }
verify_first_install_role_contract() { :; }
assert_revisions() { :; }
assert_loopback_ports() { :; }
assert_health() {
  if [[ "$failure" == health ]]; then
    printf 'simulated health failure\n' >&2
    return 74
  fi
}
assert_tunnel_running() { :; }
`;

/**
 * Invokes only specifically named Bash functions from production-server.sh in
 * a fresh local /tmp fixture. All service effects are stubbed and logged.
 */
export function runProductionShellRehearsal(f, names, expression, options = {}) {
  const { root, candidate } = f;
  assert.ok(path.basename(root).startsWith("virki-disposable-release-rehearsal-"));
  assert.ok(root.startsWith(os.tmpdir() + path.sep));
  assert.ok(!root.includes("\n") && !root.includes("'"));
  assert.ok(Array.isArray(names) && names.every((name) => exposedFunctions.has(name)));
  assert.ok(/^[a-zA-Z0-9_; '\-]+$/u.test(expression), "Only constant rehearsal commands allowed");
  const failure = options.failure ?? "none";
  assert.ok(["none", "clone-migration", "production-migration", "health", "migration-status"].includes(failure));
  const revision = options.revisions ?? candidate;
  assert.match(revision, sha);
  const operationsLog = path.join(root, "operations.log");
  writeFileSync(operationsLog, "");
  const program = `#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
root="$1"
revision="$2"
failure="$3"
readonly operations_log="$4"
readonly backup_dir="$root/backups"
readonly temp_dir="$root/.deploy-tmp"
readonly release_dir="$root/releases"
readonly current_link="$root/current"
readonly source_dir="$root/releases/$revision"
readonly verification_path="$root/.virki-migration-verification"
readonly maintenance_path="$root/.virki-maintenance"
readonly application_services=(public-site hub oidc-issuer session-cleanup email-worker)
${stubs}
${names.map(functionFromProduction).join("\n\n")}
${expression}
`;
  const result = spawnSync("bash", ["-s", "--", root, revision, failure, operationsLog], {
    input: program, encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024,
    env: { ...process.env },
  });
  assert.equal(result.error, undefined, String(result.error));
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    operations: existsSync(operationsLog) ? readFileSync(operationsLog, "utf8") : "",
    files: (directory) => readdirSync(path.join(root, directory)).sort(),
  };
}
