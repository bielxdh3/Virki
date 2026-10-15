import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifyOwnerApprovedFirstAdminRescue } from "./deploy-production.mjs";

const revision = "a".repeat(40);
const ci = { runId: 12345, codeqlRunId: 12346 };
const pointer = {
  version: 1, source_commit: revision, approved_by: "bielxdh3",
  approved_at: "2026-10-15T15:00:00Z",
  ci_run: ci.runId, codeql_run: ci.codeqlRunId, approval_run: 12347
};
const approvalRun = {
  id: 12347, name: "Authorize Virki production release",
  event: "workflow_dispatch", status: "completed", conclusion: "success",
  head_branch: "main", head_sha: revision, actor: { login: "bielxdh3" }
};
function executeWith({ approved = pointer, run = approvalRun } = {}) {
  const calls = [];
  const execute = (command, args) => {
    calls.push([command, ...args]);
    assert.equal(command, "gh");
    if (args[1]?.includes("production.json")) {
      return { status: 0, stdout: Buffer.from(JSON.stringify(approved)).toString("base64") };
    }
    return { status: 0, stdout: JSON.stringify(run) };
  };
  return { execute, calls };
}

test("exceptional pre-ADMIN rescue requires owner-approved exact SHA, CI and CodeQL", () => {
  const { execute, calls } = executeWith();
  assert.doesNotThrow(() => verifyOwnerApprovedFirstAdminRescue({ revision, ci, execute }));
  assert.equal(calls.length, 2);
  assert.ok(calls[0].some((arg) => arg.includes("production.json?ref=production")));
  assert.ok(calls[1].some((arg) => arg.endsWith("/12347")));
});

test("exceptional rescue refuses missing or forged approvals before touching the server", () => {
  const cases = [
    { approved: { ...pointer, source_commit: "b".repeat(40) } },
    { approved: { ...pointer, ci_run: 999 } },
    { approved: { ...pointer, codeql_run: 999 } },
    { approved: { ...pointer, approved_by: "attacker" } },
    { run: { ...approvalRun, status: "in_progress" } },
    { run: { ...approvalRun, conclusion: "failure" } },
    { run: { ...approvalRun, event: "push" } },
    { run: { ...approvalRun, head_sha: "b".repeat(40) } },
    { run: { ...approvalRun, actor: { login: "attacker" } } }
  ];
  for (const fixture of cases) {
    const { execute } = executeWith(fixture);
    assert.throws(() => verifyOwnerApprovedFirstAdminRescue({ revision, ci, execute }),
      (error) => error.code === "COMMAND_FAILED");
  }
  assert.throws(() => verifyOwnerApprovedFirstAdminRescue({
    revision, ci, execute: () => ({ status: 1, stdout: "", stderr: "denied" })
  }), (error) => error.code === "COMMAND_FAILED");
});

test("rescue source stays separate from active revision, refuses schema drift and never starts a tunnel", () => {
  const script = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
  assert.match(script, /first_admin_rescue_predecessor='cbd065f2c560fdbc1f32c4c1c4804c352cf84494'/u);
  assert.match(script, /verify_first_admin_rescue_state\(\) \{/u);
  assert.match(script, /assert_backup_verified/u);
  assert.match(script, /assert_tunnel_stopped/u);
  assert.match(script, /assert_first_admin_rescue_rows/u);
  assert.match(script, /diff --brief --recursive -- "\$source_dir\/\$migration_directory"/u);
  assert.match(script, /cmp -- "\$source_dir\/\$migration_schema"/u);
  assert.match(script, /if \[\[ "\$preserve_live_markers" == true \]\]; then/u);
  assert.match(script, /install_source true/u);
  assert.match(script, /\[\[ -t 0 && -t 1 \]\] \|\| fail/u);
  const rescueAction = script.match(/^if \[\[ "\$action" == first-admin-rescue \]\]; then\n([\s\S]*?)^fi$/mu);
  assert.ok(rescueAction);
  assert.match(rescueAction[1], /compose --profile bootstrap run --rm --no-deps --interactive --tty/u);
  assert.match(rescueAction[1], /create_first_admin_rescue_snapshot\s*\n\s*compose --profile bootstrap/u);
  assert.doesNotMatch(rescueAction[1], /activate_source|maintenance_off|cloudflared|migrate|docker volume rm/u);
  assert.match(script, /compose exec -T postgres pg_restore --list < "\$partial"/u);
  assert.match(script, /"metadata" IS DISTINCT FROM '\{"source":"sessions-cleanup","deletedCount":0,"deletedRateLimitCount":0\}'::jsonb/u);
  assert.match(script, /WHERE schemaname = 'public' AND tablename NOT IN \('_prisma_migrations', 'AuditLog'\)/u);
});

test("fail-closed database guard rejects a failed PostgreSQL row validation", () => {
  const source = readFileSync(new URL("./production-server.sh", import.meta.url), "utf8");
  const guard = source.match(/^assert_first_admin_rescue_rows\(\) \{[\s\S]*?^\}/mu);
  assert.ok(guard);
  const shell = process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\bash.exe" : "bash";
  const harness = `set -euo pipefail
fail() { exit 12; }
database_query() { [[ "$RESULT" == success ]]; }
${guard[0]}
assert_first_admin_rescue_rows
`;
  const execute = (result) => spawnSync(shell, ["-c", harness], {
    encoding: "utf8", env: { ...process.env, RESULT: result }
  });
  const success = execute("success");
  assert.equal(success.error, undefined);
  assert.equal(success.status, 0);
  const blocked = execute("blocked");
  assert.equal(blocked.error, undefined);
  assert.equal(blocked.status, 12);
});
