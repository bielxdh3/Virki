import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { classifyExactShaWorkflow, evaluateExactShaCi, evaluateExactShaRelease, verifyExactShaCi } from "./lib/production-ci.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8");
const codeqlWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "codeql.yml"), "utf8");
const run = (overrides = {}) => ({
  databaseId: 12345,
  headSha: revision,
  status: "completed",
  conclusion: "success",
  event: "push",
  headBranch: "main",
  createdAt: "2026-10-04T12:00:00Z",
  ...overrides,
});

test("accepts only the latest successful main push for the exact SHA", () => {
  assert.deepEqual(evaluateExactShaCi([run()], revision), { ok: true });
  assert.deepEqual(evaluateExactShaCi([run({ headSha: revision.toUpperCase() })], revision), { ok: true });
  assert.deepEqual(evaluateExactShaCi([run({ status: "in_progress" })], revision), { ok: false });
  assert.deepEqual(evaluateExactShaCi([run({ conclusion: "failure" })], revision), { ok: false });
  assert.deepEqual(evaluateExactShaCi([run({ event: "pull_request" })], revision), { ok: false });
  assert.deepEqual(evaluateExactShaCi([run({ headBranch: "feature" })], revision), { ok: false });
  assert.deepEqual(evaluateExactShaCi([run({ headSha: "f".repeat(40) })], revision), { ok: false });
});

test("release policy independently classifies exact-SHA CI and CodeQL outcomes", () => {
  assert.deepEqual(evaluateExactShaRelease([run()], [run({ databaseId: 67890 })], revision), {
    status: "PASS",
    ci: { status: "PASS", runId: 12345 },
    codeql: { status: "PASS", runId: 67890 },
  });
  assert.equal(evaluateExactShaRelease([run()], [run({ conclusion: "failure" })], revision).status, "FAIL");
  assert.equal(evaluateExactShaRelease([run()], [run({ conclusion: "skipped" })], revision).status, "SKIPPED");
  assert.equal(evaluateExactShaRelease([run()], [run({ status: "in_progress", conclusion: null })], revision).status, "PENDING");
  assert.equal(evaluateExactShaRelease([run()], [], revision).status, "BLOCKED");
  assert.equal(classifyExactShaWorkflow([run({ event: "schedule" })], revision).status, "BLOCKED");
  assert.equal(evaluateExactShaRelease([run({ headSha: "f".repeat(40) })], [run()], revision).status, "BLOCKED");
});

test("the GitHub CLI query is pinned to the exact workflow SHA and fails closed", () => {
  const calls = [];
  const result = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    execute: (command, args, options) => {
      calls.push({ command, args, options });
      const workflowName = args[args.indexOf("--workflow") + 1];
      return { status: 0, stdout: JSON.stringify([run({ databaseId: workflowName === "ci.yml" ? 12345 : 67890 })]) };
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.runId, 12345);
  assert.equal(result.codeqlRunId, 67890);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.command, "gh");
    assert.equal(call.args[call.args.indexOf("--repo") + 1], "bielxdh3/BielOS");
    assert.ok(call.args.includes("--commit"));
    assert.ok(call.args.includes(revision));
    assert.ok(call.args.includes("databaseId,headSha,status,conclusion,event,headBranch,createdAt"));
    assert.equal(call.options.cwd, "/repo");
  }
  assert.ok(calls.some(({ args }) => args.includes("ci.yml")));
  assert.ok(calls.some(({ args }) => args.includes("codeql.yml")));

  const unavailable = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    execute: () => ({ status: 1, stdout: "" }),
  });
  assert.equal(unavailable.ok, false);

  const missingRunId = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    execute: (_command, args) => ({ status: 0, stdout: JSON.stringify([run({ databaseId: args.includes("ci.yml") ? null : 67890 })]) }),
  });
  assert.equal(missingRunId.ok, false);
  assert.equal(missingRunId.status, "BLOCKED");
});

test("production images are uploaded only after exact main-push builds pass on both supported architectures", () => {
  assert.match(workflow, /production-images:[\s\S]*?if: github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/u);
  assert.match(workflow, /needs: \[validate, authenticated-e2e\][\s\S]*?arch: amd64[\s\S]*?runner: ubuntu-latest[\s\S]*?arch: arm64[\s\S]*?runner: ubuntu-24\.04-arm/u);
  assert.match(workflow, /--target production[\s\S]*?--target migrator/u);
  assert.match(workflow, /BIELOS_BUILD_REVISION=\$\{\{ github\.sha \}\}[\s\S]*?docker image inspect[\s\S]*?node scripts\/production-runtime-smoke\.mjs/u);
  assert.match(workflow, /Production migrator image smoke[\s\S]*?BIELOS_MIGRATOR_IMAGE: bielos-migrator-ci:\$\{\{ github\.sha \}\}[\s\S]*?node scripts\/production-migrator-smoke\.mjs[\s\S]*?Save tested production images/u);
  assert.match(workflow, /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7\.0\.1/u);
  assert.match(workflow, /retention-days: 14/u);
  assert.doesNotMatch(workflow, /uses: actions\/(?:checkout|setup-node)@v/u);
});

test("CodeQL workflow pins supported actions to immutable verified commits and keeps scan permissions narrow", () => {
  assert.match(codeqlWorkflow, /uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1/u);
  assert.match(codeqlWorkflow, /uses: github\/codeql-action\/(?:init|analyze)@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4\.38\.2/u);
  assert.doesNotMatch(codeqlWorkflow, /uses: [^\s]+@v\d/u);
  assert.match(codeqlWorkflow, /security-events: write/u);
  assert.match(codeqlWorkflow, /contents: read/u);
});
