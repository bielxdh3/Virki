import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { classifyExactShaWorkflow, evaluateExactShaCi, evaluateExactShaRelease, verifyExactShaCi } from "./lib/production-ci.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8");
const codeqlWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "codeql.yml"), "utf8");
const reviewedSarif = {
  version: "2.1.0",
  runs: [{
    results: [{
      ruleId: "js/file-access-to-http",
      locations: [{ physicalLocation: { artifactLocation: { uri: "scripts/e2e/access-token.mts" } } }],
      partialFingerprints: {
        primaryLocationLineHash: "90e07734df8b1ab3:1",
        primaryLocationStartColumnFingerprint: "6"
      }
    }]
  }]
};
const fakeEvidence = (document = reviewedSarif) => () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-test-ghcr-evidence-"));
  const contents = path.join(directory, "contents");
  mkdirSync(contents);
  writeFileSync(path.join(contents, "javascript.sarif"), JSON.stringify(document));
  return { directory, contents };
};

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
  assert.equal(evaluateExactShaRelease([run({ conclusion: "failure" })], [run({ databaseId: 67890 })], revision).status, "FAIL");
  assert.equal(evaluateExactShaRelease([run()], [run({ conclusion: "failure" })], revision).status, "FAIL");
  assert.equal(evaluateExactShaRelease([run()], [run({ conclusion: "skipped" })], revision).status, "SKIPPED");
  assert.equal(evaluateExactShaRelease([run()], [run({ status: "in_progress", conclusion: null })], revision).status, "PENDING");
  assert.equal(evaluateExactShaRelease([run()], [], revision).status, "BLOCKED");
  assert.equal(classifyExactShaWorkflow([run({ event: "schedule" })], revision).status, "BLOCKED");
  assert.equal(evaluateExactShaRelease([run({ headSha: "f".repeat(40) })], [run()], revision).status, "BLOCKED");
  assert.equal(evaluateExactShaRelease([run()], [run({ headSha: "f".repeat(40) })], revision).status, "BLOCKED");
  assert.equal(evaluateExactShaRelease([run()], [run({ event: "pull_request" })], revision).status, "BLOCKED");
});

test("the GitHub CLI query is pinned to the exact workflow SHA and fails closed", () => {
  const calls = [];
  const result = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: ({ revision: observed, runId, kind }) => {
      assert.equal(observed, revision);
      assert.equal(runId, 67890);
      assert.equal(kind, "codeql");
      return fakeEvidence()();
    },
    execute: (command, args, options) => {
      calls.push({ command, args, options });
      const workflowName = args[args.indexOf("--workflow") + 1];
      return { status: 0, stdout: JSON.stringify([run({ databaseId: workflowName === "ci.yml" ? 12345 : 67890 })]) };
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.runId, 12345);
  assert.equal(result.codeqlRunId, 67890);
  assert.equal(result.sarifArtifactName, `virki-evidence:${revision}-67890-codeql`);
  assert.equal(result.sarifResults, 1);
  assert.equal(calls.length, 2);
  for (const call of calls.slice(0, 2)) {
    assert.equal(call.command, "gh");
    assert.equal(call.args[call.args.indexOf("--repo") + 1], "bielxdh3/Virki");
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

test("the exact CodeQL artifact must be retrievable and pass the reviewed SARIF policy", () => {
  const runsResponse = (workflowName) => JSON.stringify([run({ databaseId: workflowName === "ci.yml" ? 12345 : 67890 })]);
  const unavailable = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: () => { throw new Error("registry inaccessible"); },
    execute: (_command, args) => ({ status: 0, stdout: runsResponse(args[args.indexOf("--workflow") + 1]) })
  });
  assert.deepEqual(unavailable, {
    ok: false,
    status: "BLOCKED",
    lines: ["Exact-SHA private GHCR CodeQL SARIF evidence is missing, inaccessible, or invalid."]
  });

  const unreviewed = {
    version: "2.1.0",
    runs: [{
      results: [{
        ruleId: "js/redos",
        locations: [{ physicalLocation: { artifactLocation: { uri: "scripts/deploy-production.mjs" } } }]
      }]
    }]
  };
  const rejected = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: fakeEvidence(unreviewed),
    execute: (_command, args) => ({ status: 0, stdout: runsResponse(args[args.indexOf("--workflow") + 1]) })
  });
  assert.deepEqual(rejected, {
    ok: false,
    status: "FAIL",
    lines: ["Reviewed exact-SHA CodeQL SARIF policy did not pass."]
  });
});

test("private GHCR images publish only after exact main-push builds pass on both architectures", () => {
  assert.match(workflow, /production-images:[\s\S]*?if: github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/u);
  assert.match(workflow, /needs: \[validate, authenticated-e2e\][\s\S]*?arch: amd64[\s\S]*?runner: ubuntu-latest[\s\S]*?arch: arm64[\s\S]*?runner: ubuntu-24\.04-arm/u);
  assert.match(workflow, /--target production[\s\S]*?--target migrator/u);
  assert.match(workflow, /VIRKI_BUILD_REVISION=\$\{\{ github\.sha \}\}[\s\S]*?docker image inspect[\s\S]*?node scripts\/production-runtime-smoke\.mjs/u);
  const migratorSmoke = workflow.indexOf("name: Production migrator image smoke");
  const publishStep = workflow.indexOf("name: Publish tested private GHCR images and record exact manifest digests");
  assert.ok(migratorSmoke >= 0 && publishStep > migratorSmoke);
  assert.ok(workflow.includes("VIRKI_MIGRATOR_IMAGE: virki-migrator-ci:${{ github.sha }}"));
  assert.ok(workflow.includes("node scripts/production-migrator-smoke.mjs"));
  assert.ok(workflow.includes("packages: write"));
  const runtimePackage = workflow.indexOf("runtime=ghcr.io/bielxdh3/virki-runtime");
  const migratorPackage = workflow.indexOf("migrator=ghcr.io/bielxdh3/virki-migrator");
  assert.ok(runtimePackage >= 0 && migratorPackage > runtimePackage);
  const privacyCheck = workflow.indexOf('test "$visibility" = private');
  const registryLogin = workflow.indexOf("docker login ghcr.io");
  const registryPush = workflow.indexOf("docker push");
  const manifest = workflow.indexOf("virki-production-images.manifest");
  assert.ok(privacyCheck > publishStep && privacyCheck < registryLogin && registryLogin < registryPush && registryPush < manifest);
  assert.ok(workflow.includes("$ACCEPTED_SHA-$ACCEPTED_RUN_ID-images-$EXPECTED_ARCH"));
  assert.ok(!workflow.includes("docker save") && !workflow.includes("virki-production-images.tar.gz"));
  assert.ok(workflow.includes("Store exact-run image digests in private GHCR evidence"));
  assert.ok(!workflow.includes("actions/upload-artifact"));
  assert.doesNotMatch(workflow, /uses: actions\/(?:checkout|setup-node)@v/u);
});

test("authenticated E2E uses the real PostgreSQL role initializer and scoped disposable credentials", () => {
  const e2e = workflow.match(/authenticated-e2e:[\s\S]*?(?=\n\x20{2}[a-z-]+:|$)/u)?.[0] ?? "";
  assert.ok(e2e);
  assert.match(e2e, /Start least-privilege disposable PostgreSQL/u);
  assert.match(e2e, /VIRKI_E2E_ACCESS_DIAGNOSTICS: "true"/u);
  assert.match(e2e, /--health-cmd 'pg_isready -h 127\.0\.0\.1 -U virki_bootstrap -d virki_e2e_test'/u);
  assert.match(e2e, /infra\/postgres-init\/10-virki-database-roles\.sh[^\n]*:ro/u);
  assert.match(e2e, /scripts\/e2e\/20-virki-e2e-runtime-test-role\.sh[^\n]*:ro/u);
  assert.match(e2e, /--tmpfs \/var\/lib\/postgresql\/data:[^\n]*/u);
  assert.match(e2e, /VIRKI_E2E_DATABASE_URL=%s:\/\/%s:%s@127\.0\.0\.1:%s/u);
  assert.match(e2e, /DATABASE_URL=%s:\/\/%s:%s@127\.0\.0\.1:%s/u);
  assert.match(e2e, /MIGRATION_DATABASE_URL=%s:\/\/%s:%s@127\.0\.0\.1:%s/u);
  assert.match(e2e, /runtime_role=virki_runtime/u);
  assert.match(e2e, /migrator_role=virki_migrator/u);
  assert.match(e2e, /e2e_test_role=virki_runtime_test/u);
  assert.match(e2e, /Guard disposable E2E database target[\s\S]*?Apply committed Prisma migrations to disposable PostgreSQL/u);
  const cleanup = e2e.slice(e2e.indexOf("- name: Remove disposable PostgreSQL"));
  assert.match(cleanup, /if: always\(\)[\s\S]*?docker ps --all --quiet[\s\S]*?docker rm --force/u);
  assert.doesNotMatch(cleanup, /docker rm[^\n]*\|\| true/u);
  assert.doesNotMatch(e2e, /services:\r?\n\x20+postgres:/u);
});

test("CI and CodeQL run on stacked cdx pull requests while production builds remain main-push only", () => {
  for (const source of [workflow, codeqlWorkflow]) {
    assert.match(source, /pull_request:\r?\n\x20{4}branches:\r?\n\x20{6}- main\r?\n\x20{6}- ["']?cdx\/\*\*["']?/u);
    assert.match(source, /push:\r?\n\x20{4}branches:\r?\n\x20{6}- main/u);
  }
  assert.match(workflow, /production-images:[\s\S]*?if: github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/u);
});

test("CodeQL analyzes without Code Scanning upload and preserves SARIF as a pinned artifact", () => {
  assert.match(codeqlWorkflow, /uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1/u);
  assert.match(codeqlWorkflow, /uses: github\/codeql-action\/(?:init|analyze)@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4\.38\.2/u);
  assert.doesNotMatch(codeqlWorkflow, /uses: [^\s]+@v\d/u);
  assert.match(codeqlWorkflow, /queries: security-extended/u);
  assert.match(codeqlWorkflow, /output: codeql-results[\s\S]*?upload: never/u);
  assert.ok(codeqlWorkflow.includes("Store reviewed CodeQL SARIF in private GHCR evidence"));
  assert.ok(codeqlWorkflow.includes('docker push "$ref"'));
  assert.ok(codeqlWorkflow.includes("packages: write"));
  assert.ok(!codeqlWorkflow.includes("actions/upload-artifact"));
  assert.doesNotMatch(codeqlWorkflow, /security-events: write/u);
  assert.match(codeqlWorkflow, /contents: read/u);
});
