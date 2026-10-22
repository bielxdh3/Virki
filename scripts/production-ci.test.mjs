import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { codeqlEvidenceRunDisplayTitle, selectCodeqlEvidenceRun } from "./lib/codeql-evidence-selection.mjs";
import { classifyExactShaWorkflow, evaluateExactShaCi, evaluateExactShaRelease, verifyExactShaCi } from "./lib/production-ci.mjs";

const revision = "0123456789abcdef0123456789abcdef01234567";
const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const workflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8");
const packageScripts = JSON.parse(readFileSync(path.join(repositoryRoot, "package.json"), "utf8")).scripts;
const isolatedRunner = readFileSync(path.join(repositoryRoot, "scripts", "e2e", "run-isolated-linux-docker.ps1"), "utf8");
const codeqlWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "codeql.yml"), "utf8");
const codeqlEvidenceWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "codeql-evidence.yml"), "utf8");
const approvalWorkflow = readFileSync(path.join(repositoryRoot, ".github", "workflows", "approve-production.yml"), "utf8");

function publicationNeedsAreSafe(source) {
  // Parse the job-level portion of this workflow instead of matching a
  // "needs:" substring that might belong to another job or a comment.
  const lines = source.split(/\r?\n/u);
  const jobsStart = lines.findIndex((line) => line === "jobs:");
  if (jobsStart < 0 || lines.filter((line) => line === "jobs:").length !== 1) return false;
  const jobs = new Map();
  let current = null;
  for (const line of lines.slice(jobsStart + 1)) {
    if (line.length > 0 && !line.startsWith(" ") && !line.startsWith("#")) break;
    const match = /^ {2}([a-z][a-z0-9-]*):\s*$/u.exec(line);
    if (match) {
      if (jobs.has(match[1])) return false;
      current = match[1];
      jobs.set(current, []);
    } else if (current !== null) {
      jobs.get(current).push(line);
    }
  }
  const publisher = jobs.get("production-images");
  if (!publisher) return false;
  const needsLines = publisher.filter((line) => /^ {4}needs:/u.test(line));
  const ifLines = publisher.filter((line) => /^ {4}if:/u.test(line));
  if (needsLines.length !== 1 || ifLines.length !== 1) return false;
  if (ifLines[0].trim() !== "if: github.event_name == 'push' && github.ref == 'refs/heads/main'") return false;
  // A custom always() or success() expression here would override the
  // GitHub Actions default success() gating on every needs dependency.
  const needs = /^ {4}needs: \[([a-z0-9, -]+)\]\s*$/u.exec(needsLines[0]);
  if (!needs) return false;
  const members = needs[1].split(",").map((name) => name.trim());
  if (members.some((name) => !name) || new Set(members).size !== members.length) return false;
  for (const dependency of ["validate", "authenticated-e2e", "production-audit", "tooling-policy"]) {
    if (!members.includes(dependency) || !jobs.has(dependency)) return false;
  }
  for (const [jobName, auditScript] of [
    ["production-audit", "node scripts/production-dependency-audit.mjs"],
    ["tooling-policy", "node scripts/tooling-audit-policy.mjs"]
  ]) {
    const job = jobs.get(jobName);
    if (job.some((line) => /^ {4}(if:|continue-on-error:)/u.test(line)) ||
        job.some((line) => /^\s+continue-on-error:\s*true\s*$/u.test(line)) ||
        !job.some((line) => line.trim() === "run: " + auditScript)) return false;
  }
  return !publisher.some((line) => /^ {4}continue-on-error:/u.test(line));
}
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
const evidencePublisherRun = (overrides = {}) => ({
  databaseId: 98765,
  displayTitle: `CodeQL evidence for ${revision} (analysis run 67890)`,
  status: "completed",
  conclusion: "success",
  event: "workflow_run",
  headBranch: "main",
  headSha: "f".repeat(40),
  createdAt: "2026-10-04T12:10:00Z",
  ...overrides,
});
const publisherLog = `Analyze JavaScript / TypeScript\tStore reviewed CodeQL SARIF in private GHCR evidence\t2026-10-11T04:00:00Z VIRKI_EVIDENCE_DIGEST revision=${revision} run=67890 kind=codeql platform=none digest=sha256:${"a".repeat(64)}\n`;

function githubRunResponse(args) {
  const workflowName = args[args.indexOf("--workflow") + 1];
  if (workflowName === "ci.yml") return [run({ databaseId: 12345 })];
  if (workflowName === "codeql.yml") return [run({ databaseId: 67890 })];
  if (workflowName === "codeql-evidence.yml") return [evidencePublisherRun()];
  return [];
}

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

test("CodeQL evidence selects the completed trusted publisher linked to the exact analysis run", () => {
  const title = codeqlEvidenceRunDisplayTitle(revision, 67890);
  assert.deepEqual(selectCodeqlEvidenceRun([evidencePublisherRun({ displayTitle: title })], revision, 67890), {
    status: "PASS",
    runId: 98765
  });
  assert.deepEqual(selectCodeqlEvidenceRun([evidencePublisherRun({ displayTitle: `CodeQL evidence for ${revision} (analysis run 67891)` })], revision, 67890), {
    status: "PENDING"
  });
  assert.deepEqual(selectCodeqlEvidenceRun([evidencePublisherRun({ status: "in_progress", conclusion: null })], revision, 67890), {
    status: "PENDING",
    runId: 98765
  });
  const olderSuccess = evidencePublisherRun({ databaseId: 98764, createdAt: "2026-10-04T12:10:00Z" });
  const newerFailure = evidencePublisherRun({ databaseId: 98766, conclusion: "failure", createdAt: "2026-10-04T12:11:00Z" });
  assert.deepEqual(selectCodeqlEvidenceRun([olderSuccess, newerFailure], revision, 67890), {
    status: "FAIL",
    runId: 98766
  });
  assert.deepEqual(selectCodeqlEvidenceRun([evidencePublisherRun({ event: "push" })], revision, 67890), {
    status: "BLOCKED"
  });
  assert.deepEqual(selectCodeqlEvidenceRun([evidencePublisherRun({ headBranch: "attacker-branch" })], revision, 67890), {
    status: "BLOCKED"
  });
  assert.deepEqual(selectCodeqlEvidenceRun([], revision, 67890), { status: "PENDING" });
});

test("CodeQL evidence command-line gates parse the exact publisher and analysis IDs", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-codeql-evidence-cli-"));
  const runsPath = path.join(directory, "runs.json");
  const logPath = path.join(directory, "publisher.log");
  try {
    writeFileSync(runsPath, JSON.stringify([evidencePublisherRun()]));
    const selection = spawnSync(process.execPath, [
      path.join(repositoryRoot, "scripts", "production-codeql-evidence-selector.mjs"),
      "--sha", revision, "--analysis-run", "67890", runsPath
    ], { encoding: "utf8" });
    assert.equal(selection.status, 0, selection.stderr);
    assert.equal(selection.stdout, "PASS 98765\n");

    writeFileSync(logPath, publisherLog);
    const verified = spawnSync(process.execPath, [
      path.join(repositoryRoot, "scripts", "production-codeql-evidence-log-check.mjs"),
      "--sha", revision, "--analysis-run", "67890", "--log", logPath
    ], { encoding: "utf8" });
    assert.equal(verified.status, 0, verified.stderr);
    assert.equal(verified.stdout, "Exact-SHA CodeQL evidence digest marker verified.\n");

    writeFileSync(logPath, publisherLog.replace("run=67890", "run=67891"));
    const rejected = spawnSync(process.execPath, [
      path.join(repositoryRoot, "scripts", "production-codeql-evidence-log-check.mjs"),
      "--sha", revision, "--analysis-run", "67890", "--log", logPath
    ], { encoding: "utf8" });
    assert.equal(rejected.status, 1);
    assert.equal(rejected.stderr, "CodeQL evidence log verification failed: exact digest marker is missing or invalid.\n");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the GitHub CLI query is pinned to the exact workflow SHA and fails closed", () => {
  const calls = [];
  const result = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: ({ revision: observed, runId, logRunId, kind }) => {
      assert.equal(observed, revision);
      assert.equal(runId, 67890);
      assert.equal(logRunId, 98765, "the digest log belongs to the evidence publisher run");
      assert.equal(kind, "codeql");
      return fakeEvidence()();
    },
    execute: (command, args, options) => {
      calls.push({ command, args, options });
      if (args[0] === "run" && args[1] === "view") return { status: 0, stdout: publisherLog };
      return { status: 0, stdout: JSON.stringify(githubRunResponse(args)) };
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.runId, 12345);
  assert.equal(result.codeqlRunId, 67890);
  assert.equal(result.codeqlEvidenceRunId, 98765);
  assert.equal(result.sarifArtifactName, `virki-evidence:${revision}-67890-codeql`);
  assert.equal(result.sarifResults, 1);
  assert.equal(calls.length, 4);
  for (const call of calls.slice(0, 3)) {
    assert.equal(call.command, "gh");
    assert.equal(call.args[call.args.indexOf("--repo") + 1], "bielxdh3/Virki");
    assert.equal(call.options.cwd, "/repo");
  }
  assert.ok(calls[0].args.includes("--commit"));
  assert.ok(calls[0].args.includes(revision));
  assert.ok(calls[1].args.includes("--commit"));
  assert.ok(calls[1].args.includes(revision));
  assert.ok(calls[0].args.includes("databaseId,headSha,status,conclusion,event,headBranch,createdAt"));
  assert.ok(calls[1].args.includes("databaseId,headSha,status,conclusion,event,headBranch,createdAt"));
  assert.ok(calls.some(({ args }) => args.includes("ci.yml")));
  assert.ok(calls.some(({ args }) => args.includes("codeql.yml")));
  const evidenceRunList = calls[2].args;
  assert.ok(evidenceRunList.includes("codeql-evidence.yml"));
  assert.ok(evidenceRunList.includes("workflow_run"));
  assert.ok(evidenceRunList.includes("databaseId,displayTitle,status,conclusion,event,headBranch,createdAt"));
  assert.deepEqual(calls[3].args, ["run", "view", "98765", "--repo", "bielxdh3/Virki", "--log"]);

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
  const runsResponse = (args) => JSON.stringify(githubRunResponse(args));
  const unavailable = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: () => { throw new Error("registry inaccessible"); },
    execute: (_command, args) => args[0] === "run" && args[1] === "view"
      ? { status: 0, stdout: publisherLog }
      : { status: 0, stdout: runsResponse(args) }
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
    execute: (_command, args) => args[0] === "run" && args[1] === "view"
      ? { status: 0, stdout: publisherLog }
      : { status: 0, stdout: runsResponse(args) }
  });
  assert.deepEqual(rejected, {
    ok: false,
    status: "FAIL",
    lines: ["Reviewed exact-SHA CodeQL SARIF policy did not pass."]
  });
});

test("an exact-SHA CodeQL run cannot pass before its matching evidence publication completes", () => {
  const result = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    execute: (_command, args) => {
      const workflowName = args[args.indexOf("--workflow") + 1];
      if (workflowName === "ci.yml") return { status: 0, stdout: JSON.stringify([run({ databaseId: 12345 })]) };
      if (workflowName === "codeql.yml") return { status: 0, stdout: JSON.stringify([run({ databaseId: 67890 })]) };
      return { status: 0, stdout: JSON.stringify([]) };
    }
  });
  assert.deepEqual(result, {
    ok: false,
    status: "PENDING",
    lines: ["Exact-SHA CodeQL evidence publication is pending for analysis run 67890."]
  });
});

test("a publisher log naming another CodeQL run cannot satisfy the exact-SHA evidence gate", () => {
  const result = verifyExactShaCi({
    revision,
    repositoryRoot: "/repo",
    retrieveEvidence: () => assert.fail("SARIF must not be downloaded after a mismatched publisher log."),
    execute: (_command, args) => {
      if (args[0] === "run" && args[1] === "view") {
        return { status: 0, stdout: publisherLog.replace("run=67890", "run=67891") };
      }
      return { status: 0, stdout: JSON.stringify(githubRunResponse(args)) };
    }
  });
  assert.deepEqual(result, {
    ok: false,
    status: "BLOCKED",
    lines: ["Exact-SHA CodeQL evidence publication is missing or invalid for analysis run 67890."]
  });
});

test("private GHCR images publish only after exact main-push builds pass on both architectures", () => {
  assert.match(workflow, /production-images:[\s\S]*?if: github\.event_name == 'push' && github\.ref == 'refs\/heads\/main'/u);
  assert.match(workflow, /needs: \[validate, authenticated-e2e, tooling-policy, production-audit\][\s\S]*?arch: amd64[\s\S]*?runner: ubuntu-latest[\s\S]*?arch: arm64[\s\S]*?runner: ubuntu-24\.04-arm/u);
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

test("GHCR publication requires successful audit jobs in GitHub Actions needs closure", () => {
  assert.equal(publicationNeedsAreSafe(workflow), true, "both audit jobs must complete successfully before GHCR publication");

  for (const removed of ["tooling-policy", "production-audit", "validate", "authenticated-e2e"]) {
    const mutated = workflow.replace(
      /^ {4}needs: \[[^\]\n]+\]$/mu,
      (line) => line.replace(new RegExp(removed + "(?:, )?|, " + removed, "u"), "")
    );
    assert.notEqual(mutated, workflow);
    assert.equal(publicationNeedsAreSafe(mutated), false, "removing " + removed + " must block publication");
  }
  assert.equal(publicationNeedsAreSafe(workflow.replace("  production-audit:", "  renamed-production-audit:")), false);
  assert.equal(publicationNeedsAreSafe(workflow.replace("  tooling-policy:", "  renamed-tooling-policy:")), false);
  assert.equal(publicationNeedsAreSafe(workflow.replace(
    "    needs: [validate, authenticated-e2e, tooling-policy, production-audit]",
    "    needs: [validate, authenticated-e2e, tooling-policy, production-audit]\n    if: always()"
  )), false, "duplicate or bypassing job conditions must block publication");
  assert.equal(publicationNeedsAreSafe(workflow.replace(
    "        run: node scripts/production-dependency-audit.mjs",
    "        run: echo audit disabled"
  )), false, "removing the production audit step must block publication");
  assert.equal(publicationNeedsAreSafe(workflow.replace(
    "        run: node scripts/tooling-audit-policy.mjs",
    "        run: echo audit disabled"
  )), false, "removing the tooling audit step must block publication");
  assert.equal(publicationNeedsAreSafe(workflow.replace(
    "  tooling-policy:", "  tooling-policy:\n    if: always()"
  )), false, "an audit job with a custom condition must not authorize publishing");
  assert.equal(publicationNeedsAreSafe(workflow.replace(
    "        run: node scripts/production-dependency-audit.mjs",
    "        run: node scripts/production-dependency-audit.mjs\n        continue-on-error: true"
  )), false, "a soft-failed production audit must not authorize publishing");
});

test("hosted Linux CI explicitly executes native machine-id race regression with root privileges", () => {
  const normalized = workflow.replace(/\r\n/gu, "\n");
  const command = 'sudo "$(command -v node)" --test infra/offline/trusted-owner-machine-id-race.test.mjs';
  assert.match(normalized, /- name: Verify native machine-id inode race defenses as root\n(?:[^\n]*\n){0,4}\s+run: sudo "\$\(command -v node\)" --test infra\/offline\/trusted-owner-machine-id-race\.test\.mjs/u);
  assert.ok(normalized.includes(command), "root-only native race tests cannot disappear from CI unnoticed");
  assert.ok(!normalized.includes("|| true " + command), "the native test must fail the job on failure");
});

test("privileged source Git tests stay mandatory in isolated root Linux CI and the local production stage", () => {
  assert.doesNotMatch(packageScripts["test:production-revision"], /infra\/offline\/trusted-source-git\.test\.mjs/u);
  assert.equal(packageScripts["test:offline:source-git:root"], "node --test infra/offline/trusted-source-git.test.mjs");

  const validate = workflow.replace(/\r\n/gu, "\n").match(/\n {2}validate:\n([\s\S]*?)(?=\n {2}[a-z][a-z-]*:\n|$)/u)?.[1] ?? "";
  assert.match(validate, /runs-on: ubuntu-latest/u);
  assert.match(validate, /name: Production control tests\n {8}run: npm run test:production-revision/u);
  const rootStep = validate.match(/ {6}- name: Native root trusted source Git tests\n {8}run: \|\n((?: {10}[^\n]*\n)+)/u)?.[1] ?? "";
  assert.ok(rootStep, "root-only tests require an explicit, non-optional CI step");
  for (const guard of [
    /docker run --rm/u,
    /--network none/u,
    /--read-only/u,
    /--cap-drop ALL/u,
    /--security-opt no-new-privileges/u,
    /--user 0:0/u,
    /--mount type=bind,source="\$GITHUB_WORKSPACE",target=\/workspace,readonly/u,
    /--tmpfs \/var\/lib:rw,nosuid,nodev,size=128m,mode=0700/u,
    /--tmpfs \/tmp:rw,nosuid,nodev,size=128m,mode=1777/u,
    /--workdir \/workspace/u,
    /node:22\.23\.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8/u,
    /npm run test:offline:source-git:root/u,
  ]) assert.match(rootStep, guard);
  assert.doesNotMatch(rootStep, /--privileged|--network host|--cap-add|--device|secrets\.|--mount [^\n]*\/var\/run\/docker\.sock/u);
  assert.match(isolatedRunner, /Invoke-LoggedStage 'production-revision-tests' 'production-revision' 'npm run test:production-revision && npm run test:offline:source-git:root'/u);
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

test("CodeQL analysis stays read-only and preserves SARIF for later trusted publication", () => {
  assert.match(codeqlWorkflow, /uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1/u);
  assert.match(codeqlWorkflow, /uses: github\/codeql-action\/(?:init|analyze)@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4\.38\.2/u);
  assert.doesNotMatch(codeqlWorkflow, /uses: [^\s]+@v\d/u);
  assert.match(codeqlWorkflow, /queries: security-extended/u);
  assert.match(codeqlWorkflow, /output: codeql-results[\s\S]*?upload: never/u);
  assert.match(codeqlWorkflow, /actions: read[\s\S]*?contents: read/u);
  assert.doesNotMatch(codeqlWorkflow, /packages: write|GHCR_PASSWORD:|secrets\.GITHUB_TOKEN|docker login ghcr\.io|docker push/u);
  assert.match(codeqlWorkflow, /actions\/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7\.0\.2/u);
  assert.match(codeqlWorkflow, /name: codeql-sarif-\$\{\{ github\.run_id \}\}[\s\S]*?retention-days: 2/u);
  assert.ok(codeqlWorkflow.includes("actions/upload-artifact"));
  assert.doesNotMatch(codeqlWorkflow, /security-events: write/u);
  assert.match(codeqlWorkflow, /contents: read/u);
});

test("CodeQL analysis has no package-write credential and trusted main publication is isolated", () => {
  assert.doesNotMatch(codeqlWorkflow, /packages: write|GHCR_PASSWORD:|docker login ghcr\.io|docker push/u);
  assert.match(codeqlEvidenceWorkflow, /workflow_run:[\s\S]*?workflows:\s*\["CodeQL"\][\s\S]*?types:\s*\[completed\]/u);
  assert.match(codeqlEvidenceWorkflow, /event == 'push'[\s\S]*?head_branch == 'main'[\s\S]*?conclusion == 'success'/u);
  assert.match(codeqlEvidenceWorkflow, /head_repository\.full_name == github\.repository/u);
  assert.match(codeqlEvidenceWorkflow, /packages: write/u);
  assert.match(codeqlEvidenceWorkflow, /actions: read/u);
  assert.match(codeqlEvidenceWorkflow, /actions\/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8\.0\.2/u);
  assert.match(codeqlEvidenceWorkflow, /github\.event\.workflow_run\.head_sha/u);
  assert.match(codeqlEvidenceWorkflow, /run-name: CodeQL evidence for \$\{\{ github\.event\.workflow_run\.head_sha \}\} \(analysis run \$\{\{ github\.event\.workflow_run\.id \}\}\)/u);
  assert.match(codeqlEvidenceWorkflow, /node scripts\/codeql-sarif-policy\.mjs/u);
  assert.ok(codeqlEvidenceWorkflow.indexOf("node scripts/codeql-sarif-policy.mjs") < codeqlEvidenceWorkflow.indexOf('docker push "$ref"'));
  assert.match(codeqlEvidenceWorkflow, /codeql-sarif-\$\{\{ github\.event\.workflow_run\.id \}\}/u);
  assert.doesNotMatch(codeqlEvidenceWorkflow, /pull_request_target/u);
});

test("production approval waits for the exact CodeQL evidence publication and checks its analysis marker", () => {
  assert.match(approvalWorkflow, /gh run list --repo "\$GITHUB_REPOSITORY" --workflow codeql-evidence\.yml --event workflow_run/u);
  assert.match(approvalWorkflow, /production-codeql-evidence-selector\.mjs --sha "\$TARGET_SHA" --analysis-run "\$codeql_run"/u);
  assert.match(approvalWorkflow, /gh run view "\$evidence_run_id" --repo "\$GITHUB_REPOSITORY" --log/u);
  assert.match(approvalWorkflow, /production-codeql-evidence-log-check\.mjs --sha "\$TARGET_SHA" --analysis-run "\$codeql_run" --log/u);
  assert.match(approvalWorkflow, /Waiting for exact-SHA main CI, CodeQL, and its evidence publication/u);
});

test("production approval selects the latest successful exact main-push run by workflow and SHA", () => {
  assert.match(approvalWorkflow, /node scripts\/production-run-selector\.mjs --name "\$workflow" --sha "\$TARGET_SHA"/u);
  assert.doesNotMatch(approvalWorkflow, /\[\[ "\$count" -eq 1 \]\]/u);
  assert.match(approvalWorkflow, /Latest exact main-push \$workflow run failed or was cancelled/u);
  assert.doesNotMatch(approvalWorkflow, /select\(\.name == "CodeQL" and \.head_sha == \$sha and \.conclusion == "success"\)/u);
});
