import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { CANONICAL_BIELOS_REPOSITORY, normalizeRevision, ProductionRevisionError } from "./production-revision.mjs";
import { evaluateCodeqlSarif, readSarifDirectory } from "../codeql-sarif-policy.mjs";

const RUN_FIELDS = "databaseId,headSha,status,conclusion,event,headBranch,createdAt";
const WORKFLOWS = ["ci.yml", "codeql.yml"];

function buildRunArgs(workflow, revision) {
  return [
    "run", "list", "--repo", CANONICAL_BIELOS_REPOSITORY,
    "--workflow", workflow, "--commit", revision,
    "--json", RUN_FIELDS, "--limit", "100"
  ];
}

function latestEligibleRun(runs, expected) {
  if (!Array.isArray(runs)) return undefined;
  return runs
    .filter((run) => run && typeof run.headSha === "string" && run.headSha.toLowerCase() === expected && run.event === "push" && run.headBranch === "main")
    .sort((left, right) => {
      const leftTime = Date.parse(left.createdAt ?? "");
      const rightTime = Date.parse(right.createdAt ?? "");
      return Number.isFinite(rightTime - leftTime) ? rightTime - leftTime : 0;
    })[0];
}

export function evaluateExactShaCi(runs, expectedRevision) {
  const expected = normalizeRevision(expectedRevision);
  const latest = latestEligibleRun(runs, expected);
  return { ok: latest?.status === "completed" && latest?.conclusion === "success" };
}

export function classifyExactShaWorkflow(runs, expectedRevision) {
  const expected = normalizeRevision(expectedRevision);
  const latest = latestEligibleRun(runs, expected);
  if (!latest || !Number.isSafeInteger(latest.databaseId) || latest.databaseId <= 0) return { status: "BLOCKED" };
  if (latest.status !== "completed") return { status: ["queued", "in_progress", "waiting", "requested", "pending"].includes(latest.status) ? "PENDING" : "BLOCKED", runId: latest.databaseId };
  switch (latest.conclusion) {
    case "success": return { status: "PASS", runId: latest.databaseId };
    case "failure":
    case "timed_out":
    case "action_required": return { status: "FAIL", runId: latest.databaseId };
    case "skipped": return { status: "SKIPPED", runId: latest.databaseId };
    case "cancelled": return { status: "CANCELLED", runId: latest.databaseId };
    default: return { status: "BLOCKED", runId: latest.databaseId };
  }
}

export function evaluateExactShaRelease(ciRuns, codeqlRuns, expectedRevision) {
  let ci;
  let codeql;
  try {
    ci = classifyExactShaWorkflow(ciRuns, expectedRevision);
    codeql = classifyExactShaWorkflow(codeqlRuns, expectedRevision);
  } catch {
    return { status: "BLOCKED", ci: { status: "BLOCKED" }, codeql: { status: "BLOCKED" } };
  }
  const checks = [ci.status, codeql.status];
  const status = checks.includes("FAIL") ? "FAIL"
    : checks.includes("CANCELLED") ? "CANCELLED"
      : checks.includes("PENDING") ? "PENDING"
        : checks.includes("SKIPPED") ? "SKIPPED"
          : checks.includes("BLOCKED") ? "BLOCKED"
            : "PASS";
  return { status, ci, codeql };
}

function verifyExactShaSarifArtifact({ revision, runId, execute, repositoryRoot }) {
  const artifactName = "codeql-sarif-" + revision;
  const directory = mkdtempSync(path.join(os.tmpdir(), "bielos-codeql-sarif-"));
  try {
    const result = execute("gh", [
      "run", "download", String(runId),
      "--repo", CANONICAL_BIELOS_REPOSITORY,
      "--name", artifactName,
      "--dir", directory
    ], { cwd: repositoryRoot });
    if (!result || result.status !== 0) return { status: "BLOCKED" };

    const entries = readdirSync(directory, { withFileTypes: true });
    if (entries.length === 0 || entries.some((entry) => !entry.isFile() || !entry.name.endsWith(".sarif"))) {
      return { status: "BLOCKED" };
    }

    const policy = evaluateCodeqlSarif(readSarifDirectory(directory));
    return policy.ok
      ? { status: "PASS", artifactName, totalResults: policy.totalResults, violations: 0 }
      : { status: "FAIL" };
  } catch {
    return { status: "BLOCKED" };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function verifyExactShaCi({ revision, execute, repositoryRoot }) {
  let expected;
  try {
    expected = normalizeRevision(revision);
  } catch (error) {
    if (error instanceof ProductionRevisionError) throw error;
    throw new ProductionRevisionError("REVISION_INVALID");
  }

  const results = new Map();
  for (const workflow of WORKFLOWS) {
    const result = execute("gh", buildRunArgs(workflow, expected), { cwd: repositoryRoot });
    if (!result || result.status !== 0 || typeof result.stdout !== "string") {
      return { ok: false, status: "BLOCKED", lines: [`Exact-SHA ${workflow} result could not be verified.`] };
    }
    try {
      results.set(workflow, JSON.parse(result.stdout));
    } catch {
      return { ok: false, status: "BLOCKED", lines: [`Exact-SHA ${workflow} response was invalid.`] };
    }
  }

  const release = evaluateExactShaRelease(results.get("ci.yml"), results.get("codeql.yml"), expected);
  if (release.status !== "PASS") {
    const lines = [
      `Exact-SHA release checks are ${release.status}.`,
      `CI: ${release.ci.status}${release.ci.runId ? ` (run ${release.ci.runId})` : ""}.`,
      `CodeQL: ${release.codeql.status}${release.codeql.runId ? ` (run ${release.codeql.runId})` : ""}.`
    ];
    return { ok: false, status: release.status, lines };
  }

  const sarif = verifyExactShaSarifArtifact({
    revision: expected,
    runId: release.codeql.runId,
    execute,
    repositoryRoot
  });
  if (sarif.status !== "PASS") {
    return {
      ok: false,
      status: sarif.status,
      lines: [sarif.status === "FAIL"
        ? "Reviewed exact-SHA CodeQL SARIF policy did not pass."
        : "Exact-SHA CodeQL SARIF artifact is missing, expired, or unavailable."]
    };
  }

  return {
    ok: true,
    status: "PASS",
    runId: release.ci.runId,
    codeqlRunId: release.codeql.runId,
    sarifArtifactName: sarif.artifactName,
    sarifResults: sarif.totalResults,
    lines: ["Exact-SHA CI, CodeQL, reviewed SARIF policy, and retained artifact checks passed for " + expected + "."]
  };
}
