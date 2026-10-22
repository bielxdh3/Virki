import { normalizeRevision, ProductionRevisionError } from "./production-revision.mjs";
import { evidenceTag } from "./ghcr-evidence.mjs";

const PENDING_STATUSES = new Set(["queued", "in_progress", "waiting", "requested", "pending"]);

export function codeqlEvidenceRunDisplayTitle(revision, analysisRunId) {
  const sha = normalizeRevision(revision);
  evidenceTag(sha, analysisRunId, "codeql");
  return `CodeQL evidence for ${sha} (analysis run ${analysisRunId})`;
}

export function selectCodeqlEvidenceRun(runs, revision, analysisRunId) {
  let expectedTitle;
  try {
    expectedTitle = codeqlEvidenceRunDisplayTitle(revision, analysisRunId);
  } catch (error) {
    if (error instanceof ProductionRevisionError) return { status: "BLOCKED" };
    return { status: "BLOCKED" };
  }
  if (!Array.isArray(runs)) return { status: "BLOCKED" };

  const exactTitleRuns = runs.filter((run) => run && typeof run === "object" && run.displayTitle === expectedTitle);
  if (exactTitleRuns.length === 0) return { status: "PENDING" };
  // workflow_run executes from the default branch; the publisher run's head SHA is not the upstream analysis SHA.
  if (exactTitleRuns.some((run) => run.event !== "workflow_run" || run.headBranch !== "main" ||
      !Number.isSafeInteger(run.databaseId) || run.databaseId <= 0 || typeof run.createdAt !== "string" || !Number.isFinite(Date.parse(run.createdAt)))) {
    return { status: "BLOCKED" };
  }

  const latest = exactTitleRuns.toSorted((left, right) => {
    const timeOrder = Date.parse(right.createdAt) - Date.parse(left.createdAt);
    return timeOrder || right.databaseId - left.databaseId;
  })[0];
  if (!latest) return { status: "BLOCKED" };
  if (latest.status !== "completed") {
    return PENDING_STATUSES.has(latest.status) ? { status: "PENDING", runId: latest.databaseId } : { status: "BLOCKED", runId: latest.databaseId };
  }
  if (latest.conclusion === "success") return { status: "PASS", runId: latest.databaseId };
  if (["failure", "timed_out", "action_required", "cancelled", "skipped"].includes(latest.conclusion)) {
    return { status: "FAIL", runId: latest.databaseId };
  }
  return { status: "BLOCKED", runId: latest.databaseId };
}
