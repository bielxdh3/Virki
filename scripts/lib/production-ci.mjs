import { CANONICAL_BIELOS_REPOSITORY, normalizeRevision, ProductionRevisionError } from "./production-revision.mjs";

const CI_ARGS = [
  "run",
  "list",
  "--repo",
  CANONICAL_BIELOS_REPOSITORY,
  "--workflow",
  "ci.yml",
  "--json",
  "databaseId,headSha,status,conclusion,event,headBranch",
  "--limit",
  "100",
];

export function evaluateExactShaCi(runs, expectedRevision) {
  const expected = normalizeRevision(expectedRevision);
  if (!Array.isArray(runs)) return { ok: false };

  const matchingRuns = runs.filter((run) =>
    run &&
    typeof run.headSha === "string" &&
    run.headSha.toLowerCase() === expected &&
    run.event === "push" &&
    run.headBranch === "main",
  );
  const latest = matchingRuns[0];
  return {
    ok: latest?.status === "completed" && latest?.conclusion === "success",
  };
}

export function verifyExactShaCi({ revision, execute, repositoryRoot }) {
  let expected;
  try {
    expected = normalizeRevision(revision);
  } catch (error) {
    if (error instanceof ProductionRevisionError) throw error;
    throw new ProductionRevisionError("REVISION_INVALID");
  }

  const result = execute("gh", [...CI_ARGS, "--commit", expected], {
    cwd: repositoryRoot,
  });
  if (!result || result.status !== 0 || typeof result.stdout !== "string") {
    return { ok: false, lines: ["Exact-SHA CI could not be verified."] };
  }

  let runs;
  try {
    runs = JSON.parse(result.stdout);
  } catch {
    return { ok: false, lines: ["Exact-SHA CI response was invalid."] };
  }

  if (!evaluateExactShaCi(runs, expected).ok) {
    return { ok: false, lines: ["The latest main push CI run for this exact revision is not green."] };
  }

  const latest = runs.find((run) =>
    run &&
    typeof run.headSha === "string" &&
    run.headSha.toLowerCase() === expected &&
    run.event === "push" &&
    run.headBranch === "main",
  );
  if (!Number.isSafeInteger(latest?.databaseId) || latest.databaseId <= 0) {
    return { ok: false, lines: ["The exact-SHA CI run identity could not be verified."] };
  }

  return { ok: true, runId: latest.databaseId, lines: [`Exact-SHA CI is green for ${expected}.`] };
}
