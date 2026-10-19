const allowedWorkflowNames = new Set(["CI", "CodeQL"]);

export function selectLatestWorkflowRun(workflowRuns, workflowName, expectedSha) {
  if (!Array.isArray(workflowRuns) || !allowedWorkflowNames.has(workflowName) || !/^[a-f0-9]{40}$/iu.test(expectedSha)) {
    throw new TypeError("Invalid exact-SHA workflow selection input.");
  }

  const candidates = workflowRuns
    .filter((run) => run && run.name === workflowName && run.head_sha === expectedSha &&
      run.head_branch === "main" && run.event === "push")
    .sort(compareNewestFirst);

  const latest = candidates[0];
  if (!latest) return { state: "missing", id: null };

  const id = typeof latest.id === "number" && Number.isSafeInteger(latest.id) && latest.id > 0
    ? String(latest.id)
    : typeof latest.id === "string" && /^[1-9][0-9]*$/u.test(latest.id)
      ? latest.id
      : null;
  if (!id) return { state: "failure", id: null };
  if (latest.status !== "completed") return { state: "pending", id };
  if (latest.conclusion !== "success") return { state: "failure", id };
  return { state: "success", id };
}

function compareNewestFirst(left, right) {
  return compareInteger(right.run_number, left.run_number) ||
    compareInteger(right.run_attempt, left.run_attempt) ||
    compareInteger(right.id, left.id) ||
    String(right.run_started_at ?? right.created_at ?? "").localeCompare(String(left.run_started_at ?? left.created_at ?? ""));
}

function compareInteger(left, right) {
  const leftValue = Number(left);
  const rightValue = Number(right);
  if (!Number.isFinite(leftValue) || !Number.isFinite(rightValue)) return 0;
  return leftValue === rightValue ? 0 : leftValue > rightValue ? 1 : -1;
}
