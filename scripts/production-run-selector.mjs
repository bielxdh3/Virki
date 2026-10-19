import { readFileSync } from "node:fs";
import { selectLatestWorkflowRun } from "./lib/production-run-selection.mjs";

const args = process.argv.slice(2);
if (args.length !== 5 || args[0] !== "--name" || args[2] !== "--sha") {
  console.error("Workflow run selection failed: invalid arguments.");
  process.exit(2);
}

try {
  const document = JSON.parse(readFileSync(args[4], "utf8"));
  const result = selectLatestWorkflowRun(document.workflow_runs, args[1], args[3]);
  process.stdout.write(`${result.state} ${result.id ?? ""}\n`);
} catch {
  console.error("Workflow run selection failed: invalid response or exact-SHA identity.");
  process.exit(2);
}
