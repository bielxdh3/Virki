import { readFileSync } from "node:fs";
import { selectCodeqlEvidenceRun } from "./lib/codeql-evidence-selection.mjs";

const args = process.argv.slice(2);
if (args.length !== 5 || args[0] !== "--sha" || args[2] !== "--analysis-run") {
  console.error("CodeQL evidence selection failed: invalid arguments.");
  process.exit(2);
}

try {
  const runs = JSON.parse(readFileSync(args[4], "utf8"));
  const result = selectCodeqlEvidenceRun(runs, args[1], Number(args[3]));
  process.stdout.write(`${result.status} ${result.runId ?? ""}\n`);
} catch {
  console.error("CodeQL evidence selection failed: invalid response or source identity.");
  process.exit(2);
}
