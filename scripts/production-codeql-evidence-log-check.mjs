import { readFileSync } from "node:fs";
import { evidenceDigestFromRunLog } from "./lib/ghcr-evidence.mjs";

const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== "--sha" || args[2] !== "--analysis-run" || args[4] !== "--log") {
  console.error("CodeQL evidence log verification failed: invalid arguments.");
  process.exit(2);
}

try {
  const log = readFileSync(args[5], "utf8");
  evidenceDigestFromRunLog(log, { revision: args[1], runId: Number(args[3]), kind: "codeql" });
  process.stdout.write("Exact-SHA CodeQL evidence digest marker verified.\n");
} catch {
  console.error("CodeQL evidence log verification failed: exact digest marker is missing or invalid.");
  process.exit(1);
}
