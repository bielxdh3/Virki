import { fileURLToPath } from "node:url";
import { readStableLocalEvidenceFile } from "./lib/offline-ci-local-runner.mjs";
import { inspectIndependentManualRunnerProvenance } from "./lib/offline-manual-runner-provenance.mjs";

const FLAGS = new Map([
  ["--revision", "revision"], ["--ci-manifest", "ciManifestBytes"],
  ["--scanner-report", "scannerReportBytes"], ["--attestation", "attestationBytes"],
  ["--ci-console", "ciConsoleBytes"], ["--scanner-console", "scannerConsoleBytes"],
]);
const MAX_BYTES = new Map([
  ["ciManifestBytes", 64 * 1024], ["scannerReportBytes", 4 * 1024 * 1024],
  ["attestationBytes", 64 * 1024], ["ciConsoleBytes", 64 * 1024 * 1024],
  ["scannerConsoleBytes", 64 * 1024 * 1024],
]);

/** Owner-installed Linux verifier entrypoint: no key/path/runner overrides. */
export function previewManualRunnerProvenance(argv) {
  if (!Array.isArray(argv) || argv.length !== FLAGS.size * 2) {
    throw new Error("Expected exactly six revision/evidence file arguments; no trust overrides accepted");
  }
  const parsed = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = FLAGS.get(argv[i]);
    if (!key || Object.hasOwn(parsed, key) || typeof argv[i + 1] !== "string" || !argv[i + 1]) {
      throw new Error("Unknown, missing or repeated manual provenance argument");
    }
    parsed[key] = key === "revision" ? argv[i + 1] : readStableLocalEvidenceFile(argv[i + 1], MAX_BYTES.get(key));
  }
  return inspectIndependentManualRunnerProvenance(parsed);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let outcome;
  try { outcome = previewManualRunnerProvenance(process.argv.slice(2)); }
  catch (error) {
    outcome = { status: "NO_GO", reason: error instanceof Error ? error.message : "verification failed",
      codeql: "NOT_RUN", hostedCi: "NOT_RUN", deployAuthorized: false };
  }
  console.log(JSON.stringify(outcome));
  if (outcome.status !== "MANUAL_RUNNER_PROVENANCE_VERIFIED_LOCAL_ONLY") process.exitCode = 1;
}
