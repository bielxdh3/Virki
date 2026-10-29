import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PINNED_DIAGNOSTIC, verifyPinnedManualCodeqlCliSarif } from "./lib/manual-codeql-cli-diagnostic.mjs";

// Fixed inputs only. The source checkout and SARIF are the original *read-only*
// W50 evidence; the CLI does not receive paths, pins, identities or review data
// from argv, env, stdin or the candidate release.
const worktreeRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const siblings = path.dirname(worktreeRoot);
const sarifPath = path.join(siblings, "_scratch-w50-codeql-20261029", "codeql-results", "c3ea768-js-security-extended.sarif");

if (process.argv.length !== 2) {
  process.stderr.write("Manual CodeQL CLI diagnostic accepts no arguments or caller-selected fixed-input overrides.\n");
  process.exitCode = 2;
} else {
  let result;
  try {
    // The bytes are read at the original W50 path, never copied or parsed as
    // an executable. Their SHA-256 is checked before consuming any JSON claims.
    result = verifyPinnedManualCodeqlCliSarif(readFileSync(sarifPath));
  } catch {
    result = { status: "INVALID", authorizesRelease: false,
      trustedScannerExecution: false, sourceCommit: PINNED_DIAGNOSTIC.sourceCommit,
      blockers: ["PINNED_SARIF_UNAVAILABLE"] };
  }
  // The pinned archived sample identifies one original detached source SHA,
  // but an ambient Git checkout is neither execution provenance nor safe to
  // inspect via `git status` (repo-local filters may execute arbitrary code).
  // Do not execute Git or candidate-controlled helpers from this diagnostic.
  const sourceCheckoutMatchesPin = false;
  const blockers = [...result.blockers, "PINNED_SOURCE_CHECKOUT_UNVERIFIED"];
  const output = {
    diagnosticOnly: true,
    status: result.status === "INVALID" ? "INVALID" : "NO_GO",
    gateDecision: "NO_GO",
    authorizesRelease: false,
    trustedScannerExecution: false,
    sourceCommit: PINNED_DIAGNOSTIC.sourceCommit,
    sourceCheckoutMatchesPin,
    sourceCheckoutIsScannerAttestation: false,
    ...(result.counts ? { counts: result.counts, missingExpectedJsTs: result.missingExpectedJsTs } : {}),
    blockers,
  };
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
  // Even a digest-matched archive and a clean source checkout cannot prove
  // execution provenance, finding adjudication or deployment readiness.
  process.exitCode = output.status === "INVALID" ? 2 : 1;
}
