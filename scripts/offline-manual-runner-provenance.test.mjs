import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  inspectIndependentManualRunnerProvenance,
  verifySignedManualRunnerStatement,
} from "./lib/offline-manual-runner-provenance.mjs";
import { validateOfflineCiEvidence } from "./lib/offline-ci-evidence.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const revision = "a".repeat(40);
const names = [
  "tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check",
];
const emptySha = sha(Buffer.alloc(0));
function fabricatedManifest() {
  const start = Date.parse("2026-10-29T00:00:00Z");
  return Buffer.from(JSON.stringify({
    runId: "f".repeat(32), sourceBranch: "main", sourceHead: revision,
    startedUtc: new Date(start).toISOString(), finishedUtc: new Date(start + 300_000).toISOString(),
    nodeVersion: "v22.23.3", npmVersion: "10.9.9", stagedPatchSha256: emptySha,
    workingTreePatchSha256: emptySha, untrackedFiles: [],
    dockerMutationJournal: "docker-mutations.jsonl", dockerMutationUncertain: false,
    dockerCleanupVerified: true, bootstrapVirginTestsLog: "bootstrap-virgin-tests.tap.log",
    bootstrapVirginTestsExitCode: 0, unitTestsFailureCount: 0, unitTestsFailures: [],
    integrationTestsFailureCount: 0, integrationTestsFailures: [],
    productionOperationsFailureCount: 0, productionOperationsFailures: [],
    exitCode: 0, failedStages: [], stages: names.map((name, i) => ({
      name, startedUtc: new Date(start + i * 10_000 + 1000).toISOString(),
      finishedUtc: new Date(start + i * 10_000 + 2000).toISOString(),
      durationMs: 1000, exitCode: 0,
    })),
  }));
}

const scannerBytes = Buffer.from(JSON.stringify({version: "1.2.0", errors: [], results: [], paths: {scanned: ["src"], skipped: []}}));
const ciConsoleBytes = Buffer.from("real runner stdout");
const scannerConsoleBytes = Buffer.from("real scanner stdout");
const policy = {
  version: 1, keyId: "", runnerId: "installed-manual-runner-1",
  runnerExecutableSha256: sha("runner"), runnerLauncherSha256: sha("launcher"),
  scannerExecutableSha256: sha("semgrep"), scannerRulesCommit: "b".repeat(40),
};
const keys = generateKeyPairSync("ed25519");
policy.publicKeySpkiBase64 = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
policy.keyId = sha(Buffer.from(policy.publicKeySpkiBase64, "base64"));

function statement(ciManifestBytes = fabricatedManifest(), scanned = scannerBytes) {
  return {
    version: 1, kind: "VIRKI_INDEPENDENT_MANUAL_RUNNER_V1", sourceSha: revision, sourceBranch: "main",
    manifestSha256: sha(ciManifestBytes), scannerReportSha256: sha(scanned),
    runnerId: policy.runnerId, runnerExecutableSha256: policy.runnerExecutableSha256,
    runnerLauncherSha256: policy.runnerLauncherSha256,
    scannerExecutableSha256: policy.scannerExecutableSha256, scannerRulesCommit: policy.scannerRulesCommit,
    ciProcess: { exitCode: 0, timedOut: false, truncated: false, spawnError: false,
      stdoutSha256: sha("real runner stdout"), capturedBytes: 18 },
    scannerProcess: { exitCode: 0, timedOut: false, truncated: false, spawnError: false,
      stdoutSha256: sha("real scanner stdout"), capturedBytes: 19 },
    observedStages: names.map((name) => ({ name, exitCode: 0 })),
  };
}
const domain = Buffer.from("virki:manual-independent-runner:v1\0", "utf8");
const envelope = (entry) => {
  const statementBytes = Buffer.from(JSON.stringify(entry));
  return Buffer.from(JSON.stringify({statement: entry,
    signatureBase64: sign(null, Buffer.concat([domain, statementBytes]), keys.privateKey).toString("base64") }));
};

test("fabricated 19-stage success remains structural metadata; independent manual gate refuses it", () => {
  const fabricated = fabricatedManifest();
  assert.equal(validateOfflineCiEvidence(fabricated, revision, "main", {requireOfflineFixture: true}).ok, true);
  for (const overrides of [
    {}, { attestationBytes: Buffer.from(JSON.stringify({ ...statement(fabricated), codeql: "PASS" })) },
    { attestationBytes: envelope(statement(fabricated)), trustedKeys: { runner: policy.publicKeySpkiBase64 } },
  ]) {
    const result = inspectIndependentManualRunnerProvenance({
      ciManifestBytes: fabricated, scannerReportBytes: scannerBytes, revision, ...overrides,
    });
    assert.equal(result.status, "NO_GO");
    assert.equal(result.codeql, "NOT_RUN");
    assert.equal(result.hostedCi, "NOT_RUN");
  }
});

test("independently pinned Ed25519 signature binds the manifest, scanner, runner and actual child exit observations", () => {
  const ciManifestBytes = fabricatedManifest();
  const verified = verifySignedManualRunnerStatement({
    ciManifestBytes, scannerReportBytes: scannerBytes, revision,
    ciConsoleBytes, scannerConsoleBytes,
    attestationBytes: envelope(statement(ciManifestBytes)), trustedInstalledPolicy: policy,
  });
  assert.equal(verified.status, "CRYPTOGRAPHIC_BINDING_OK_ONLY");
  assert.equal(verified.codeql, "NOT_RUN");
  assert.equal(verified.hostedCi, "NOT_RUN");
  assert.equal(verified.deployAuthorized, false);
  for (const bad of [
    { ciManifestBytes: Buffer.concat([ciManifestBytes, Buffer.from(" ")]) },
    { scannerReportBytes: Buffer.concat([scannerBytes, Buffer.from(" ")]) },
    { ciConsoleBytes: Buffer.from("forged console") },
    { scannerConsoleBytes: Buffer.alloc(0) },
    { trustedInstalledPolicy: { ...policy, runnerExecutableSha256: sha("other executable") } },
    { trustedInstalledPolicy: { ...policy, publicKeySpkiBase64: generateKeyPairSync("ed25519").publicKey.export({type: "spki", format: "der"}).toString("base64") } },
    { attestationBytes: envelope({ ...statement(ciManifestBytes), scannerProcess: { ...statement(ciManifestBytes).scannerProcess, exitCode: 1 } }) },
    { attestationBytes: envelope({ ...statement(ciManifestBytes), observedStages: [{name: names[0], exitCode: 0}] }) },
    { attestationBytes: envelope({ ...statement(ciManifestBytes), ciProcess: { ...statement(ciManifestBytes).ciProcess, timedOut: true } }) },
  ]) {
    assert.throws(() => verifySignedManualRunnerStatement({
      ciManifestBytes, scannerReportBytes: scannerBytes, revision,
      ciConsoleBytes, scannerConsoleBytes,
      attestationBytes: envelope(statement(ciManifestBytes)), trustedInstalledPolicy: policy, ...bad,
    }), /manual runner|trusted|attestation|provenance|process|stage/iu);
  }
});

test("signed scanner raw pretty JSON and complete console bytes bind without caller key selection", () => {
  const ciManifestBytes = fabricatedManifest();
  const rawScanner = Buffer.from(JSON.stringify(JSON.parse(scannerBytes.toString()), null, 2));
  const verified = verifySignedManualRunnerStatement({
    ciManifestBytes, scannerReportBytes: rawScanner, revision, ciConsoleBytes, scannerConsoleBytes,
    attestationBytes: envelope(statement(ciManifestBytes, rawScanner)), trustedInstalledPolicy: policy,
  });
  assert.equal(verified.scannerReportSha256, sha(rawScanner));
});

test("RED: even a valid independent runner signature must refuse scanner findings", () => {
  const ciManifestBytes = fabricatedManifest();
  for (const severity of ["ERROR", "WARNING", "INFO"]) {
    const maliciousReport = Buffer.from(JSON.stringify({
      version: "1.2.0", errors: [],
      results: [{ check_id: "security.review-required", extra: { severity } }],
      paths: { scanned: ["src"], skipped: [] },
    }));
    assert.throws(() => verifySignedManualRunnerStatement({
      ciManifestBytes, scannerReportBytes: maliciousReport, revision,
      ciConsoleBytes, scannerConsoleBytes,
      attestationBytes: envelope(statement(ciManifestBytes, maliciousReport)),
      trustedInstalledPolicy: policy,
    }), /scanner|finding|review/iu, `unreviewed ${severity} finding must block`);
  }
});
