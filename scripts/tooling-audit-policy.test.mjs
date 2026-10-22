import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateToolingAudit, interpretNpmAuditResult, npmAuditArguments, summarizeToolingAuditReport, EXPECTED_TOOLING_VERSIONS } from "./tooling-audit-policy.mjs";

const accepted = JSON.parse(readFileSync(new URL("./fixtures/tooling-audit/accepted.json", import.meta.url), "utf8"));

function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

test("accepts a clean Prisma tooling audit at the pinned versions", () => {
  const result = evaluateToolingAudit(accepted, { versions: EXPECTED_TOOLING_VERSIONS });
  assert.equal(result.ok, true);
  assert.equal(result.status, "passed");
});

test("rejects production reachability", () => {
  const result = evaluateToolingAudit(accepted, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: true });
  assert.equal(result.ok, false);
});

test("rejects any tooling advisory", () => {
  const unrelated = copy(accepted);
  unrelated.vulnerabilities["other-package"] = { name: "other-package", severity: "high", isDirect: false, via: [], effects: [], range: "<1.0.0", nodes: ["node_modules/other-package"], fixAvailable: false };
  unrelated.metadata.vulnerabilities.high = 1;
  unrelated.metadata.vulnerabilities.total = 1;
  assert.equal(evaluateToolingAudit(unrelated, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);
});

test("rejects count and version drift", () => {
  const countDrift = copy(accepted);
  countDrift.metadata.vulnerabilities.high = 2;
  assert.equal(evaluateToolingAudit(countDrift, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);

  const versionDrift = { ...EXPECTED_TOOLING_VERSIONS, "deepmerge-ts": "8.0.1" };
  assert.equal(evaluateToolingAudit(accepted, { versions: versionDrift }).ok, false);
});

test("npm audit network error JSON is unavailable, never a vulnerability report", () => {
  const sensitiveMarker = "NON_SENSITIVE_TEST_MARKER";
  const result = interpretNpmAuditResult({
    status: 1, stdout: JSON.stringify({ error: { code: "FETCH_ERROR", summary: `request with ${sensitiveMarker} timed out`, detail: sensitiveMarker } }), stderr: sensitiveMarker
  });
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "registry-or-network-error");
  assert.equal(JSON.stringify(result).includes(sensitiveMarker), false);
});

test("timeout, spawn error, empty, malformed, and non-report output fail closed", () => {
  for (const [output, reason] of [
    [{ error: Object.assign(new Error("SENSITIVE_DATA"), { code: "ETIMEDOUT" }), status: null, stdout: "" }, "process-timeout"],
    [{ error: Object.assign(new Error("SENSITIVE_DATA"), { code: "ENOENT" }), status: null, stdout: "" }, "execution-error"],
    [{ status: 1, stdout: "" }, "empty-output"],
    [{ status: 1, stdout: "SENSITIVE_DATA not JSON" }, "invalid-json"],
    [{ status: 1, stdout: JSON.stringify({ auditReportVersion: null, metadata: null }) }, "invalid-report"],
    [{ status: 0, stdout: JSON.stringify(accepted).replace('"auditReportVersion":2', '"auditReportVersion":null') }, "invalid-report"]
  ]) {
    const result = interpretNpmAuditResult(output);
    assert.equal(result.status, "unavailable");
    assert.equal(result.reason, reason);
    assert.equal(JSON.stringify(result).includes("SENSITIVE_DATA"), false);
  }
});

test("a legitimate advisory cannot be masked by audit exit status 1", () => {
  const vulnerable = copy(accepted);
  vulnerable.vulnerabilities["test-private-path"] = { name: "test-private-path", severity: "high" };
  vulnerable.metadata.vulnerabilities.high = 1;
  vulnerable.metadata.vulnerabilities.total = 1;
  const result = interpretNpmAuditResult({ status: 1, stdout: JSON.stringify(vulnerable) });
  assert.equal(result.status, "reported");
  assert.equal(evaluateToolingAudit(result.report, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);
  const safeDiagnostic = summarizeToolingAuditReport(result.report, EXPECTED_TOOLING_VERSIONS);
  assert.equal(safeDiagnostic.ok, false);
  assert.equal(safeDiagnostic.observed.vulnerabilityCounts.high, 1);
  assert.equal(JSON.stringify(safeDiagnostic).includes("test-private-path"), false, "never expose raw report via diagnostic");
});

test("only a valid complete npm audit report from a successful command is accepted", () => {
  assert.equal(interpretNpmAuditResult({ status: 0, stdout: JSON.stringify(accepted) }).status, "reported");
  assert.equal(interpretNpmAuditResult({ status: 2, stdout: JSON.stringify(accepted) }).status, "unavailable");
  assert.equal(interpretNpmAuditResult({ status: 0, stdout: JSON.stringify({ ...accepted, error: { code: "SENSITIVE" } }) }).status, "unavailable");
  assert.deepEqual(npmAuditArguments(), [
    "audit", "--package-lock-only", "--json", "--fetch-retries=0", "--fetch-timeout=25000"
  ]);
});

test("policy command cannot replace live audit with an environment-provided JSON fixture", () => {
  const source = readFileSync(new URL("./tooling-audit-policy.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /process\.env\.VIRKI_TOOLING_AUDIT_JSON/u);
  assert.match(source, /timeout: AUDIT_PROCESS_TIMEOUT_MS/u);
  assert.match(source, /const AUDIT_PROCESS_TIMEOUT_MS = 45_000/u);
  assert.match(source, /const execution = runAudit\(\)/u);
});
