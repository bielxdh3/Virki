import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateToolingAudit, EXPECTED_TOOLING_VERSIONS } from "./tooling-audit-policy.mjs";

const accepted = JSON.parse(readFileSync(new URL("./fixtures/tooling-audit/accepted.json", import.meta.url), "utf8"));

function copy(value) {
  return JSON.parse(JSON.stringify(value));
}

test("accepts only the exact Prisma tooling advisory path", () => {
  const result = evaluateToolingAudit(accepted, { versions: EXPECTED_TOOLING_VERSIONS });
  assert.equal(result.ok, true);
  assert.equal(result.status, "passed");
});

test("rejects production reachability even for the accepted advisory", () => {
  const result = evaluateToolingAudit(accepted, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: true });
  assert.equal(result.ok, false);
});

test("rejects an unrelated or second advisory", () => {
  const unrelated = copy(accepted);
  unrelated.vulnerabilities["other-package"] = { name: "other-package", severity: "high", isDirect: false, via: [], effects: [], range: "<1.0.0", nodes: ["node_modules/other-package"], fixAvailable: false };
  unrelated.metadata.vulnerabilities.high = 4;
  unrelated.metadata.vulnerabilities.total = 4;
  assert.equal(evaluateToolingAudit(unrelated, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);

  const second = copy(accepted);
  second.vulnerabilities["deepmerge-ts"].via.push({ source: 999999, name: "deepmerge-ts", dependency: "deepmerge-ts", title: "Second advisory", url: "https://github.com/advisories/GHSA-test", severity: "high", cwe: [], cvss: { score: 0, vectorString: null }, range: "<8.0.0" });
  assert.equal(evaluateToolingAudit(second, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);
});

test("rejects count, path, and version drift", () => {
  const countDrift = copy(accepted);
  countDrift.metadata.vulnerabilities.high = 2;
  assert.equal(evaluateToolingAudit(countDrift, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);

  const pathDrift = copy(accepted);
  pathDrift.vulnerabilities.prisma.nodes = ["packages/database/node_modules/prisma"];
  assert.equal(evaluateToolingAudit(pathDrift, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);

  const versionDrift = { ...EXPECTED_TOOLING_VERSIONS, "deepmerge-ts": "8.0.0" };
  assert.equal(evaluateToolingAudit(accepted, { versions: versionDrift }).ok, false);
});

test("signals removal when the audit becomes clean", () => {
  const clean = copy(accepted);
  clean.vulnerabilities = {};
  clean.metadata.vulnerabilities = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  const result = evaluateToolingAudit(clean, { versions: { prisma: "7.0.0" } });
  assert.equal(result.ok, true);
  assert.equal(result.status, "exception-no-longer-needed");
});
