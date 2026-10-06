import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateToolingAudit, EXPECTED_TOOLING_VERSIONS } from "./tooling-audit-policy.mjs";

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
