import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCodeqlSarif } from "./codeql-sarif-policy.mjs";

function sarif(results) {
  return {
    version: "2.1.0",
    runs: [{
      results: results.map(({ ruleId, path }) => ({
        ruleId,
        locations: [{ physicalLocation: { artifactLocation: { uri: path } } }]
      }))
    }]
  };
}

test("CodeQL policy accepts only the reviewed test-harness findings", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/incomplete-url-substring-sanitization", path: "apps/hub/src/lib/connection-policy.test.ts" },
    { ruleId: "js/incomplete-url-substring-sanitization", path: "apps/hub/src/lib/connection-policy.test.ts" },
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts" },
    { ruleId: "js/user-controlled-bypass", path: "scripts/e2e/jwks-server.mjs" }
  ])]);
  assert.equal(result.ok, true);
  assert.equal(result.totalResults, 4);
  assert.deepEqual(result.violations, []);
});

test("CodeQL policy fails closed on an unreviewed finding", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/redos", path: "scripts/deploy-production.mjs" }
  ])]);
  assert.equal(result.ok, false);
  assert.equal(result.violations[0]?.reason, "unreviewed-finding");
});

test("CodeQL policy rejects additional findings even on an accepted rule and path", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts" },
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts" }
  ])]);
  assert.equal(result.ok, false);
  assert.equal(result.violations.at(-1)?.reason, "accepted-finding-count-exceeded");
});

test("CodeQL policy normalizes GitHub workspace artifact paths", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/user-controlled-bypass", path: "file:///github/workspace/scripts/e2e/jwks-server.mjs" }
  ])]);
  assert.equal(result.ok, true);
});
