import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCodeqlSarif } from "./codeql-sarif-policy.mjs";

function sarif(results) {
  return {
    version: "2.1.0",
    runs: [{
      results: results.map(({ ruleId, path, lineFingerprint, columnFingerprint }) => ({
        ruleId,
        locations: [{ physicalLocation: { artifactLocation: { uri: path } } }],
        ...(lineFingerprint && columnFingerprint
          ? { partialFingerprints: {
            primaryLocationLineHash: lineFingerprint,
            primaryLocationStartColumnFingerprint: columnFingerprint
          } }
          : {})
      }))
    }]
  };
}

test("CodeQL policy accepts only the reviewed test-harness findings", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/incomplete-url-substring-sanitization", path: "apps/hub/src/lib/connection-policy.test.ts", lineFingerprint: "da86d8805094bfc3:1", columnFingerprint: "13" },
    { ruleId: "js/incomplete-url-substring-sanitization", path: "apps/hub/src/lib/connection-policy.test.ts", lineFingerprint: "60631c9015b3ab5a:1", columnFingerprint: "13" },
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts", lineFingerprint: "90e07734df8b1ab3:1", columnFingerprint: "6" },
    { ruleId: "js/user-controlled-bypass", path: "scripts/e2e/jwks-server.mjs", lineFingerprint: "ebcb3e6db1dd4911:1", columnFingerprint: "33" }
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
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts", lineFingerprint: "90e07734df8b1ab3:1", columnFingerprint: "6" },
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts", lineFingerprint: "90e07734df8b1ab3:1", columnFingerprint: "6" }
  ])]);
  assert.equal(result.ok, false);
  assert.equal(result.violations.at(-1)?.reason, "accepted-finding-count-exceeded");
});

test("CodeQL policy rejects new findings that reuse an approved rule and path", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts", lineFingerprint: "new-finding:1", columnFingerprint: "6" }
  ])]);
  assert.equal(result.ok, false);
  assert.equal(result.violations[0]?.reason, "unreviewed-finding");
});

test("CodeQL policy fails closed on malformed SARIF structure", () => {
  for (const document of [
    { version: "2.1.0" },
    { version: "2.1.0", runs: {} },
    { version: "2.1.0", runs: [{ results: {} }] }
  ]) {
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
});

test("CodeQL policy normalizes GitHub workspace artifact paths", () => {
  const result = evaluateCodeqlSarif([sarif([
    { ruleId: "js/user-controlled-bypass", path: "file:///github/workspace/scripts/e2e/jwks-server.mjs", lineFingerprint: "ebcb3e6db1dd4911:1", columnFingerprint: "33" }
  ])]);
  assert.equal(result.ok, true);
});
