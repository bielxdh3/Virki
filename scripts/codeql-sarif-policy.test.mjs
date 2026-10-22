import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCodeqlSarif } from "./codeql-sarif-policy.mjs";
import { codeqlDocument } from "./fixtures/codeql-documented-sarif.mjs";

const sarif = codeqlDocument;

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

const accepted = {
  ruleId: "js/file-access-to-http", path: "scripts/e2e/access-token.mts",
  lineFingerprint: "90e07734df8b1ab3:1", columnFingerprint: "6"
};

test("CodeQL documented driver/version and optional ruleIndex are accepted", () => {
  const document = sarif([accepted]);
  const run = document.runs[0];
  const result = run.results[0];
  assert.equal(result.ruleIndex, run.tool.driver.rules.findIndex((rule) => rule.id === accepted.ruleId));
  assert.equal(evaluateCodeqlSarif([document]).ok, true);
  result.rule = { id: accepted.ruleId, index: result.ruleIndex };
  assert.equal(evaluateCodeqlSarif([document]).ok, true);
  delete result.ruleIndex;
  delete result.rule;
  delete result.locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(evaluateCodeqlSarif([document]).ok, true);
});

test("CodeQL documented zero findings with zero artifacts is structurally valid", () => {
  const document = sarif([]);
  assert.equal(document.runs[0].artifacts.length, 0);
  assert.deepEqual(evaluateCodeqlSarif([document]), {
    ok: true, totalResults: 0, acceptedResults: 0, violations: []
  });
});

test("CodeQL grouped-by-pack rules resolve only through explicit tool component references", () => {
  const document = sarif([accepted]);
  const run = document.runs[0];
  const descriptor = run.tool.driver.rules.find((rule) => rule.id === accepted.ruleId);
  run.tool.driver.rules = run.tool.driver.rules.filter((rule) => rule.id !== accepted.ruleId);
  run.tool.extensions = [{ name: "codeql/javascript-queries", rules: [descriptor] }];
  const result = run.results[0];
  result.ruleIndex = 0;
  result.rule = { id: accepted.ruleId, index: 0, toolComponent: { index: 0 } };
  assert.equal(evaluateCodeqlSarif([document]).ok, true);

  delete result.rule.toolComponent;
  assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  result.rule.toolComponent = { index: 1 };
  assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  result.rule.toolComponent = { index: 0 };
  result.ruleIndex = 5;
  assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
});

test("CodeQL zero findings with grouped rules and no driver rules remains valid", () => {
  const document = sarif([]);
  const run = document.runs[0];
  run.tool.extensions = [{ name: "codeql/javascript-queries", rules: run.tool.driver.rules }];
  run.tool.driver.rules = [];
  assert.equal(evaluateCodeqlSarif([document]).ok, true);
});

test("CodeQL rule components with no rules are allowed and driver index -1 resolves correctly", () => {
  const document = sarif([accepted]);
  const result = document.runs[0].results[0];
  document.runs[0].tool.extensions = [{ name: "codeql/no-rules" }];
  result.rule = { toolComponent: { index: -1 }, index: result.ruleIndex };
  assert.equal(evaluateCodeqlSarif([document]).ok, true);
});

test("CodeQL policy refuses fake or unversioned driver and missing exporter proof", () => {
  for (const mutation of [
    (run) => { run.tool.driver.name = "CodeQL"; },
    (run) => { run.tool.driver.organization = "Untrusted"; },
    (run) => { delete run.tool.driver.version; },
    (run) => { run.tool.driver.semanticVersion = run.tool.driver.version; delete run.tool.driver.version; },
    (run) => { delete run.properties; },
    (run) => { run.tool.driver.rules = []; },
    (run) => { run.tool.driver.rules.push(run.tool.driver.rules[0]); },
    (run) => { run.automationDetails = { id: "/language:python/" }; }
  ]) {
    const document = sarif([]);
    mutation(document.runs[0]);
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
});

test("CodeQL policy rejects inconsistent rule references, truncated findings and artifact indexes", () => {
  for (const mutation of [
    (run, result) => { delete result.ruleId; },
    (run, result) => { delete result.message; },
    (run, result) => { result.ruleIndex = 0; },
    (run, result) => { result.rule = { id: "js/path-injection" }; },
    (run, result) => { result.rule = { index: 0 }; },
    (run, result) => { result.locations = []; },
    (run, result) => { delete result.locations[0].physicalLocation.artifactLocation.uri; delete result.locations[0].physicalLocation.artifactLocation.index; },
    (run, result) => { result.locations[0].physicalLocation.artifactLocation.index = 9; },
    (run, result) => { result.locations[0].physicalLocation.artifactLocation.index = -1; },
    (run, result) => { result.locations[0].physicalLocation.artifactLocation.index = 0; run.artifacts[0].location.uri = "other/file.ts"; },
    (run) => { run.artifacts = []; },
    (run) => { run.artifacts.push(run.artifacts[0]); },
    (run) => { run.artifacts[0].location.index = 12; },
    (run) => { run.artifacts[0].location.uri = "../scripts/e2e/access-token.mts"; }
  ]) {
    const document = sarif([accepted]);
    mutation(document.runs[0], document.runs[0].results[0]);
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
});

test("CodeQL policy rejects duplicate reviewed findings across files and runs", () => {
  const document = sarif([accepted, accepted]);
  const result = evaluateCodeqlSarif([document]);
  assert.equal(result.ok, false);
  assert.equal(result.violations[0]?.reason, "accepted-finding-count-exceeded");
  assert.throws(() => evaluateCodeqlSarif([document, document]), /Invalid SARIF/u);
  document.runs.push(structuredClone(document.runs[0]));
  assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
});

test("CodeQL policy rejects unsuccessful scan diagnostics when actually present", () => {
  for (const invocations of [
    [{ executionSuccessful: false }],
    [{ executionSuccessful: true, toolExecutionNotifications: [{ level: "error" }] }],
    [{ executionSuccessful: true, toolExecutionNotifications: [{ level: "note", descriptor: { id: "js/diagnostics/extraction-errors" } }] }]
  ]) {
    const document = sarif([]);
    document.runs[0].invocations = invocations;
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
});

test("CodeQL policy rejects path spoofing against reviewed fingerprints", () => {
  for (const path of [
    "file:///tmp/github/workspace/scripts/e2e/access-token.mts",
    "file:///etc/scripts/e2e/access-token.mts",
    "../scripts/e2e/access-token.mts",
    "scripts/other/../e2e/access-token.mts",
    "scripts//e2e/access-token.mts",
    "scripts/%2e%2e/e2e/access-token.mts",
    "scripts\\e2e\\access-token.mts"
  ]) {
    const document = sarif([{ ...accepted, path }]);
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
});
