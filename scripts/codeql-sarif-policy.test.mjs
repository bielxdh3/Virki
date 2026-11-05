import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateCodeqlSarif } from "./codeql-sarif-policy.mjs";
import { codeqlDocument, codeqlHostedCliDocument } from "./fixtures/codeql-documented-sarif.mjs";

const sarif = codeqlDocument;

// Source-of-truth test inputs are the 42 independently reviewed dispositions.
// This synthetic document only exercises fail-closed policy matching: real
// scanner provenance must still come from an exact-SHA hosted CodeQL run.
const reviewedLedger = readFileSync(new URL("../docs/security/codeql-reviewed-20261105.md", import.meta.url), "utf8");
const reviewed42 = reviewedLedger.split(/\r?\n/u)
  .filter((line) => /^\|\s*\d+\s*\|/u.test(line))
  .map((line) => {
    const fields = line.replaceAll("\\|", "/").split("|").map((value) => value.trim());
    const index = Number(fields[1]);
    const source = /^(.*):(\d+)$/u.exec(fields[4]);
    assert.ok(source, `invalid reviewed source for index ${index}`);
    assert.equal(fields[2], "GO: PEER-REVIEWED BENIGN");
    return {
      index,
      ruleId: fields[3],
      path: source[1],
      sourceLine: Number(source[2]),
      lineFingerprint: fields[5],
      columnFingerprint: fields[6]
    };
  });

const fixedFdRace = {
  index: 10,
  ruleId: "js/file-system-race",
  path: "infra/offline/native-supervisor/run-disposable-fd-lifecycle-test.mjs",
  lineFingerprint: "bc6600c95727700f:1",
  columnFingerprint: "11"
};

test("42 CodeQL dispositions are unique, individually documented and all accepted", () => {
  assert.equal(reviewed42.length, 42);
  assert.equal(new Set(reviewed42.map((entry) => entry.index)).size, 42);
  assert.ok(!reviewed42.some((entry) => entry.index === 10));
  assert.equal(new Set(reviewed42.map(({ ruleId, path, lineFingerprint, columnFingerprint }) =>
    JSON.stringify([ruleId, path, lineFingerprint, columnFingerprint]))).size, 42);
  for (const item of reviewed42) {
    assert.match(item.ruleId, /^js\/[a-z0-9-]+$/u);
    assert.match(item.lineFingerprint, /^[a-f0-9]{8,24}:\d+$/u);
    assert.match(item.columnFingerprint, /^\d+$/u);
    assert.ok(Number.isInteger(item.sourceLine) && item.sourceLine > 0);
  }
  const result = evaluateCodeqlSarif([codeqlHostedCliDocument(reviewed42)]);
  assert.equal(result.ok, true, JSON.stringify(result.violations));
  assert.equal(result.totalResults, 42);
  assert.equal(result.acceptedResults, 42);
});

test("real CID pathname race finding #10 is NEVER accepted by historical 46-result policy", () => {
  const result = evaluateCodeqlSarif([codeqlHostedCliDocument([...reviewed42, fixedFdRace])]);
  assert.equal(result.ok, false);
  assert.equal(result.totalResults, 43);
  assert.equal(result.acceptedResults, 42);
  assert.deepEqual(result.violations, [{
    ruleId: fixedFdRace.ruleId,
    path: fixedFdRace.path,
    reason: "unreviewed-finding"
  }]);
});

test("all 42 reviewed CodeQL fingerprints fail closed on altered rule, path, hash, column or duplicate count", () => {
  for (const entry of reviewed42) {
    const variants = [
      { ...entry, ruleId: `${entry.ruleId}-unreviewed` },
      { ...entry, path: `scripts/unreviewed/${entry.path.split("/").at(-1)}` },
      { ...entry, lineFingerprint: `f${entry.lineFingerprint}` },
      { ...entry, columnFingerprint: `${entry.columnFingerprint}1` },
      { ...entry, lineFingerprint: undefined },
      { ...entry, columnFingerprint: undefined }
    ];
    for (const changed of variants) {
      const output = evaluateCodeqlSarif([codeqlHostedCliDocument([changed])]);
      assert.equal(output.ok, false, `mutation accepted for index ${entry.index}`);
      assert.equal(output.violations[0]?.reason, "unreviewed-finding");
    }
    const duplicate = evaluateCodeqlSarif([codeqlHostedCliDocument([entry, entry])]);
    assert.equal(duplicate.ok, false, `duplicate accepted for index ${entry.index}`);
    assert.equal(duplicate.violations[0]?.reason, "accepted-finding-count-exceeded");
  }
});

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

test("CodeQL documented driver/version and consistent ruleIndex are accepted", () => {
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
  assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
});

test("hosted CodeQL 2.27.1 driver and component-scoped rule indexes are accepted", () => {
  const hosted = codeqlHostedCliDocument([accepted]);
  const run = hosted.runs[0];
  const result = run.results[0];
  assert.equal(run.tool.driver.name, "CodeQL");
  assert.equal(run.tool.driver.semanticVersion, "2.27.1");
  assert.equal(run.tool.driver.rules.length, 0);
  assert.equal(run.tool.extensions[1].rules[result.rule.index].id, result.ruleId);
  assert.equal("ruleIndex" in result, false);
  assert.equal(evaluateCodeqlSarif([hosted]).ok, true);
  assert.equal(evaluateCodeqlSarif([codeqlHostedCliDocument([])]).ok, true);

  const unreviewed = codeqlHostedCliDocument([
    { ruleId: "js/path-injection", path: "apps/hub/src/path.ts", lineFingerprint: "new:1", columnFingerprint: "5" }
  ]);
  assert.deepEqual(evaluateCodeqlSarif([unreviewed]).violations.map((violation) => violation.reason),
    ["unreviewed-finding"]);
});

test("hosted CLI metadata must be an exact supported CodeQL driver/version pairing", () => {
  const changes = [
    (run) => { run.tool.driver.name = "CodeQL command-line toolchain"; },
    (run) => { run.tool.driver.organization = "SomeoneElse"; },
    (run) => { delete run.tool.driver.semanticVersion; },
    (run) => { run.tool.driver.semanticVersion = "2.27.1-not-semver-!"; },
    (run) => { run.tool.driver.semanticVersion = "2.27"; },
    (run) => { run.tool.driver.semanticVersion = "02.27.1"; },
    (run) => { run.tool.driver.semanticVersion = "2.27.1-alpha.01"; },
    (run) => { run.tool.driver.semanticVersion = "2.27.1+"; },
    (run) => { run.tool.driver.version = "2.27.1"; },
    (run) => { delete run.tool.driver.rules; },
  ];
  for (const mutate of changes) {
    const hosted = codeqlHostedCliDocument([]);
    mutate(hosted.runs[0]);
    assert.throws(() => evaluateCodeqlSarif([hosted]), /Invalid SARIF/u);
  }
  const legacy = codeqlDocument([]);
  legacy.runs[0].tool.driver.semanticVersion = legacy.runs[0].tool.driver.version;
  assert.throws(() => evaluateCodeqlSarif([legacy]), /Invalid SARIF/u);
});

test("hosted CLI results reject ambiguous, missing and inconsistent rule component indexes", () => {
  const changes = [
    (run, result) => { delete result.rule.index; },
    (run, result) => { result.rule.index = "1"; },
    (run, result) => { result.rule.index = 999; },
    (run, result) => { result.rule.index = -1; },
    (run, result) => { result.rule.index = 0; },
    (run, result) => { result.ruleId = "js/unknown"; },
    (run, result) => { result.rule.id = "js/unknown"; },
    (run, result) => { delete result.rule.toolComponent; },
    (run, result) => { result.rule.toolComponent = { index: -1 }; },
    (run, result) => { result.rule.toolComponent = { index: 2 }; },
    (run, result) => { result.rule.toolComponent = { index: 4 }; },
    (run, result) => { result.ruleIndex = result.rule.index + 1; },
    (run, result) => { run.tool.extensions[1].rules[result.rule.index].id = "js/unknown"; },
    (run) => { run.tool.extensions[1].rules.push(run.tool.extensions[1].rules[0]); },
    (run) => { run.tool.extensions[1].rules = []; }
  ];
  for (const mutate of changes) {
    const hosted = codeqlHostedCliDocument([accepted]);
    mutate(hosted.runs[0], hosted.runs[0].results[0]);
    assert.throws(() => evaluateCodeqlSarif([hosted]), /Invalid SARIF/u);
  }
  const both = codeqlHostedCliDocument([accepted]);
  both.runs[0].results[0].ruleIndex = both.runs[0].results[0].rule.index;
  assert.equal(evaluateCodeqlSarif([both]).ok, true);
});

test("RED→GREEN: SARIF 2.1 artifactLocation index, rule and invocation consistency fail closed", () => {
  const valid = sarif([accepted]);
  assert.equal(evaluateCodeqlSarif([valid]).ok, true,
    "canonical SARIF artifact has a location, not a required top-level index");
  valid.runs[0].artifacts[0].location.index = 0;
  assert.equal(evaluateCodeqlSarif([valid]).ok, true,
    "an artifactLocation index is allowed when it matches its array position");
  for (const mutation of [
    (run) => { run.artifacts[0].location.index = 999; },
    (run) => { run.artifacts[0].location.index = "0"; },
    (run) => { delete run.results[0].ruleIndex; },
    (run) => { run.results[0].ruleIndex = "1"; },
    (run) => { run.invocations = [{ executionSuccessful: "false" }]; },
    (run) => { run.properties["semmle.formatSpecifier"] = "not-a-codeql-format"; },
  ]) {
    const document = sarif([accepted]);
    mutation(document.runs[0]);
    assert.throws(() => evaluateCodeqlSarif([document]), /Invalid SARIF/u);
  }
  for (const format of ["sarifv2.1.0", "sarif-latest"]) {
    const document = sarif([]);
    document.runs[0].properties["semmle.formatSpecifier"] = format;
    assert.equal(evaluateCodeqlSarif([document]).ok, true);
  }
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
