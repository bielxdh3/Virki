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

// Independently verified NEW hosted PR #102 post-fix scanner residual.
// The vulnerable pre-fix fingerprint above remains permanently unaccepted.
const postFixCidOpenReviewed = {
  ruleId: "js/file-system-race",
  path: "infra/offline/native-supervisor/run-disposable-fd-lifecycle-test.mjs",
  lineFingerprint: "e0fc364b7545cc38:1",
  columnFingerprint: "11"
};

// Genuine post-merge PUSH CodeQL run 42065751041 (main afcac349): 51 results,
// compared by exact fingerprint SET with PR105's 46-result hosted SARIF.
// These are distinct new paths and require a separately reasoned disposition;
// the original exploitable CID pathname race remains permanently disallowed.
const postMergePushFindings = [
  { ruleId: "js/insufficient-password-hash", path: "packages/auth/src/index.ts",
    lineFingerprint: "eab442f12c97c7a3:1", columnFingerprint: "35" },
  { ruleId: "js/insufficient-password-hash", path: "packages/auth/src/passkeys.ts",
    lineFingerprint: "aa299375b7be0290:1", columnFingerprint: "101" },
  { ruleId: "js/clear-text-logging", path: "scripts/oidc-node-disposable-postgres.mjs",
    lineFingerprint: "a3ae442c044fad66:1", columnFingerprint: "14" },
  { ruleId: "js/insecure-temporary-file", path: "infra/offline/trusted-host-entry.mjs",
    lineFingerprint: "b02a714376336c8a:1", columnFingerprint: "26" }
];

// Exact findings captured from public-repository CodeQL security-extended,
// run 43136441828 attempt 2 on SHA 261177e3. The independent review
// explicitly does NOT promote the offline preflight into staging authority.
const publicHostedFindings = [
  { ruleId: "js/file-system-race", path: "scripts/staging-otp-preflight.mjs",
    lineFingerprint: "1a5be53b7e24b39c:1", columnFingerprint: "5" },
  { ruleId: "js/user-controlled-bypass", path: "scripts/integration/loopback-smtp-sink.mjs",
    lineFingerprint: "a7bddb165db5ff66:1", columnFingerprint: "4" }
];
const publicReviewedLedger = readFileSync(new URL("../docs/security/codeql-reviewed-public-20261112.md", import.meta.url), "utf8");

test("public hosted CodeQL findings require two individually documented exact dispositions", () => {
  assert.equal(publicHostedFindings.length, 2);
  for (const entry of publicHostedFindings) {
    const key = `${entry.ruleId}|${entry.path}|${entry.lineFingerprint}|${entry.columnFingerprint}`;
    assert.ok(publicReviewedLedger.includes(`\`${key}\``), `undocumented CodeQL finding: ${entry.path}`);
  }
  const result = evaluateCodeqlSarif([codeqlHostedCliDocument(publicHostedFindings)]);
  assert.deepEqual(result, { ok: true, totalResults: 2, acceptedResults: 2, violations: [] });
});

test("public hosted CodeQL dispositions fail closed on changed location, rule, missing fingerprints and duplicates", () => {
  for (const entry of publicHostedFindings) {
    for (const mutation of [
      { ...entry, ruleId: `${entry.ruleId}-unreviewed` },
      { ...entry, path: `scripts/unreviewed/${entry.path.split("/").at(-1)}` },
      { ...entry, lineFingerprint: `f${entry.lineFingerprint}` },
      { ...entry, columnFingerprint: String(Number(entry.columnFingerprint) + 1) },
      { ...entry, lineFingerprint: undefined },
      { ...entry, columnFingerprint: undefined }
    ]) {
      const result = evaluateCodeqlSarif([codeqlHostedCliDocument([mutation])]);
      assert.equal(result.ok, false, `unexpected acceptance: ${entry.path}`);
      assert.equal(result.violations[0]?.reason, "unreviewed-finding");
    }
    const duplicate = evaluateCodeqlSarif([codeqlHostedCliDocument([entry, entry])]);
    assert.deepEqual(duplicate.violations, [{
      ruleId: entry.ruleId, path: entry.path, reason: "accepted-finding-count-exceeded"
    }]);
  }
  const originalPathRace = evaluateCodeqlSarif([codeqlHostedCliDocument([
    ...publicHostedFindings, fixedFdRace
  ])]);
  assert.equal(originalPathRace.ok, false);
  assert.deepEqual(originalPathRace.violations, [{
    ruleId: fixedFdRace.ruleId, path: fixedFdRace.path, reason: "unreviewed-finding"
  }]);
});

test("postmerge PUSH findings require four individually documented exact dispositions", () => {
  assert.equal(postMergePushFindings.length, 4);
  assert.equal(new Set(postMergePushFindings.map(({ ruleId, path, lineFingerprint, columnFingerprint }) =>
    JSON.stringify([ruleId, path, lineFingerprint, columnFingerprint]))).size, 4);
  for (const { ruleId, path, lineFingerprint, columnFingerprint } of postMergePushFindings) {
    assert.ok(reviewedLedger.includes(`\`${ruleId}|${path}|${lineFingerprint}|${columnFingerprint}\``),
      `missing independent disposition: ${ruleId} at ${path}`);
  }
  const push = evaluateCodeqlSarif([codeqlHostedCliDocument([
    ...reviewed42, postFixCidOpenReviewed, ...postMergePushFindings
  ])]);
  assert.equal(push.ok, true, JSON.stringify(push.violations));
  assert.equal(push.totalResults, 47);
  assert.equal(push.acceptedResults, 47);
  const oldRace = evaluateCodeqlSarif([codeqlHostedCliDocument([
    ...postMergePushFindings, fixedFdRace
  ])]);
  assert.equal(oldRace.ok, false);
  assert.deepEqual(oldRace.violations, [{
    ruleId: fixedFdRace.ruleId, path: fixedFdRace.path, reason: "unreviewed-finding"
  }]);
});

test("each postmerge PUSH disposition rejects rule, path, hash, column, missing metadata and duplicates", () => {
  for (const entry of postMergePushFindings) {
    for (const mutated of [
      { ...entry, ruleId: entry.ruleId + "-unreviewed" },
      { ...entry, path: "test/unreviewed/" + entry.path.split("/").at(-1) },
      { ...entry, lineFingerprint: "0" + entry.lineFingerprint },
      { ...entry, columnFingerprint: String(Number(entry.columnFingerprint) + 1) },
      { ...entry, lineFingerprint: undefined },
      { ...entry, columnFingerprint: undefined }
    ]) {
      const result = evaluateCodeqlSarif([codeqlHostedCliDocument([mutated])]);
      assert.equal(result.ok, false, `mutated postmerge finding unexpectedly accepted: ${entry.path}`);
      assert.equal(result.violations[0]?.reason, "unreviewed-finding");
    }
    const duplicated = evaluateCodeqlSarif([codeqlHostedCliDocument([entry, entry])]);
    assert.equal(duplicated.ok, false, `duplicate postmerge finding accepted: ${entry.path}`);
    assert.equal(duplicated.violations[0]?.reason, "accepted-finding-count-exceeded");
  }
});

test("post-fix CID FD-open residual is individually reviewed, but original CID path race is still denied", () => {
  const newScanner = evaluateCodeqlSarif([codeqlHostedCliDocument([
    ...reviewed42, postFixCidOpenReviewed
  ])]);
  assert.equal(newScanner.ok, true, JSON.stringify(newScanner.violations));
  assert.equal(newScanner.totalResults, 43);
  assert.equal(newScanner.acceptedResults, 43);

  const both = evaluateCodeqlSarif([codeqlHostedCliDocument([
    postFixCidOpenReviewed, fixedFdRace
  ])]);
  assert.equal(both.ok, false);
  assert.equal(both.acceptedResults, 1);
  assert.deepEqual(both.violations, [{
    ruleId: fixedFdRace.ruleId,
    path: fixedFdRace.path,
    reason: "unreviewed-finding"
  }]);
});

test("new post-fix CID residual cannot accept any changed fingerprint, path, rule or duplicate", () => {
  const variants = [
    { ...postFixCidOpenReviewed, ruleId: "js/file-system-race-unreviewed" },
    { ...postFixCidOpenReviewed, path: "infra/offline/native-supervisor/other.mjs" },
    { ...postFixCidOpenReviewed, lineFingerprint: "be0fc364b7545cc38:1" },
    { ...postFixCidOpenReviewed, columnFingerprint: "12" },
    { ...postFixCidOpenReviewed, lineFingerprint: undefined },
    { ...postFixCidOpenReviewed, columnFingerprint: undefined }
  ];
  for (const modified of variants) {
    const result = evaluateCodeqlSarif([codeqlHostedCliDocument([modified])]);
    assert.equal(result.ok, false);
    assert.equal(result.violations[0]?.reason, "unreviewed-finding");
  }
  const duplicated = evaluateCodeqlSarif([codeqlHostedCliDocument([
    postFixCidOpenReviewed, postFixCidOpenReviewed
  ])]);
  assert.equal(duplicated.ok, false);
  assert.equal(duplicated.violations[0]?.reason, "accepted-finding-count-exceeded");
});

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
