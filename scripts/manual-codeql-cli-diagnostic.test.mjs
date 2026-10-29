import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  PINNED_DIAGNOSTIC,
  inspectUntrustedCodeqlCliDocument,
  verifyPinnedManualCodeqlCliSarif,
} from "./lib/manual-codeql-cli-diagnostic.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scratchRoot = path.resolve(projectRoot, "..", "_scratch-w50-codeql-20261029");
const authenticSarif = path.join(scratchRoot, "codeql-results", "c3ea768-js-security-extended.sarif");
const diagnosticEntry = path.join(projectRoot, "scripts", "manual-codeql-cli-diagnostic.mjs");
const deepCopy = object => JSON.parse(JSON.stringify(object));

function littleCliDocument() {
  const file = "infra/offline/trusted-host-entry.mjs";
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "CodeQL", organization: "GitHub", semanticVersion: "2.27.3",
        rules: [{ id: "js/file-system-race" }] } },
      properties: { "semmle.formatSpecifier": "sarifv2.1.0" },
      automationDetails: { id: "/language:javascript-typescript/" },
      artifacts: [{ location: { uri: file, uriBaseId: "%SRCROOT%" } }],
      results: [{ ruleId: "js/file-system-race", ruleIndex: 0,
        message: { text: "Sample unsafe filesystem access" },
        locations: [{ physicalLocation: { artifactLocation: { uri: file, uriBaseId: "%SRCROOT%", index: 0 },
          region: { startLine: 75 } } }] }],
      invocations: [{ executionSuccessful: true, toolExecutionNotifications: [
        ...["js/baseline/expected-extracted-files", "js/diagnostics/successfully-extracted-files"].map(id => ({
          descriptor: { id }, level: "none",
          locations: [{ physicalLocation: { artifactLocation: { uri: file, uriBaseId: "%SRCROOT%", index: 0 } } }],
        })),
      ] }],
    }],
  };
}

test("RED: authentic pinned CodeQL CLI 2.27.3 bytes yield detailed NO-GO for 72 findings, 458/459 and missing independent execution", t => {
  if (!existsSync(authenticSarif)) return t.skip("original read-only W50 SARIF fixture unavailable");
  const bytes = readFileSync(authenticSarif);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), PINNED_DIAGNOSTIC.sarifSha256);
  const result = verifyPinnedManualCodeqlCliSarif(bytes);
  assert.equal(result.status, "NO_GO");
  assert.equal(result.gateDecision, "NO_GO");
  assert.equal(result.authorizesRelease, false);
  assert.equal(result.trustedScannerExecution, false);
  assert.equal(result.sourceCommit, PINNED_DIAGNOSTIC.sourceCommit);
  assert.equal(result.counts.findings, 72);
  assert.equal(result.counts.expectedJsTs, 459);
  assert.equal(result.counts.extractedExpectedJsTs, 458);
  assert.deepEqual(result.missingExpectedJsTs, ["infra/offline/fixtures/fake-image-import-docker"]);
  assert.ok(result.blockers.includes("UNADJUDICATED_FINDINGS"));
  assert.ok(result.blockers.includes("INCOMPLETE_JS_TS_EXTRACTION"));
  assert.ok(result.blockers.includes("NO_INDEPENDENT_SCANNER_EXECUTION_ATTESTATION"));
});

test("RED: artificial CodeQL driver claims and tampered bytes never impersonate the fixed SARIF", () => {
  const input = littleCliDocument();
  assert.equal(inspectUntrustedCodeqlCliDocument(input).status, "NO_GO");
  for (const change of [
    run => { run.tool.driver.name = "CodeQL command-line toolchain"; },
    run => { run.tool.driver.organization = "Other"; },
    run => { run.tool.driver.semanticVersion = "2.27.4"; },
    run => { delete run.tool.driver.semanticVersion; run.tool.driver.version = "2.27.3"; },
    run => { run.tool.driver.name = "CodeQL"; run.tool.driver.semanticVersion = "2.27.3"; run.properties["semmle.formatSpecifier"] = "custom"; },
  ]) {
    const forged = deepCopy(input);
    change(forged.runs[0]);
    assert.equal(inspectUntrustedCodeqlCliDocument(forged).status, "INVALID");
    assert.equal(verifyPinnedManualCodeqlCliSarif(Buffer.from(JSON.stringify(forged))).status, "INVALID");
  }
});

test("RED: false success and count/suppression spoofing fail closed", () => {
  const valid = littleCliDocument();
  const noFindings = deepCopy(valid);
  noFindings.runs[0].results = [];
  const result = inspectUntrustedCodeqlCliDocument(noFindings);
  assert.equal(result.status, "NO_GO");
  assert.equal(result.gateDecision, "NO_GO");
  assert.equal(result.trustedScannerExecution, false);
  assert.ok(result.blockers.includes("NO_INDEPENDENT_SCANNER_EXECUTION_ATTESTATION"));

  const unknown = deepCopy(valid);
  delete unknown.runs[0].invocations[0].executionSuccessful;
  assert.equal(inspectUntrustedCodeqlCliDocument(unknown).status, "INVALID");
  const failed = deepCopy(valid);
  failed.runs[0].invocations[0].executionSuccessful = false;
  assert.equal(inspectUntrustedCodeqlCliDocument(failed).status, "INVALID");
  for (const change of [
    run => { run.results[0].ruleIndex = 999; },
    run => { run.results[0].ruleId = "js/arbitrary"; },
    run => { run.results[0].message = {}; },
    run => { run.invocations[0].toolExecutionNotifications[1].descriptor.id = "js/baseline/expected-extracted-files"; },
  ]) {
    const altered = deepCopy(valid);
    change(altered.runs[0]);
    assert.equal(inspectUntrustedCodeqlCliDocument(altered).status, "INVALID");
  }
});

test("RED: traversal, mismatched artifact identities, duplicate telemetry, and forged extraction paths are invalid", () => {
  for (const change of [
    run => { run.artifacts[0].location.uri = "../outside.mjs"; },
    run => { run.results[0].locations[0].physicalLocation.artifactLocation.uri = "/tmp/evil.mjs"; },
    run => { run.results[0].locations[0].physicalLocation.artifactLocation.index = 42; },
    run => { run.invocations[0].toolExecutionNotifications[0].locations[0].physicalLocation.artifactLocation.uri = "../../traversal.mjs"; },
    run => { run.invocations[0].toolExecutionNotifications.push(deepCopy(run.invocations[0].toolExecutionNotifications[0])); },
    run => { run.invocations[0].toolExecutionNotifications[1].locations[0].physicalLocation.artifactLocation.uri = "malicious.mjs"; },
    run => { run.automationDetails.id = "/language:python/"; },
  ]) {
    const altered = littleCliDocument();
    change(altered.runs[0]);
    assert.equal(inspectUntrustedCodeqlCliDocument(altered).status, "INVALID");
  }
});

test("RED: changing the genuine SARIF result count or adding fake 459th extraction invalidates its independent digest", t => {
  if (!existsSync(authenticSarif)) return t.skip("original read-only W50 SARIF fixture unavailable");
  const doc = JSON.parse(readFileSync(authenticSarif, "utf8"));
  doc.runs[0].results.pop();
  assert.equal(verifyPinnedManualCodeqlCliSarif(Buffer.from(JSON.stringify(doc))).status, "INVALID");
  const full = JSON.parse(readFileSync(authenticSarif, "utf8"));
  const baseline = full.runs[0].invocations[0].toolExecutionNotifications.find(
    notice => notice.descriptor?.id === "js/baseline/expected-extracted-files" &&
      notice.locations?.[0]?.physicalLocation?.artifactLocation?.uri === "infra/offline/fixtures/fake-image-import-docker");
  assert.ok(baseline);
  full.runs[0].invocations[0].toolExecutionNotifications.push({ ...deepCopy(baseline),
    descriptor: { id: "js/diagnostics/successfully-extracted-files", index: 0 } });
  assert.equal(verifyPinnedManualCodeqlCliSarif(Buffer.from(JSON.stringify(full))).status, "INVALID");
});

test("RED: CLI accepts no caller-selected file, source SHA, output override or trust pin", () => {
  const spawn = spawnSync(process.execPath, [diagnosticEntry, "--sarif", "attacker.json"], {
    cwd: projectRoot, encoding: "utf8", timeout: 10000,
  });
  assert.equal(spawn.status, 2);
  assert.match(spawn.stderr, /fixed-input.*argument|no arguments/iu);
});

test("RED→GREEN: no-argument CLI binds archived source but never asserts checkout execution proof", t => {
  if (!existsSync(authenticSarif)) return t.skip("original read-only W50 SARIF fixture unavailable");
  const spawn = spawnSync(process.execPath, [diagnosticEntry], {
    cwd: projectRoot, encoding: "utf8", timeout: 15000,
  });
  assert.equal(spawn.status, 1);
  const report = JSON.parse(spawn.stdout);
  assert.equal(report.sourceCommit, PINNED_DIAGNOSTIC.sourceCommit);
  assert.equal(report.sourceCheckoutMatchesPin, false);
  assert.ok(report.blockers.includes("PINNED_SOURCE_CHECKOUT_UNVERIFIED"));
  assert.equal(report.sourceCheckoutIsScannerAttestation, false);
  assert.equal(report.gateDecision, "NO_GO");
  assert.equal(report.trustedScannerExecution, false);
  assert.equal(report.authorizesRelease, false);
});

test("RED: CLI must not spawn Git or other native commands while parsing archived SARIF", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-codeql-child-exec-"));
  try {
    const marker = path.join(root, "native-process-launched");
    const preload = path.join(root, "intercept.cjs");
    writeFileSync(preload, `const cp = require('node:child_process');\nconst fs = require('node:fs');\ncp.spawnSync = (...args) => { fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify(args.slice(0, 1))); return { status: 1, stdout: '', stderr: '' }; };\nrequire('node:module').syncBuiltinESMExports();\n`);
    const run = spawnSync(process.execPath, ["--require", preload, diagnosticEntry], {
      cwd: projectRoot, encoding: "utf8", timeout: 15000,
    });
    assert.equal(run.status, 1);
    assert.equal(existsSync(marker), false, "untrusted local Git config must not cause child process execution");
    const report = JSON.parse(run.stdout);
    assert.equal(report.gateDecision, "NO_GO");
    assert.equal(report.trustedScannerExecution, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("RED: attacker-controlled PATH cannot execute a fake Git during source diagnostics", { skip: process.platform === "win32" }, () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "virki-codeql-cli-path-"));
  try {
    const marker = path.join(root, "fake-git-executed");
    const fake = path.join(root, "git");
    writeFileSync(fake, `#!/bin/sh\nprintf 'executed' > '${marker}'\nexit 1\n`);
    chmodSync(fake, 0o755);
    const run = spawnSync(process.execPath, [diagnosticEntry], {
      cwd: projectRoot,
      encoding: "utf8",
      timeout: 15000,
      env: { ...process.env, PATH: `${root}${path.delimiter}${process.env.PATH ?? ""}` },
    });
    assert.equal(run.status, 1);
    assert.equal(existsSync(marker), false, "untrusted PATH must not execute a fake Git");
    const report = JSON.parse(run.stdout);
    assert.equal(report.gateDecision, "NO_GO");
    assert.equal(report.trustedScannerExecution, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
