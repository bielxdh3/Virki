import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { validateOfflineCiEvidence } from "./lib/offline-ci-evidence.mjs";

const revision = "fbac177b91414ff8d047cef40cc9920d0ba882cd";
const emptySha256 = createHash("sha256").update(Buffer.alloc(0)).digest("hex");
const stageNames = [
  "tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check",
];

function goodManifest() {
  const base = Date.parse("2026-10-21T14:00:00Z");
  return {
    runId: "e5f8bc3d5c",
    sourceBranch: "main",
    sourceHead: revision,
    startedUtc: new Date(base).toISOString(),
    finishedUtc: new Date(base + 300_000).toISOString(),
    nodeVersion: "v22.23.3",
    npmVersion: "10.9.9",
    stagedPatchSha256: emptySha256,
    workingTreePatchSha256: emptySha256,
    untrackedFiles: [],
    unitTestsFailureCount: 0,
    unitTestsFailures: [],
    integrationTestsFailureCount: 0,
    integrationTestsFailures: [],
    productionOperationsFailureCount: 0,
    productionOperationsFailures: [],
    exitCode: 0,
    failedStages: [],
    stages: stageNames.map((name, i) => ({
      name,
      startedUtc: new Date(base + i * 10_000 + 1_000).toISOString(),
      finishedUtc: new Date(base + i * 10_000 + 2_000).toISOString(),
      durationMs: 1_000,
      exitCode: 0,
    })),
  };
}

const bytes = (value) => Buffer.from(JSON.stringify(value), "utf8");

test("accepts a complete clean exact-SHA 19-stage claim and hashes the exact bytes", () => {
  const raw = bytes(goodManifest());
  const accepted = validateOfflineCiEvidence(raw, revision);
  assert.equal(accepted.ok, true);
  assert.equal(accepted.revision, revision);
  assert.equal(accepted.branch, "main");
  assert.equal(accepted.stageCount, 19);
  assert.equal(accepted.manifestSha256, createHash("sha256").update(raw).digest("hex"));
  assert.match(accepted.limitation, /untrusted|not prove|not attest/iu);

  const spaced = Buffer.from(JSON.stringify(goodManifest(), null, 2));
  assert.notEqual(validateOfflineCiEvidence(spaced, revision).manifestSha256, accepted.manifestSha256);
  assert.equal(validateOfflineCiEvidence(new Uint8Array(raw), revision).manifestSha256, accepted.manifestSha256);
});

test("accepts actual isolated Docker cleanup proof but refuses incomplete bootstrap or uncertain cleanup", () => {
  const manifest = goodManifest();
  Object.assign(manifest, {
    dockerMutationJournal: "docker-mutations.jsonl",
    dockerMutationUncertain: false,
    dockerCleanupVerified: true,
    bootstrapVirginTestsLog: "bootstrap-virgin-tests.tap.log",
    bootstrapVirginTestsExitCode: 0,
  });
  assert.equal(validateOfflineCiEvidence(bytes(manifest), revision).stageCount, 19);
  for (const [name, value] of [
    ["dockerMutationUncertain", true], ["dockerCleanupVerified", false],
    ["bootstrapVirginTestsExitCode", 1], ["bootstrapVirginTestsLog", "../../escape"],
  ]) {
    const altered = { ...manifest, [name]: value };
    assert.throws(() => validateOfflineCiEvidence(bytes(altered), revision), name);
  }
  const missing = { ...manifest };
  delete missing.bootstrapVirginTestsExitCode;
  assert.throws(() => validateOfflineCiEvidence(bytes(missing), revision));
});

test("requires exact branch and exact full SHA; branch must be explicitly overridden for pre-merge run", () => {
  const manifest = goodManifest();
  manifest.sourceBranch = "cdx/virki-five-report-security-triage-20261020";
  assert.throws(() => validateOfflineCiEvidence(bytes(manifest), revision));
  assert.equal(validateOfflineCiEvidence(bytes(manifest), revision, manifest.sourceBranch).ok, true);
  assert.throws(() => validateOfflineCiEvidence(bytes(manifest), "F".repeat(40), manifest.sourceBranch));
  assert.throws(() => validateOfflineCiEvidence(bytes(manifest), "f".repeat(40), manifest.sourceBranch));
  assert.throws(() => validateOfflineCiEvidence(bytes(manifest), revision.slice(0, 12), manifest.sourceBranch));
  assert.throws(() => validateOfflineCiEvidence(bytes(manifest), revision, ""));
});

test("rejects malformed, oversized or ambiguous raw bytes", async (suite) => {
  const invalid = [
    "plain string input",
    null,
    {},
    Buffer.alloc(65_537, 32),
    Buffer.from("{"),
    Buffer.from("{}{}"),
    Buffer.from("null"),
    Buffer.from("[]"),
    Buffer.from([0xc3, 0x28]),
    Buffer.concat([bytes(goodManifest()), Buffer.from([0x00])]),
  ];
  for (const [index, raw] of invalid.entries()) {
    await suite.test(`invalid raw input ${index}`, () => {
      assert.throws(() => validateOfflineCiEvidence(raw, revision));
    });
  }
});

test("rejects duplicate root, escaped and nested keys while preserving ordinary pretty JSON", () => {
  const manifest = goodManifest();
  const base = JSON.stringify(manifest);
  const pretty = JSON.stringify(manifest, null, 2);
  assert.equal(validateOfflineCiEvidence(Buffer.from(pretty), revision).ok, true);
  const attempts = [
    base.replace('"exitCode":0', '"exitCode":1,"exitCode":0'),
    base.replace('"exitCode":0', '"exit\\u0043ode":1,"exitCode":0'),
    base.replace('"failedStages":[]', '"failedStages":["masked"],"failedStages":[]'),
    base.replace('"durationMs":1000', '"durationMs":-1,"durationMs":1000'),
    base.replace('"name":"tooling-policy-dependencies"', '"name":"fake","name":"tooling-policy-dependencies"'),
    base.replace('"untrackedFiles":[]', '"untrackedFiles":[{"name":"a","name":"b"}]'),
    base.replace('"stages":[', '"unknownAuthorize":true,"stages":['),
    base.replace('"durationMs":1000', '"unreviewed":true,"durationMs":1000'),
  ];
  for (const [index, altered] of attempts.entries()) {
    assert.notEqual(altered, base, `fixture mutation ${index} must apply`);
    assert.throws(() => validateOfflineCiEvidence(Buffer.from(altered), revision),
      /Invalid offline CI manifest/u, `invalid CI evidence variant ${index} must fail`);
  }
});

test("rejects fabricated, duplicated, partial and nonzero stages", async (suite) => {
  const cases = {
    "missing stage": (m) => { m.stages.pop(); },
    "duplicate stage": (m) => { m.stages[1].name = m.stages[0].name; },
    "unknown stage": (m) => { m.stages[1].name = "fake-security-scan"; },
    "empty stages": (m) => { m.stages = []; },
    "stages object": (m) => { m.stages = {}; },
    "nonzero stage": (m) => { m.stages[4].exitCode = 1; },
    "missing stage exit": (m) => { delete m.stages[3].exitCode; },
    "null stage exit": (m) => { m.stages[3].exitCode = null; },
    "string stage exit": (m) => { m.stages[3].exitCode = "0"; },
    "failed outer exit": (m) => { m.exitCode = 1; },
    "missing outer exit": (m) => { delete m.exitCode; },
    "failedStages nonempty": (m) => { m.failedStages = ["browser-e2e=1"]; },
    "failedStages absent": (m) => { delete m.failedStages; },
    "missing stage interval": (m) => { delete m.stages[0].startedUtc; },
    "missing duration": (m) => { delete m.stages[0].durationMs; },
    "negative duration": (m) => { m.stages[0].durationMs = -1; },
  };
  for (const [name, breakCase] of Object.entries(cases)) {
    await suite.test(name, () => {
      const altered = goodManifest();
      breakCase(altered);
      assert.throws(() => validateOfflineCiEvidence(bytes(altered), revision));
    });
  }
});

test("rejects dirty and incomplete test evidence", async (suite) => {
  const cases = {
    "staged patch": (m) => { m.stagedPatchSha256 = "a".repeat(64); },
    "unstaged patch": (m) => { m.workingTreePatchSha256 = "a".repeat(64); },
    "missing staged patch hash": (m) => { delete m.stagedPatchSha256; },
    "bad patch hash": (m) => { m.workingTreePatchSha256 = "not-a-hash"; },
    "untracked source": (m) => { m.untrackedFiles = ["apps/hub/src/file.ts"]; },
    "untrackedFiles absent": (m) => { delete m.untrackedFiles; },
    "unit test failures": (m) => { m.unitTestsFailureCount = 1; },
    "integration test failures": (m) => { m.integrationTestsFailures = [{ name: "failed case" }]; },
    "operations test failures": (m) => { m.productionOperationsFailureCount = 1; },
  };
  for (const [name, breakCase] of Object.entries(cases)) {
    await suite.test(name, () => {
      const altered = goodManifest();
      breakCase(altered);
      assert.throws(() => validateOfflineCiEvidence(bytes(altered), revision));
    });
  }
});

test("rejects malformed dates, out-of-run stages and unsupported runtime versions", async (suite) => {
  const cases = {
    "reverse run time": (m) => { m.finishedUtc = "2026-10-21T13:59:59Z"; },
    "impossible calendar date": (m) => { m.startedUtc = "2026-02-30T14:00:00Z"; },
    "unbounded run duration": (m) => { m.finishedUtc = "2026-11-21T14:00:00Z"; },
    "stage after outer finish": (m) => { m.stages.at(-1).finishedUtc = "2026-10-21T15:00:00Z"; },
    "stage before outer start": (m) => { m.stages[0].startedUtc = "2026-10-21T13:59:00Z"; },
    "reversed stage": (m) => { m.stages[0].finishedUtc = "2026-10-21T13:59:00Z"; },
    "overlapping stage": (m) => { m.stages[1].startedUtc = m.stages[0].startedUtc; },
    "nonfinite stage duration": (m) => { m.stages[0].durationMs = "Infinity"; },
    "wrong Node major": (m) => { m.nodeVersion = "v24.14.1"; },
    "too old Node22": (m) => { m.nodeVersion = "v22.12.0"; },
    "wrong npm major": (m) => { m.npmVersion = "11.11.0"; },
    "too old npm10": (m) => { m.npmVersion = "10.9.2"; },
    "missing versions": (m) => { delete m.nodeVersion; },
  };
  for (const [name, breakCase] of Object.entries(cases)) {
    await suite.test(name, () => {
      const altered = goodManifest();
      breakCase(altered);
      assert.throws(() => validateOfflineCiEvidence(bytes(altered), revision));
    });
  }
});
