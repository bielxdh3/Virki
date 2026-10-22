import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  evaluateProductionDependencies,
  interpretProductionNpmResult,
  npmProductionArguments
} from "./production-dependency-audit.mjs";

const zeroCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
const cleanAudit = {
  auditReportVersion: 2,
  metadata: { vulnerabilities: zeroCounts },
  vulnerabilities: {}
};
const healthyTree = {
  name: "virki",
  version: "0.1.0",
  dependencies: {
    "@prisma/client": { version: "6.19.3" },
    "next": { version: "16.3.8", dependencies: { "react": { version: "19.2.0" } } }
  }
};
const clone = (value) => JSON.parse(JSON.stringify(value));
const npmResult = (status, body, stderr = "") => ({
  status, stdout: typeof body === "string" ? body : JSON.stringify(body), stderr
});
const goodAudit = () => interpretProductionNpmResult("audit", npmResult(0, cleanAudit));
const goodTree = () => interpretProductionNpmResult("ls", npmResult(0, healthyTree));
const evaluate = (overrides = {}) => evaluateProductionDependencies({
  audit: goodAudit(), tree: goodTree(), requiredClient: true,
  physicalForbidden: [], prismaBinaryFound: false, ...overrides
});

test("production policy accepts only clean reported results and a present Prisma client", () => {
  const result = evaluate();
  assert.equal(result.status, "passed");
  assert.equal(result.requiredClient, true);
  assert.deepEqual(result.errors, []);
});

test("npm audit distinguishes network/registry errors from vulnerability findings without leaking stderr", () => {
  const marker = "SENSITIVE_TEST_MARKER";
  const execution = interpretProductionNpmResult("audit", npmResult(1, {
    error: { code: "FETCH_ERROR", summary: "fetch SENSITIVE_TEST_MARKER", detail: marker }
  }, marker));
  assert.equal(execution.status, "unavailable");
  assert.equal(execution.reason, "registry-or-network-error");
  const result = evaluate({ audit: execution });
  assert.equal(result.status, "failed");
  assert.match(result.errors.join(" "), /unavailable/i);
  assert.doesNotMatch(result.errors.join(" "), /vulnerabilit/i);
  assert.equal(JSON.stringify(result).includes(marker), false);
  const otherError = interpretProductionNpmResult("audit", npmResult(1, {
    error: { code: "EUSAGE", summary: marker }
  }));
  assert.equal(otherError.reason, "audit-command-error");
});

test("npm audit exit 1 with real findings is reported as vulnerabilities", () => {
  const vulnerable = clone(cleanAudit);
  vulnerable.vulnerabilities.private_test_package = { name: "private_test_package", severity: "high" };
  vulnerable.metadata.vulnerabilities.high = 1;
  vulnerable.metadata.vulnerabilities.total = 1;
  const audit = interpretProductionNpmResult("audit", npmResult(1, vulnerable));
  assert.equal(audit.status, "reported");
  const result = evaluate({ audit });
  assert.equal(result.status, "failed");
  assert.match(result.errors.join(" "), /vulnerabilit/i);
  assert.equal(result.vulnerabilities.high, 1);
  assert.equal(JSON.stringify(result).includes("private_test_package"), false);
});

test("npm audit clean exit 1 or process timeout never permits PASS", () => {
  const cleanError = interpretProductionNpmResult("audit", npmResult(1, cleanAudit));
  assert.equal(cleanError.status, "unavailable");
  assert.equal(evaluate({ audit: cleanError }).status, "failed");
  const timedOut = interpretProductionNpmResult("audit", {
    error: Object.assign(new Error("SENSITIVE_TEST_MARKER"), { code: "ETIMEDOUT" }),
    status: null, stdout: "", stderr: "SENSITIVE_TEST_MARKER"
  });
  assert.equal(timedOut.reason, "process-timeout");
  assert.equal(JSON.stringify(evaluate({ audit: timedOut })).includes("SENSITIVE_TEST_MARKER"), false);
});

test("npm audit clean status 0 accompanied by stderr fails closed without echoing diagnostics", () => {
  const execution = interpretProductionNpmResult("audit", npmResult(0, cleanAudit,
    "SENSITIVE_TEST_MARKER audit endpoint unreachable"));
  assert.equal(execution.status, "unavailable");
  assert.equal(execution.reason, "command-stderr");
  const evaluated = evaluate({ audit: execution });
  assert.equal(evaluated.status, "failed");
  assert.equal(JSON.stringify(evaluated).includes("SENSITIVE_TEST_MARKER"), false);
  assert.doesNotMatch(evaluated.errors.join(" "), /reported one or more vulnerabilities/u);
});

test("npm ls exit 1 with plausible JSON and stderr still fails closed", () => {
  const tree = interpretProductionNpmResult("ls", npmResult(1, healthyTree, "private registry URL"));
  assert.equal(tree.status, "unavailable");
  const result = evaluate({ tree });
  assert.equal(result.status, "failed");
  assert.match(result.errors.join(" "), /npm ls unavailable/i);
  assert.equal(JSON.stringify(result).includes("private registry URL"), false);
  const brokenTree = interpretProductionNpmResult("ls", npmResult(1, {
    ...healthyTree, error: { code: "ELSPROBLEMS", message: "private registry URL" }
  }));
  assert.equal(brokenTree.reason, "invalid-dependency-tree");
  const stderrOnly = interpretProductionNpmResult("ls", npmResult(0, healthyTree, "private registry URL"));
  assert.equal(stderrOnly.status, "unavailable");
  assert.equal(evaluate({ tree: stderrOnly }).status, "failed");
});

test("npm ls rejects malformed, incomplete, and error-bearing JSON trees", () => {
  const cases = [
    [], null, { name: "virki" },
    { ...healthyTree, dependencies: [] },
    { ...healthyTree, dependencies: { react: null } },
    { ...healthyTree, problems: ["missing: private"] },
    { ...healthyTree, dependencies: { react: { invalid: true } } },
    { ...healthyTree, dependencies: { react: { dependencies: [] } } },
    { ...healthyTree, error: { message: "SENSITIVE_TEST_MARKER" } }
  ];
  for (const value of cases) {
    const tree = interpretProductionNpmResult("ls", npmResult(0, value));
    assert.equal(tree.status, "unavailable", JSON.stringify(value));
    assert.equal(evaluate({ tree }).status, "failed");
  }
});

test("audit parser rejects fake version, malformed counts, and inconsistent entries", () => {
  const cases = [
    { ...cleanAudit, auditReportVersion: 1 },
    { ...cleanAudit, vulnerabilities: [] },
    { ...cleanAudit, metadata: { vulnerabilities: { total: 0 } } },
    { ...cleanAudit, metadata: { vulnerabilities: { ...zeroCounts, high: -1 } } },
    { ...cleanAudit, metadata: { vulnerabilities: { ...zeroCounts, low: 1 } } },
    { ...cleanAudit, vulnerabilities: { hidden: { severity: "high" } } },
    { ...cleanAudit, error: { code: "EUNKNOWN" } }
  ];
  for (const value of cases) {
    const audit = interpretProductionNpmResult("audit", npmResult(0, value));
    assert.equal(audit.status, "unavailable", JSON.stringify(value));
    assert.equal(evaluate({ audit }).status, "failed");
  }
});

test("missing Prisma client or physical/tooling tree reachability fail independently", () => {
  assert.match(evaluate({ requiredClient: false }).errors.join(" "), /missing/i);
  const missingFromTree = clone(healthyTree);
  delete missingFromTree.dependencies["@prisma/client"];
  const incomplete = evaluate({ tree: interpretProductionNpmResult("ls", npmResult(0, missingFromTree)) });
  assert.match(incomplete.errors.join(" "), /@prisma\/client is missing/i);
  assert.equal(evaluate({ physicalForbidden: ["@prisma/config"] }).status, "failed");
  assert.equal(evaluate({ prismaBinaryFound: true }).status, "failed");
  const tree = clone(healthyTree);
  tree.dependencies.prisma = { version: "6.19.3" };
  const result = evaluate({ tree: interpretProductionNpmResult("ls", npmResult(0, tree)) });
  assert.equal(result.status, "failed");
  assert.deepEqual(result.forbiddenPackages, ["prisma"]);
});

test("npm ls omitted peer placeholders do not masquerade as installed Prisma CLI", () => {
  const tree = clone(healthyTree);
  tree.dependencies["@prisma/client"].dependencies = {
    prisma: {}, typescript: {}
  };
  const execution = interpretProductionNpmResult("ls", npmResult(0, tree));
  assert.equal(execution.status, "reported");
  assert.equal(evaluate({ tree: execution }).status, "passed");
  const installed = clone(tree);
  installed.dependencies["@prisma/client"].dependencies.prisma = { version: "6.19.3" };
  const result = evaluate({ tree: interpretProductionNpmResult("ls", npmResult(0, installed)) });
  assert.equal(result.status, "failed");
  assert.deepEqual(result.forbiddenPackages, ["prisma"]);
});

test("both npm commands are bounded and real audit is required in the CLI", () => {
  const { audit, ls } = npmProductionArguments();
  assert.deepEqual(audit.slice(0, 2), ["audit", "--omit=dev"]);
  assert.ok(audit.includes("--fetch-retries=0"));
  assert.ok(audit.includes("--fetch-timeout=25000"));
  assert.ok(ls.includes("--all"));
  const source = readFileSync(new URL("./production-dependency-audit.mjs", import.meta.url), "utf8");
  assert.match(source, /timeout:\s*PRODUCTION_NPM_TIMEOUT_MS/u);
  assert.match(source, /const PRODUCTION_NPM_TIMEOUT_MS = 45_000/u);
});
