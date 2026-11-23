import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateToolingAudit, interpretNpmAuditResult, npmAuditArguments, summarizeToolingAuditReport, EXPECTED_TOOLING_VERSIONS, TEMPORARY_TOOLING_ADVISORY_EXCEPTION } from "./tooling-audit-policy.mjs";

const accepted = JSON.parse(readFileSync(new URL("./fixtures/tooling-audit/accepted.json", import.meta.url), "utf8"));
const rootPackage = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const databasePackage = JSON.parse(readFileSync(new URL("../packages/database/package.json", import.meta.url), "utf8"));
const lockfile = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
const ciWorkflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const runtimeDockerfiles = [
  readFileSync(new URL("../infra/Dockerfile", import.meta.url), "utf8"),
  readFileSync(new URL("../infra/Dockerfile.prod", import.meta.url), "utf8")
];

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

test("npm audit network error JSON is unavailable, never a vulnerability report", () => {
  const sensitiveMarker = "NON_SENSITIVE_TEST_MARKER";
  const result = interpretNpmAuditResult({
    status: 1, stdout: JSON.stringify({ error: { code: "FETCH_ERROR", summary: `request with ${sensitiveMarker} timed out`, detail: sensitiveMarker } }), stderr: sensitiveMarker
  });
  assert.equal(result.status, "unavailable");
  assert.equal(result.reason, "registry-or-network-error");
  assert.equal(JSON.stringify(result).includes(sensitiveMarker), false);
});

test("timeout, spawn error, empty, malformed, and non-report output fail closed", () => {
  for (const [output, reason] of [
    [{ error: Object.assign(new Error("SENSITIVE_DATA"), { code: "ETIMEDOUT" }), status: null, stdout: "" }, "process-timeout"],
    [{ error: Object.assign(new Error("SENSITIVE_DATA"), { code: "ENOENT" }), status: null, stdout: "" }, "execution-error"],
    [{ status: 1, stdout: "" }, "empty-output"],
    [{ status: 1, stdout: "SENSITIVE_DATA not JSON" }, "invalid-json"],
    [{ status: 1, stdout: JSON.stringify({ auditReportVersion: null, metadata: null }) }, "invalid-report"],
    [{ status: 0, stdout: JSON.stringify(accepted).replace('"auditReportVersion":2', '"auditReportVersion":null') }, "invalid-report"]
  ]) {
    const result = interpretNpmAuditResult(output);
    assert.equal(result.status, "unavailable");
    assert.equal(result.reason, reason);
    assert.equal(JSON.stringify(result).includes("SENSITIVE_DATA"), false);
  }
});

test("a legitimate advisory cannot be masked by audit exit status 1", () => {
  const vulnerable = copy(accepted);
  vulnerable.vulnerabilities["test-private-path"] = { name: "test-private-path", severity: "high" };
  vulnerable.metadata.vulnerabilities.high = 1;
  vulnerable.metadata.vulnerabilities.total = 1;
  const result = interpretNpmAuditResult({ status: 1, stdout: JSON.stringify(vulnerable) });
  assert.equal(result.status, "reported");
  assert.equal(evaluateToolingAudit(result.report, { versions: EXPECTED_TOOLING_VERSIONS }).ok, false);
  const safeDiagnostic = summarizeToolingAuditReport(result.report, EXPECTED_TOOLING_VERSIONS);
  assert.equal(safeDiagnostic.ok, false);
  assert.equal(safeDiagnostic.observed.vulnerabilityCounts.high, 1);
  assert.equal(JSON.stringify(safeDiagnostic).includes("test-private-path"), false, "never expose raw report via diagnostic");
});

test("only a valid complete npm audit report from a successful command is accepted", () => {
  assert.equal(interpretNpmAuditResult({ status: 0, stdout: JSON.stringify(accepted) }).status, "reported");
  assert.equal(interpretNpmAuditResult({ status: 2, stdout: JSON.stringify(accepted) }).status, "unavailable");
  assert.equal(interpretNpmAuditResult({ status: 0, stdout: JSON.stringify({ ...accepted, error: { code: "SENSITIVE" } }) }).status, "unavailable");
  assert.deepEqual(npmAuditArguments(), [
    "audit", "--package-lock-only", "--json", "--fetch-retries=0", "--fetch-timeout=25000"
  ]);
});

test("policy command cannot replace live audit with an environment-provided JSON fixture", () => {
  const source = readFileSync(new URL("./tooling-audit-policy.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /process\.env\.VIRKI_TOOLING_AUDIT_JSON/u);
  assert.match(source, /timeout: AUDIT_PROCESS_TIMEOUT_MS/u);
  assert.match(source, /const AUDIT_PROCESS_TIMEOUT_MS = 45_000/u);
  assert.match(source, /const execution = runAudit\(\)/u);
});

test("keeps Prisma CLI, Client, Config, workspace manifests and lockfile on one pinned version", () => {
  const cliVersion = databasePackage.devDependencies?.prisma;
  const clientVersion = databasePackage.dependencies?.["@prisma/client"];
  const configVersion = EXPECTED_TOOLING_VERSIONS["@prisma/config"];

  assert.equal(rootPackage.overrides?.prisma, cliVersion);
  assert.equal(cliVersion, EXPECTED_TOOLING_VERSIONS.prisma);
  assert.equal(clientVersion, EXPECTED_TOOLING_VERSIONS["@prisma/client"]);
  assert.equal(cliVersion, clientVersion);
  assert.equal(configVersion, cliVersion);
  assert.equal(lockfile.packages["node_modules/prisma"]?.version, cliVersion);
  assert.equal(lockfile.packages["node_modules/@prisma/client"]?.version, clientVersion);
  assert.equal(lockfile.packages["node_modules/@prisma/config"]?.link, true);
  assert.equal(lockfile.packages["vendor/prisma-config-6.19.3"]?.version, configVersion);
});

test("local Prisma Config declares safe exact dependencies satisfied by the actual lockfile", () => {
  const config = lockfile.packages["vendor/prisma-config-6.19.3"];
  assert.ok(config, "Prisma Config must be installed and pinned");
  assert.equal(rootPackage.overrides?.["@prisma/config"], undefined,
    "do not override the upstream exact dependency contract");
  for (const name of ["deepmerge-ts", "effect"]) {
    const required = config.dependencies?.[name];
    assert.match(required ?? "", /^\d+\.\d+\.\d+$/u, `${name} must be an exact Prisma Config dependency`);
    const installed = lockfile.packages[`packages/database/node_modules/@prisma/config/node_modules/${name}`] ??
      lockfile.packages[`packages/database/node_modules/${name}`] ??
      lockfile.packages[`node_modules/${name}`];
    assert.equal(installed?.version, required, `${name} installed version must satisfy Prisma Config`);
  }
});

test("patched Prisma Config is a source-identical, licensed local package with fixed advisory dependencies", () => {
  const packagePath = new URL("../vendor/prisma-config-6.19.3/package.json", import.meta.url);
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  const source = readFileSync(new URL("../vendor/prisma-config-6.19.3/dist/index.js", import.meta.url));
  const license = readFileSync(new URL("../vendor/prisma-config-6.19.3/LICENSE", import.meta.url), "utf8");
  assert.equal(manifest.name, "@prisma/config");
  assert.equal(manifest.version, "6.19.3");
  assert.equal(manifest.license, "Apache-2.0");
  assert.match(license, /Apache License/u);
  assert.equal(createHash("sha256").update(source).digest("hex"),
    "92e63036b4da306abcb5fa4cfaa3a5b87508268e4f773f2b7638a061bf500a64",
    "the vendor fork must not change upstream executed JavaScript");
  assert.equal(manifest.dependencies?.["deepmerge-ts"], "8.0.2");
  assert.equal(manifest.dependencies?.effect, "3.22.5");
  assert.equal(manifest.devDependencies, undefined,
    "local package links must not install unused upstream Vitest tooling into the security audit");
  assert.equal(manifest.scripts, undefined,
    "bundled, prebuilt Prisma Config must not execute or require upstream build/test scripts");
  assert.equal(rootPackage.devDependencies?.["@prisma/config"], "file:vendor/prisma-config-6.19.3");
  assert.equal(rootPackage.overrides?.["@prisma/config"], undefined,
    "the safe dependency contracts must be declared, not forced through invalid overrides");
});

test("Docker build and runtime dependency stages carry the auditable local Prisma Config source", () => {
  const dockerignore = readFileSync(new URL("../.dockerignore", import.meta.url), "utf8");
  const gitignore = readFileSync(new URL("../.gitignore", import.meta.url), "utf8");
  assert.match(gitignore, /^!vendor\/prisma-config-6\.19\.3\/dist\/$/mu,
    "Git must track the upstream executable source rather than silently omitting dist");
  assert.match(gitignore, /^!vendor\/prisma-config-6\.19\.3\/dist\/\*\*$/mu);
  assert.match(dockerignore, /^!vendor\/prisma-config-6\.19\.3\/dist\/?$/mu,
    "the vendored source dist directory cannot be excluded from the Docker context");
  assert.match(dockerignore, /^!vendor\/prisma-config-6\.19\.3\/dist\/\*\*$/mu);
  for (const dockerfile of runtimeDockerfiles) {
    for (const section of dockerfile.split(/RUN npm ci\b/u).slice(0, -1)) {
      assert.match(section, /COPY vendor\/prisma-config-6\.19\.3\/ \.\/vendor\/prisma-config-6\.19\.3\//u,
        "each npm ci stage must copy local Prisma Config before dependency installation");
    }
  }
});

test("keeps Node engines, type declarations, CI and runtime images on Node 22", () => {
  assert.match(rootPackage.engines?.node ?? "", /^>=22\.\d+\.\d+\s+<23$/u);
  assert.match(rootPackage.devDependencies?.["@types/node"] ?? "", /^22\./u);

  const ciMajors = [...ciWorkflow.matchAll(/^\s*node-version:\s*(\d+)\.\d+\.\d+\s*$/gmu)].map((match) => match[1]);
  assert.ok(ciMajors.length > 0, "CI must declare explicit Node.js versions");
  assert.deepEqual([...new Set(ciMajors)], ["22"]);

  const imageMajors = runtimeDockerfiles.flatMap((dockerfile) =>
    [...dockerfile.matchAll(/^FROM\s+node:(\d+)-/gmu)].map((match) => match[1])
  );
  assert.ok(imageMajors.length > 0, "runtime Dockerfiles must declare Node.js base images");
  assert.deepEqual([...new Set(imageMajors)], ["22"]);
});

function buildPicomatchExceptionReport() {
  const report = copy(accepted);
  report.vulnerabilities = {
    picomatch: {
      name: "picomatch",
      severity: "high",
      isDirect: false,
      via: [{ name: "picomatch", url: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf", severity: "high", range: "<=4.0.7" }]
    },
    fdir: { name: "fdir", severity: "high", isDirect: false, via: ["picomatch"] },
    tinyglobby: { name: "tinyglobby", severity: "high", isDirect: false, via: ["fdir", "picomatch"] },
    "@typescript-eslint/typescript-estree": { name: "@typescript-eslint/typescript-estree", severity: "high", isDirect: false, via: ["tinyglobby"] },
    "@typescript-eslint/utils": { name: "@typescript-eslint/utils", severity: "high", isDirect: false, via: ["@typescript-eslint/typescript-estree"] },
    "@typescript-eslint/parser": { name: "@typescript-eslint/parser", severity: "high", isDirect: false, via: ["@typescript-eslint/typescript-estree"] },
    "@typescript-eslint/type-utils": { name: "@typescript-eslint/type-utils", severity: "high", isDirect: false, via: ["@typescript-eslint/typescript-estree", "@typescript-eslint/utils"] },
    "@typescript-eslint/eslint-plugin": { name: "@typescript-eslint/eslint-plugin", severity: "high", isDirect: false, via: ["@typescript-eslint/parser", "@typescript-eslint/type-utils", "@typescript-eslint/utils"] },
    "typescript-eslint": { name: "typescript-eslint", severity: "high", isDirect: true, via: ["@typescript-eslint/eslint-plugin", "@typescript-eslint/parser", "@typescript-eslint/typescript-estree", "@typescript-eslint/utils"] }
  };
  report.metadata.vulnerabilities = { info: 0, low: 0, moderate: 0, high: 9, critical: 0, total: 9 };
  return report;
}

test("temporary GHSA-fc5q-39xc-vjpf exception has <=14-day window, risk record, and removal condition", () => {
  const createdMs = Date.parse(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.createdAt);
  const expiresMs = Date.parse(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.expiresAt);
  assert.ok(Number.isFinite(createdMs) && Number.isFinite(expiresMs) && expiresMs > createdMs);
  assert.ok(expiresMs - createdMs <= 14 * 24 * 60 * 60 * 1000);
  assert.equal(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.advisoryId, "GHSA-fc5q-39xc-vjpf");
  assert.ok(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.acceptedRisk.length > 20);
  assert.ok(TEMPORARY_TOOLING_ADVISORY_EXCEPTION.removalCondition.length > 20);
});

test("temporary exception allows only exact dev-only GHSA-fc5q-39xc-vjpf chain before expiry", () => {
  const report = buildPicomatchExceptionReport();
  const valid = evaluateToolingAudit(report, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: false, now: new Date("2026-11-18T12:00:00Z") });
  assert.equal(valid.ok, true);
  assert.equal(valid.temporaryException, "GHSA-fc5q-39xc-vjpf");

  // Negative: expired
  const expired = evaluateToolingAudit(report, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: false, now: new Date("2026-12-02T00:00:01Z") });
  assert.equal(expired.ok, false);

  // Negative: reachable from production
  const prod = evaluateToolingAudit(report, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: true, now: new Date("2026-11-18T12:00:00Z") });
  assert.equal(prod.ok, false);

  // Negative: omitted productionReachable fails closed for temporary exception
  const omittedProd = evaluateToolingAudit(report, { versions: EXPECTED_TOOLING_VERSIONS, now: new Date("2026-11-18T12:00:00Z") });
  assert.equal(omittedProd.ok, false);
  assert.equal(summarizeToolingAuditReport(report, EXPECTED_TOOLING_VERSIONS, { now: new Date("2026-11-18T12:00:00Z") }).ok, false);

  // Negative: different advisory on picomatch
  const otherAdvisory = buildPicomatchExceptionReport();
  otherAdvisory.vulnerabilities.picomatch.via.push({ name: "picomatch", url: "https://github.com/advisories/GHSA-0000-0000-0000", severity: "high", range: "<=4.0.7" });
  assert.equal(evaluateToolingAudit(otherAdvisory, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: false, now: new Date("2026-11-18T12:00:00Z") }).ok, false);

  // Negative: unrelated package outside allowed dev chain
  const extraPkg = buildPicomatchExceptionReport();
  extraPkg.vulnerabilities.lodash = { name: "lodash", severity: "high", isDirect: false, via: ["picomatch"] };
  extraPkg.metadata.vulnerabilities.high = 10;
  extraPkg.metadata.vulnerabilities.total = 10;
  assert.equal(evaluateToolingAudit(extraPkg, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: false, now: new Date("2026-11-18T12:00:00Z") }).ok, false);

  // Negative: critical vulnerability present
  const withCritical = buildPicomatchExceptionReport();
  withCritical.metadata.vulnerabilities.critical = 1;
  withCritical.metadata.vulnerabilities.total = 10;
  assert.equal(evaluateToolingAudit(withCritical, { versions: EXPECTED_TOOLING_VERSIONS, productionReachable: false, now: new Date("2026-11-18T12:00:00Z") }).ok, false);
});
