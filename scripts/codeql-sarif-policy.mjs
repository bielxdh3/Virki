import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const acceptedFindings = new Map([
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|da86d8805094bfc3:1|13", 1],
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|60631c9015b3ab5a:1|13", 1],
  ["js/file-access-to-http|scripts/e2e/access-token.mts|90e07734df8b1ab3:1|6", 1],
  ["js/user-controlled-bypass|scripts/e2e/jwks-server.mjs|ebcb3e6db1dd4911:1|33", 1],
  // 42 independent benign dispositions from original hosted CodeQL 42033025663.
  // Exact 4-part keys, maximum count 1; see docs/security/codeql-reviewed-20261105.md.
  // Original vulnerable CID pathname-read race #10 intentionally NOT accepted.
  ["js/disabling-certificate-validation|examples/oidc-node-rp/live-issuer.integration.test.mjs|a4a3e085780e0bef:1|0", 1], // SARIF #0
  ["js/incomplete-url-substring-sanitization|apps/hub/src/lib/connection-policy.test.ts|7de8f5c65e802007:1|13", 1], // SARIF #3
  ["js/incomplete-url-substring-sanitization|examples/oidc-node-rp/server.test.mjs|36bfd13774f73533:1|11", 1], // SARIF #4
  ["js/user-controlled-bypass|examples/oidc-node-rp/server.mjs|bbaf321e98e807d7:1|59", 1], // SARIF #5
  ["js/file-system-race|infra/offline/disposable-recovery-coordinator.mjs|bacf6361e17909bd:1|11", 1], // SARIF #7
  ["js/file-system-race|infra/offline/disposable-recovery-coordinator.mjs|8ddbf1d8225f3992:1|11", 1], // SARIF #8
  ["js/file-system-race|infra/offline/isolated-docker-daemon-identity.mjs|440419f7da9737fb:1|11", 1], // SARIF #9
  ["js/file-system-race|infra/offline/trusted-host-entry.mjs|b02a714376336c8a:1|21", 1], // SARIF #11
  ["js/file-system-race|infra/offline/trusted-host-entry.mjs|5b3a841cfe1cbe84:1|11", 1], // SARIF #12
  ["js/file-system-race|infra/offline/trusted-host-installer.mjs|5debf7e6b5fd261b:1|11", 1], // SARIF #13
  ["js/file-system-race|infra/offline/trusted-host-installer.mjs|1cf763d12111daa4:1|11", 1], // SARIF #14
  ["js/file-system-race|infra/offline/trusted-image-import.mjs|be09ad5635012edf:1|14", 1], // SARIF #15
  ["js/file-system-race|infra/offline/trusted-image-import.mjs|4e0312eda018c177:1|11", 1], // SARIF #16
  ["js/file-system-race|infra/offline/trusted-image-import.mjs|ae57bb45e7e299c5:1|15", 1], // SARIF #17
  ["js/file-system-race|infra/offline/trusted-image-loader.mjs|aa5922770d4e7396:1|21", 1], // SARIF #18
  ["js/file-system-race|infra/offline/trusted-native-stage-fixture.mjs|5debf7e6b75c0066:1|11", 1], // SARIF #19
  ["js/file-system-race|infra/offline/trusted-native-stage-fixture.test.mjs|801c34c09549d5e2:1|20", 1], // SARIF #20
  ["js/file-system-race|infra/offline/trusted-native-stage-fixture.test.mjs|d36af1cf20792d7:1|17", 1], // SARIF #21
  ["js/file-system-race|infra/offline/trusted-owner-installation.mjs|1ec6d384897263b9:1|11", 1], // SARIF #22
  ["js/file-system-race|infra/offline/trusted-owner-installation.mjs|9dcc80231a25771b:1|11", 1], // SARIF #23
  ["js/file-system-race|infra/offline/trusted-owner-installation.mjs|3894463d7024618f:1|11", 1], // SARIF #24
  ["js/file-system-race|infra/offline/trusted-source-git.mjs|d5021b1656bfed67:1|17", 1], // SARIF #25
  ["js/file-system-race|infra/offline/trusted-verifier-dependency-closure.test.mjs|7441e153e2742241:1|15", 1], // SARIF #26
  ["js/file-system-race|scripts/lib/offline-artifact-inventory.mjs|8ed28f7edc997e1:1|21", 1], // SARIF #27
  ["js/file-system-race|scripts/lib/offline-artifact-inventory.mjs|f5640aba92a19896:1|25", 1], // SARIF #28
  ["js/file-system-race|scripts/lib/offline-docker-tar-verifier.mjs|8ed28f7edc997e1:1|21", 1], // SARIF #29
  ["js/file-system-race|scripts/lib/offline-independent-witness-service.mjs|6ff3631558eb0391:1|11", 1], // SARIF #30
  ["js/file-system-race|scripts/lib/offline-release-bundle.mjs|df4d0ec56e34ce94:1|11", 1], // SARIF #31
  ["js/file-system-race|scripts/lib/offline-source-tar-verifier.mjs|5bc9404f0d127e2a:1|11", 1], // SARIF #32
  ["js/file-system-race|scripts/lib/role-fixture-docker.test.mjs|52a5e9e31791b677:1|13", 1], // SARIF #33
  ["js/file-system-race|scripts/offline-docker-tar-verifier.test.mjs|53ee0d0beab5650b:1|0", 1], // SARIF #34
  ["js/file-system-race|scripts/offline-docker-tar-verifier.test.mjs|ed819fa4666df6fc:1|0", 1], // SARIF #35
  ["js/file-system-race|scripts/offline-production-transport.mjs|b9223cf05fb8c46f:1|15", 1], // SARIF #36
  ["js/file-system-race|scripts/offline-release-build.mjs|5bc9404f24a5ed85:1|11", 1], // SARIF #37
  ["js/file-system-race|scripts/offline-release-bundle.test.mjs|e6998a15e9a91656:1|48", 1], // SARIF #38
  ["js/file-system-race|scripts/offline-release-bundle.test.mjs|f3b51bb48c9b5792:1|0", 1], // SARIF #39
  ["js/file-system-race|scripts/offline-release-bundle.test.mjs|916157443b8472e7:1|17", 1], // SARIF #40
  ["js/file-system-race|scripts/offline-release-finalize.mjs|cf0a231a6765af42:1|11", 1], // SARIF #41
  ["js/file-system-race|scripts/offline-release-finalize.mjs|781e4d7388b75862:1|13", 1], // SARIF #42
  ["js/file-system-race|scripts/offline-release-finalize.mjs|9c6b0210cee7a745:1|11", 1], // SARIF #43
  ["js/file-system-race|scripts/offline-release-finalize.test.mjs|b3276e65263e1134:1|49", 1], // SARIF #44
  ["js/file-system-race|scripts/production-migration-pg-failclosed.test.mjs|ff3b02194231a1aa:1|0", 1], // SARIF #45
  // Separate independently reviewed post-fix PR #102 residual: genuine hosted
  // CodeQL run 42059112721, source SHA a6171526, FD-pinned and bounded read.
  // The older vulnerable bc6600c95727700f:1 fingerprint remains UNACCEPTED.
  ["js/file-system-race|infra/offline/native-supervisor/run-disposable-fd-lifecycle-test.mjs|e0fc364b7545cc38:1|11", 1],
]);

function invalidSarif(message) {
  throw new Error(`Invalid SARIF: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validSemver(value) {
  if (typeof value !== "string") return false;
  const parts = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.exec(value);
  return Boolean(parts) && (!parts[1] || parts[1].split(".").every((identifier) =>
    !/^\d+$/u.test(identifier) || identifier === "0" || !identifier.startsWith("0")));
}

// CodeQL's documented SARIF contains rules for queries in the analysis and
// artifacts for files referenced by results. Neither is a coverage inventory.
// Keep this validator structural; only the exact-SHA hosted workflow provides
// evidence that the scanner really ran on the intended checkout.
function validateCodeqlRun(run) {
  if (!isObject(run) || !Array.isArray(run.results)) invalidSarif("each run needs a results array.");
  const driver = run.tool?.driver;
  // CodeQL CLI SARIF has two observed metadata shapes. Require the exact
  // name/version-field pairing so arbitrary scan tools cannot impersonate it.
  const legacyDriver = driver?.name === "CodeQL command-line toolchain"
    && driver.semanticVersion === undefined && validSemver(driver.version);
  const currentDriver = driver?.name === "CodeQL"
    && driver.version === undefined && validSemver(driver.semanticVersion);
  if (!isObject(driver) || driver.organization !== "GitHub" || (!legacyDriver && !currentDriver)) {
    invalidSarif("expected a versioned CodeQL CLI driver.");
  }
  if (!isObject(run.properties) || !["sarif-latest", "sarifv2.1.0"].includes(
    run.properties["semmle.formatSpecifier"])) {
    invalidSarif("CodeQL exporter format is missing.");
  }
  if (run.automationDetails !== undefined && (!isObject(run.automationDetails)
    || !["/language:javascript-typescript", "/language:javascript-typescript/"].includes(run.automationDetails.id))) {
    invalidSarif("unexpected CodeQL analysis category.");
  }
  // CodeQL can group query descriptors by pack with --sarif-group-rules-by-pack.
  // A result referring to an extension must identify that component explicitly.
  const extensions = run.tool.extensions ?? [];
  if (!Array.isArray(driver.rules) || !Array.isArray(extensions)) invalidSarif("invalid rule component inventory.");
  const ruleTables = [driver, ...extensions].map((component) => {
    if (!isObject(component) || (component.rules !== undefined && !Array.isArray(component.rules))) {
      invalidSarif("invalid CodeQL rule component.");
    }
    const rules = new Map();
    for (const [index, descriptor] of (component.rules ?? []).entries()) {
      if (!isObject(descriptor) || typeof descriptor.id !== "string" || !descriptor.id.trim()
        || rules.has(descriptor.id)) invalidSarif("invalid or duplicate CodeQL rule descriptor.");
      rules.set(descriptor.id, index);
    }
    return rules;
  });
  if (ruleTables.every((rules) => rules.size === 0)) invalidSarif("CodeQL rule descriptors are missing.");
  if (!Array.isArray(run.artifacts)) invalidSarif("CodeQL artifact table is missing.");
  const artifactPaths = new Map();
  run.artifacts.forEach((artifact, index) => {
    // SARIF 2.1 defines index on artifactLocation, not on artifact itself.
    // The CodeQL CLI documentation has an inconsistent table entry naming
    // artifact.index; do not make that non-schema property a release gate.
    if (!isObject(artifact) || !isObject(artifact.location)) invalidSarif("invalid artifact entry.");
    const location = artifact.location;
    if (location.index !== undefined && location.index !== index) invalidSarif("inconsistent artifact index.");
    const normalized = normalizeArtifactPath(location.uri);
    if (!normalized || (location.uriBaseId !== undefined && location.uriBaseId !== "%SRCROOT%")) {
      invalidSarif("invalid artifact source location.");
    }
    if (artifactPaths.has(normalized)) invalidSarif("duplicate artifact source location.");
    artifactPaths.set(normalized, index);
  });
  if (run.invocations !== undefined) {
    if (!Array.isArray(run.invocations) || run.invocations.some((invocation) =>
      !isObject(invocation) || (invocation.executionSuccessful !== undefined
        && invocation.executionSuccessful !== true)
      || (invocation.toolExecutionNotifications !== undefined
        && (!Array.isArray(invocation.toolExecutionNotifications)
          || invocation.toolExecutionNotifications.some((notice) =>
            !isObject(notice) || notice.level === "error"
            || notice.descriptor?.id === "js/diagnostics/extraction-errors"))))) {
      invalidSarif("CodeQL invocation reports failure or invalid diagnostics.");
    }
  }
  for (const result of run.results) {
    if (!isObject(result) || typeof result.ruleId !== "string"
      || !isObject(result.message) || ![result.message.text, result.message.markdown]
        .some((value) => typeof value === "string" && value.trim())) {
      invalidSarif("result has no rule identifier or message.");
    }
    const toolComponent = result.rule?.toolComponent;
    let componentIndex = 0;
    if (toolComponent !== undefined) {
      if (!isObject(toolComponent) || !Number.isSafeInteger(toolComponent.index)
        || toolComponent.index < -1 || toolComponent.index >= extensions.length) {
        invalidSarif("invalid CodeQL tool extension reference.");
      }
      componentIndex = toolComponent.index + 1;
    }
    const registeredIndex = ruleTables[componentIndex].get(result.ruleId);
    if (registeredIndex === undefined) invalidSarif("result rule is absent from referenced component.");
    // Earlier exporters used result.ruleIndex. Hosted CodeQL 2.27.1 instead
    // emits result.rule.index, scoped to result.rule.toolComponent. Accept
    // either, but never a missing or inconsistent index.
    const legacyIndexPresent = result.ruleIndex !== undefined;
    const componentIndexPresent = isObject(result.rule) && result.rule.index !== undefined;
    if ((!legacyIndexPresent && !componentIndexPresent)
      || (legacyIndexPresent && (!Number.isSafeInteger(result.ruleIndex)
        || result.ruleIndex !== registeredIndex))) {
      invalidSarif("result rule index does not match ruleId.");
    }
    if (result.rule !== undefined && (!isObject(result.rule)
      || (result.rule.id !== undefined && result.rule.id !== result.ruleId)
      || (result.rule.index !== undefined && result.rule.index !== registeredIndex))) {
      invalidSarif("result rule reference does not match its component.");
    }
    const locations = result.locations;
    if (!Array.isArray(locations) || locations.length !== 1
      || !isObject(locations[0]?.physicalLocation?.artifactLocation)) {
      invalidSarif("result needs one source location.");
    }
    const location = locations[0].physicalLocation.artifactLocation;
    if (location.uriBaseId !== undefined && location.uriBaseId !== "%SRCROOT%") {
      invalidSarif("unexpected result source root.");
    }
    const normalized = location.uri === undefined ? undefined : normalizeArtifactPath(location.uri);
    if (location.uri !== undefined && !normalized) invalidSarif("invalid result source location.");
    if (location.index !== undefined && (!Number.isSafeInteger(location.index)
      || location.index < 0 || location.index >= run.artifacts.length)) {
      invalidSarif("result references an unknown artifact index.");
    }
    const artifactPath = location.index === undefined
      ? normalized : normalizeArtifactPath(run.artifacts[location.index].location.uri);
    if (!artifactPath || (normalized !== undefined && normalized !== artifactPath)
      || artifactPaths.get(artifactPath) === undefined) {
      invalidSarif("result source location is inconsistent with its artifact.");
    }
  }
}

export function evaluateCodeqlSarif(documents) {
  if (!Array.isArray(documents) || documents.length !== 1) {
    throw new Error("Invalid SARIF: expected one JavaScript/TypeScript SARIF document.");
  }
  const acceptedCounts = new Map();
  const violations = [];
  let totalResults = 0;

  for (const document of documents) {
    if (!isObject(document) || document.version !== "2.1.0" || !Array.isArray(document.runs) || document.runs.length !== 1) {
      throw new Error("Invalid SARIF: expected version 2.1.0 and exactly one run.");
    }
    for (const run of document.runs) {
      validateCodeqlRun(run);
      for (const result of run.results) {
        totalResults += 1;
        const ruleId = result.ruleId;
        const location = result.locations[0].physicalLocation.artifactLocation;
        const artifactPath = normalizeArtifactPath(location.uri ?? run.artifacts[location.index].location.uri);
        const lineFingerprint = result?.partialFingerprints?.primaryLocationLineHash;
        const columnFingerprint = result?.partialFingerprints?.primaryLocationStartColumnFingerprint;
        const hasFingerprint = typeof lineFingerprint === "string" && lineFingerprint.trim()
          && typeof columnFingerprint === "string" && columnFingerprint.trim();
        const key = hasFingerprint
          ? `${ruleId}|${artifactPath}|${lineFingerprint}|${columnFingerprint}`
          : `${ruleId}|${artifactPath}|missing-fingerprint`;
        const maximum = acceptedFindings.get(key);
        if (maximum === undefined) {
          violations.push({ ruleId, path: artifactPath, reason: "unreviewed-finding" });
          continue;
        }
        const count = (acceptedCounts.get(key) ?? 0) + 1;
        acceptedCounts.set(key, count);
        if (count > maximum) {
          violations.push({ ruleId, path: artifactPath, reason: "accepted-finding-count-exceeded" });
        }
      }
    }
  }

  return {
    ok: violations.length === 0,
    totalResults,
    acceptedResults: totalResults - violations.length,
    violations
  };
}

function normalizeArtifactPath(uri) {
  if (typeof uri !== "string" || !uri || uri.trim() !== uri || /[\\?#]/u.test(uri)) return null;
  let value = uri;
  try {
    if (value.startsWith("file://")) {
      const location = new URL(value);
      if (location.protocol !== "file:" || location.host) return null;
      value = location.pathname;
    }
    value = decodeURIComponent(value);
  } catch {
    return null;
  }
  const workspaceMarker = "/github/workspace/";
  if (value.startsWith(workspaceMarker)) value = value.slice(workspaceMarker.length);
  else if (value.startsWith("/")) return null;
  value = value.replace(/^\.\//u, "");
  if (!value || /[:\\]/u.test(value) || [...value].some((char) => char.charCodeAt(0) < 32)
    || value.split("/").some((part) => !part || part === "." || part === "..")) return null;
  return value;
}

export function readSarifDirectory(directory) {
  const absolute = path.resolve(directory);
  const files = collectSarifFiles(absolute);
  if (files.length === 0) throw new Error("CodeQL SARIF policy found no SARIF files.");
  return files.map((file) => JSON.parse(readFileSync(file, "utf8")));
}

function collectSarifFiles(directory) {
  const results = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) results.push(...collectSarifFiles(fullPath));
    else if (entry.isFile() && entry.name.endsWith(".sarif")) results.push(fullPath);
  }
  return results.sort();
}

function isMainModule() {
  return Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  try {
    const directory = process.argv[2];
    if (!directory || process.argv.length !== 3) throw new Error("Usage: node scripts/codeql-sarif-policy.mjs <sarif-directory>");
    const result = evaluateCodeqlSarif(readSarifDirectory(directory));
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : "CodeQL SARIF policy failed.");
    process.exitCode = 1;
  }
}
