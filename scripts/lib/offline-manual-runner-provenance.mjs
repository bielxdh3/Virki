import { createHash, createPublicKey, verify } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { validateOfflineCiEvidence } from "./offline-ci-evidence.mjs";

// Provisioned out of band on a root-owned Linux verifier. Never look for a
// trust path, trust key, executable override or policy in candidate artifacts,
// caller options, process environment or the repository under review.
const OWNER_TRUST_PATH = "/etc/virki/manual-runner-trust.json";
const DOMAIN = Buffer.from("virki:manual-independent-runner:v1\0", "utf8");
const HASH = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const STAGES = Object.freeze([
  "tooling-policy-dependencies", "tooling-policy-tests", "chromium-dependencies",
  "production-hub-build", "runtime", "secrets-scan", "production-revision-tests",
  "backup-inventory-tests", "production-operations-tests", "public-site-tests",
  "unit-tests", "integration-tests", "browser-e2e", "lint", "typecheck",
  "prisma-validate", "build", "windows-ca-helper-tests", "worktree-diff-check",
]);
const POLICY_FIELDS = ["version", "keyId", "runnerId", "runnerExecutableSha256",
  "runnerLauncherSha256", "scannerExecutableSha256", "scannerRulesCommit", "publicKeySpkiBase64"];
const STATEMENT_FIELDS = ["version", "kind", "sourceSha", "sourceBranch", "manifestSha256",
  "scannerReportSha256", "runnerId", "runnerExecutableSha256", "runnerLauncherSha256",
  "scannerExecutableSha256", "scannerRulesCommit", "ciProcess", "scannerProcess", "observedStages"];
const PROCESS_FIELDS = ["exitCode", "timedOut", "truncated", "spawnError", "stdoutSha256", "capturedBytes"];

function refuse(message) { throw new Error(`Independent manual runner provenance refused: ${message}`); }
function need(condition, reason) { if (!condition) refuse(reason); }
function record(value, keys, label) {
  need(value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)),
  `${label} schema is invalid`);
}
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function parseCanonical(bytes, limit, label) {
  need(bytes instanceof Uint8Array && bytes.byteLength >= 2 && bytes.byteLength <= limit,
    `${label} must be bounded raw bytes`);
  let parsed;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { refuse(`${label} must be strict UTF-8 JSON`); }
  need(Buffer.from(JSON.stringify(parsed)).equals(Buffer.from(bytes)),
    `${label} must be canonical JSON without duplicate keys`);
  return parsed;
}
function parseScannerBytes(bytes) {
  need(bytes instanceof Uint8Array && bytes.byteLength > 2 && bytes.byteLength <= 4 * 1024 * 1024,
    "scanner report must be bounded raw evidence bytes");
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { refuse("scanner report has malformed UTF-8 or JSON"); }
}
function matchObservedConsole(actual, claimed, label) {
  need(actual instanceof Uint8Array && actual.byteLength > 0 &&
    actual.byteLength <= 64 * 1024 * 1024 &&
    claimed.capturedBytes === actual.byteLength && claimed.stdoutSha256 === digest(actual),
  `${label} process console bytes do not match the signed independent observation`);
}
function validateProcess(result, label) {
  record(result, PROCESS_FIELDS, `${label} process observation`);
  need(result.exitCode === 0 && result.timedOut === false && result.truncated === false &&
    result.spawnError === false && HASH.test(result.stdoutSha256 ?? "") &&
    Number.isSafeInteger(result.capturedBytes) && result.capturedBytes > 0 &&
    result.capturedBytes <= 64 * 1024 * 1024,
  `${label} process was not independently observed to complete successfully`);
}

/**
 * Cryptographic primitive for unit testing an ALREADY INDEPENDENTLY INSTALLED
 * trust policy. Passing a policy into this low-level primitive never grants
 * release authority; only inspectIndependentManualRunnerProvenance loads
 * the owner-installed trust anchor and makes the operational decision.
 * A signed statement attests what an independent runner observed; the signing
 * agent must itself pin binaries and capture real process exit/output.
 */
export function verifySignedManualRunnerStatement({
  ciManifestBytes, scannerReportBytes, revision, branch = "main", attestationBytes,
  ciConsoleBytes, scannerConsoleBytes,
  trustedInstalledPolicy,
} = {}) {
  const claimed = validateOfflineCiEvidence(ciManifestBytes, revision, branch, { requireOfflineFixture: true });
  record(trustedInstalledPolicy, POLICY_FIELDS, "owner-installed runner policy");
  const pinned = trustedInstalledPolicy;
  need(pinned.version === 1 && typeof pinned.runnerId === "string" &&
    /^[A-Za-z0-9_-]{8,80}$/u.test(pinned.runnerId) &&
    [pinned.runnerExecutableSha256, pinned.runnerLauncherSha256, pinned.scannerExecutableSha256]
      .every((value) => HASH.test(value ?? "")) && SHA.test(pinned.scannerRulesCommit ?? ""),
  "trusted installed runner identities are incomplete");
  need(typeof pinned.publicKeySpkiBase64 === "string" && B64.test(pinned.publicKeySpkiBase64),
    "trusted runner public key is invalid");
  const keyBytes = Buffer.from(pinned.publicKeySpkiBase64, "base64");
  need(keyBytes.toString("base64") === pinned.publicKeySpkiBase64 && digest(keyBytes) === pinned.keyId,
    "trusted runner key identity is invalid");
  let publicKey;
  try { publicKey = createPublicKey({ key: keyBytes, type: "spki", format: "der" }); }
  catch { refuse("trusted runner public key cannot be parsed"); }
  need(publicKey.asymmetricKeyType === "ed25519", "trusted runner key is not Ed25519");

  const scanner = parseScannerBytes(scannerReportBytes);
  need(scanner && Array.isArray(scanner.errors) && scanner.errors.length === 0 &&
    // A zero-exit scanner can still report findings. Until a separately
    // authenticated review policy exists, every result must fail closed.
    Array.isArray(scanner.results) && scanner.results.length === 0 && scanner.paths &&
    Array.isArray(scanner.paths.scanned) && scanner.paths.scanned.length > 0 &&
    Array.isArray(scanner.paths.skipped) && scanner.paths.skipped.length === 0,
  "scanner report has findings, errors or incomplete coverage metadata");
  const envelope = parseCanonical(attestationBytes, 64 * 1024, "independent runner attestation");
  record(envelope, ["statement", "signatureBase64"], "attestation envelope");
  record(envelope.statement, STATEMENT_FIELDS, "attested execution statement");
  const statement = envelope.statement;
  need(statement.version === 1 && statement.kind === "VIRKI_INDEPENDENT_MANUAL_RUNNER_V1" &&
    statement.sourceSha === revision && statement.sourceBranch === branch &&
    statement.manifestSha256 === claimed.manifestSha256 &&
    statement.scannerReportSha256 === digest(scannerReportBytes),
  "attestation does not bind the exact source, 19-stage manifest and scanner report");
  for (const field of ["runnerId", "runnerExecutableSha256", "runnerLauncherSha256",
    "scannerExecutableSha256", "scannerRulesCommit"]) {
    need(statement[field] === pinned[field], `attestation differs from installed trusted ${field}`);
  }
  validateProcess(statement.ciProcess, "CI");
  validateProcess(statement.scannerProcess, "scanner");
  matchObservedConsole(ciConsoleBytes, statement.ciProcess, "CI");
  matchObservedConsole(scannerConsoleBytes, statement.scannerProcess, "scanner");
  need(Array.isArray(statement.observedStages) && statement.observedStages.length === STAGES.length,
    "attestation lacks all observed process stage results");
  for (const [index, stage] of statement.observedStages.entries()) {
    record(stage, ["name", "exitCode"], `observed stage ${index + 1}`);
    need(stage.name === STAGES[index] && stage.exitCode === 0,
      `observed process stage ${index + 1} is missing or unsuccessful`);
  }
  need(typeof envelope.signatureBase64 === "string" && B64.test(envelope.signatureBase64),
    "attestation signature is invalid");
  const signature = Buffer.from(envelope.signatureBase64, "base64");
  need(signature.length === 64 && signature.toString("base64") === envelope.signatureBase64 &&
    verify(null, Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(statement))]), publicKey, signature),
  "independent runner attestation signature is invalid");
  return Object.freeze({
    status: "CRYPTOGRAPHIC_BINDING_OK_ONLY", sourceSha: revision,
    manifestSha256: claimed.manifestSha256, scannerReportSha256: digest(scannerReportBytes),
    runnerId: pinned.runnerId, trustedRunnerKeyId: pinned.keyId,
    codeql: "NOT_RUN", hostedCi: "NOT_RUN", deployAuthorized: false,
  });
}

function ownerInstalledLinuxPolicy() {
  need(process.platform === "linux" && typeof process.getuid === "function" && process.getuid() === 0,
    "independent root-owned Linux verifier is required");
  for (const directory of ["/etc", "/etc/virki"]) {
    const parent = lstatSync(directory, { bigint: true });
    need(parent.isDirectory() && !parent.isSymbolicLink() && parent.uid === 0n &&
      (parent.mode & 0o022n) === 0n && realpathSync(directory) === directory,
    "trusted policy directory must be root-owned and protected");
  }
  const before = lstatSync(OWNER_TRUST_PATH, { bigint: true });
  need(before.isFile() && !before.isSymbolicLink() && before.uid === 0n && before.nlink === 1n &&
    (before.mode & 0o7777n) === 0o600n && before.size > 1n && before.size <= 4096n &&
    realpathSync(OWNER_TRUST_PATH) === OWNER_TRUST_PATH,
  "owner-installed trust policy must be a root-owned 0600 single-link file");
  const fd = openSync(OWNER_TRUST_PATH, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const same = (a, b) => ["dev", "ino", "uid", "mode", "nlink", "size", "ctimeNs", "mtimeNs"]
      .every((field) => a[field] === b[field]);
    need(same(before, fstatSync(fd, { bigint: true })), "installed policy changed before read");
    const raw = readFileSync(fd);
    need(same(before, fstatSync(fd, { bigint: true })) &&
      same(before, lstatSync(OWNER_TRUST_PATH, { bigint: true })),
    "installed policy changed during read");
    return parseCanonical(raw, 4096, "owner-installed trust policy");
  } finally { closeSync(fd); }
}

/** Fail-closed MANUAL preview/gate. No caller-provided public keys or trust paths. */
export function inspectIndependentManualRunnerProvenance(input = {}) {
  const denied = (reason) => Object.freeze({
    status: "NO_GO", reason, codeql: "NOT_RUN", hostedCi: "NOT_RUN", deployAuthorized: false,
  });
  try {
    record(input, ["ciManifestBytes", "scannerReportBytes", "revision", "attestationBytes",
      "ciConsoleBytes", "scannerConsoleBytes"],
      "independent gate inputs");
    const policy = ownerInstalledLinuxPolicy();
    const checked = verifySignedManualRunnerStatement({
      ...input, trustedInstalledPolicy: policy,
    });
    return Object.freeze({ ...checked, status: "MANUAL_RUNNER_PROVENANCE_VERIFIED_LOCAL_ONLY",
      trustedPolicyLocation: OWNER_TRUST_PATH });
  } catch (error) {
    return denied(error instanceof Error ? error.message : "manual provenance verification failed");
  }
}
