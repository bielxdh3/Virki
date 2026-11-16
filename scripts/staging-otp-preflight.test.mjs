import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  canonicalStagingJson, evaluateStagingOtpPreflight, runStagingOtpPreflightCli
} from "./staging-otp-preflight.mjs";

const NOW = new Date("2026-11-10T20:00:00.000Z");
const SOURCE = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    privateKey,
    fingerprint: `sha256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")}`
  };
}

function signed(field, payload, signer) {
  return {
    version: 1,
    [field]: payload,
    signature: sign(null, Buffer.from(`Virki staging OTP ${field} v1\n${canonicalStagingJson(payload)}`), signer.privateKey).toString("base64")
  };
}

function fixture() {
  const approver = keys();
  const observer = keys();
  const staging = {
    hostId: "staging-host", dbHostId: "staging-postgres", dbName: "virki_stage",
    dbRoles: ["stage-migrator", "stage-runtime", "stage-worker"], smtpTenantId: "staging-smtp",
    smtpEndpointId: "staging-smtp-endpoint", smtpAccountId: "staging-smtp-account",
    smtpHost: "smtp.staging.example.invalid", smtpPort: 587, smtpSecure: false,
    smtpUsernameSha256: "1".repeat(64),
    networkId: "d".repeat(64)
  };
  const approval = {
    authorizationId: "authorization-001", ownerId: "owner-001", operatorId: "operator-001",
    observerId: "observer-001", observerKeySha256: observer.fingerprint,
    issuedAt: "2026-11-10T19:50:00.000Z", expiresAt: "2026-11-10T21:00:00.000Z",
    sourceSha: SOURCE, ociDigest: DIGEST, hubOciDigest: `sha256:${"c".repeat(64)}`,
    workerComposeProject: "virki-stage-worker", hubComposeProject: "virki-stage-hub",
    hubComposeFileSha256: "f".repeat(64),
    staging,
    production: {
      hostId: "production-host", dbHostId: "production-postgres", dbName: "virki_prod",
      dbRoles: ["prod-migrator", "prod-runtime", "prod-worker"], smtpTenantId: "production-smtp",
      smtpEndpointId: "production-smtp-endpoint", smtpAccountId: "production-smtp-account",
      smtpHost: "smtp.production.example.invalid", smtpPort: 587, smtpSecure: false,
      smtpUsernameSha256: "2".repeat(64),
      networkId: "e".repeat(64)
    },
    workerResourcePolicyId: "worker-resource-policy-001",
    workerMemoryLimitBytes: 536870912,
    workerCpuLimitNano: 1000000000,
    workerPidsLimit: 128,
    recipientPolicyId: "staging-policy-001", recipientIds: ["test-admin-inbox", "test-user-inbox"],
    workerIntervalMs: 2500, maxHandoffs: 6, providerPerMinuteQuota: 30
  };
  const observation = {
    authorizationId: approval.authorizationId, observerId: approval.observerId,
    observedAt: "2026-11-10T19:59:00.000Z", sourceSha: SOURCE, ociDigest: DIGEST,
    hubOciDigest: approval.hubOciDigest, workerComposeProject: approval.workerComposeProject,
    hubComposeProject: approval.hubComposeProject, hubComposeFileSha256: approval.hubComposeFileSha256,
    staging: structuredClone(staging),
    worker: {
      state: "stopped", runningReplicas: 0, restartDisabled: true, autostartDisabled: true,
      outboxDrainStarted: false, effectiveIntervalMs: 2500,
      servicesWithInterval: ["email-worker"],
      observedServiceNames: ["audit-maintenance", "email-worker", "first-admin-bootstrap", "hub", "migrate", "oidc-issuer", "postgres", "public-site", "session-cleanup"],
      resourcePolicyId: "worker-resource-policy-001", resourcePolicyEvidenceRef: "observer-resource-policy-001",
      memoryLimitBytes: 536870912, cpuLimitNano: 1000000000, pidsLimit: 128,
      evidenceRef: "observer-worker-status-001"
    },
    relay: {
      smtpTenantId: staging.smtpTenantId, smtpEndpointId: staging.smtpEndpointId,
      smtpAccountId: staging.smtpAccountId, smtpHost: staging.smtpHost,
      smtpPort: staging.smtpPort, smtpSecure: staging.smtpSecure,
      smtpUsernameSha256: staging.smtpUsernameSha256,
      smtpAuthenticationVerified: true, smtpAuthenticationEvidenceRef: "observer-smtp-auth-001",
      enforcement: "relay-hard-enforced", recipientPolicyId: "staging-policy-001",
      recipientIds: ["test-admin-inbox", "test-user-inbox"],
      unlistedRecipientRejected: true, denyEvidenceRef: "observer-deny-sample-001",
      policyEvidenceRef: "observer-policy-snapshot-001", hardRateCapPerMinute: 30,
      hardMaxHandoffs: 6, remainingDailyQuota: 50
    },
    queue: { queued: 0, processing: 0, retryable: 0, sent: 0, terminal: 0, deliveryAttempts: 0, evidenceRef: "observer-queue-empty-001" }
  };
  const smtpConfig = {
    tenantId: staging.smtpTenantId, endpointId: staging.smtpEndpointId,
    accountId: staging.smtpAccountId, host: staging.smtpHost,
    port: staging.smtpPort, secure: staging.smtpSecure,
    usernameSha256: staging.smtpUsernameSha256
  };
  const invoke = () => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", approval, approver),
    observationEnvelope: signed("observation", observation, observer),
    approverPublicKey: approver.publicKey, observerPublicKey: observer.publicKey,
    expectedSourceSha: SOURCE, smtpConfig, now: NOW
  });
  return { approver, observer, approval, observation, smtpConfig, invoke };
}

test("offline signed declaration result NEVER claims live worker verification, staging authorization or release", () => {
  const result = fixture().invoke();
  assert.deepEqual(result, {
    status: "SIGNED_OFFLINE_DECLARATIONS_CONSISTENT",
    liveWorkerState: "NOT_OBSERVED_BY_THIS_TOOL",
    stagingAuthorization: "NOT_GRANTED_BY_THIS_TOOL",
    release: "NO_GO"
  });
});

test("independently signed approval and observation accept semantically equal staging with different key insertion order", () => {
  const f = fixture();
  // Both principals serialize and sign their OWN declarations. Changing only
  // object key insertion order must not cause a comparison false-red.
  f.approval.staging = Object.fromEntries(Object.entries(f.approval.staging).reverse());
  f.observation.staging = Object.fromEntries(
    Object.entries(f.observation.staging).sort(([a], [b]) => a.localeCompare(b))
  );
  assert.notEqual(JSON.stringify(f.approval.staging), JSON.stringify(f.observation.staging));
  assert.equal(canonicalStagingJson(f.approval.staging), canonicalStagingJson(f.observation.staging));
  assert.equal(f.invoke().status, "SIGNED_OFFLINE_DECLARATIONS_CONSISTENT");
});

test("independently signed reordered staging objects still reject a mismatched value", () => {
  const f = fixture();
  f.approval.staging = Object.fromEntries(Object.entries(f.approval.staging).reverse());
  f.observation.staging = Object.fromEntries(Object.entries(f.observation.staging).reverse());
  f.observation.staging.hostId = "unexpected-stage-host";
  assert.notEqual(canonicalStagingJson(f.approval.staging), canonicalStagingJson(f.observation.staging));
  assert.throws(f.invoke, { code: "ATTESTATION_MISMATCH" });
});

test("signed staging list order remains security-significant and rejects reordered database roles", () => {
  const f = fixture();
  f.observation.staging = Object.fromEntries(Object.entries(f.observation.staging).reverse());
  f.observation.staging.dbRoles.reverse();
  assert.notEqual(canonicalStagingJson(f.approval.staging), canonicalStagingJson(f.observation.staging));
  assert.throws(f.invoke, { code: "INVALID_IDENTITIES" });
});

test("local preflight has no network, SMTP, Docker, SSH or child-process dependency", () => {
  const source = readFileSync(new URL("./staging-otp-preflight.mjs", import.meta.url), "utf8");
  assert.deepEqual([...source.matchAll(/\bfrom "(node:[^"]+)"/gu)].map((match) => match[1]).sort(),
    ["node:crypto", "node:fs", "node:path", "node:url"]);
  assert.doesNotMatch(source, /\b(?:fetch|spawn|spawnSync|exec|execFile|execSync|connect|createConnection|createTransport)\s*\(/u);
  assert.doesNotMatch(source, /\bprocess\.env\b/u);
});

test("mutations without valid signatures cannot acquire a pass", () => {
  const f = fixture();
  const approvalEnvelope = signed("approval", f.approval, f.approver);
  const observationEnvelope = signed("observation", f.observation, f.observer);
  const options = {
    approvalEnvelope, observationEnvelope,
    approverPublicKey: f.approver.publicKey, observerPublicKey: f.observer.publicKey,
    expectedSourceSha: SOURCE, smtpConfig: f.smtpConfig, now: NOW
  };
  observationEnvelope.observation.worker.state = "running";
  assert.throws(() => evaluateStagingOtpPreflight(options), { code: "INVALID_SIGNATURE" });
  observationEnvelope.observation.worker.state = "stopped";
  approvalEnvelope.approval.staging.hostId = "production-host";
  assert.throws(() => evaluateStagingOtpPreflight(options), { code: "INVALID_SIGNATURE" });
});

const negativeCases = [
    ["unknown approval field", (a) => { a.smtpPassword = "secret-do-not-print"; }, "INVALID_SCHEMA"],
    ["different owner and observer required", (a) => { a.observerId = a.ownerId; }, "OBSERVER_NOT_INDEPENDENT"],
    ["different operator and observer required", (a) => { a.observerId = a.operatorId; }, "OBSERVER_NOT_INDEPENDENT"],
    ["host shared with production", (a, o) => { a.staging.hostId = o.staging.hostId = a.production.hostId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["postgres host shared with production", (a, o) => { a.staging.dbHostId = o.staging.dbHostId = a.production.dbHostId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["database name shared with production", (a, o) => { a.staging.dbName = o.staging.dbName = a.production.dbName; }, "PRODUCTION_IDENTITY_REUSE"],
    ["role shared with production", (a) => { a.production.dbRoles[0] = a.staging.dbRoles[0]; a.production.dbRoles.sort(); }, "PRODUCTION_IDENTITY_REUSE"],
    ["SMTP tenant shared with production", (a, o) => { a.staging.smtpTenantId = o.staging.smtpTenantId = a.production.smtpTenantId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["SMTP endpoint shared with production", (a, o) => { a.staging.smtpEndpointId = o.staging.smtpEndpointId = a.production.smtpEndpointId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["SMTP account shared with production", (a, o) => { a.staging.smtpAccountId = o.staging.smtpAccountId = a.production.smtpAccountId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["SMTP username fingerprint shared with production", (a, o) => { a.staging.smtpUsernameSha256 = o.staging.smtpUsernameSha256 = a.production.smtpUsernameSha256; }, "PRODUCTION_IDENTITY_REUSE"],
    ["missing SMTP endpoint identity", (a) => { delete a.staging.smtpEndpointId; }, "INVALID_SCHEMA"],
    ["missing SMTP account identity", (a) => { delete a.staging.smtpAccountId; }, "INVALID_SCHEMA"],
    ["invalid SMTP endpoint hostname", (a) => { a.staging.smtpHost = "https://smtp.example.invalid"; }, "INVALID_FIELD"],
    ["invalid SMTP endpoint port", (a) => { a.staging.smtpPort = 0; }, "INVALID_LIMIT"],
    ["invalid SMTP secure mode", (a) => { a.staging.smtpSecure = "false"; }, "INVALID_FIELD"],
    ["invalid SMTP username fingerprint", (a) => { a.staging.smtpUsernameSha256 = "not-a-hash"; }, "INVALID_FIELD"],
    ["no recipient allowlist", (a) => { a.recipientIds = []; }, "INVALID_IDENTITIES"],
    ["duplicate recipient", (a) => { a.recipientIds = ["test-user-inbox", "test-user-inbox"]; }, "INVALID_IDENTITIES"],
    ["address/PII instead of opaque recipient ID", (a) => { a.recipientIds = ["user@example.invalid"]; }, "INVALID_IDENTITIES"],
    ["empty budget", (a) => { a.maxHandoffs = 0; }, "INVALID_LIMIT"],
    ["worker memory must be explicitly bounded", (a) => { a.workerMemoryLimitBytes = 0; }, "INVALID_LIMIT"],
    ["worker CPU must be explicitly bounded", (a) => { a.workerCpuLimitNano = 0; }, "INVALID_LIMIT"],
    ["worker process count must be explicitly bounded", (a) => { a.workerPidsLimit = 0; }, "INVALID_LIMIT"],
    ["missing worker memory approval", (a) => { delete a.workerMemoryLimitBytes; }, "INVALID_SCHEMA"],
    ["missing worker CPU approval", (a) => { delete a.workerCpuLimitNano; }, "INVALID_SCHEMA"],
    ["missing worker PID approval", (a) => { delete a.workerPidsLimit; }, "INVALID_SCHEMA"],
    ["missing worker resource policy identity", (a) => { delete a.workerResourcePolicyId; }, "INVALID_SCHEMA"],
    ["observed worker memory differs from signed policy", (_a, o) => { o.worker.memoryLimitBytes += 1; }, "ATTESTATION_MISMATCH"],
    ["observed worker CPU differs from signed policy", (_a, o) => { o.worker.cpuLimitNano += 1; }, "ATTESTATION_MISMATCH"],
    ["observed worker process count differs from signed policy", (_a, o) => { o.worker.pidsLimit += 1; }, "ATTESTATION_MISMATCH"],
    ["missing observed worker memory", (_a, o) => { delete o.worker.memoryLimitBytes; }, "INVALID_SCHEMA"],
    ["missing observed worker CPU", (_a, o) => { delete o.worker.cpuLimitNano; }, "INVALID_SCHEMA"],
    ["missing observed worker PID limit", (_a, o) => { delete o.worker.pidsLimit; }, "INVALID_SCHEMA"],
    ["missing observed worker resource policy evidence", (_a, o) => { delete o.worker.resourcePolicyEvidenceRef; }, "INVALID_SCHEMA"],
    ["worker resource policy identity differs from approval", (_a, o) => { o.worker.resourcePolicyId = "different-resource-policy"; }, "ATTESTATION_MISMATCH"],
    ["worker resource policy evidence reference is missing", (_a, o) => { o.worker.resourcePolicyEvidenceRef = ""; }, "INVALID_FIELD"],
    ["zero interval not an enforceable quota", (a) => { a.workerIntervalMs = 0; }, "INVALID_LIMIT"],
    ["interval outside worker range", (a) => { a.workerIntervalMs = 60_001; }, "INVALID_LIMIT"],
    ["theoretical successful-send rate exceeds provider budget", (a, o) => { a.workerIntervalMs = o.worker.effectiveIntervalMs = 250; }, "SEND_BUDGET_NOT_PROVEN"],
    ["bad OCI digest", (a) => { a.ociDigest = "sha256:unsafe"; }, "INVALID_FIELD"],
    ["missing Hub OCI digest", (a) => { delete a.hubOciDigest; }, "INVALID_SCHEMA"],
    ["invalid Hub OCI digest", (a) => { a.hubOciDigest = "sha256:unsafe"; }, "INVALID_FIELD"],
    ["missing worker Compose project", (a) => { delete a.workerComposeProject; }, "INVALID_SCHEMA"],
    ["missing Hub Compose project", (a) => { delete a.hubComposeProject; }, "INVALID_SCHEMA"],
    ["worker and Hub reuse the same Compose project", (a) => { a.hubComposeProject = a.workerComposeProject; }, "PRODUCTION_IDENTITY_REUSE"],
    ["worker reuses the production Compose project", (a) => { a.workerComposeProject = "virki-prod"; }, "PRODUCTION_IDENTITY_REUSE"],
    ["Hub reuses the deManage Compose namespace", (a) => { a.hubComposeProject = "demanage-stage"; }, "PRODUCTION_IDENTITY_REUSE"],
    ["missing Hub Compose file digest", (a) => { delete a.hubComposeFileSha256; }, "INVALID_SCHEMA"],
    ["invalid Hub Compose file digest", (a) => { a.hubComposeFileSha256 = "unsafe"; }, "INVALID_FIELD"],
    ["missing staging Docker network identity", (a) => { delete a.staging.networkId; }, "INVALID_SCHEMA"],
    ["invalid staging Docker network identity", (a) => { a.staging.networkId = "not-a-network-id"; }, "INVALID_FIELD"],
    ["staging reuses the production Docker network", (a) => { a.production.networkId = a.staging.networkId; }, "PRODUCTION_IDENTITY_REUSE"],
    ["missing production Docker network identity", (a) => { delete a.production.networkId; }, "INVALID_SCHEMA"],
    ["observed Hub OCI digest differs from approval", (_a, o) => { o.hubOciDigest = `sha256:${"d".repeat(64)}`; }, "ATTESTATION_MISMATCH"],
    ["observed worker Compose project differs from approval", (_a, o) => { o.workerComposeProject = "other-stage-worker"; }, "ATTESTATION_MISMATCH"],
    ["observed Hub Compose project differs from approval", (_a, o) => { o.hubComposeProject = "other-stage-hub"; }, "ATTESTATION_MISMATCH"],
    ["observed Hub Compose file digest differs from approval", (_a, o) => { o.hubComposeFileSha256 = "a".repeat(64); }, "ATTESTATION_MISMATCH"],
    ["observed staging Docker network differs from approval", (_a, o) => { o.staging.networkId = "f".repeat(64); }, "ATTESTATION_MISMATCH"],
    ["expired authorization", (a) => { a.expiresAt = "2026-11-10T19:58:00.000Z"; }, "STALE_OR_UNAUTHORIZED_EVIDENCE"],
    ["unknown evidence field", (_a, o) => { o.smtpSecret = "secret-do-not-print"; }, "INVALID_SCHEMA"],
    ["wrong observed host", (_a, o) => { o.staging.hostId = "another-host"; }, "ATTESTATION_MISMATCH"],
    ["wrong observed OCI digest", (_a, o) => { o.ociDigest = `sha256:${"c".repeat(64)}`; }, "ATTESTATION_MISMATCH"],
    ["wrong observer identity", (_a, o) => { o.observerId = "unapproved-observer"; }, "ATTESTATION_MISMATCH"],
    ["stale observation", (_a, o) => { o.observedAt = "2026-11-10T19:54:59.000Z"; }, "STALE_OR_UNAUTHORIZED_EVIDENCE"],
    ["future worker observation", (_a, o) => { o.observedAt = "2026-11-10T20:01:00.000Z"; }, "STALE_OR_UNAUTHORIZED_EVIDENCE"],
    ["worker running", (_a, o) => { o.worker.state = "running"; }, "INVALID_ATTESTATION"],
    ["worker process live", (_a, o) => { o.worker.runningReplicas = 1; }, "INVALID_LIMIT"],
    ["worker can restart", (_a, o) => { o.worker.restartDisabled = false; }, "INVALID_ATTESTATION"],
    ["worker autostarts", (_a, o) => { o.worker.autostartDisabled = false; }, "INVALID_ATTESTATION"],
    ["outbox already drained", (_a, o) => { o.worker.outboxDrainStarted = true; }, "INVALID_ATTESTATION"],
    ["wrong effective interval", (_a, o) => { o.worker.effectiveIntervalMs = 2800; }, "ATTESTATION_MISMATCH"],
    ["interval injected in another service", (_a, o) => { o.worker.servicesWithInterval.push("hub"); }, "ATTESTATION_MISMATCH"],
    ["omitted service undermines worker-only check", (_a, o) => { o.worker.observedServiceNames.pop(); }, "ATTESTATION_MISMATCH"],
    ["missing worker observation ref", (_a, o) => { o.worker.evidenceRef = ""; }, "INVALID_FIELD"],
    ["allowlist not enforced at relay", (_a, o) => { o.relay.enforcement = "document-only"; }, "INVALID_ATTESTATION"],
    ["unlisted recipient not rejected", (_a, o) => { o.relay.unlistedRecipientRejected = false; }, "INVALID_ATTESTATION"],
    ["allowlist altered", (_a, o) => { o.relay.recipientIds = ["test-admin-inbox"]; }, "ATTESTATION_MISMATCH"],
    ["relay tenant differs from owner approval", (_a, o) => { o.relay.smtpTenantId = "other-stage-tenant"; }, "ATTESTATION_MISMATCH"],
    ["relay endpoint differs from owner approval", (_a, o) => { o.relay.smtpEndpointId = "other-stage-endpoint"; }, "ATTESTATION_MISMATCH"],
    ["relay account differs from owner approval", (_a, o) => { o.relay.smtpAccountId = "other-stage-account"; }, "ATTESTATION_MISMATCH"],
    ["relay hostname differs from owner approval", (_a, o) => { o.relay.smtpHost = "smtp.other.invalid"; }, "ATTESTATION_MISMATCH"],
    ["relay port differs from owner approval", (_a, o) => { o.relay.smtpPort = 465; }, "ATTESTATION_MISMATCH"],
    ["relay secure mode differs from owner approval", (_a, o) => { o.relay.smtpSecure = true; }, "ATTESTATION_MISMATCH"],
    ["relay account username fingerprint differs from owner approval", (_a, o) => { o.relay.smtpUsernameSha256 = "3".repeat(64); }, "ATTESTATION_MISMATCH"],
    ["relay SMTP authentication was not verified against the signed tenant", (_a, o) => { o.relay.smtpAuthenticationVerified = false; }, "INVALID_ATTESTATION"],
    ["relay SMTP authentication evidence is missing", (_a, o) => { o.relay.smtpAuthenticationEvidenceRef = ""; }, "INVALID_FIELD"],
    ["provider budget cannot cover handoffs", (_a, o) => { o.relay.hardMaxHandoffs = 3; }, "SEND_BUDGET_NOT_PROVEN"],
    ["rate cap lower than actual interval throughput", (_a, o) => { o.relay.hardRateCapPerMinute = 20; }, "SEND_BUDGET_NOT_PROVEN"],
    ["daily quota unavailable", (_a, o) => { o.relay.remainingDailyQuota = 5; }, "INVALID_LIMIT"],
    ["preexisting queued email", (_a, o) => { o.queue.queued = 1; }, "INVALID_LIMIT"],
    ["preexisting processing email", (_a, o) => { o.queue.processing = 1; }, "INVALID_LIMIT"],
    ["preexisting retryable email", (_a, o) => { o.queue.retryable = 1; }, "INVALID_LIMIT"],
    ["earlier sent email invalidates pre-drain evidence", (_a, o) => { o.queue.sent = 1; }, "INVALID_LIMIT"],
    ["historical failed email invalidates virgin queue", (_a, o) => { o.queue.terminal = 1; }, "INVALID_LIMIT"],
    ["historical delivery attempt invalidates pre-drain evidence", (_a, o) => { o.queue.deliveryAttempts = 1; }, "INVALID_LIMIT"]
];
for (const [label, mutate, expected] of negativeCases) {
  test(`signed negative: ${label}`, () => {
    const f = fixture();
    mutate(f.approval, f.observation, f.smtpConfig);
    assert.throws(f.invoke, { code: expected }, label);
  });
}

test("effective SMTP host, port, TLS mode and account fingerprint must match the signed tenant/endpoint/account", () => {
  const f = fixture();
  for (const [field, value] of [
    ["tenantId", "other-stage-tenant"], ["endpointId", "other-stage-endpoint"],
    ["accountId", "other-stage-account"], ["host", "smtp.other.invalid"],
    ["port", 465], ["secure", true], ["usernameSha256", "4".repeat(64)]
  ]) {
    const changed = { ...f.smtpConfig, [field]: value };
    assert.throws(() => evaluateStagingOtpPreflight({
      approvalEnvelope: signed("approval", f.approval, f.approver),
      observationEnvelope: signed("observation", f.observation, f.observer),
      approverPublicKey: f.approver.publicKey, observerPublicKey: f.observer.publicKey,
      expectedSourceSha: SOURCE, smtpConfig: changed, now: NOW
    }), { code: "ATTESTATION_MISMATCH" }, `changed ${field} must not pass`);
  }
});

test("wrong independent key, forged observer fingerprint, expired approved signer and mismatched target SHA fail closed", () => {
  const f = fixture();
  const other = keys();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", f.approval, f.approver),
    observationEnvelope: signed("observation", f.observation, f.observer),
    approverPublicKey: f.approver.publicKey, observerPublicKey: other.publicKey,
    expectedSourceSha: SOURCE, smtpConfig: f.smtpConfig, now: NOW
  }), { code: "INVALID_SIGNATURE" });
  f.approval.observerKeySha256 = other.fingerprint;
  assert.throws(f.invoke, { code: "OBSERVER_NOT_INDEPENDENT" });
  const g = fixture();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", g.approval, g.approver),
    observationEnvelope: signed("observation", g.observation, g.observer),
    approverPublicKey: g.approver.publicKey, observerPublicKey: g.observer.publicKey,
    expectedSourceSha: "c".repeat(40), smtpConfig: g.smtpConfig, now: NOW
  }), { code: "ATTESTATION_MISMATCH" });
  const identical = fixture();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", identical.approval, identical.approver),
    observationEnvelope: signed("observation", identical.observation, identical.approver),
    approverPublicKey: identical.approver.publicKey, observerPublicKey: identical.approver.publicKey,
    expectedSourceSha: SOURCE, smtpConfig: identical.smtpConfig, now: NOW
  }), { code: "OBSERVER_NOT_INDEPENDENT" });
});

test("CLI reads only explicit JSON/public-key documents, never leaks input fields, and never claims live staging", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "virki-offline-otp-preflight-"));
  try {
    const f = fixture();
    const args = [
      "--approval", path.join(dir, "approval.json"),
      "--observation", path.join(dir, "observation.json"),
      "--approver-public-key", path.join(dir, "owner.pub.pem"),
      "--observer-public-key", path.join(dir, "observer.pub.pem"),
      "--expected-source-sha", SOURCE,
      "--smtp-tenant-id", f.smtpConfig.tenantId,
      "--smtp-endpoint-id", f.smtpConfig.endpointId,
      "--smtp-account-id", f.smtpConfig.accountId,
      "--smtp-host", f.smtpConfig.host,
      "--smtp-port", String(f.smtpConfig.port),
      "--smtp-secure", String(f.smtpConfig.secure),
      "--smtp-username-sha256", f.smtpConfig.usernameSha256,
      "--runtime-worker-oci-digest", f.approval.ociDigest,
      "--runtime-hub-oci-digest", f.approval.hubOciDigest,
      "--runtime-worker-compose-project", f.approval.workerComposeProject,
      "--runtime-hub-compose-project", f.approval.hubComposeProject,
      "--runtime-hub-compose-file-sha256", f.approval.hubComposeFileSha256,
      "--runtime-network-id", f.approval.staging.networkId,
      "--runtime-db-name", f.approval.staging.dbName,
      "--runtime-resource-policy-id", f.approval.workerResourcePolicyId,
      "--runtime-resource-policy-evidence-ref", f.observation.worker.resourcePolicyEvidenceRef,
      "--runtime-worker-memory-bytes", String(f.approval.workerMemoryLimitBytes),
      "--runtime-worker-cpu-nano", String(f.approval.workerCpuLimitNano),
      "--runtime-worker-pids-limit", String(f.approval.workerPidsLimit),
      "--runtime-worker-interval-ms", String(f.approval.workerIntervalMs)
    ];
    writeFileSync(args[1], JSON.stringify(signed("approval", f.approval, f.approver)));
    writeFileSync(args[3], JSON.stringify(signed("observation", f.observation, f.observer)));
    writeFileSync(args[5], f.approver.publicKey);
    writeFileSync(args[7], f.observer.publicKey);
    const capture = () => {
      let stdout = "";
      let stderr = "";
      const status = runStagingOtpPreflightCli(args, { now: NOW,
        out: { write: (text) => { stdout += text; } }, err: { write: (text) => { stderr += text; } }
      });
      return { stdout, stderr, status };
    };
    const pass = capture();
    assert.equal(pass.status, 0, pass.stderr);
    assert.match(pass.stdout, /SIGNED_OFFLINE_DECLARATIONS_CONSISTENT/u);
    assert.match(pass.stdout, /LIVE_WORKER_STATE=NOT_OBSERVED_BY_THIS_TOOL/u);
    assert.match(pass.stdout, /STAGING_AUTHORIZATION=NOT_GRANTED_BY_THIS_TOOL/u);
    assert.match(pass.stdout, /PRODUCTION_RELEASE=NO_GO/u);
    assert.equal(pass.stderr, "");
    for (const [name, malformed] of [
      ["--runtime-worker-oci-digest", `sha256:${"f".repeat(64)}`],
      ["--runtime-hub-oci-digest", `sha256:${"d".repeat(64)}`],
      ["--runtime-worker-compose-project", "different-worker-project"],
      ["--runtime-hub-compose-project", "different-hub-project"],
      ["--runtime-hub-compose-file-sha256", "e".repeat(64)],
      ["--runtime-network-id", "a".repeat(64)],
      ["--runtime-db-name", "different_stage_db"],
      ["--runtime-resource-policy-id", "different-policy-001"],
      ["--runtime-resource-policy-evidence-ref", "different-receipt-001"],
      ["--runtime-worker-memory-bytes", "1073741824"],
      ["--runtime-worker-cpu-nano", "2000000000"],
      ["--runtime-worker-pids-limit", "129"],
      ["--runtime-worker-interval-ms", "3000"]
    ]) {
      const index = args.indexOf(name) + 1;
      const original = args[index];
      args[index] = malformed;
      const rejected = capture();
      assert.equal(rejected.status, 1, `${name} mismatch must block`);
      assert.match(rejected.stderr, /BLOCK:ATTESTATION_MISMATCH/u);
      args[index] = original;
    }
    const omittedRuntime = args.splice(args.indexOf("--runtime-network-id"), 2);
    assert.equal(capture().status, 1, "missing runtime comparison must fail closed");
    args.splice(args.indexOf("--runtime-db-name"), 0, ...omittedRuntime);
    const smtpHostIndex = args.indexOf("--smtp-host") + 1;
    const approvedSmtpHost = args[smtpHostIndex];
    args[smtpHostIndex] = "smtp.production.example.invalid";
    const wrongSmtp = capture();
    assert.equal(wrongSmtp.status, 1);
    assert.match(wrongSmtp.stderr, /BLOCK:ATTESTATION_MISMATCH/u);
    args[smtpHostIndex] = approvedSmtpHost;
    const approvedBytes = JSON.stringify(signed("approval", f.approval, f.approver));
    const observedBytes = JSON.stringify(signed("observation", f.observation, f.observer));
    // JSON.parse would silently take the last value, thus preserving the
    // canonical signed payload while hiding an extra ambiguous earlier key.
    for (const duplicated of [
      approvedBytes.replace('"staging":{', '"staging":{"hostId":"shadow-host",'),
      approvedBytes.replace('"staging":{', '"staging":{"\\u0068ostId":"shadow-host",'),
      approvedBytes.replace('"version":1,', '"version":2,"version":1,')
    ]) {
      writeFileSync(args[1], duplicated);
      const rejected = capture();
      assert.equal(rejected.status, 1);
      assert.match(rejected.stderr, /BLOCK:DUPLICATE_JSON_KEY/u);
      assert.doesNotMatch(rejected.stderr, /shadow-host|staging-host|shadow|password/u);
    }
    writeFileSync(args[1], approvedBytes);
    writeFileSync(args[3], observedBytes.replace('"worker":{', '"worker":{"state":"running",'));
    const nestedObservation = capture();
    assert.equal(nestedObservation.status, 1);
    assert.match(nestedObservation.stderr, /BLOCK:DUPLICATE_JSON_KEY/u);
    writeFileSync(args[3], observedBytes);
    // The command must refuse UNC/SMB before any open, including a missing
    // share. Aliased parent directories and hardlinks cannot be trusted.
    args[1] = "\\\\127.0.0.1\\unreachable-share\\approval.json";
    assert.equal(capture().status, 1);
    args[1] = path.join(dir, "approval.json");
    const alias = path.join(dir, "aliased-parent");
    symlinkSync(dir, alias, process.platform === "win32" ? "junction" : "dir");
    args[1] = path.join(alias, "approval.json");
    assert.equal(capture().status, 1);
    args[1] = path.join(dir, "approval.json");
    const hardlink = path.join(dir, "hardlink.json");
    linkSync(args[1], hardlink);
    args[1] = hardlink;
    assert.equal(capture().status, 1);
    args[1] = path.join(dir, "approval.json");
    rmSync(hardlink);
    const poisoned = structuredClone(f.approval);
    poisoned.VIRKI_EMAIL_SMTP_PASSWORD = "SECRET_SENTINEL_NOT_FOR_OUTPUT";
    writeFileSync(args[1], JSON.stringify(signed("approval", poisoned, f.approver)));
    const denied = capture();
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /BLOCK:INVALID_SCHEMA/u);
    assert.doesNotMatch(denied.stdout + denied.stderr, /SECRET_SENTINEL|production-host|staging-host|@[a-z]/u);
    args[1] = path.join(dir, ".env");
    assert.equal(capture().status, 1, "must refuse reading .env or arbitrary secret files");
    args[1] = path.join(dir, "approval.json");
    args[5] = path.join(dir, "owner.private.pem");
    assert.equal(capture().status, 1, "must refuse loading private key files");
    args[5] = path.join(dir, "owner.pub.pem");
    args[8] = "--unknown-option";
    assert.equal(capture().status, 1, "must fail unknown flags before any file read");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
