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
    dbRoles: ["stage-migrator", "stage-runtime", "stage-worker"], smtpTenantId: "staging-smtp"
  };
  const approval = {
    authorizationId: "authorization-001", ownerId: "owner-001", operatorId: "operator-001",
    observerId: "observer-001", observerKeySha256: observer.fingerprint,
    issuedAt: "2026-11-10T19:50:00.000Z", expiresAt: "2026-11-10T21:00:00.000Z",
    sourceSha: SOURCE, ociDigest: DIGEST,
    staging,
    production: {
      hostId: "production-host", dbHostId: "production-postgres", dbName: "virki_prod",
      dbRoles: ["prod-migrator", "prod-runtime", "prod-worker"], smtpTenantId: "production-smtp"
    },
    recipientPolicyId: "staging-policy-001", recipientIds: ["test-admin-inbox", "test-user-inbox"],
    workerIntervalMs: 2500, maxHandoffs: 6, providerPerMinuteQuota: 30
  };
  const observation = {
    authorizationId: approval.authorizationId, observerId: approval.observerId,
    observedAt: "2026-11-10T19:59:00.000Z", sourceSha: SOURCE, ociDigest: DIGEST,
    staging: structuredClone(staging),
    worker: {
      state: "stopped", runningReplicas: 0, restartDisabled: true, autostartDisabled: true,
      outboxDrainStarted: false, effectiveIntervalMs: 2500,
      servicesWithInterval: ["email-worker"],
      observedServiceNames: ["audit-maintenance", "email-worker", "first-admin-bootstrap", "hub", "migrate", "oidc-issuer", "postgres", "public-site", "session-cleanup"],
      evidenceRef: "observer-worker-status-001"
    },
    relay: {
      enforcement: "relay-hard-enforced", recipientPolicyId: "staging-policy-001",
      recipientIds: ["test-admin-inbox", "test-user-inbox"],
      unlistedRecipientRejected: true, denyEvidenceRef: "observer-deny-sample-001",
      policyEvidenceRef: "observer-policy-snapshot-001", hardRateCapPerMinute: 30,
      hardMaxHandoffs: 6, remainingDailyQuota: 50
    },
    queue: { queued: 0, processing: 0, retryable: 0, sent: 0, terminal: 0, deliveryAttempts: 0, evidenceRef: "observer-queue-empty-001" }
  };
  const invoke = () => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", approval, approver),
    observationEnvelope: signed("observation", observation, observer),
    approverPublicKey: approver.publicKey, observerPublicKey: observer.publicKey,
    expectedSourceSha: SOURCE, now: NOW
  });
  return { approver, observer, approval, observation, invoke };
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
    expectedSourceSha: SOURCE, now: NOW
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
    ["no recipient allowlist", (a) => { a.recipientIds = []; }, "INVALID_IDENTITIES"],
    ["duplicate recipient", (a) => { a.recipientIds = ["test-user-inbox", "test-user-inbox"]; }, "INVALID_IDENTITIES"],
    ["address/PII instead of opaque recipient ID", (a) => { a.recipientIds = ["user@example.invalid"]; }, "INVALID_IDENTITIES"],
    ["empty budget", (a) => { a.maxHandoffs = 0; }, "INVALID_LIMIT"],
    ["zero interval not an enforceable quota", (a) => { a.workerIntervalMs = 0; }, "INVALID_LIMIT"],
    ["interval outside worker range", (a) => { a.workerIntervalMs = 60_001; }, "INVALID_LIMIT"],
    ["theoretical successful-send rate exceeds provider budget", (a, o) => { a.workerIntervalMs = o.worker.effectiveIntervalMs = 250; }, "SEND_BUDGET_NOT_PROVEN"],
    ["bad OCI digest", (a) => { a.ociDigest = "sha256:unsafe"; }, "INVALID_FIELD"],
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
    mutate(f.approval, f.observation);
    assert.throws(f.invoke, { code: expected }, label);
  });
}

test("wrong independent key, forged observer fingerprint, expired approved signer and mismatched target SHA fail closed", () => {
  const f = fixture();
  const other = keys();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", f.approval, f.approver),
    observationEnvelope: signed("observation", f.observation, f.observer),
    approverPublicKey: f.approver.publicKey, observerPublicKey: other.publicKey,
    expectedSourceSha: SOURCE, now: NOW
  }), { code: "INVALID_SIGNATURE" });
  f.approval.observerKeySha256 = other.fingerprint;
  assert.throws(f.invoke, { code: "OBSERVER_NOT_INDEPENDENT" });
  const g = fixture();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", g.approval, g.approver),
    observationEnvelope: signed("observation", g.observation, g.observer),
    approverPublicKey: g.approver.publicKey, observerPublicKey: g.observer.publicKey,
    expectedSourceSha: "c".repeat(40), now: NOW
  }), { code: "ATTESTATION_MISMATCH" });
  const identical = fixture();
  assert.throws(() => evaluateStagingOtpPreflight({
    approvalEnvelope: signed("approval", identical.approval, identical.approver),
    observationEnvelope: signed("observation", identical.observation, identical.approver),
    approverPublicKey: identical.approver.publicKey, observerPublicKey: identical.approver.publicKey,
    expectedSourceSha: SOURCE, now: NOW
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
      "--expected-source-sha", SOURCE
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
