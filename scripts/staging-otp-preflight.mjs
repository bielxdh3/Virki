#!/usr/bin/env node
// Offline consistency check of separately signed staging declarations. Never connects to a host,
// inspects containers, reads .env, enables a worker, or authorizes staging/release operations.
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_SHA = /^[a-f0-9]{40}$/u;
const OCI_DIGEST = /^sha256:[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9._-]{2,95}$/u;
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_OBSERVATION_AGE_MS = 5 * 60_000;
const NON_WORKER_SERVICES = ["audit-maintenance", "first-admin-bootstrap", "hub", "migrate", "oidc-issuer", "postgres", "public-site", "session-cleanup"];

export class StagingOtpPreflightError extends Error {
  constructor(code) {
    super(code);
    this.name = "StagingOtpPreflightError";
    this.code = code;
  }
}

function block(code) { throw new StagingOtpPreflightError(code); }
function shape(value, keys) {
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) block("INVALID_SCHEMA");
}
function requireMatch(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) block("INVALID_FIELD");
}
function requireBool(value, expected) {
  if (value !== expected) block("INVALID_ATTESTATION");
}
function requireInteger(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) block("INVALID_LIMIT");
}
function requireIds(value, min = 1, max = 20) {
  if (!Array.isArray(value) || value.length < min || value.length > max ||
      value.some((id) => typeof id !== "string" || !IDENTIFIER.test(id)) ||
      new Set(value).size !== value.length ||
      JSON.stringify(value) !== JSON.stringify([...value].sort())) block("INVALID_IDENTITIES");
}
function requireSame(a, b) {
  if (JSON.stringify(a) !== JSON.stringify(b)) block("ATTESTATION_MISMATCH");
}
function requireTime(value) {
  requireMatch(value, UTC_TIME);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) block("INVALID_TIME");
  return ms;
}

// Signatures cover JSON values with deterministic key ordering, not human-readable claims alone.
// This is not a substitute for obtaining and pinning the two public keys out of band.
export function canonicalStagingJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalStagingJson).join(",")}]`;
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) block("INVALID_SCHEMA");
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalStagingJson(value[key])}`).join(",")}}`;
  }
  if (value === null || typeof value === "string" || typeof value === "boolean" ||
      (typeof value === "number" && Number.isSafeInteger(value))) return JSON.stringify(value);
  block("INVALID_SCHEMA");
}

function publicEd25519(value) {
  if (typeof value !== "string" || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$/u.test(value)) block("INVALID_PUBLIC_KEY");
  try {
    const key = createPublicKey(value);
    if (key.asymmetricKeyType !== "ed25519") block("INVALID_PUBLIC_KEY");
    return {
      key,
      fingerprint: `sha256:${createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex")}`
    };
  } catch { block("INVALID_PUBLIC_KEY"); }
}

function authenticated(envelope, field, publicKey) {
  shape(envelope, ["version", field, "signature"]);
  if (envelope.version !== 1 || typeof envelope.signature !== "string" ||
      !/^[A-Za-z0-9+/]{86}==$/u.test(envelope.signature)) block("INVALID_SIGNATURE");
  const signature = Buffer.from(envelope.signature, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== envelope.signature) block("INVALID_SIGNATURE");
  const payload = envelope[field];
  const input = Buffer.from(`Virki staging OTP ${field} v1\n${canonicalStagingJson(payload)}`, "utf8");
  if (!verify(null, input, publicKey.key, signature)) block("INVALID_SIGNATURE");
  return payload;
}

function site(site) {
  shape(site, ["hostId", "dbHostId", "dbName", "dbRoles", "smtpTenantId"]);
  for (const field of ["hostId", "dbHostId", "dbName", "smtpTenantId"]) requireMatch(site[field], IDENTIFIER);
  requireIds(site.dbRoles, 3, 3);
}

/** Returns only a static consistency result. Never claims the worker is stopped NOW. */
export function evaluateStagingOtpPreflight({ approvalEnvelope, observationEnvelope, approverPublicKey, observerPublicKey, expectedSourceSha, now = new Date() }) {
  requireMatch(expectedSourceSha, SOURCE_SHA);
  const approver = publicEd25519(approverPublicKey);
  const observer = publicEd25519(observerPublicKey);
  if (approver.fingerprint === observer.fingerprint) block("OBSERVER_NOT_INDEPENDENT");

  const approval = authenticated(approvalEnvelope, "approval", approver);
  const observed = authenticated(observationEnvelope, "observation", observer);
  shape(approval, ["authorizationId", "ownerId", "operatorId", "observerId", "observerKeySha256", "issuedAt", "expiresAt", "sourceSha", "ociDigest", "staging", "production", "recipientPolicyId", "recipientIds", "workerIntervalMs", "maxHandoffs", "providerPerMinuteQuota"]);
  shape(observed, ["authorizationId", "observerId", "observedAt", "sourceSha", "ociDigest", "staging", "worker", "relay", "queue"]);
  for (const id of [approval.authorizationId, approval.ownerId, approval.operatorId, approval.observerId, approval.recipientPolicyId]) requireMatch(id, IDENTIFIER);
  if (new Set([approval.ownerId, approval.operatorId, approval.observerId]).size !== 3 ||
      approval.observerKeySha256 !== observer.fingerprint) block("OBSERVER_NOT_INDEPENDENT");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) block("INVALID_TIME");
  const issuedAt = requireTime(approval.issuedAt);
  const expiresAt = requireTime(approval.expiresAt);
  const observedAt = requireTime(observed.observedAt);
  const clock = now.getTime();
  if (issuedAt > clock || expiresAt <= clock || expiresAt <= issuedAt ||
      observedAt < issuedAt || observedAt > clock || clock - observedAt > MAX_OBSERVATION_AGE_MS) block("STALE_OR_UNAUTHORIZED_EVIDENCE");
  requireMatch(approval.sourceSha, SOURCE_SHA);
  requireMatch(approval.ociDigest, OCI_DIGEST);
  if (approval.sourceSha !== expectedSourceSha || observed.sourceSha !== expectedSourceSha ||
      observed.ociDigest !== approval.ociDigest || observed.authorizationId !== approval.authorizationId ||
      observed.observerId !== approval.observerId) block("ATTESTATION_MISMATCH");

  site(approval.staging);
  site(approval.production);
  site(observed.staging);
  requireSame(observed.staging, approval.staging);
  for (const field of ["hostId", "dbHostId", "dbName", "smtpTenantId"]) {
    if (approval.staging[field] === approval.production[field]) block("PRODUCTION_IDENTITY_REUSE");
  }
  if (approval.staging.dbRoles.some((role) => approval.production.dbRoles.includes(role))) block("PRODUCTION_IDENTITY_REUSE");
  requireIds(approval.recipientIds, 1, 20); // Opaque IDs only; never email addresses or recipient secrets.
  requireInteger(approval.workerIntervalMs, 1, 60_000);
  requireInteger(approval.maxHandoffs, 1, 20);
  requireInteger(approval.providerPerMinuteQuota, 1, 10_000);
  // +1 also covers sends on both edges of a rolling one-minute window.
  if (Math.floor(60_000 / approval.workerIntervalMs) + 1 > approval.providerPerMinuteQuota ||
      approval.maxHandoffs > approval.providerPerMinuteQuota) block("SEND_BUDGET_NOT_PROVEN");

  shape(observed.worker, ["state", "runningReplicas", "restartDisabled", "autostartDisabled", "outboxDrainStarted", "effectiveIntervalMs", "servicesWithInterval", "observedServiceNames", "evidenceRef"]);
  requireBool(observed.worker.state, "stopped");
  requireInteger(observed.worker.runningReplicas, 0, 0);
  requireBool(observed.worker.restartDisabled, true);
  requireBool(observed.worker.autostartDisabled, true);
  requireBool(observed.worker.outboxDrainStarted, false);
  requireMatch(observed.worker.evidenceRef, IDENTIFIER);
  requireSame(observed.worker.effectiveIntervalMs, approval.workerIntervalMs);
  requireSame(observed.worker.servicesWithInterval, ["email-worker"]);
  requireSame(observed.worker.observedServiceNames, ["email-worker", ...NON_WORKER_SERVICES].sort());

  shape(observed.relay, ["enforcement", "recipientPolicyId", "recipientIds", "unlistedRecipientRejected", "denyEvidenceRef", "policyEvidenceRef", "hardRateCapPerMinute", "hardMaxHandoffs", "remainingDailyQuota"]);
  requireBool(observed.relay.enforcement, "relay-hard-enforced");
  requireSame(observed.relay.recipientPolicyId, approval.recipientPolicyId);
  requireIds(observed.relay.recipientIds, 1, 20);
  requireSame(observed.relay.recipientIds, approval.recipientIds);
  requireBool(observed.relay.unlistedRecipientRejected, true);
  requireMatch(observed.relay.denyEvidenceRef, IDENTIFIER);
  requireMatch(observed.relay.policyEvidenceRef, IDENTIFIER);
  requireInteger(observed.relay.hardRateCapPerMinute, 1, approval.providerPerMinuteQuota);
  requireInteger(observed.relay.hardMaxHandoffs, 1, approval.maxHandoffs);
  requireInteger(observed.relay.remainingDailyQuota, approval.maxHandoffs, 1_000_000);
  if (Math.floor(60_000 / approval.workerIntervalMs) + 1 > observed.relay.hardRateCapPerMinute ||
      approval.maxHandoffs > observed.relay.hardRateCapPerMinute ||
      observed.relay.hardMaxHandoffs !== approval.maxHandoffs) block("SEND_BUDGET_NOT_PROVEN");

  shape(observed.queue, ["queued", "processing", "retryable", "sent", "terminal", "deliveryAttempts", "evidenceRef"]);
  // A fresh, not-yet-drained staging queue cannot have even historical sent/failed attempts.
  for (const field of ["queued", "processing", "retryable", "sent", "terminal", "deliveryAttempts"]) requireInteger(observed.queue[field], 0, 0);
  requireMatch(observed.queue.evidenceRef, IDENTIFIER);
  return Object.freeze({
    status: "SIGNED_OFFLINE_DECLARATIONS_CONSISTENT",
    liveWorkerState: "NOT_OBSERVED_BY_THIS_TOOL",
    stagingAuthorization: "NOT_GRANTED_BY_THIS_TOOL",
    release: "NO_GO"
  });
}

function readUnlinkedText(filename, suffix, maximumBytes) {
  if (typeof filename !== "string" || !filename.toLowerCase().endsWith(suffix)) block("UNSAFE_INPUT_PATH");
  let metadata;
  try { metadata = lstatSync(filename); } catch { block("UNSAFE_INPUT_PATH"); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 1 || metadata.size > maximumBytes) block("UNSAFE_INPUT_PATH");
  try { return readFileSync(filename, "utf8"); } catch { block("UNSAFE_INPUT_PATH"); }
}

export function runStagingOtpPreflightCli(argv, { out = process.stdout, err = process.stderr, now = new Date() } = {}) {
  try {
    const allowed = ["--approval", "--observation", "--approver-public-key", "--observer-public-key", "--expected-source-sha"];
    if (argv.length !== allowed.length * 2) block("INVALID_ARGUMENTS");
    const args = new Map();
    for (let i = 0; i < argv.length; i += 2) {
      if (!allowed.includes(argv[i]) || args.has(argv[i]) || !argv[i + 1]) block("INVALID_ARGUMENTS");
      args.set(argv[i], argv[i + 1]);
    }
    const approvalEnvelope = JSON.parse(readUnlinkedText(args.get("--approval"), ".json", 32_768));
    const observationEnvelope = JSON.parse(readUnlinkedText(args.get("--observation"), ".json", 32_768));
    const approverPublicKey = readUnlinkedText(args.get("--approver-public-key"), ".pub.pem", 4096);
    const observerPublicKey = readUnlinkedText(args.get("--observer-public-key"), ".pub.pem", 4096);
    const result = evaluateStagingOtpPreflight({ approvalEnvelope, observationEnvelope, approverPublicKey, observerPublicKey, expectedSourceSha: args.get("--expected-source-sha"), now });
    out.write(`STAGING_OTP_PREFLIGHT=${result.status}\nLIVE_WORKER_STATE=${result.liveWorkerState}\nSTAGING_AUTHORIZATION=${result.stagingAuthorization}\nPRODUCTION_RELEASE=${result.release}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof StagingOtpPreflightError ? error.code : "INVALID_INPUT";
    err.write(`STAGING_OTP_PREFLIGHT=BLOCK:${code}\nPRODUCTION_RELEASE=NO_GO\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runStagingOtpPreflightCli(process.argv.slice(2));
}
