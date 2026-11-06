import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";

// REVIEW EVIDENCE ONLY. No account recovery, database mutation, auth bypass,
// password handling, key generation, or capability issuance lives in this file.
const REQUEST_KEYS = [
  "schema", "action", "incidentId", "environment", "deploymentRef", "targetUserId",
  "targetEmailSha256", "sourceRevision", "backupSha256", "credentialKeyVersion",
  "nonce", "issuedAt", "expiresAt"
];
const EXPECTED_KEYS = ["environment", "deploymentRef", "targetUserId", "targetEmailSha256", "sourceRevision", "backupSha256", "credentialKeyVersion"];
const ROLES = ["OWNER", "INDEPENDENT_REVIEWER"];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const SAFE_ID = /^[A-Za-z0-9_-]{8,80}$/;
const KEY_ID = /^[A-Za-z0-9_-]{3,80}$/;
const MAX_APPROVAL_MS = 24 * 60 * 60 * 1000;
const SIGNING_DOMAIN = "VIRKI_SOLE_ADMIN_RECOVERY_REVIEW_V1\n";

export class SoleAdminApprovalError extends Error {
  constructor() {
    super("Sole-ADMIN review evidence rejected.");
    this.name = "SoleAdminApprovalError";
  }
}

function requireExactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== keys.length ||
      !keys.every((key) => Object.hasOwn(value, key))) throw new SoleAdminApprovalError();
}

function validateRequest(request) {
  requireExactKeys(request, REQUEST_KEYS);
  if (request.schema !== "virki-sole-admin-recovery-review-v1" ||
      request.action !== "REVIEW_SEPARATE_ADMIN_CREDENTIAL_RECOVERY_ONLY" ||
      !SAFE_ID.test(request.incidentId) ||
      !["staging", "production"].includes(request.environment) ||
      !SAFE_ID.test(request.deploymentRef) ||
      !SAFE_ID.test(request.targetUserId) ||
      !HEX64.test(request.targetEmailSha256) ||
      !HEX40.test(request.sourceRevision) ||
      !HEX64.test(request.backupSha256) ||
      !Number.isSafeInteger(request.credentialKeyVersion) || request.credentialKeyVersion < 1 ||
      !HEX32.test(request.nonce)) throw new SoleAdminApprovalError();
  const issuedAt = parseUtcTimestamp(request.issuedAt);
  const expiresAt = parseUtcTimestamp(request.expiresAt);
  if (issuedAt >= expiresAt || expiresAt - issuedAt > MAX_APPROVAL_MS) throw new SoleAdminApprovalError();
  return { issuedAt, expiresAt };
}

function parseUtcTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new SoleAdminApprovalError();
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) throw new SoleAdminApprovalError();
  return parsed.getTime();
}

// Every approver signs identical, unambiguous field-order JSON bytes with
// a domain prefix. No supplied signature/field can select another algorithm.
export function approvalSigningPayload(request) {
  validateRequest(request);
  const ordered = Object.fromEntries(REQUEST_KEYS.map((key) => [key, request[key]]));
  return Buffer.from(SIGNING_DOMAIN + JSON.stringify(ordered), "utf8");
}

function validateRegistry(registry) {
  requireExactKeys(registry, ["schema", "environment", "deploymentRef", "approvers"]);
  if (registry.schema !== "virki-independent-approver-registry-v1" ||
      !["staging", "production"].includes(registry.environment) ||
      !SAFE_ID.test(registry.deploymentRef) ||
      !Array.isArray(registry.approvers) || registry.approvers.length !== 2) throw new SoleAdminApprovalError();
  const roles = new Set();
  const ids = new Set();
  const fingerprints = new Set();
  const keys = new Map();
  for (const approver of registry.approvers) {
    requireExactKeys(approver, ["keyId", "role", "publicKeyPem"]);
    if (!KEY_ID.test(approver.keyId) || !ROLES.includes(approver.role) ||
        typeof approver.publicKeyPem !== "string" || approver.publicKeyPem.length > 2048 ||
        roles.has(approver.role) || ids.has(approver.keyId)) throw new SoleAdminApprovalError();
    let key;
    try { key = createPublicKey(approver.publicKeyPem); } catch { throw new SoleAdminApprovalError(); }
    if (key.asymmetricKeyType !== "ed25519") throw new SoleAdminApprovalError();
    const canonicalPem = key.export({ type: "spki", format: "pem" });
    if (canonicalPem !== approver.publicKeyPem) throw new SoleAdminApprovalError();
    const fingerprint = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
    if (fingerprints.has(fingerprint)) throw new SoleAdminApprovalError();
    fingerprints.add(fingerprint);
    roles.add(approver.role);
    ids.add(approver.keyId);
    keys.set(approver.keyId, { key, role: approver.role });
  }
  if (roles.size !== ROLES.length) throw new SoleAdminApprovalError();
  return keys;
}

export function verifySoleAdminApprovalBundle({ bundle, registryBytes, expectedRegistrySha256, expected, now = new Date() }) {
  if (!Buffer.isBuffer(registryBytes) || registryBytes.length < 32 || registryBytes.length > 16 * 1024 ||
      typeof expectedRegistrySha256 !== "string" || !HEX64.test(expectedRegistrySha256) ||
      !(now instanceof Date) || !Number.isFinite(now.getTime())) throw new SoleAdminApprovalError();
  const actual = createHash("sha256").update(registryBytes).digest();
  if (!timingSafeEqual(actual, Buffer.from(expectedRegistrySha256, "hex"))) throw new SoleAdminApprovalError();
  let registry;
  try { registry = JSON.parse(registryBytes.toString("utf8")); } catch { throw new SoleAdminApprovalError(); }
  // Reject ambiguous registries including duplicate JSON keys or hidden padding.
  if (JSON.stringify(registry) !== registryBytes.toString("utf8")) throw new SoleAdminApprovalError();
  const keys = validateRegistry(registry);

  requireExactKeys(expected, EXPECTED_KEYS);
  requireExactKeys(bundle, ["request", "approvals"]);
  const { issuedAt, expiresAt } = validateRequest(bundle.request);
  if (now.getTime() < issuedAt || now.getTime() >= expiresAt) throw new SoleAdminApprovalError();
  if (registry.environment !== bundle.request.environment || registry.deploymentRef !== bundle.request.deploymentRef ||
      !EXPECTED_KEYS.every((field) => expected[field] === bundle.request[field])) throw new SoleAdminApprovalError();
  if (!Array.isArray(bundle.approvals) || bundle.approvals.length !== 2) throw new SoleAdminApprovalError();

  const payload = approvalSigningPayload(bundle.request);
  const approvedRoles = new Set();
  const usedKeyIds = new Set();
  for (const approval of bundle.approvals) {
    requireExactKeys(approval, ["keyId", "signature"]);
    const approver = keys.get(approval.keyId);
    if (!approver || usedKeyIds.has(approval.keyId) ||
        typeof approval.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(approval.signature)) throw new SoleAdminApprovalError();
    const signature = Buffer.from(approval.signature, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== approval.signature ||
        !verify(null, payload, approver.key, signature)) throw new SoleAdminApprovalError();
    usedKeyIds.add(approval.keyId);
    approvedRoles.add(approver.role);
  }
  if (approvedRoles.size !== ROLES.length) throw new SoleAdminApprovalError();
  return Object.freeze({
    valid: true,
    incidentId: bundle.request.incidentId,
    approvers: [...usedKeyIds],
    requestSha256: createHash("sha256").update(payload).digest("hex"),
    permitsCredentialMutation: false,
    requiresIndependentHumanVerification: true
  });
}
