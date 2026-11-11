import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Prisma, prisma } from "@virki/database";
import {
  generateAuthenticationOptions, verifyAuthenticationResponse
} from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { enqueueEmailMessageForClient, getEmailTransportStatus, type EmailLocale } from "./email";
import { isSingleMailboxAddress } from "./email-address";
import { consumeRateLimitAttemptInTransaction, hashAuditIdentifier, isTrustedClientAddress, lockRateLimitIdentifierInTransaction, writeAuditLogInTransaction } from "./index";
import {
  type AccountRecoveryRole, decryptTotpSecret, generateNumericCode, getApprovedAccountRecoveryExpiry,
  getRecoveryActionBaseUrl, hashEmailAddress, hashRecoveryRequestKey, hashSecurityCode,
  isAccountRecoveryEligible, lockActiveRecoveryAccountInTransaction, verifySecurityCode, verifyTotpCode
} from "./security";
import { expectedPasskeyRP, hashPasskeyChallenge, passkeysEnabledForRequest, readClientChallenge } from "./passkeys";

export type RecoveryProof = "EMAIL" | "PASSKEY" | "TOTP";
export type RecoveryPolicy = { proofs: RecoveryProof[]; adminReview: boolean };
export type RecoveryBrowserState = { requestId: string; requestKey: string; browserToken: string };
type ProofState = { emailVerifiedAt: Date | null; recoveryPasskeyVerifiedAt: Date | null; recoveryTotpVerifiedAt: Date | null; reviewedByUserId: string | null };

const PROOFS: readonly RecoveryProof[] = ["EMAIL", "PASSKEY", "TOTP"];
const TTL_MS = 30 * 60_000;
const PASSKEY_TTL_MS = 5 * 60_000;
const FAILURE = new Error("Security mutation rejected.");

export function normalizeRecoveryPolicy(candidate: { proofs?: unknown; adminReview?: unknown }): RecoveryPolicy | null {
  if (!Array.isArray(candidate?.proofs) || typeof candidate.adminReview !== "boolean") return null;
  const proofs = candidate.proofs;
  if (!proofs.every((proof): proof is RecoveryProof => PROOFS.includes(proof as RecoveryProof)) || new Set(proofs).size !== proofs.length) return null;
  // The public contract exposes exactly the three independent pairs, or one
  // factor with a different eligible ADMIN. Reject undocumented combinations
  // even when an HTTP caller bypasses the UI method selector.
  if (proofs.length !== (candidate.adminReview ? 1 : 2)) return null;
  return { proofs: [...proofs].sort(), adminReview: candidate.adminReview };
}

export function sanitizeRecoveryComment(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  // Match the UI's visible-character count, not UTF-16 code units. A 300
  // character comment may contain emoji (two UTF-16 units each).
  if (typeof value !== "string" || [...value].length > 300 || [...value].some((character) => {
    const code = character.codePointAt(0)!;
    return code <= 31 || (code >= 127 && code <= 159);
  })) throw FAILURE;
  const cleaned = value.trim();
  return cleaned || null;
}

export function isRecoveryProofSatisfied(proofs: readonly string[], adminReview: boolean, state: ProofState): boolean {
  if (!normalizeRecoveryPolicy({ proofs: [...proofs], adminReview })) return false;
  if (!proofs.every((proof) =>
    proof === "EMAIL" ? Boolean(state.emailVerifiedAt) :
    proof === "PASSKEY" ? Boolean(state.recoveryPasskeyVerifiedAt) :
    Boolean(state.recoveryTotpVerifiedAt))) return false;
  return !adminReview || Boolean(state.reviewedByUserId);
}

function isBrowserToken(value: string): boolean { return /^[A-Za-z0-9_-]{43}$/u.test(value); }
function isRequestKey(value: string): boolean { return /^[A-Za-z0-9_-]{32}$/u.test(value); }
function isRequestId(value: string): boolean { return /^[A-Za-z0-9_-]{8,80}$/u.test(value); }
// This public identifier has the same CSPRNG distribution on both paths.
// Prisma's default CUID has a recognizable timestamp prefix and must never
// be used for an existing account while nonexistent accounts get random IDs.
export function generateRecoveryPublicRequestId(): string {
  return randomBytes(32).toString("base64url");
}
function browserHash(value: string): string { return createHash("sha256").update("Virki recovery browser v1:").update(value).digest("hex"); }
export function recoveryTotpBinding(factor: { id: string; secretCiphertext: string; keyVersion: number; confirmedAt: Date | null }): string {
  return hashPasskeyChallenge(JSON.stringify(["recovery-totp-factor-v1", factor.id, factor.secretCiphertext, factor.keyVersion, factor.confirmedAt?.toISOString() ?? null]));
}
export function recoveryPasskeyBinding(credential: { id: string; userId: string; credentialId: string; publicKey: Uint8Array; rpID?: string }): string {
  return hashPasskeyChallenge(JSON.stringify(["recovery-passkey-factor-v2", credential.id, credential.userId, credential.credentialId, credential.rpID ?? "portal.biel.dev.br", Buffer.from(credential.publicKey).toString("base64url")]));
}

function credentialRPMatchesRole(rpID: string, role: AccountRecoveryRole) {
  if (rpID === (role === "ADMIN" ? "hub.biel.dev.br" : "portal.biel.dev.br")) return true;
  return process.env.NODE_ENV !== "production" && process.env.VIRKI_PASSKEYS_LOCAL_TESTING === "true" &&
    (rpID === "localhost" || rpID === (role === "ADMIN" ? "hub.localhost" : "portal.localhost"));
}
function matchesHash(value: string, expected: string | null): boolean {
  if (!expected || !/^[a-f0-9]{64}$/.test(expected)) return false;
  const a = Buffer.from(value, "hex"); const b = Buffer.from(expected, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
function verifyCapability(request: { recoveryBrowserHash: string | null; requestKeyHash: string }, key: string, token: string): boolean {
  return isRequestKey(key) && isBrowserToken(token) && matchesHash(hashRecoveryRequestKey(key), request.requestKeyHash) && matchesHash(browserHash(token), request.recoveryBrowserHash);
}
function verifiedFactor(row: ProofState, proof: RecoveryProof): boolean {
  return proof === "EMAIL" ? Boolean(row.emailVerifiedAt) : proof === "TOTP" ? Boolean(row.recoveryTotpVerifiedAt) : Boolean(row.recoveryPasskeyVerifiedAt);
}
type RequestRow = { id: string; userId: string; recoveryProofs: string[]; recoveryRole: string | null; recoveryAdminReview: boolean; status: string; purpose: string; expiresAt: Date; recoveryBrowserHash: string | null; requestKeyHash: string; emailAddressHash: string; emailVerifiedAt: Date | null; recoveryTotpVerifiedAt: Date | null; recoveryPasskeyVerifiedAt: Date | null; reviewedByUserId: string | null; user: { email: string; emailNormalized: string | null; role: string; isActive: boolean; accountStatus: string } };
export function needsRecoveryNewMailbox(proofs: readonly string[]): boolean {
  return proofs.length > 0 && !proofs.includes("EMAIL");
}
function validPending(row: RequestRow | null, expectedRole: AccountRecoveryRole, key: string, token: string, now = new Date()) {
  return Boolean(row && row.purpose === "RECOVERY" && row.recoveryRole === expectedRole && row.status === "PENDING" && row.expiresAt > now &&
    isAccountRecoveryEligible(row.user, expectedRole) && row.emailAddressHash === hashEmailAddress(row.user.emailNormalized ?? row.user.email) &&
    normalizeRecoveryPolicy({ proofs: row.recoveryProofs, adminReview: row.recoveryAdminReview }) &&
    verifyCapability(row, key, token));
}
function recoveryWhere(requestId: string) { return { id: requestId }; }
const recoverySelect = {
  id: true, userId: true, recoveryProofs: true, recoveryRole: true, recoveryAdminReview: true, status: true, purpose: true,
  expiresAt: true, recoveryBrowserHash: true, requestKeyHash: true, emailAddressHash: true,
  emailVerifiedAt: true, recoveryTotpVerifiedAt: true, recoveryPasskeyVerifiedAt: true,
  reviewedByUserId: true, recoveryNewEmail: true, recoveryNewEmailChallengeHash: true,
  recoveryNewEmailExpiresAt: true, recoveryNewEmailVerifiedAt: true,
  user: { select: { email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true } }
} as const;

async function afterProof(tx: Prisma.TransactionClient, requestId: string, now: Date): Promise<void> {
  const row = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: {
    ...recoverySelect, recoveryTotpBindingHash: true, recoveryTotpUsedStep: true,
    recoveryPasskeyCredentialId: true, recoveryPasskeyBindingHash: true
  } });
  if (!row || row.status !== "PENDING" || row.expiresAt <= new Date()) throw FAILURE;
  if (row.recoveryAdminReview || !isRecoveryProofSatisfied(row.recoveryProofs, false, row)) return;
  // The earlier proof may have been revoked while its sibling was pending.
  // Reject stale approval before expiring any other recovery for this owner.
  await requireLiveRecoveryProofsInTransaction(tx, row);
  const claimed = await tx.accountRecoveryRequest.updateMany({
    where: { id: requestId, status: "PENDING", expiresAt: { gt: new Date() } },
    data: { status: "APPROVED", approvedAt: now, expiresAt: getApprovedAccountRecoveryExpiry(now) }
  });
  if (claimed.count !== 1) throw FAILURE;
  // Do not let an anonymous request invalidate this proven recovery.
  await tx.accountRecoveryRequest.updateMany({ where: { userId: row.userId, id: { not: requestId }, status: { in: ["PENDING", "APPROVED"] } }, data: { status: "EXPIRED" } });
  await writeAuditLogInTransaction(tx, {
    eventType: "ACCOUNT_RECOVERY_APPROVED", result: "SUCCESS", resource: "identity.recovery",
    message: "Independent recovery proofs satisfied the selected policy.",
    metadata: { requestRef: hashAuditIdentifier(requestId) }
  });
}

export async function startMultiMethodRecovery(
  email: string, expectedRole: AccountRecoveryRole, selected: RecoveryPolicy,
  locale: EmailLocale, now = new Date(), clientAddress?: string, comment?: string,
  host = expectedRole === "ADMIN" ? "hub.biel.dev.br" : "portal.biel.dev.br"
): Promise<RecoveryBrowserState> {
  const started = Date.now();
  try {
    return await createMultiMethodRecovery(email, expectedRole, selected, locale, now, clientAddress, comment, host);
  } finally {
    const remaining = started + 500 - Date.now();
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

async function createMultiMethodRecovery(
  email: string, expectedRole: AccountRecoveryRole, selected: RecoveryPolicy,
  locale: EmailLocale, now: Date, clientAddress?: string, comment?: string, host = expectedRole === "ADMIN" ? "hub.biel.dev.br" : "portal.biel.dev.br"
): Promise<RecoveryBrowserState> {
  const policy = normalizeRecoveryPolicy(selected);
  if (!policy || (comment !== undefined && !policy.adminReview)) throw FAILURE;
  const recoveryComment = sanitizeRecoveryComment(comment);
  if (process.env.NODE_ENV === "production" && !isTrustedClientAddress(clientAddress)) throw FAILURE;
  if (clientAddress && !isTrustedClientAddress(clientAddress)) throw FAILURE;
  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail.length > 320 || !/^\S+@\S+$/.test(normalizedEmail)) throw FAILURE;
  const requestKey = randomBytes(24).toString("base64url");
  const browserToken = randomBytes(32).toString("base64url");
  const requestId = generateRecoveryPublicRequestId();
  const publicState: RecoveryBrowserState = { requestId, requestKey, browserToken };
  const sourceKey = clientAddress || "unknown";
  const attempts = await prisma.$transaction(async (tx) => {
    const source = await consumeRateLimitAttemptInTransaction(tx, `recovery-source:${expectedRole}:${sourceKey}`, now, 30);
    const address = await consumeRateLimitAttemptInTransaction(tx, `account-recovery-address:${expectedRole}:${normalizedEmail}`, now);
    return source.allowed && address.allowed;
  });
  if (!attempts) return publicState;
  // A forged POST cannot bypass the current role-specific feature/RP gate.
  const passkeySurface = host === "localhost" ? "local" : expectedRole === "ADMIN" ? "hub" : "portal";
  if (policy.proofs.includes("PASSKEY") && !passkeysEnabledForRequest(passkeySurface, host, process.env, expectedRole)) return publicState;
  const recoveryRpID = policy.proofs.includes("PASSKEY") ? expectedPasskeyRP(process.env, host, expectedRole).rpID : null;
  const account = await prisma.user.findUnique({ where: { emailNormalized: normalizedEmail }, select: { id: true, email: true, emailNormalized: true, role: true, isActive: true, accountStatus: true, displayName: true } });
  if (!account || !isAccountRecoveryEligible(account, expectedRole)) return publicState;
  const actionBase = policy.proofs.includes("EMAIL") ? getRecoveryActionBaseUrl(expectedRole) : null;
  if (policy.proofs.includes("EMAIL") && !actionBase) return publicState;
  await prisma.$transaction(async (tx) => {
    await lockRateLimitIdentifierInTransaction(tx, `account-recovery:${expectedRole}:${normalizedEmail}`);
    if (!await lockActiveRecoveryAccountInTransaction(tx, account.id, expectedRole)) return null;
    // No-enrollment and unknown-account requests remain synthetic and identical.
    // Credentials minted at the USER portal never qualify as ADMIN factors.
    if (recoveryRpID && await tx.passkeyCredential.count({ where: { userId: account.id, rpID: recoveryRpID, revokedAt: null } }) < 1) return null;
    if (policy.proofs.includes("TOTP")) {
      const [factor, owner] = await Promise.all([
        tx.totpFactor.findUnique({ where: { userId: account.id }, select: { status: true, confirmedAt: true } }),
        tx.user.findUnique({ where: { id: account.id }, select: { secondFactorMethod: true } })
      ]);
      if (factor?.status !== "ACTIVE" || !factor.confirmedAt || owner?.secondFactorMethod !== "TOTP") return null;
    }
    if (policy.adminReview && await tx.user.count({ where: { role: "ADMIN", isActive: true, accountStatus: "ACTIVE", id: { not: account.id } } }) < 1) return null;
    // Limit repeated anonymous requests without letting a compromised former
    // mailbox monopolize the account. EMAIL alone is not an independent owner
    // proof: it cannot veto a new PASSKEY/TOTP or ADMIN-reviewed recovery.
    const latest = await tx.accountRecoveryRequest.findFirst({ where: { userId: account.id }, select: { createdAt: true }, orderBy: { createdAt: "desc" } });
    if (latest && latest.createdAt.getTime() + 60_000 > now.getTime()) return null;
    // Protect any completed approval (including invitations and reviewed
    // EMAIL+ADMIN) and any live independent owner factor, even before its
    // second proof. These must never be displaced by a new anonymous request.
    const proven = await tx.accountRecoveryRequest.findFirst({ where: { userId: account.id, status: { in: ["PENDING", "APPROVED"] }, expiresAt: { gt: now }, OR: [
      { status: "APPROVED" }, { recoveryPasskeyVerifiedAt: { not: null } }, { recoveryTotpVerifiedAt: { not: null } }
    ] }, select: { id: true } });
    if (proven) return null;
    const accountLimit = await consumeRateLimitAttemptInTransaction(tx, `account-recovery:${expectedRole}:${normalizedEmail}`, now);
    if (!accountLimit.allowed) return null;
    const code = generateNumericCode();
    const record = await tx.accountRecoveryRequest.create({ data: {
      id: requestId, userId: account.id, purpose: "RECOVERY", requestKeyHash: hashRecoveryRequestKey(requestKey),
      recoveryBrowserHash: browserHash(browserToken), recoveryProofs: policy.proofs, recoveryRole: expectedRole,
      recoveryAdminReview: policy.adminReview, recoveryComment,
      emailAddressHash: hashEmailAddress(account.emailNormalized ?? account.email),
      emailChallengeHash: hashSecurityCode(code), expiresAt: new Date(now.getTime() + TTL_MS)
    } });
    if (policy.proofs.includes("EMAIL")) {
      // The emailed code is typed into the initiating browser. Do not disclose
      // a browser-bound request key in an email link or use the legacy open route.
      const actionUrl = new URL("/recover", actionBase!).toString();
      await enqueueEmailMessageForClient(tx, { idempotencyKey: `account-recovery:${randomBytes(24).toString("base64url")}`, kind: "ACCOUNT_RECOVERY", recipientEmail: account.email, locale, payload: { publicValues: { displayName: account.displayName ?? "" }, protectedValues: { code, actionUrl } } });
    }
    await writeAuditLogInTransaction(tx, { eventType: "ACCOUNT_RECOVERY_REQUESTED", result: "SUCCESS", resource: "identity.recovery", metadata: { requestRef: hashAuditIdentifier(record.id), targetRef: hashAuditIdentifier(account.id) } });
  }, { isolationLevel: "Serializable" });
  // A real account never exposes the ORM's ID generation behavior or result.
  return publicState;
}

export async function verifyMultiMethodRecoveryEmail(requestId: string, key: string, browserToken: string, code: string, expectedRole: AccountRecoveryRole, now = new Date()): Promise<void> {
  if (!isRequestId(requestId) || !/^\d{6}$/.test(code)) throw FAILURE;
  const result = await prisma.$transaction(async (tx) => {
    const initial = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: { userId: true } });
    if (!initial || !await lockActiveRecoveryAccountInTransaction(tx, initial.userId, expectedRole)) throw FAILURE;
    const row = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: { ...recoverySelect, emailChallengeHash: true } });
    if (!validPending(row, expectedRole, key, browserToken, now) || !row!.recoveryProofs.includes("EMAIL") || row!.emailVerifiedAt) throw FAILURE;
    const userLimit = await consumeRateLimitAttemptInTransaction(tx, `account-recovery-verification-user:${row!.userId}`, now);
    const requestLimit = await consumeRateLimitAttemptInTransaction(tx, `account-recovery-verification:${requestId}`, now);
    if (!userLimit.allowed || !requestLimit.allowed || !verifySecurityCode(code, row!.emailChallengeHash)) return false;
    const changed = await tx.accountRecoveryRequest.updateMany({ where: { id: requestId, status: "PENDING", emailVerifiedAt: null, expiresAt: { gt: now }, requestKeyHash: row!.requestKeyHash }, data: { emailVerifiedAt: now } });
    if (changed.count !== 1) throw FAILURE;
    await writeAuditLogInTransaction(tx, { eventType: "ACCOUNT_RECOVERY_EMAIL_VERIFIED", result: "SUCCESS", resource: "identity.recovery", metadata: { requestRef: hashAuditIdentifier(requestId) } });
    await afterProof(tx, requestId, now);
    return true;
  }, { isolationLevel: "Serializable" });
  if (!result) throw FAILURE;
}

export async function verifyMultiMethodRecoveryTotp(requestId: string, key: string, browserToken: string, code: string, expectedRole: AccountRecoveryRole, now = new Date()): Promise<void> {
  if (!isRequestId(requestId) || !/^\d{6}$/.test(code) || !isRequestKey(key) || !isBrowserToken(browserToken)) throw FAILURE;
  // A public request ID alone cannot exhaust a genuine browser's TOTP budget.
  // Keep the code check after rate limiting so wrong codes still cost attempts.
  const preflight = await prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
  if (!validPending(preflight, expectedRole, key, browserToken, now) ||
      !preflight!.recoveryProofs.includes("TOTP") || preflight!.recoveryTotpVerifiedAt) throw FAILURE;
  const permitted = await prisma.$transaction(async (tx) => {
    const a = await consumeRateLimitAttemptInTransaction(tx, `account-recovery-totp:${requestId}`, now);
    return a.allowed;
  });
  if (!permitted) throw FAILURE;
  await prisma.$transaction(async (tx) => {
    const initial = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: { userId: true } });
    if (!initial || !await lockActiveRecoveryAccountInTransaction(tx, initial.userId, expectedRole)) throw FAILURE;
    const row = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
    if (!validPending(row, expectedRole, key, browserToken, now) || !row!.recoveryProofs.includes("TOTP") || row!.recoveryTotpVerifiedAt) throw FAILURE;
    const [factor, owner] = await Promise.all([
      tx.totpFactor.findUnique({ where: { userId: row!.userId }, select: { id: true, secretCiphertext: true, keyVersion: true, confirmedAt: true, status: true, lastUsedStep: true } }),
      tx.user.findUnique({ where: { id: row!.userId }, select: { secondFactorMethod: true } })
    ]);
    if (factor?.status !== "ACTIVE" || owner?.secondFactorMethod !== "TOTP") throw FAILURE;
    // Start the TOTP clock after the SQL User lock, not before a potentially
    // long lock wait. Any pre-lock timestamp could accept an expired step.
    const verificationNow = new Date();
    if (row!.expiresAt <= verificationNow) throw FAILURE;
    const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, verificationNow, factor.lastUsedStep);
    if (step === null) throw FAILURE;
    const consumed = await tx.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { lastUsedStep: step } });
    if (consumed.count !== 1) throw FAILURE;
    const changed = await tx.accountRecoveryRequest.updateMany({ where: { id: requestId, status: "PENDING", recoveryTotpVerifiedAt: null, expiresAt: { gt: verificationNow } }, data: { recoveryTotpVerifiedAt: verificationNow, recoveryTotpBindingHash: recoveryTotpBinding(factor), recoveryTotpUsedStep: step } });
    if (changed.count !== 1) throw FAILURE;
    await writeAuditLogInTransaction(tx, { eventType: "ACCOUNT_RECOVERY_TOTP_VERIFIED", result: "SUCCESS", resource: "identity.recovery", metadata: { requestRef: hashAuditIdentifier(requestId) } });
    await afterProof(tx, requestId, verificationNow);
  }, { isolationLevel: "Serializable" });
}

export async function startRecoveryPasskeyAssertion(requestId: string, key: string, browserToken: string, expectedRole: AccountRecoveryRole, host = "portal.biel.dev.br") {
  if (!isRequestId(requestId) || !isRequestKey(key) || !isBrowserToken(browserToken) ||
    !passkeysEnabledForRequest(host === "localhost" ? "local" : expectedRole === "ADMIN" ? "hub" : "portal", host, process.env, expectedRole)) throw FAILURE;
  const row = await prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
  const { rpID, origin } = expectedPasskeyRP(process.env, host, expectedRole);
  // Before any independent owner proof, an anonymous caller must not learn
  // which passkeys are enrolled. Once EMAIL or TOTP is verified for this exact
  // browser-bound request, list the IDs to support previously enrolled
  // non-discoverable security keys. The ADMIN reviewer alone does not count
  // as an owner proof, and invalid/synthetic requests never receive IDs.
  const ownerProofVerified = validPending(row, expectedRole, key, browserToken) &&
    row!.recoveryProofs.includes("PASSKEY") && row!.recoveryPasskeyVerifiedAt === null && (
    (row!.recoveryProofs.includes("EMAIL") && row!.emailVerifiedAt !== null) ||
    (row!.recoveryProofs.includes("TOTP") && row!.recoveryTotpVerifiedAt !== null)
  );
  const credentials = ownerProofVerified ? await prisma.passkeyCredential.findMany({
    where: { userId: row!.userId, rpID, revokedAt: null },
    select: { credentialId: true, transports: true }, take: 20
  }) : [];
  const options = await generateAuthenticationOptions({
    rpID, userVerification: "required", timeout: PASSKEY_TTL_MS,
    ...(ownerProofVerified ? { allowCredentials: credentials.map(credential => ({
      id: credential.credentialId, transports: credential.transports as never
    })) } : {})
  });
  // Synthetic attempts get identical public options; without a persisted
  // challenge no assertion can ever succeed.
  if (!validPending(row, expectedRole, key, browserToken) || !row!.recoveryProofs.includes("PASSKEY") || row!.recoveryPasskeyVerifiedAt) return options;
  await prisma.$transaction(async (tx) => {
    const limit = await consumeRateLimitAttemptInTransaction(tx, `recovery-passkey-start:${requestId}`, new Date(), 12);
    if (!limit.allowed) throw FAILURE;
    if (!await lockActiveRecoveryAccountInTransaction(tx, row!.userId, expectedRole)) throw FAILURE;
    const current = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
    if (!validPending(current, expectedRole, key, browserToken) || current!.recoveryPasskeyVerifiedAt) throw FAILURE;
    await tx.passkeyChallenge.create({ data: {
      ceremony: "RECOVERY", challengeHash: hashPasskeyChallenge(options.challenge), browserHash: browserHash(browserToken),
      proofHash: hashPasskeyChallenge(`recovery:${requestId}:${row!.requestKeyHash}`), userId: row!.userId,
      rpID, origin, expiresAt: new Date(Date.now() + PASSKEY_TTL_MS)
    } });
  });
  return options;
}

export async function finishRecoveryPasskeyAssertion(requestId: string, key: string, browserToken: string, response: AuthenticationResponseJSON, expectedRole: AccountRecoveryRole, host = "portal.biel.dev.br"): Promise<void> {
  if (!isRequestId(requestId) || !passkeysEnabledForRequest(host === "localhost" ? "local" : expectedRole === "ADMIN" ? "hub" : "portal", host, process.env, expectedRole) ||
    !/^[A-Za-z0-9_-]{8,1400}$/u.test(response?.id ?? "")) throw FAILURE;
  const challenge = readClientChallenge(response?.response?.clientDataJSON, "webauthn.get");
  if (!challenge) throw FAILURE;
  const { rpID, origin } = expectedPasskeyRP(process.env, host, expectedRole);
  const [row, ceremony, credential] = await Promise.all([
    prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect }),
    prisma.passkeyChallenge.findUnique({ where: { challengeHash: hashPasskeyChallenge(challenge) } }),
    prisma.passkeyCredential.findUnique({ where: { credentialId: response.id } })
  ]);
  if (!validPending(row, expectedRole, key, browserToken) || !row!.recoveryProofs.includes("PASSKEY") || row!.recoveryPasskeyVerifiedAt ||
    !ceremony || ceremony.ceremony !== "RECOVERY" || ceremony.userId !== row!.userId || ceremony.sessionId !== null ||
    ceremony.browserHash !== browserHash(browserToken) || ceremony.rpID !== rpID || ceremony.origin !== origin ||
    ceremony.proofHash !== hashPasskeyChallenge(`recovery:${requestId}:${row!.requestKeyHash}`) ||
    ceremony.consumedAt || ceremony.expiresAt <= new Date() || !credential || credential.revokedAt || credential.rpID !== rpID ||
    credential.userId !== row!.userId || credential.counter > BigInt(Number.MAX_SAFE_INTEGER)) throw FAILURE;
  if (response.response.userHandle != null && response.response.userHandle !== Buffer.from(row!.userId).toString("base64url")) throw FAILURE;
  const result = await verifyAuthenticationResponse({
    response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
    credential: { id: credential.credentialId, publicKey: new Uint8Array(credential.publicKey), counter: Number(credential.counter), transports: credential.transports as never }
  });
  if (!result.verified || (result.authenticationInfo.credentialDeviceType === "multiDevice") !== credential.backupEligible) throw FAILURE;
  const newCounter = BigInt(result.authenticationInfo.newCounter);
  if (newCounter < credential.counter || (credential.counter > 0n && newCounter <= credential.counter)) throw FAILURE;
  await prisma.$transaction(async (tx) => {
    if (!await lockActiveRecoveryAccountInTransaction(tx, row!.userId, expectedRole)) throw FAILURE;
    const current = await tx.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
    if (!validPending(current, expectedRole, key, browserToken) || current!.recoveryPasskeyVerifiedAt) throw FAILURE;
    const claimed = await tx.passkeyChallenge.updateMany({ where: { id: ceremony.id, consumedAt: null, expiresAt: { gt: new Date() }, ceremony: "RECOVERY", userId: row!.userId, proofHash: ceremony.proofHash, browserHash: ceremony.browserHash }, data: { consumedAt: new Date() } });
    if (claimed.count !== 1 || ceremony.expiresAt <= new Date()) throw FAILURE;
    const used = await tx.passkeyCredential.updateMany({
      where: { id: credential.id, userId: row!.userId, rpID, revokedAt: null, counter: credential.counter, revision: credential.revision },
      data: { counter: newCounter, revision: { increment: 1 }, lastUsedAt: new Date(), backupState: result.authenticationInfo.credentialBackedUp }
    });
    if (used.count !== 1) throw FAILURE;
    const now = new Date();
    const changed = await tx.accountRecoveryRequest.updateMany({ where: { id: requestId, status: "PENDING", recoveryPasskeyVerifiedAt: null, expiresAt: { gt: now } }, data: { recoveryPasskeyVerifiedAt: now, recoveryPasskeyCredentialId: credential.id, recoveryPasskeyBindingHash: recoveryPasskeyBinding(credential) } });
    if (changed.count !== 1) throw FAILURE;
    await writeAuditLogInTransaction(tx, { eventType: "ACCOUNT_RECOVERY_PASSKEY_VERIFIED", result: "SUCCESS", resource: "identity.recovery", metadata: { requestRef: hashAuditIdentifier(requestId) } });
    await afterProof(tx, requestId, now);
  }, { isolationLevel: "Serializable" });
}

export function isRecoveryCapabilityAuthorized(row: { recoveryProofs: string[]; recoveryAdminReview: boolean; recoveryBrowserHash: string | null; requestKeyHash: string } & ProofState, requestKey: string, browserToken: string): boolean {
  return Boolean(row.recoveryBrowserHash && verifyCapability(row, requestKey, browserToken) && isRecoveryProofSatisfied(row.recoveryProofs, row.recoveryAdminReview, row));
}

export function recoveryReviewReady(row: { recoveryProofs: string[]; recoveryAdminReview: boolean } & ProofState): boolean {
  return row.recoveryAdminReview && Boolean(normalizeRecoveryPolicy({ proofs: row.recoveryProofs, adminReview: true })) &&
    row.recoveryProofs.some((proof) => verifiedFactor(row, proof as RecoveryProof));
}

export async function requireLiveRecoveryProofsInTransaction(
  tx: Prisma.TransactionClient,
  row: { userId: string; recoveryRole?: string | null; recoveryProofs: string[]; recoveryTotpBindingHash: string | null; recoveryTotpUsedStep: number | null; recoveryPasskeyCredentialId: string | null; recoveryPasskeyBindingHash: string | null }
): Promise<void> {
  if (row.recoveryProofs.includes("TOTP")) {
    const [factor, owner] = await Promise.all([
      tx.totpFactor.findUnique({ where: { userId: row.userId }, select: { id: true, secretCiphertext: true, keyVersion: true, confirmedAt: true, lastUsedStep: true, status: true } }),
      tx.user.findUnique({ where: { id: row.userId }, select: { secondFactorMethod: true } })
    ]);
    if (!factor || factor.status !== "ACTIVE" || owner?.secondFactorMethod !== "TOTP" ||
        row.recoveryTotpUsedStep === null || factor.lastUsedStep === null || factor.lastUsedStep < row.recoveryTotpUsedStep ||
        !matchesHash(recoveryTotpBinding(factor), row.recoveryTotpBindingHash)) throw FAILURE;
  }
  if (row.recoveryProofs.includes("PASSKEY")) {
    if (!row.recoveryPasskeyCredentialId) throw FAILURE;
    const credential = await tx.passkeyCredential.findFirst({ where: { id: row.recoveryPasskeyCredentialId, userId: row.userId, revokedAt: null }, select: { id: true, userId: true, credentialId: true, rpID: true, publicKey: true } });
    if (!credential || (row.recoveryRole && !credentialRPMatchesRole(credential.rpID, row.recoveryRole as AccountRecoveryRole)) ||
      !matchesHash(recoveryPasskeyBinding(credential), row.recoveryPasskeyBindingHash)) throw FAILURE;
  }
}

export async function hasIndependentAdministratorForRole(expectedRole: AccountRecoveryRole): Promise<boolean> {
  return (await prisma.user.count({ where: { role: "ADMIN", accountStatus: "ACTIVE", isActive: true } })) >= (expectedRole === "ADMIN" ? 2 : 1);
}

const REPLACEMENT_EMAIL_CODE_MS = 10 * 60_000;

type ApprovedReplacementRow = RequestRow & {
  recoveryNewEmail: string | null; recoveryNewEmailChallengeHash: string | null;
  recoveryNewEmailExpiresAt: Date | null; recoveryNewEmailVerifiedAt: Date | null;
  recoveryTotpBindingHash: string | null; recoveryTotpUsedStep: number | null;
  recoveryPasskeyCredentialId: string | null; recoveryPasskeyBindingHash: string | null;
};

function validReplacement(row: ApprovedReplacementRow | null, role: AccountRecoveryRole, key: string, browser: string, now: Date): row is ApprovedReplacementRow {
  return Boolean(row && row.status === "APPROVED" && row.expiresAt > now &&
    row.purpose === "RECOVERY" && row.recoveryRole === role &&
    needsRecoveryNewMailbox(row.recoveryProofs) && isRecoveryProofSatisfied(row.recoveryProofs, row.recoveryAdminReview, row) &&
    isAccountRecoveryEligible(row.user, role) &&
    row.emailAddressHash === hashEmailAddress(row.user.emailNormalized ?? row.user.email) &&
    verifyCapability(row, key, browser));
}

const replacementSelect = {
  ...recoverySelect, purpose: true, recoveryTotpBindingHash: true, recoveryTotpUsedStep: true,
  recoveryPasskeyCredentialId: true, recoveryPasskeyBindingHash: true
} as const;

async function lockReplacementRequest(tx: Prisma.TransactionClient, requestId: string, role: AccountRecoveryRole) {
  const initial = await tx.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: { userId: true } });
  if (!initial || !await lockActiveRecoveryAccountInTransaction(tx, initial.userId, role)) throw FAILURE;
  const locked = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "AccountRecoveryRequest" WHERE "id" = ${requestId} FOR UPDATE
  `;
  if (locked.length !== 1) throw FAILURE;
  return tx.accountRecoveryRequest.findUnique({ where: { id: requestId }, select: replacementSelect });
}

async function rateLimitReplacement(requestId: string, stage: "start" | "verify", subject: string): Promise<void> {
  const permitted = await prisma.$transaction(async (tx) => {
    const ceremony = await consumeRateLimitAttemptInTransaction(tx, `recovery-new-mail-${stage}:${requestId}`, new Date());
    const subjectBudget = await consumeRateLimitAttemptInTransaction(tx, `recovery-new-mail-${stage}-subject:${subject}`, new Date());
    return ceremony.allowed && subjectBudget.allowed;
  });
  if (!permitted) throw FAILURE;
}

export async function startRecoveryNewMailbox(
  requestId: string, key: string, browserToken: string, role: AccountRecoveryRole, proposedEmail: string
): Promise<void> {
  const newEmail = proposedEmail.trim().toLowerCase();
  if (!isRequestId(requestId) || !isRequestKey(key) || !isBrowserToken(browserToken) ||
      !isSingleMailboxAddress(newEmail) || getEmailTransportStatus().state !== "configured") throw FAILURE;
  const preflight = await prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: replacementSelect });
  if (!validReplacement(preflight, role, key, browserToken, new Date())) throw FAILURE;
  await rateLimitReplacement(requestId, "start", hashEmailAddress(newEmail));
  await prisma.$transaction(async (tx) => {
    const row = await lockReplacementRequest(tx, requestId, role);
    const now = new Date();
    if (!validReplacement(row, role, key, browserToken, now)) throw FAILURE;
    await requireLiveRecoveryProofsInTransaction(tx, row);
    if (newEmail === (row.user.emailNormalized ?? row.user.email.trim().toLowerCase()) ||
        await tx.user.count({ where: { OR: [{ email: newEmail }, { emailNormalized: newEmail }] } }) !== 0) throw FAILURE;
    const expiry = new Date(Math.min(now.getTime() + REPLACEMENT_EMAIL_CODE_MS, row.expiresAt.getTime()));
    if (expiry <= now) throw FAILURE;
    const code = generateNumericCode();
    const changed = await tx.accountRecoveryRequest.updateMany({
      where: { id: requestId, status: "APPROVED", requestKeyHash: row.requestKeyHash,
        emailAddressHash: row.emailAddressHash, expiresAt: { gt: now } },
      data: { recoveryNewEmail: newEmail, recoveryNewEmailChallengeHash: hashSecurityCode(code),
        recoveryNewEmailExpiresAt: expiry, recoveryNewEmailVerifiedAt: null }
    });
    if (changed.count !== 1) throw FAILURE;
    await enqueueEmailMessageForClient(tx, {
      idempotencyKey: `recovery-new-mail:${requestId}:${randomBytes(16).toString("hex")}`,
      kind: "RECOVERY_EMAIL_REBIND", recipientEmail: newEmail, locale: "pt-BR",
      payload: { protectedValues: { code } }
    });
    await writeAuditLogInTransaction(tx, {
      eventType: "ACCOUNT_RECOVERY_REQUESTED", result: "SUCCESS",
      resource: "identity.recovery", message: "Replacement mailbox proof requested.",
      metadata: { requestRef: hashAuditIdentifier(requestId) }
    });
  }, { isolationLevel: "ReadCommitted" });
}

export async function verifyRecoveryNewMailbox(
  requestId: string, key: string, browserToken: string, role: AccountRecoveryRole, code: string
): Promise<void> {
  if (!isRequestId(requestId) || !/^\d{6}$/u.test(code) || !isRequestKey(key) || !isBrowserToken(browserToken)) throw FAILURE;
  const preflight = await prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: replacementSelect });
  if (!validReplacement(preflight, role, key, browserToken, new Date()) ||
      !preflight.recoveryNewEmail || !preflight.recoveryNewEmailChallengeHash ||
      !preflight.recoveryNewEmailExpiresAt || preflight.recoveryNewEmailExpiresAt <= new Date() ||
      preflight.recoveryNewEmailVerifiedAt) throw FAILURE;
  await rateLimitReplacement(requestId, "verify", hashRecoveryRequestKey(key));
  await prisma.$transaction(async (tx) => {
    const row = await lockReplacementRequest(tx, requestId, role);
    const now = new Date();
    if (!validReplacement(row, role, key, browserToken, now) ||
        !row.recoveryNewEmail || !row.recoveryNewEmailChallengeHash || !row.recoveryNewEmailExpiresAt ||
        row.recoveryNewEmailExpiresAt <= now || row.recoveryNewEmailVerifiedAt ||
        !verifySecurityCode(code, row.recoveryNewEmailChallengeHash)) throw FAILURE;
    await requireLiveRecoveryProofsInTransaction(tx, row);
    if (await tx.user.count({ where: { OR: [{ email: row.recoveryNewEmail }, { emailNormalized: row.recoveryNewEmail }] } }) !== 0) throw FAILURE;
    // Evaluate the OTP lifetime at the PostgreSQL UPDATE, after acquiring the
    // User and recovery row locks; never trust a pre-lock JavaScript timestamp.
    const claimed = await tx.$executeRaw`
      WITH verification_time AS MATERIALIZED (
        SELECT (clock_timestamp() AT TIME ZONE 'UTC') AS "at"
      )
      UPDATE "AccountRecoveryRequest" AS recovery SET
        "recoveryNewEmailVerifiedAt" = verification_time."at",
        "updatedAt" = verification_time."at"
      FROM verification_time
      WHERE recovery."id" = ${requestId}
        AND recovery."requestKeyHash" = ${row.requestKeyHash}
        AND recovery."recoveryBrowserHash" = ${row.recoveryBrowserHash}
        AND recovery."emailAddressHash" = ${row.emailAddressHash}
        AND recovery."recoveryRole" = ${role}::"UserRole"
        AND recovery."status" = 'APPROVED'::"RecoveryRequestStatus"
        AND recovery."recoveryNewEmail" = ${row.recoveryNewEmail}
        AND recovery."recoveryNewEmailChallengeHash" = ${row.recoveryNewEmailChallengeHash}
        AND recovery."recoveryNewEmailVerifiedAt" IS NULL
        AND recovery."recoveryNewEmailExpiresAt" > verification_time."at"
        AND recovery."expiresAt" > verification_time."at"
    `;
    if (claimed !== 1) throw FAILURE;
    await writeAuditLogInTransaction(tx, {
      eventType: "ACCOUNT_RECOVERY_EMAIL_VERIFIED", result: "SUCCESS",
      resource: "identity.recovery", message: "Replacement mailbox ownership verified.",
      metadata: { requestRef: hashAuditIdentifier(requestId) }
    });
  }, { isolationLevel: "ReadCommitted" });
}

export async function getMultiMethodRecoveryState(
  requestId: string, key: string, browserToken: string, expectedRole: AccountRecoveryRole,
  selected: RecoveryPolicy, now = new Date()
) {
  const policy = normalizeRecoveryPolicy(selected);
  if (!policy || !isRequestId(requestId) || !isRequestKey(key) || !isBrowserToken(browserToken)) throw FAILURE;
  const empty = { status: "PENDING" as const, proofs: policy.proofs, adminReview: policy.adminReview, emailVerified: false, passkeyVerified: false, totpVerified: false,
    newMailboxRequired: needsRecoveryNewMailbox(policy.proofs), newMailboxChallengeSent: false, newMailboxVerified: false };
  if (policy.proofs.includes("PASSKEY") && process.env.VIRKI_PASSKEYS_ENABLED !== "true") return empty;
  const row = await prisma.accountRecoveryRequest.findUnique({ where: recoveryWhere(requestId), select: recoverySelect });
  if (!row || row.recoveryRole !== expectedRole || !verifyCapability(row, key, browserToken) ||
      row.recoveryProofs.join(",") !== policy.proofs.join(",") || row.recoveryAdminReview !== policy.adminReview ||
      row.emailAddressHash !== hashEmailAddress(row.user.emailNormalized ?? row.user.email) ||
      !isAccountRecoveryEligible(row.user, expectedRole)) return empty;
  const hasProven = Boolean(row.emailVerifiedAt || row.recoveryPasskeyVerifiedAt || row.recoveryTotpVerifiedAt);
  if (!hasProven) return empty;
  return {
    status: row.expiresAt > now ? row.status : "EXPIRED" as const,
    proofs: policy.proofs, adminReview: policy.adminReview,
    emailVerified: Boolean(row.emailVerifiedAt), passkeyVerified: Boolean(row.recoveryPasskeyVerifiedAt), totpVerified: Boolean(row.recoveryTotpVerifiedAt),
    newMailboxRequired: needsRecoveryNewMailbox(row.recoveryProofs),
    newMailboxChallengeSent: Boolean(row.recoveryNewEmail && row.recoveryNewEmailExpiresAt && row.recoveryNewEmailExpiresAt > now),
    newMailboxVerified: Boolean(row.recoveryNewEmailVerifiedAt)
  };
}
