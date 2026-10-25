import { createHash, randomBytes } from "node:crypto";
import { Prisma, prisma } from "@virki/database";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import {
  authenticateUser,
  consumeRateLimitAttemptInTransaction,
  generateSessionToken,
  getSessionExpiresAt,
  hashSessionToken,
  isTrustedClientAddress,
  normalizeEmail,
  verifyPassword
} from "./index";
import { writeAuditLogInTransaction } from "./audit";
import { consumeSecurityProofAttempt, decryptTotpSecret, lockActiveLoginAccountInTransaction, verifyTotpCode } from "./security";

const RP_ID = "portal.biel.dev.br";
const ORIGIN = `https://${RP_ID}`;
const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_PASSKEYS = 20;
const FAILURE = new Error("Passkey ceremony rejected.");

export const PASSKEY_BROWSER_COOKIE = "virki_passkey_browser";

export function expectedPasskeyRP(env: Readonly<Record<string, string | undefined>> = process.env, host = RP_ID) {
  // Only for the TLS Playwright portal.localhost fixture; production never accepts this RP.
  if (env.NODE_ENV !== "production" && env.VIRKI_PASSKEYS_LOCAL_TESTING === "true" && host === "portal.localhost") {
    return { rpID: "portal.localhost", origin: "https://portal.localhost:3001" };
  }
  if (env.NODE_ENV !== "production" && env.VIRKI_PASSKEYS_LOCAL_TESTING === "true" && host === "localhost") {
    return { rpID: "localhost", origin: "http://localhost:3001" };
  }
  return { rpID: RP_ID, origin: ORIGIN };
}

export function passkeysEnabledForRequest(surface: string, host: string, env: Readonly<Record<string, string | undefined>> = process.env) {
  return env.VIRKI_PASSKEYS_ENABLED === "true" && (
    (surface === "portal" && host === RP_ID) ||
    (env.NODE_ENV !== "production" && env.VIRKI_PASSKEYS_LOCAL_TESTING === "true" && surface === "portal" && host === "portal.localhost") ||
    (env.NODE_ENV !== "production" && env.VIRKI_PASSKEYS_LOCAL_TESTING === "true" && surface === "local" && host === "localhost")
  );
}

export function createPasskeyBrowserToken(): string { return randomBytes(32).toString("base64url"); }
export function hashPasskeyChallenge(challenge: string): string { return createHash("sha256").update(challenge).digest("hex"); }
function browserDigest(token: string): string { return hashPasskeyChallenge(`browser:${token}`); }

export function readClientChallenge(encoded: string, type: "webauthn.get" | "webauthn.create"): string | null {
  try {
    if (encoded.length > 8192 || !/^[A-Za-z0-9_-]+={0,2}$/u.test(encoded)) return null;
    const data = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Record<string, unknown>;
    if (data.type !== type || typeof data.challenge !== "string" || !/^[A-Za-z0-9_-]{32,128}$/u.test(data.challenge)) return null;
    return data.challenge;
  } catch { return null; }
}

export function validatePasskeyName(name: string): string | null {
  if ([...name].some(character => { const point = character.codePointAt(0)!; return point <= 31 || point === 127; })) return null;
  const clean = name.trim();
  return clean.length > 0 && clean.length <= 80 ? clean : null;
}

function requireBrowserToken(token: string) {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) throw FAILURE;
}

async function checkActiveUser(userId: string, sessionId?: string) {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, email: true, passwordHash: true, isActive: true, accountStatus: true, role: true } });
  if (!user || !user.isActive || user.accountStatus !== "ACTIVE" || user.role !== "USER") throw FAILURE;
  if (sessionId) {
    const active = await prisma.session.count({ where: { id: sessionId, userId, revokedAt: null, expiresAt: { gt: new Date() } } });
    if (active !== 1) throw FAILURE;
  }
  return user;
}

async function consumeChallenge(challenge: string, ceremony: "REGISTRATION" | "AUTHENTICATION", token: string, sessionId: string | null, rpID: string, origin: string, now = new Date()) {
  requireBrowserToken(token);
  const digest = hashPasskeyChallenge(challenge);
  return prisma.$transaction(async (tx) => {
    const row = await tx.passkeyChallenge.findUnique({ where: { challengeHash: digest } });
    if (!row || row.ceremony !== ceremony || row.browserHash !== browserDigest(token) || row.rpID !== rpID || row.origin !== origin || row.sessionId !== sessionId) throw FAILURE;
    const consumed = await tx.passkeyChallenge.updateMany({
      where: { id: row.id, consumedAt: null, expiresAt: { gt: new Date() } },
      data: { consumedAt: now }
    });
    if (consumed.count !== 1) throw FAILURE;
    // A concurrent row lock can delay the UPDATE past expiry. Re-evaluate the
    // wall clock AFTER acquiring the write lock; throw rolls back the claim.
    if (row.expiresAt <= new Date()) throw FAILURE;
    return row;
  });
}

async function saveChallenge(challenge: string, ceremony: "REGISTRATION" | "AUTHENTICATION", token: string, rpID: string, origin: string, userId?: string, sessionId?: string, proofHash?: string) {
  requireBrowserToken(token);
  await prisma.passkeyChallenge.create({ data: {
    challengeHash: hashPasskeyChallenge(challenge), ceremony, browserHash: browserDigest(token),
    userId: userId ?? null, sessionId: sessionId ?? null, rpID, origin, proofHash: proofHash ?? null,
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS)
  } });
  // Bounded maintenance: don't hold an authentication request on a full-table cleanup.
  const expired = await prisma.passkeyChallenge.findMany({ where: { expiresAt: { lte: new Date() } }, select: { id: true }, take: 64, orderBy: { expiresAt: "asc" } });
  if (expired.length) await prisma.passkeyChallenge.deleteMany({ where: { id: { in: expired.map(row => row.id) }, expiresAt: { lte: new Date() } } });
}

async function lockLiveSession(tx: Prisma.TransactionClient, userId: string, sessionId: string) {
  const sessions = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id" FROM "Session"
    WHERE "id" = ${sessionId} AND "userId" = ${userId}
      AND "revokedAt" IS NULL AND "expiresAt" > (clock_timestamp() AT TIME ZONE 'UTC')
    FOR UPDATE
  `;
  if (sessions.length !== 1) throw FAILURE;
}

async function requireConfiguredTotpProof(tx: Prisma.TransactionClient, userId: string, code: string) {
  const account = await tx.user.findUnique({ where: { id: userId }, select: { secondFactorMethod: true } });
  if (account?.secondFactorMethod !== "TOTP") return;
  const factor = await tx.totpFactor.findUnique({ where: { userId }, select: { id: true, status: true, secretCiphertext: true, lastUsedStep: true } });
  if (factor?.status !== "ACTIVE") throw FAILURE;
  const step = verifyTotpCode(decryptTotpSecret(factor.secretCiphertext), code, new Date(), factor.lastUsedStep);
  if (step === null) throw FAILURE;
  const consumed = await tx.totpFactor.updateMany({ where: { id: factor.id, status: "ACTIVE", lastUsedStep: factor.lastUsedStep }, data: { lastUsedStep: step } });
  if (consumed.count !== 1) throw FAILURE;
}

// Bind a registration attempt to the actual factor policy and credential state
// after its password/TOTP proof. All supported factor mutations acquire the
// User lock before changing either User or TotpFactor. Exclude lastUsedStep:
// consuming a normal TOTP assertion must not invalidate an otherwise valid
// proof, while enabling, disabling or replacing the factor always must.
async function registrationProofBinding(tx: Prisma.TransactionClient, userId: string) {
  const user = await tx.user.findUnique({ where: { id: userId }, select: {
    passwordHash: true, secondFactorMethod: true, updatedAt: true,
    totpFactor: { select: { id: true, status: true, secretCiphertext: true, confirmedAt: true } }
  } });
  if (!user?.passwordHash) throw FAILURE;
  const factor = user.totpFactor;
  if (user.secondFactorMethod === "TOTP" && factor?.status !== "ACTIVE") throw FAILURE;
  return {
    passwordHash: user.passwordHash,
    digest: hashPasskeyChallenge(JSON.stringify([
      "passkey-registration-factor-policy-v2", user.passwordHash, user.updatedAt.toISOString(),
      user.secondFactorMethod, factor?.id ?? null, factor?.status ?? null,
      factor?.secretCiphertext ?? null, factor?.confirmedAt?.toISOString() ?? null
    ]))
  };
}

export async function startPasskeyRegistration(userId: string, sessionId: string, password: string, token: string, host = RP_ID, totpCode = "") {
  requireBrowserToken(token);
  await consumeSecurityProofAttempt(userId);
  const user = await checkActiveUser(userId, sessionId);
  if (!user.passwordHash || !await verifyPassword(user.passwordHash, password)) throw FAILURE;
  const proofHash = await prisma.$transaction(async (tx) => {
    if (!await lockActiveLoginAccountInTransaction(tx, userId, "USER")) throw FAILURE;
    const lockedUser = await tx.user.findUnique({ where: { id: userId }, select: { passwordHash: true } });
    if (!lockedUser?.passwordHash || lockedUser.passwordHash !== user.passwordHash) throw FAILURE;
    await lockLiveSession(tx, userId, sessionId);
    await requireConfiguredTotpProof(tx, userId, totpCode);
    const binding = await registrationProofBinding(tx, userId);
    if (binding.passwordHash !== user.passwordHash) throw FAILURE;
    return binding.digest;
  });
  const existing = await prisma.passkeyCredential.findMany({ where: { userId, revokedAt: null }, select: { credentialId: true, transports: true }, take: MAX_PASSKEYS });
  if (existing.length >= MAX_PASSKEYS) throw FAILURE;
  const { rpID, origin } = expectedPasskeyRP(process.env, host);
  const options = await generateRegistrationOptions({
    rpName: "Virki", rpID, userID: Buffer.from(userId, "utf8"), userName: user.email,
    attestationType: "none", authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
    excludeCredentials: existing.map((entry) => ({ id: entry.credentialId, transports: entry.transports as never })),
    supportedAlgorithmIDs: [-7, -257], timeout: CHALLENGE_TTL_MS
  });
  await saveChallenge(options.challenge, "REGISTRATION", token, rpID, origin, userId, sessionId, proofHash);
  return options;
}

export async function finishPasskeyRegistration(userId: string, sessionId: string, token: string, response: RegistrationResponseJSON, name: string, host = RP_ID) {
  const safeName = validatePasskeyName(name);
  if (!safeName) throw FAILURE;
  const challenge = readClientChallenge(response?.response?.clientDataJSON, "webauthn.create");
  if (!challenge) throw FAILURE;
  const { rpID, origin } = expectedPasskeyRP(process.env, host);
  const row = await consumeChallenge(challenge, "REGISTRATION", token, sessionId, rpID, origin);
  if (row.userId !== userId) throw FAILURE;
  await checkActiveUser(userId, sessionId);
  const verification = await verifyRegistrationResponse({ response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
  if (!verification.verified || !verification.registrationInfo) throw FAILURE;
  if (row.expiresAt <= new Date()) throw FAILURE;
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  await prisma.$transaction(async (tx) => {
    if (!await lockActiveLoginAccountInTransaction(tx, userId, "USER")) throw FAILURE;
    if (row.expiresAt <= new Date()) throw FAILURE;
    await lockLiveSession(tx, userId, sessionId);
    if ((await registrationProofBinding(tx, userId)).digest !== row.proofHash) throw FAILURE;
    if (await tx.passkeyCredential.count({ where: { userId, revokedAt: null } }) >= MAX_PASSKEYS) throw FAILURE;
    await tx.passkeyCredential.create({ data: {
      credentialId: credential.id, publicKey: Buffer.from(credential.publicKey), counter: BigInt(credential.counter),
      transports: credential.transports ?? [], backupEligible: credentialDeviceType === "multiDevice", backupState: credentialBackedUp,
      userId, name: safeName
    } });
    await writeAuditLogInTransaction(tx, { eventType: "PASSKEY_REGISTERED", result: "SUCCESS", actorUserId: userId, resource: "identity.passkey" });
    await lockLiveSession(tx, userId, sessionId);
    if ((await registrationProofBinding(tx, userId)).digest !== row.proofHash) throw FAILURE;
    if (row.expiresAt <= new Date()) throw FAILURE;
  });
}

export async function startPasskeyAuthentication(token: string, source: string, email?: string, host = RP_ID, password = "") {
  requireBrowserToken(token);
  if (source ? !isTrustedClientAddress(source) : process.env.NODE_ENV === "production") throw FAILURE;
  const limiter = await prisma.$transaction(tx => consumeRateLimitAttemptInTransaction(tx, `passkey-start:v1:${source}`, new Date(), 30));
  if (!limiter.allowed) throw FAILURE;
  let userId: string | undefined;
  let proofHash: string | undefined;
  let allowCredentials: Array<{ id: string; transports: never }> | undefined;
  if (email) {
    if (email.length > 320 || password.length > 256 || !password) throw FAILURE;
    // Credential IDs/transports are stable metadata. Disclose only after a password proof,
    // so an arbitrary unauthenticated email cannot enumerate passkey enrollment.
    const normalizedEmail = normalizeEmail(email);
    const accountLimit = await prisma.$transaction(tx => consumeRateLimitAttemptInTransaction(tx, `passkey-lookup:v1:${normalizedEmail}`, new Date(), 8));
    if (!accountLimit.allowed) throw FAILURE;
    // Use the existing constant-cost dummy-hash path for missing/inactive actors.
    // The identity is still revalidated and pinned to the password verifier below.
    const actor = await authenticateUser(normalizedEmail, password);
    const user = actor?.role === "USER"
      ? await prisma.user.findUnique({ where: { id: actor.id }, select: { id: true, passwordHash: true, isActive: true, accountStatus: true, role: true } })
      : null;
    if (user?.isActive && user.accountStatus === "ACTIVE" && user.role === "USER" && user.passwordHash) {
      userId = user.id;
      proofHash = hashPasskeyChallenge(user.passwordHash);
      const credentials = await prisma.passkeyCredential.findMany({ where: { userId, revokedAt: null }, select: { credentialId: true, transports: true }, take: MAX_PASSKEYS });
      allowCredentials = credentials.map(credential => ({ id: credential.credentialId, transports: credential.transports as never }));
    } else throw FAILURE;
  }
  const { rpID, origin } = expectedPasskeyRP(process.env, host);
  const options = await generateAuthenticationOptions({
    rpID, userVerification: "required", timeout: CHALLENGE_TTL_MS,
    ...(email ? { allowCredentials: allowCredentials ?? [] } : {})
  });
  await saveChallenge(options.challenge, "AUTHENTICATION", token, rpID, origin, userId, undefined, proofHash);
  return options;
}

export async function finishPasskeyAuthentication(token: string, response: AuthenticationResponseJSON, host = RP_ID) {
  const challenge = readClientChallenge(response?.response?.clientDataJSON, "webauthn.get");
  if (!challenge || !/^[A-Za-z0-9_-]{8,1400}$/u.test(response?.id ?? "")) throw FAILURE;
  const { rpID, origin } = expectedPasskeyRP(process.env, host);
  const row = await consumeChallenge(challenge, "AUTHENTICATION", token, null, rpID, origin);
  const credential = await prisma.passkeyCredential.findUnique({ where: { credentialId: response.id }, include: { user: { select: { isActive: true, accountStatus: true, role: true } } } });
  if (!credential || credential.revokedAt || credential.user.role !== "USER" || !credential.user.isActive || credential.user.accountStatus !== "ACTIVE" || (row.userId && row.userId !== credential.userId)) throw FAILURE;
  if (response.response.userHandle !== undefined && response.response.userHandle !== null && response.response.userHandle !== Buffer.from(credential.userId, "utf8").toString("base64url")) throw FAILURE;
  if (credential.counter > BigInt(Number.MAX_SAFE_INTEGER)) throw FAILURE;
  const verified = await verifyAuthenticationResponse({
    response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
    credential: { id: credential.credentialId, publicKey: new Uint8Array(credential.publicKey), counter: Number(credential.counter), transports: credential.transports as never }
  });
  if (!verified.verified) throw FAILURE;
  if (row.expiresAt <= new Date()) throw FAILURE;
  const newCounter = BigInt(verified.authenticationInfo.newCounter);
  // Authenticator counters can remain zero on synced passkeys. CAS revision also fences concurrent zero-counter assertions.
  if (newCounter < credential.counter || (credential.counter > 0n && newCounter <= credential.counter)) throw FAILURE;
  return prisma.$transaction(async (tx) => {
    if (!await lockActiveLoginAccountInTransaction(tx, credential.userId, "USER")) throw FAILURE;
    if (row.expiresAt <= new Date()) throw FAILURE;
    if (row.proofHash) {
      const user = await tx.user.findUnique({ where: { id: credential.userId }, select: { passwordHash: true } });
      if (!user?.passwordHash || hashPasskeyChallenge(user.passwordHash) !== row.proofHash) throw FAILURE;
    }
    const updated = await tx.passkeyCredential.updateMany({
      where: { id: credential.id, userId: credential.userId, revokedAt: null, revision: credential.revision, counter: credential.counter },
      data: { counter: newCounter, revision: { increment: 1 }, lastUsedAt: new Date(), backupState: verified.authenticationInfo.credentialBackedUp }
    });
    if (updated.count !== 1) throw FAILURE;
    const tokenValue = generateSessionToken();
    const expiresAt = getSessionExpiresAt();
    await tx.session.create({ data: { userId: credential.userId, sessionKey: randomBytes(24).toString("base64url"), tokenHash: hashSessionToken(tokenValue), authenticationMethods: row.proofHash ? ["pwd", "webauthn"] : ["webauthn"], expiresAt } });
    await writeAuditLogInTransaction(tx, { eventType: "PASSKEY_AUTHENTICATED", result: "SUCCESS", actorUserId: credential.userId, resource: "identity.passkey" });
    if (row.expiresAt <= new Date()) throw FAILURE;
    return { token: tokenValue, expiresAt };
  }, { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted });
}

export async function listUserPasskeys(userId: string) {
  return prisma.passkeyCredential.findMany({ where: { userId, revokedAt: null }, select: { id: true, name: true, createdAt: true, lastUsedAt: true, backupEligible: true, backupState: true }, orderBy: { createdAt: "desc" } });
}

export async function mutatePasskey(userId: string, sessionId: string, id: string, password: string, operation: "rename" | "revoke", name?: string, totpCode = "") {
  if (!/^[A-Za-z0-9_-]{8,80}$/u.test(id)) throw FAILURE;
  const safeName = operation === "rename" ? validatePasskeyName(name ?? "") : null;
  if (operation === "rename" && !safeName) throw FAILURE;
  await consumeSecurityProofAttempt(userId);
  const user = await checkActiveUser(userId, sessionId);
  if (!user.passwordHash || !await verifyPassword(user.passwordHash, password)) throw FAILURE;
  await prisma.$transaction(async (tx) => {
    if (!await lockActiveLoginAccountInTransaction(tx, userId, "USER")) throw FAILURE;
    const lockedUser = await tx.user.findUnique({ where: { id: userId }, select: { passwordHash: true } });
    if (!lockedUser?.passwordHash || lockedUser.passwordHash !== user.passwordHash) throw FAILURE;
    await lockLiveSession(tx, userId, sessionId);
    await requireConfiguredTotpProof(tx, userId, totpCode);
    const result = await tx.passkeyCredential.updateMany({
      where: { id, userId, revokedAt: null },
      data: operation === "rename" ? { name: safeName! } : { revokedAt: new Date() }
    });
    if (result.count !== 1) throw FAILURE;
    await writeAuditLogInTransaction(tx, { eventType: operation === "rename" ? "PASSKEY_RENAMED" : "PASSKEY_REVOKED", result: "SUCCESS", actorUserId: userId, resource: "identity.passkey" });
    await lockLiveSession(tx, userId, sessionId);
  });
}
