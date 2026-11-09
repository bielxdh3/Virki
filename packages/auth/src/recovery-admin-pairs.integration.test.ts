import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { after, test } from "node:test";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, seedAdminSessionWithElevation, uniqueEmail } from "./integration-fixtures";
import {
  finishRecoveryPasskeyAssertion, getMultiMethodRecoveryState, startMultiMethodRecovery,
  startRecoveryNewMailbox, startRecoveryPasskeyAssertion, verifyMultiMethodRecoveryEmail,
  verifyMultiMethodRecoveryTotp, verifyRecoveryNewMailbox
} from "./recovery-methods";
import { confirmTotpEnrollment, consumeApprovedAccountRecovery, startTotpEnrollment } from "./security";
import { hashPassword, verifyPassword } from "./index";
import { createPasskeyBrowserToken, finishPasskeyRegistration, startPasskeyRegistration } from "./passkeys";

// This file is discovered by the guarded integration runner. An explicit,
// independently named disposable PostgreSQL 18 DB is required even for direct
// invocations; do not write to another worker's/shared fixture database.
after(() => prisma.$disconnect());

function dedicatedAdminPairsTargetConfigured(): boolean {
  const selected = process.env.VIRKI_INTEGRATION_DATABASE_URL;
  if (process.env.VIRKI_INTEGRATION_ENABLED !== "true" ||
      process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable" ||
      !selected || process.env.DATABASE_URL !== selected) return false;
  try {
    const url = new URL(selected);
    return url.protocol === "postgresql:" && url.hostname === "127.0.0.1" &&
      url.username === "virki_runtime_test" &&
      /^virki_w11_admin_pairs_[A-Za-z0-9_]+$/u.test(decodeURIComponent(url.pathname.slice(1)));
  } catch {
    return false;
  }
}

// Generic hosted CI intentionally uses its own PostgreSQL 17 disposable DB.
// These extra real-PG18 tests need a separate worker-owned PG18 database and
// must be reported as SKIP, not as false failures or silently repointed tests.
const adminPairsOptions = {
  skip: integrationOptions.skip || (dedicatedAdminPairsTargetConfigured()
    ? false : "requires separately named, confirmed disposable PostgreSQL 18 database virki_w11_admin_pairs_*")
};

const HUB_RP = "hub.biel.dev.br";
const HUB_ORIGIN = `https://${HUB_RP}`;
const sha = (value: Buffer | string) => createHash("sha256").update(value).digest();
type Recovery = Awaited<ReturnType<typeof startMultiMethodRecovery>>;
type Admin = { id: string; email: string; password: string; privilegedPassword: string };
type Factor = "EMAIL" | "PASSKEY" | "TOTP";

async function requireGuardedPg18() {
  // Verify the same guarded target as scripts/integration/run.mjs before any
  // fixture writes. Direct invocation with an arbitrary DATABASE_URL is denied.
  const configured = process.env.VIRKI_INTEGRATION_DATABASE_URL;
  assert.equal(process.env.VIRKI_INTEGRATION_ENABLED, "true");
  assert.equal(process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM, "disposable");
  assert.ok(configured && process.env.DATABASE_URL === configured, "only the explicitly selected disposable target is admitted");
  const parsed = new URL(configured);
  assert.equal(parsed.protocol, "postgresql:");
  assert.equal(parsed.hostname, "127.0.0.1");
  assert.equal(parsed.username, "virki_runtime_test");
  const databaseName = decodeURIComponent(parsed.pathname.slice(1));
  assert.match(databaseName, /^virki_w11_admin_pairs_[A-Za-z0-9_]+$/u,
    "ADMIN pair tests require their own explicitly named disposable DB");
  assert.notEqual(process.env.NODE_ENV, "production");
  const [observed] = await prisma.$queryRaw<Array<{ version: number; database: string; role: string }>>`
    SELECT current_setting('server_version_num')::int AS "version",
      current_database() AS "database", current_user AS "role"
  `;
  assert.ok(observed && observed.version >= 180000 && observed.version < 190000, "the integration server must be PostgreSQL 18");
  assert.equal(observed.role, "virki_runtime_test");
  assert.equal(observed.database, databaseName);
}

function sourceAddress() {
  const hex = randomUUID().replaceAll("-", "");
  return `2001:db8:${hex.slice(0, 4)}:${hex.slice(4, 8)}:${hex.slice(8, 12)}:${hex.slice(12, 16)}:${hex.slice(16, 20)}:${hex.slice(20, 24)}`;
}

function totpAt(secret: string, at = new Date()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const char of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) { bytes.push((buffer >>> (bits - 8)) & 255); bits -= 8; buffer &= (1 << bits) - 1; }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function eligibleAdmin(label: string, totpSecret?: string): Promise<Admin> {
  const owner = await createTestUser({ role: "ADMIN", label, ...(totpSecret ? { totpSecret } : {}) });
  const privilegedPassword = randomBytes(32).toString("base64url");
  await prisma.administrativeCredential.create({
    data: { userId: owner.id, status: "ACTIVE", passwordHash: await hashPassword(privilegedPassword) }
  });
  const before = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(before.role, "ADMIN");
  assert.equal(before.accountStatus, "ACTIVE");
  assert.equal(before.isActive, true);
  assert.ok(before.emailVerifiedAt, "old ADMIN account starts with verified mailbox");
  assert.equal(await verifyPassword(before.passwordHash ?? "", privilegedPassword), false,
    "normal and privileged administrative credentials must be independent");
  return { ...owner, privilegedPassword };
}

function newSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]
  ]));
  return { id: randomBytes(32).toString("base64url"), cose, privateKey };
}
type Signer = ReturnType<typeof newSigner>;

function clientData(type: "webauthn.create" | "webauthn.get", challenge: string, origin = HUB_ORIGIN) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false })).toString("base64url");
}

function signedRegistration(signer: Signer, challenge: string): RegistrationResponseJSON {
  const id = Buffer.from(signer.id, "base64url");
  const authData = Buffer.concat([
    sha(HUB_RP), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([id.length >> 8, id.length & 255]), id, Buffer.from(signer.cose)
  ]);
  const attestation = isoCBOR.encode(new Map<string, string | Map<string, never> | Uint8Array>([
    ["fmt", "none"], ["attStmt", new Map<string, never>()], ["authData", authData]
  ]));
  return {
    id: signer.id, rawId: signer.id, type: "public-key",
    response: { clientDataJSON: clientData("webauthn.create", challenge),
      attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"] },
    clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

function signedAssertion(signer: Signer, ownerId: string, challenge: string, overrides: { rpID?: string; origin?: string; flags?: number; counter?: number } = {}): AuthenticationResponseJSON {
  const authenticatorData = Buffer.concat([
    sha(overrides.rpID ?? HUB_RP), Buffer.from([overrides.flags ?? 0x05]),
    Buffer.from([0, 0, 0, overrides.counter ?? 1])
  ]);
  const encoded = clientData("webauthn.get", challenge, overrides.origin);
  const signature = sign("sha256", Buffer.concat([authenticatorData, sha(Buffer.from(encoded, "base64url"))]), signer.privateKey);
  return {
    id: signer.id, rawId: signer.id, type: "public-key",
    response: { authenticatorData: authenticatorData.toString("base64url"), clientDataJSON: encoded,
      signature: signature.toString("base64url"), userHandle: Buffer.from(ownerId).toString("base64url") },
    clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

function enableAdminPasskeys(t: { after: (callback: () => void) => void }) {
  const oldGlobal = process.env.VIRKI_PASSKEYS_ENABLED;
  const oldAdmin = process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "true";
  t.after(() => {
    if (oldGlobal === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = oldGlobal;
    if (oldAdmin === undefined) delete process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
    else process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = oldAdmin;
  });
}

async function enrollHubSigner(owner: Admin): Promise<Signer> {
  const { sessionId, elevationId } = await seedAdminSessionWithElevation(owner.id, "ADMIN_CREDENTIAL_CHANGE");
  await prisma.securityElevation.update({ where: { id: elevationId }, data: { activatedAt: new Date() } });
  const browserToken = createPasskeyBrowserToken();
  const signer = newSigner();
  const options = await startPasskeyRegistration(owner.id, sessionId, owner.password, browserToken, HUB_RP, "", "ADMIN");
  assert.equal(options.rp.id, HUB_RP);
  await finishPasskeyRegistration(owner.id, sessionId, browserToken,
    signedRegistration(signer, options.challenge), "Independent recovery factor", HUB_RP, "ADMIN");
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, rpID: HUB_RP, credentialId: signer.id, revokedAt: null } }), 1);
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, rpID: "portal.biel.dev.br", revokedAt: null } }), 0,
    "USER portal keys cannot be an ADMIN enrolled factor");
  return signer;
}

async function proveHubPasskey(recovery: Recovery, signer: Signer, ownerId: string) {
  await assert.rejects(startRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", "portal.biel.dev.br"),
    "a hub ADMIN challenge cannot be started at the USER RP");
  const options = await startRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", HUB_RP);
  assert.equal(options.rpId, HUB_RP);
  const valid = signedAssertion(signer, ownerId, options.challenge);
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    signedAssertion(signer, ownerId, options.challenge, { rpID: "portal.biel.dev.br" }), "ADMIN", HUB_RP), "wrong signed RP hash");
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    signedAssertion(signer, ownerId, options.challenge, { origin: "https://portal.biel.dev.br" }), "ADMIN", HUB_RP), "wrong signed origin");
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    signedAssertion(signer, ownerId, options.challenge, { flags: 0x01 }), "ADMIN", HUB_RP), "no user verification");
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, createPasskeyBrowserToken(),
    valid, "ADMIN", HUB_RP), "cross-browser challenge theft");
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    valid, "USER", HUB_RP), "cross-role ADMIN assertion denied");
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "false";
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    valid, "ADMIN", HUB_RP), "disabled ADMIN flag rejects previously minted challenge");
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "true";
  await finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken, valid, "ADMIN", HUB_RP);
  await assert.rejects(finishRecoveryPasskeyAssertion(recovery.requestId, recovery.requestKey, recovery.browserToken,
    valid, "ADMIN", HUB_RP), "signed assertion cannot replay");
  assert.ok((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: recovery.requestId } })).recoveryPasskeyVerifiedAt);
}

async function proveOriginalEmail(recovery: Recovery, email: string) {
  const code = (await queuedEmails(email)).filter(item => item.kind === "ACCOUNT_RECOVERY").at(-1)?.code;
  assert.match(code ?? "", /^\d{6}$/u);
  await assert.rejects(verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey,
    createPasskeyBrowserToken(), code!, "ADMIN"), "other browser cannot claim email proof");
  await assert.rejects(verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey,
    recovery.browserToken, code!, "USER"), "cross-role email proof denied");
  await verifyMultiMethodRecoveryEmail(recovery.requestId, recovery.requestKey, recovery.browserToken, code!, "ADMIN");
}

async function oneResetWinner(recovery: Recovery, owner: Admin, label: string, factors: Factor[], newEmail?: string) {
  const attempts = [`new-normal-${label}-password-alpha-2026`, `new-normal-${label}-password-bravo-2026`];
  const outcomes = await Promise.allSettled(attempts.map(password =>
    consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey, password, new Date(), "ADMIN", recovery.browserToken)));
  assert.equal(outcomes.filter(outcome => outcome.status === "fulfilled").length, 1, "one concurrent reset must win");
  assert.equal(outcomes.filter(outcome => outcome.status === "rejected").length, 1, "other request must fail closed");
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
    `replayed-${label}-normal-password-2026`, new Date(), "ADMIN", recovery.browserToken));
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: recovery.requestId } })).status, "CONSUMED");
  const account = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(account.role, "ADMIN");
  assert.equal((await Promise.all(attempts.map(password => verifyPassword(account.passwordHash ?? "", password)))).filter(Boolean).length, 1);
  assert.equal(account.emailNormalized, newEmail ?? owner.email);
  assert.ok(account.emailVerifiedAt);
  assert.equal(account.secondFactorMethod, "EMAIL", "normal-password recovery replaces compromised login MFA");
  const privileged = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: owner.id } });
  assert.equal(privileged.status, "ACTIVE");
  assert.equal(await verifyPassword(privileged.passwordHash, owner.privilegedPassword), true,
    "separate elevation password is retained unchanged");
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } }), 0);
  if (factors.includes("TOTP")) assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "REVOKED");
  const activeSessions = await prisma.session.count({ where: { userId: owner.id, revokedAt: null, expiresAt: { gt: new Date() } } });
  assert.equal(activeSessions, 1, "only the recovered bootstrap session remains live");
}

async function assertRecoveryRemainsUnconsumed(recovery: Recovery, owner: Admin, originalHash: string) {
  const current = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(current.email, owner.email, "a rejected stale proof must not replace the mailbox");
  assert.equal(current.emailNormalized, owner.email);
  assert.equal(current.passwordHash, originalHash, "a rejected stale proof must not replace the normal password");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: recovery.requestId } })).status, "APPROVED",
    "failed final proof validation must not consume the recovery request");
}

test("PG18 ADMIN normal-password: independent TOTP_EMAIL, cross-role proof and concurrent one-winner", adminPairsOptions, async () => {
  await requireGuardedPg18();
  const owner = await eligibleAdmin("admin-pair-totp-email");
  const enrolled = await startTotpEnrollment(owner.id, owner.email);
  const older = new Date(Date.now() - 30_000);
  await confirmTotpEnrollment(owner.id, totpAt(enrolled.secret, older), older);
  const policy = { proofs: ["TOTP" as const, "EMAIL" as const], adminReview: false };
  const recovery = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR", new Date(), sourceAddress());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: recovery.requestId, userId: owner.id } }), 1);
  await proveOriginalEmail(recovery, owner.email);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).status, "PENDING");
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey, "only-one-factor-password", new Date(), "ADMIN", recovery.browserToken));
  await assert.rejects(verifyMultiMethodRecoveryTotp(recovery.requestId, recovery.requestKey, recovery.browserToken,
    totpAt(enrolled.secret), "USER"));
  await verifyMultiMethodRecoveryTotp(recovery.requestId, recovery.requestKey, recovery.browserToken, totpAt(enrolled.secret), "ADMIN");
  const approved = await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy);
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.newMailboxRequired, false);
  await oneResetWinner(recovery, owner, "admin-totp-email", ["TOTP", "EMAIL"]);
});

test("PG18 ADMIN normal-password: signed Hub PASSKEY_EMAIL, RP isolation, flag and replay", adminPairsOptions, async (t) => {
  await requireGuardedPg18();
  enableAdminPasskeys(t);
  const owner = await eligibleAdmin("admin-pair-passkey-email");
  const signer = await enrollHubSigner(owner);
  const policy = { proofs: ["PASSKEY" as const, "EMAIL" as const], adminReview: false };
  const recovery = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR", new Date(), sourceAddress(), undefined, HUB_RP);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: recovery.requestId, userId: owner.id } }), 1);
  await proveHubPasskey(recovery, signer, owner.id);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).status, "PENDING");
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey, "only-passkey-password", new Date(), "ADMIN", recovery.browserToken));
  await proveOriginalEmail(recovery, owner.email);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).status, "APPROVED");
  const before = (await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).passwordHash!;
  // The ADMIN feature flag is a use-time authorization gate, not a flag
  // captured only when the passkey challenge was minted or verified.
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "false";
  try {
    await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
      "flag-off-admin-password-must-fail", new Date(), "ADMIN", recovery.browserToken));
    await assertRecoveryRemainsUnconsumed(recovery, owner, before);
  } finally {
    process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "true";
  }
  await oneResetWinner(recovery, owner, "admin-passkey-email", ["PASSKEY", "EMAIL"]);
});

test("PG18 ADMIN normal-password: revoking signed Hub passkey after both proofs invalidates approved reset", adminPairsOptions, async (t) => {
  await requireGuardedPg18();
  enableAdminPasskeys(t);
  const owner = await eligibleAdmin("admin-pair-stale-passkey");
  const signer = await enrollHubSigner(owner);
  const policy = { proofs: ["PASSKEY" as const, "EMAIL" as const], adminReview: false };
  const recovery = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR", new Date(), sourceAddress(), undefined, HUB_RP);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: recovery.requestId, userId: owner.id } }), 1);
  await proveHubPasskey(recovery, signer, owner.id);
  await proveOriginalEmail(recovery, owner.email);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).status, "APPROVED");
  const originalHash = (await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).passwordHash!;
  await prisma.passkeyCredential.update({ where: { credentialId: signer.id }, data: { revokedAt: new Date() } });
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
    "revoked-passkey-admin-must-fail", new Date(), "ADMIN", recovery.browserToken));
  await assertRecoveryRemainsUnconsumed(recovery, owner, originalHash);
});

test("PG18 ADMIN normal-password: TOTP key rotation after approval invalidates stale verified step", adminPairsOptions, async () => {
  await requireGuardedPg18();
  const owner = await eligibleAdmin("admin-pair-stale-totp");
  const enrollment = await startTotpEnrollment(owner.id, owner.email);
  const previousStep = new Date(Date.now() - 30_000);
  await confirmTotpEnrollment(owner.id, totpAt(enrollment.secret, previousStep), previousStep);
  const policy = { proofs: ["TOTP" as const, "EMAIL" as const], adminReview: false };
  const recovery = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR", new Date(), sourceAddress());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: recovery.requestId, userId: owner.id } }), 1);
  await proveOriginalEmail(recovery, owner.email);
  await verifyMultiMethodRecoveryTotp(recovery.requestId, recovery.requestKey, recovery.browserToken, totpAt(enrollment.secret), "ADMIN");
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).status, "APPROVED");
  const originalHash = (await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).passwordHash!;
  await prisma.totpFactor.update({ where: { userId: owner.id }, data: { keyVersion: { increment: 1 } } });
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
    "rotated-totp-admin-must-fail", new Date(), "ADMIN", recovery.browserToken));
  await assertRecoveryRemainsUnconsumed(recovery, owner, originalHash);
});

test("PG18 ADMIN normal-password: Hub PASSKEY_TOTP requires independently verified new mailbox before reset", adminPairsOptions, async (t) => {
  await requireGuardedPg18();
  enableAdminPasskeys(t);
  const owner = await eligibleAdmin("admin-pair-passkey-totp");
  const signer = await enrollHubSigner(owner);
  // Enroll TOTP after passkey: the fresh TOTP used for recovery cannot reuse
  // the step consumed during passkey enrollment.
  const enrolled = await startTotpEnrollment(owner.id, owner.email);
  const older = new Date(Date.now() - 30_000);
  await confirmTotpEnrollment(owner.id, totpAt(enrolled.secret, older), older);
  const policy = { proofs: ["PASSKEY" as const, "TOTP" as const], adminReview: false };
  const recovery = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR", new Date(), sourceAddress(), undefined, HUB_RP);
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: recovery.requestId, userId: owner.id } }), 1);
  await proveHubPasskey(recovery, signer, owner.id);
  await assert.rejects(verifyMultiMethodRecoveryTotp(recovery.requestId, recovery.requestKey, createPasskeyBrowserToken(),
    totpAt(enrolled.secret), "ADMIN"));
  await verifyMultiMethodRecoveryTotp(recovery.requestId, recovery.requestKey, recovery.browserToken, totpAt(enrolled.secret), "ADMIN");
  const approved = await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy);
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.newMailboxRequired, true);
  assert.equal(approved.newMailboxVerified, false);
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
    "no-new-mail-proven-admin-password", new Date(), "ADMIN", recovery.browserToken));

  const replacement = uniqueEmail("admin-pair-new-mailbox");
  await assert.rejects(startRecoveryNewMailbox(recovery.requestId, recovery.requestKey, createPasskeyBrowserToken(), "ADMIN", replacement));
  await startRecoveryNewMailbox(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", replacement);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).newMailboxChallengeSent, true);
  await assert.rejects(consumeApprovedAccountRecovery(recovery.requestId, recovery.requestKey,
    "challenge-sent-not-verified-password", new Date(), "ADMIN", recovery.browserToken));
  const code = (await queuedEmails(replacement)).filter(item => item.kind === "RECOVERY_EMAIL_REBIND").at(-1)?.code;
  assert.match(code ?? "", /^\d{6}$/u);
  await assert.rejects(verifyRecoveryNewMailbox(recovery.requestId, recovery.requestKey, createPasskeyBrowserToken(), "ADMIN", code!));
  await assert.rejects(verifyRecoveryNewMailbox(recovery.requestId, recovery.requestKey, recovery.browserToken, "USER", code!));
  await verifyRecoveryNewMailbox(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", code!);
  assert.equal((await getMultiMethodRecoveryState(recovery.requestId, recovery.requestKey, recovery.browserToken, "ADMIN", policy)).newMailboxVerified, true);
  await oneResetWinner(recovery, owner, "admin-passkey-totp", ["PASSKEY", "TOTP"], replacement);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE" } }), 1,
    "original mailbox receives a privacy-preserving account-change notice");
});
