// Physical PostgreSQL integration tests for the three one-factor + independent
// ADMIN recovery policies.  Never share the existing worker-18/20 databases.
// Invoke through scripts/integration/run.mjs with an explicitly provisioned
// disposable virki_w2_assisted_* database, never a production/owned fixture.
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { after, test } from "node:test";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, seedAdminSessionWithElevation, uniqueEmail } from "./integration-fixtures";
import { hashPassword, verifyPassword } from "./index";
import {
  finishRecoveryPasskeyAssertion, startMultiMethodRecovery, startRecoveryNewMailbox,
  startRecoveryPasskeyAssertion, verifyMultiMethodRecoveryEmail,
  verifyMultiMethodRecoveryTotp, verifyRecoveryNewMailbox
} from "./recovery-methods";
import { approveAccountRecovery, consumeApprovedAccountRecovery, createTotpSecret } from "./security";

after(() => prisma.$disconnect());

function ownedDatabaseConfigured(): boolean {
  const uri = process.env.VIRKI_INTEGRATION_DATABASE_URL;
  if (!uri || !process.env.DATABASE_URL || uri !== process.env.DATABASE_URL ||
      process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") return false;
  try {
    const url = new URL(uri);
    const name = decodeURIComponent(url.pathname.slice(1));
    return url.protocol === "postgresql:" && url.hostname === "127.0.0.1" &&
      url.username === "virki_runtime_test" && /^virki_w2_assisted_[a-zA-Z0-9_]+$/u.test(name);
  } catch {
    return false;
  }
}

const assistedOptions = {
  skip: integrationOptions.skip || (ownedDatabaseConfigured() ? false :
    "requires separate confirmed disposable PG18 database virki_w2_assisted_* (not worker18/20)")
};

async function assertDedicatedPg18(): Promise<void> {
  // Additional physical witness on the same Prisma connection, before any
  // fixture mutation: a mislabeled PG/DB target must fail closed.
  const [server] = await prisma.$queryRaw<Array<{ version: number; database: string; role: string }>>`
    SELECT current_setting('server_version_num')::integer AS "version",
      current_database() AS "database", current_user AS "role"
  `;
  assert.ok(server, "PostgreSQL connection must report its identity");
  assert.ok(server.version >= 180000 && server.version < 190000, "requires actual PostgreSQL 18");
  assert.match(server.database, /^virki_w2_assisted_[a-zA-Z0-9_]+$/u);
  assert.equal(server.role, "virki_runtime_test");
}

function isolatedSource(): string {
  const random = randomUUID().replaceAll("-", "");
  return `2001:db8:${random.slice(0, 4)}:${random.slice(4, 8)}:${random.slice(8, 12)}:${random.slice(12, 16)}:${random.slice(16, 20)}:${random.slice(20, 24)}`;
}

function totpAt(secret: string, now = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const letter of secret) {
    const digit = alphabet.indexOf(letter);
    assert.ok(digit >= 0);
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const step = Buffer.alloc(8);
  step.writeBigUInt64BE(BigInt(Math.floor(now.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(step).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function latestCode(email: string, kind: string): Promise<string> {
  const code = (await queuedEmails(email)).filter((entry) => entry.kind === kind).at(-1)?.code;
  assert.match(code ?? "", /^\d{6}$/u, "the test-only encrypted outbox holds the OTP");
  return code!;
}

async function unchangedOwner(ownerId: string, originalEmail: string, originalHash: string, requestId: string) {
  const current = await prisma.user.findUniqueOrThrow({ where: { id: ownerId },
    select: { email: true, emailNormalized: true, passwordHash: true } });
  assert.equal(current.email, originalEmail, "unconsumed recovery must not rebind the mailbox");
  assert.equal(current.emailNormalized, originalEmail);
  assert.equal(current.passwordHash, originalHash, "unconsumed recovery must not replace the password");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: requestId } })).status, "APPROVED");
}

test("PG18 EMAIL_ADMIN: verified old inbox plus elevated other ADMIN resets USER without replacement mailbox", assistedOptions, async () => {
  await assertDedicatedPg18();
  const owner = await createTestUser({ label: "assisted-email-user" });
  const reviewer = await createTestUser({ role: "ADMIN", label: "assisted-email-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const selected = { proofs: ["EMAIL" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", new Date(), isolatedSource());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1);

  await assert.rejects(approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId),
    "administrator cannot approve before the independent email proof");
  await verifyMultiMethodRecoveryEmail(request.requestId, request.requestKey, request.browserToken,
    await latestCode(owner.email, "ACCOUNT_RECOVERY"), "USER");
  const withoutElevation = await prisma.session.create({ data: {
    userId: reviewer.id, tokenHash: randomBytes(32).toString("base64url"),
    expiresAt: new Date(Date.now() + 3_600_000)
  } });
  await assert.rejects(approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, withoutElevation.id, request.requestId),
    "ADMIN role alone cannot substitute active scope elevation");
  const demoted = await createTestUser({ role: "ADMIN", label: "assisted-email-demoted-reviewer" });
  const { sessionId: demotedSession } = await seedAdminSessionWithElevation(demoted.id, "ACCOUNT_STATE_CHANGE");
  await prisma.user.update({ where: { id: demoted.id }, data: { role: "USER" } });
  await assert.rejects(approveAccountRecovery({ id: demoted.id, role: "ADMIN" }, demotedSession, request.requestId),
    "a reviewer demoted after elevation cannot authorize recovery");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId);
  const resetPassword = "assisted-email-other-admin-normal-login";
  const session = await consumeApprovedAccountRecovery(request.requestId, request.requestKey, resetPassword, new Date(), "USER", request.browserToken);
  assert.ok(session, "approved browser-bound recovery creates a new bootstrap session");
  const final = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(final.email, owner.email, "proving original email must never require a replacement mailbox");
  assert.equal(await verifyPassword(final.passwordHash ?? "", resetPassword), true);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).status, "CONSUMED");
});

test("PG18 TOTP_ADMIN: revoked reviewer cannot consume even after verified replacement inbox", assistedOptions, async () => {
  await assertDedicatedPg18();
  const secret = createTotpSecret();
  const owner = await createTestUser({ label: "assisted-totp-user", totpSecret: secret });
  const reviewer = await createTestUser({ role: "ADMIN", label: "assisted-totp-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const originalHash = (await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).passwordHash!;
  const selected = { proofs: ["TOTP" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", new Date(), isolatedSource());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1);
  await verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, request.browserToken, totpAt(secret), "USER");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId);

  const password = "assisted-totp-revoked-admin-must-fail";
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, password, new Date(), "USER", request.browserToken),
    "lost original mailbox requires verified new mailbox before any reset");
  await unchangedOwner(owner.id, owner.email, originalHash, request.requestId);

  const replacement = uniqueEmail("assisted-totp-inbox");
  await startRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "USER", replacement);
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, password, new Date(), "USER", request.browserToken),
    "sending a replacement OTP does not establish inbox ownership");
  await unchangedOwner(owner.id, owner.email, originalHash, request.requestId);
  await verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "USER",
    await latestCode(replacement, "RECOVERY_EMAIL_REBIND"));
  await unchangedOwner(owner.id, owner.email, originalHash, request.requestId);

  await prisma.user.update({ where: { id: reviewer.id }, data: { isActive: false } });
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, password, new Date(), "USER", request.browserToken),
    "losing reviewer active status must invalidate approved request, even after inbox proof");
  await unchangedOwner(owner.id, owner.email, originalHash, request.requestId);
  assert.equal(await prisma.user.count({ where: { id: reviewer.id, role: "ADMIN", isActive: true, accountStatus: "ACTIVE" } }), 0);
});

test("PG18 TOTP_ADMIN: USER reset succeeds only after independent review and new mailbox ownership proof", assistedOptions, async () => {
  await assertDedicatedPg18();
  const secret = createTotpSecret();
  const owner = await createTestUser({ label: "assisted-totp-success-owner", totpSecret: secret });
  const reviewer = await createTestUser({ role: "ADMIN", label: "assisted-totp-success-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const initial = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  const policy = { proofs: ["TOTP" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "USER", policy, "pt-BR", new Date(), isolatedSource());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1);
  await verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, request.browserToken, totpAt(secret), "USER");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId);
  const newPassword = "assisted-totp-user-new-login-password";
  const newEmail = uniqueEmail("assisted-totp-success-inbox");
  await startRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "USER", newEmail);
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey,
    newPassword, new Date(), "USER", request.browserToken),
  "an OTP sent but not verified must not permit resetting the account");
  await unchangedOwner(owner.id, owner.email, initial.passwordHash!, request.requestId);
  await verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken,
    "USER", await latestCode(newEmail, "RECOVERY_EMAIL_REBIND"));
  const bootstrap = await consumeApprovedAccountRecovery(request.requestId, request.requestKey,
    newPassword, new Date(), "USER", request.browserToken);
  assert.ok(bootstrap);
  const final = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(final.email, newEmail);
  assert.equal(final.emailNormalized, newEmail);
  assert.ok(final.emailVerifiedAt);
  assert.equal(await verifyPassword(final.passwordHash ?? "", newPassword), true);
  assert.equal(final.secondFactorMethod, "EMAIL");
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "REVOKED");
  assert.equal(await prisma.emailOutboxMessage.count({ where: {
    recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE"
  } }), 1);
});

function makeHubAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]
  ]));
  return { privateKey, publicKeyCose: Buffer.from(cose), credentialId: randomBytes(32).toString("base64url") };
}

function signedHubAssertion(
  authenticator: ReturnType<typeof makeHubAuthenticator>, userId: string, challenge: string,
  origin = "https://hub.biel.dev.br"
): AuthenticationResponseJSON {
  const authData = Buffer.concat([createHash("sha256").update("hub.biel.dev.br").digest(),
    Buffer.from([0x05, 0, 0, 0, 1])]); // user present + user verified + increasing counter
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get", challenge, origin, crossOrigin: false
  })).toString("base64url");
  const digest = createHash("sha256").update(Buffer.from(clientDataJSON, "base64url")).digest();
  return {
    id: authenticator.credentialId, rawId: authenticator.credentialId, type: "public-key",
    response: {
      authenticatorData: authData.toString("base64url"), clientDataJSON,
      signature: sign("sha256", Buffer.concat([authData, digest]), authenticator.privateKey).toString("base64url"),
      userHandle: Buffer.from(userId, "utf8").toString("base64url")
    },
    clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

test("PG18 PASSKEY_ADMIN: signed hub RP assertion, no self-review, independent elevated ADMIN and pre-reset mailbox safety", assistedOptions, async (t) => {
  await assertDedicatedPg18();
  const originalPasskeys = process.env.VIRKI_PASSKEYS_ENABLED;
  const originalAdminPasskeys = process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = "true";
  t.after(() => {
    if (originalPasskeys === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED;
    else process.env.VIRKI_PASSKEYS_ENABLED = originalPasskeys;
    if (originalAdminPasskeys === undefined) delete process.env.VIRKI_ADMIN_PASSKEYS_ENABLED;
    else process.env.VIRKI_ADMIN_PASSKEYS_ENABLED = originalAdminPasskeys;
  });

  const owner = await createTestUser({ role: "ADMIN", label: "assisted-passkey-owner" });
  const reviewer = await createTestUser({ role: "ADMIN", label: "assisted-passkey-reviewer" });
  const { sessionId: reviewerSession } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const { sessionId: ownerSession } = await seedAdminSessionWithElevation(owner.id, "ACCOUNT_STATE_CHANGE");
  const distinctAdminPassword = "assisted-privileged-credential-remains";
  await prisma.administrativeCredential.update({
    where: { userId: owner.id }, data: { passwordHash: await hashPassword(distinctAdminPassword), status: "ACTIVE" }
  });
  const initial = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  const authenticator = makeHubAuthenticator();
  // Seed a valid RP-scoped COSE public key; sign the real challenge below.
  const registered = await prisma.passkeyCredential.create({ data: {
    userId: owner.id, credentialId: authenticator.credentialId, rpID: "hub.biel.dev.br",
    publicKey: authenticator.publicKeyCose, backupEligible: false, backupState: false, name: "Assisted hub test passkey"
  } });
  const policy = { proofs: ["PASSKEY" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "ADMIN", policy, "pt-BR",
    new Date(), isolatedSource(), "Perdi acesso ao email", "hub.biel.dev.br");
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1,
    "ADMIN hub credential and feature gates must permit the request");
  const begun = await startRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, "ADMIN", "hub.biel.dev.br");
  const incorrectOrigin = signedHubAssertion(authenticator, owner.id, begun.challenge, "https://portal.biel.dev.br");
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey,
    request.browserToken, incorrectOrigin, "ADMIN", "hub.biel.dev.br"), "valid signature with wrong RP origin cannot prove owner");

  const valid = signedHubAssertion(authenticator, owner.id, begun.challenge);
  await finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, valid, "ADMIN", "hub.biel.dev.br");
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey,
    request.browserToken, valid, "ADMIN", "hub.biel.dev.br"), "consumed assertion cannot be replayed");
  await assert.rejects(approveAccountRecovery({ id: owner.id, role: "ADMIN" }, ownerSession, request.requestId),
    "the recovering ADMIN cannot approve their own request, even with elevation");

  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, reviewerSession, request.requestId);
  const password = "assisted-passkey-hub-normal-password-reset";
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, password,
    new Date(), "ADMIN", request.browserToken), "hub passkey proof must not silently attest mailbox control");
  await unchangedOwner(owner.id, owner.email, initial.passwordHash!, request.requestId);
  const mailbox = uniqueEmail("assisted-passkey-new-mail");
  await startRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "ADMIN", mailbox);
  await unchangedOwner(owner.id, owner.email, initial.passwordHash!, request.requestId);
  await verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "ADMIN",
    await latestCode(mailbox, "RECOVERY_EMAIL_REBIND"));
  await unchangedOwner(owner.id, owner.email, initial.passwordHash!, request.requestId);

  const bootstrap = await consumeApprovedAccountRecovery(request.requestId, request.requestKey, password,
    new Date(), "ADMIN", request.browserToken);
  assert.ok(bootstrap, "an independent other ADMIN can authorize signed hub recovery");
  const final = await prisma.user.findUniqueOrThrow({ where: { id: owner.id } });
  assert.equal(final.email, mailbox);
  assert.equal(final.emailNormalized, mailbox);
  assert.ok(final.emailVerifiedAt);
  assert.equal(await verifyPassword(final.passwordHash ?? "", password), true);
  assert.equal((await prisma.passkeyCredential.findUniqueOrThrow({ where: { id: registered.id } })).revokedAt !== null, true);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).status, "CONSUMED");
  const privileged = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: owner.id } });
  assert.equal(await verifyPassword(privileged.passwordHash, distinctAdminPassword), true,
    "normal password recovery must not reset the separate privileged credential");
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE" } }), 1,
    "old mailbox must receive one nonsecret takeover notice");
});
