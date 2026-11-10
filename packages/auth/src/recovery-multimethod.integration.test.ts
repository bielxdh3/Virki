import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { after, test } from "node:test";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, seedAdminSessionWithElevation, uniqueEmail } from "./integration-fixtures";
import {
  getMultiMethodRecoveryState,
  finishRecoveryPasskeyAssertion,
  startMultiMethodRecovery,
  startRecoveryNewMailbox,
  startRecoveryPasskeyAssertion,
  verifyMultiMethodRecoveryEmail,
  verifyMultiMethodRecoveryTotp,
  verifyRecoveryNewMailbox
} from "./recovery-methods";
import { approveAccountRecovery, confirmTotpEnrollment, consumeApprovedAccountRecovery, createTotpSecret, startTotpEnrollment } from "./security";
import { hashPassword, verifyPassword } from "./index";
import { createPasskeyBrowserToken, finishPasskeyRegistration, startPasskeyRegistration } from "./passkeys";

after(() => prisma.$disconnect());

// Independent RFC 6238 code generation for the test account's enrolled TOTP secret.
function totpAt(secret: string, date = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(date.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

function isolatedSource(): string {
  const uuid = randomUUID().replaceAll("-", "");
  return `2001:db8:${uuid.slice(0, 4)}:${uuid.slice(4, 8)}:${uuid.slice(8, 12)}:${uuid.slice(12, 16)}:${uuid.slice(16, 20)}:${uuid.slice(20, 24)}`;
}

async function requireStep(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch (error) {
    assert.fail(`integration stage ${label}: ${error instanceof Error ? error.name : "unknown error"}`);
  }
}

const recoveryRp = "portal.biel.dev.br";
const recoveryOrigin = "https://portal.biel.dev.br";
const sha256 = (value: Buffer | string) => createHash("sha256").update(value).digest();

// Real ECDSA P-256 COSE public key + WebAuthn CBOR and signed authenticatorData.
// No mocked verification, browser profile, production request or real email send.
function recoveryAuthenticator() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]
  ]));
  return { id: randomBytes(32).toString("base64url"), cose, privateKey };
}

type RecoverySigner = ReturnType<typeof recoveryAuthenticator>;

function signedRecoveryClientData(type: "webauthn.create" | "webauthn.get", challenge: string, origin = recoveryOrigin) {
  return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false })).toString("base64url");
}

function signedRecoveryRegistration(signer: RecoverySigner, challenge: string): RegistrationResponseJSON {
  const credentialId = Buffer.from(signer.id, "base64url");
  const authenticatorData = Buffer.concat([
    sha256(recoveryRp), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([credentialId.length >> 8, credentialId.length & 255]), credentialId, Buffer.from(signer.cose)
  ]);
  const attestation = isoCBOR.encode(new Map<string, string | Map<string, never> | Uint8Array>([
    ["fmt", "none"], ["attStmt", new Map<string, never>()], ["authData", authenticatorData]
  ]));
  return {
    id: signer.id, rawId: signer.id, type: "public-key",
    response: {
      clientDataJSON: signedRecoveryClientData("webauthn.create", challenge),
      attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"]
    }, clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

function signedRecoveryAssertion(signer: RecoverySigner, userId: string, challenge: string, overrides: { rpID?: string; origin?: string; flags?: number; counter?: number } = {}): AuthenticationResponseJSON {
  const authenticatorData = Buffer.concat([
    sha256(overrides.rpID ?? recoveryRp), Buffer.from([overrides.flags ?? 0x05]),
    Buffer.from([0, 0, 0, overrides.counter ?? 1])
  ]);
  const clientData = signedRecoveryClientData("webauthn.get", challenge, overrides.origin);
  const signed = Buffer.concat([authenticatorData, sha256(Buffer.from(clientData, "base64url"))]);
  return {
    id: signer.id, rawId: signer.id, type: "public-key",
    response: {
      authenticatorData: authenticatorData.toString("base64url"), clientDataJSON: clientData,
      signature: sign("sha256", signed, signer.privateKey).toString("base64url"),
      userHandle: Buffer.from(userId, "utf8").toString("base64url")
    }, clientExtensionResults: {}, authenticatorAttachment: "platform"
  };
}

async function enrollSignedRecoveryPasskey(owner: { id: string; password: string }) {
  const session = await prisma.session.create({
    data: { userId: owner.id, tokenHash: randomBytes(32).toString("hex"), expiresAt: new Date(Date.now() + 60_000) }
  });
  const browserToken = createPasskeyBrowserToken();
  const signer = recoveryAuthenticator();
  const options = await startPasskeyRegistration(owner.id, session.id, owner.password, browserToken, recoveryRp);
  await finishPasskeyRegistration(owner.id, session.id, browserToken, signedRecoveryRegistration(signer, options.challenge), "Recovery integration signer", recoveryRp);
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, credentialId: signer.id, rpID: recoveryRp, revokedAt: null } }), 1);
  return signer;
}

async function signAndVerifyRecoveryProof(request: { requestId: string; requestKey: string; browserToken: string }, signer: RecoverySigner, userId: string) {
  const options = await startRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, "USER", recoveryRp);
  const wrongRp = signedRecoveryAssertion(signer, userId, options.challenge, { rpID: "hub.biel.dev.br" });
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, wrongRp, "USER", recoveryRp),
    "genuinely signed assertion with wrong RP hash cannot satisfy recovery");
  const wrongOrigin = signedRecoveryAssertion(signer, userId, options.challenge, { origin: "https://hub.biel.dev.br" });
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, wrongOrigin, "USER", recoveryRp),
    "genuinely signed assertion with wrong clientData origin cannot satisfy recovery");
  const noUv = signedRecoveryAssertion(signer, userId, options.challenge, { flags: 0x01 });
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, noUv, "USER", recoveryRp),
    "signed but non-user-verified authenticatorData must be rejected");
  const signed = signedRecoveryAssertion(signer, userId, options.challenge);
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, createPasskeyBrowserToken(), signed, "USER", recoveryRp),
    "a signed assertion cannot be stolen by another recovery browser capability");
  const challengeHash = sha256(options.challenge).toString("hex");
  assert.equal((await prisma.passkeyChallenge.findUniqueOrThrow({ where: { challengeHash } })).consumedAt, null,
    "wrong RP/origin/UV/browser must never consume a legitimate challenge");
  await finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, signed, "USER", recoveryRp);
  assert.ok((await prisma.passkeyChallenge.findUniqueOrThrow({ where: { challengeHash } })).consumedAt,
    "valid recovery ceremony must consume exactly its own challenge");
  await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, signed, "USER", recoveryRp),
    "cryptographically valid response cannot replay a consumed recovery ceremony");
  assert.ok((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).recoveryPasskeyVerifiedAt);
}

async function assertSingleResetWinner(request: { requestId: string; requestKey: string; browserToken: string }, owner: { id: string }, label: string) {
  const candidates = [`${label}-new-password-first-2026`, `${label}-new-password-second-2026`];
  const results = await Promise.allSettled(candidates.map(password =>
    consumeApprovedAccountRecovery(request.requestId, request.requestKey, password, new Date(), "USER", request.browserToken)));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1, "only one concurrent reset may win");
  assert.equal(results.filter(result => result.status === "rejected").length, 1, "the duplicate reset must fail closed");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).status, "CONSUMED");
  const saved = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true } });
  assert.equal((await Promise.all(candidates.map(password => verifyPassword(saved.passwordHash ?? "", password)))).filter(Boolean).length, 1);
}

for (const secondProof of ["EMAIL", "TOTP"] as const) {
  test(`real PostgreSQL: legacy non-discoverable USER passkey IDs require independent ${secondProof} proof`, integrationOptions, async (t) => {
    const previous = process.env.VIRKI_PASSKEYS_ENABLED;
    process.env.VIRKI_PASSKEYS_ENABLED = "true";
    t.after(() => { if (previous === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED; else process.env.VIRKI_PASSKEYS_ENABLED = previous; });

    const owner = await createTestUser({ label: `recovery-nondiscoverable-${secondProof.toLowerCase()}` });
    const signer = await enrollSignedRecoveryPasskey(owner);
    let totpSecret: string | undefined;
    if (secondProof === "TOTP") {
      const enrollment = await startTotpEnrollment(owner.id, owner.email);
      totpSecret = enrollment.secret;
      const previousWindow = new Date(Date.now() - 30_000);
      await confirmTotpEnrollment(owner.id, totpAt(totpSecret, previousWindow), previousWindow);
    }
    const policy = { proofs: ["PASSKEY" as const, secondProof], adminReview: false };
    const request = await startMultiMethodRecovery(owner.email, "USER", policy, "pt-BR", new Date(), isolatedSource());
    const synthetic = await startMultiMethodRecovery(uniqueEmail("recovery-unknown-passkey"), "USER", policy, "pt-BR", new Date(), isolatedSource());
    assert.equal((await startRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, "USER", recoveryRp)).allowCredentials, undefined,
      "real pending recovery must not enumerate keys before another factor is verified");
    assert.equal((await startRecoveryPasskeyAssertion(synthetic.requestId, synthetic.requestKey, synthetic.browserToken, "USER", recoveryRp)).allowCredentials, undefined,
      "synthetic recovery must never expose account-selected credential IDs");

    if (secondProof === "EMAIL") {
      const code = (await queuedEmails(owner.email)).filter(message => message.kind === "ACCOUNT_RECOVERY").at(-1)?.code;
      assert.match(code ?? "", /^\d{6}$/u);
      await verifyMultiMethodRecoveryEmail(request.requestId, request.requestKey, request.browserToken, code!, "USER");
    } else {
      await verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, request.browserToken, totpAt(totpSecret!), "USER");
    }
    const options = await startRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, "USER", recoveryRp);
    assert.deepEqual(options.allowCredentials?.map(credential => credential.id), [signer.id],
      "only after independent owner proof may legacy non-discoverable passkey IDs be selected");
    assert.equal((await startRecoveryPasskeyAssertion(request.requestId, request.requestKey, createPasskeyBrowserToken(), "USER", recoveryRp)).allowCredentials, undefined,
      "another browser capability must not enumerate even after the owner verified a factor");
    const signed = signedRecoveryAssertion(signer, owner.id, options.challenge);
    await finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, signed, "USER", recoveryRp);
    await assert.rejects(finishRecoveryPasskeyAssertion(request.requestId, request.requestKey, request.browserToken, signed, "USER", recoveryRp),
      "the selected legacy passkey assertion must remain one-use");
    assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).status, "APPROVED");
  });
}

test("real PostgreSQL: signed PASSKEY + independent EMAIL proof gates one-winner USER reset", integrationOptions, async (t) => {
  const previous = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  t.after(() => { if (previous === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED; else process.env.VIRKI_PASSKEYS_ENABLED = previous; });

  const owner = await createTestUser({ label: "multimethod-signed-passkey-email" });
  const signer = await enrollSignedRecoveryPasskey(owner);
  const selected = { proofs: ["PASSKEY" as const, "EMAIL" as const], adminReview: false };
  const request = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", new Date(), isolatedSource());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId, userId: owner.id } }), 1);
  await signAndVerifyRecoveryProof(request, signer, owner.id);

  const passkeyOnly = await getMultiMethodRecoveryState(request.requestId, request.requestKey, request.browserToken, "USER", selected);
  assert.equal(passkeyOnly.passkeyVerified, true);
  assert.equal(passkeyOnly.emailVerified, false);
  assert.equal(passkeyOnly.status, "PENDING", "a verified passkey is insufficient without independent email proof");
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, "passkey-alone-never-approves", new Date(), "USER", request.browserToken));

  const emailCode = (await queuedEmails(owner.email)).filter(message => message.kind === "ACCOUNT_RECOVERY").at(-1)?.code;
  assert.match(emailCode ?? "", /^\d{6}$/u, "second proof must come from the test-only outbox");
  await assert.rejects(verifyMultiMethodRecoveryEmail(request.requestId, request.requestKey, createPasskeyBrowserToken(), emailCode!, "USER"));
  await verifyMultiMethodRecoveryEmail(request.requestId, request.requestKey, request.browserToken, emailCode!, "USER");
  const approved = await getMultiMethodRecoveryState(request.requestId, request.requestKey, request.browserToken, "USER", selected);
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.emailVerified, true);
  await assertSingleResetWinner(request, owner, "signed-passkey-email");
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } }), 0,
    "reset invalidates the previously signed recovery passkey");
});

test("real PostgreSQL: signed PASSKEY + independent TOTP requires new mailbox and one-winner USER reset", integrationOptions, async (t) => {
  const previous = process.env.VIRKI_PASSKEYS_ENABLED;
  process.env.VIRKI_PASSKEYS_ENABLED = "true";
  t.after(() => { if (previous === undefined) delete process.env.VIRKI_PASSKEYS_ENABLED; else process.env.VIRKI_PASSKEYS_ENABLED = previous; });

  const owner = await createTestUser({ label: "multimethod-signed-passkey-totp" });
  const signer = await enrollSignedRecoveryPasskey(owner);
  const enrollment = await startTotpEnrollment(owner.id, owner.email);
  const previousWindow = new Date(Date.now() - 30_000);
  await confirmTotpEnrollment(owner.id, totpAt(enrollment.secret, previousWindow), previousWindow);
  const selected = { proofs: ["PASSKEY" as const, "TOTP" as const], adminReview: false };
  const request = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", new Date(), isolatedSource());
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId, userId: owner.id } }), 1);
  await signAndVerifyRecoveryProof(request, signer, owner.id);

  const passkeyOnly = await getMultiMethodRecoveryState(request.requestId, request.requestKey, request.browserToken, "USER", selected);
  assert.equal(passkeyOnly.passkeyVerified, true);
  assert.equal(passkeyOnly.totpVerified, false);
  assert.equal(passkeyOnly.status, "PENDING");
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, "passkey-without-totp-denied", new Date(), "USER", request.browserToken));

  await assert.rejects(verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, createPasskeyBrowserToken(), totpAt(enrollment.secret), "USER"),
    "valid TOTP from another browser capability cannot complete recovery");
  await verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, request.browserToken, totpAt(enrollment.secret), "USER");
  const approved = await getMultiMethodRecoveryState(request.requestId, request.requestKey, request.browserToken, "USER", selected);
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.totpVerified, true);
  assert.equal(approved.newMailboxRequired, true);
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, "two-proofs-still-require-new-mail", new Date(), "USER", request.browserToken));

  const replacement = uniqueEmail("multimethod-signed-passkey-totp-new-mail");
  await startRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "USER", replacement);
  const mailboxCode = (await queuedEmails(replacement)).filter(message => message.kind === "RECOVERY_EMAIL_REBIND").at(-1)?.code;
  assert.match(mailboxCode ?? "", /^\d{6}$/u);
  await verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "USER", mailboxCode!);
  await assertSingleResetWinner(request, owner, "signed-passkey-totp");
  const stored = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { emailNormalized: true, secondFactorMethod: true } });
  assert.equal(stored.emailNormalized, replacement);
  assert.equal(stored.secondFactorMethod, "EMAIL");
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "REVOKED");
  assert.equal(await prisma.passkeyCredential.count({ where: { userId: owner.id, revokedAt: null } }), 0);
});

test("real PostgreSQL: EMAIL plus TOTP requires both proofs, then concurrent reset has one winner", integrationOptions, async () => {
  const secret = createTotpSecret();
  const owner = await createTestUser({ label: "multimethod-email-totp", totpSecret: secret });
  const policy = { proofs: ["EMAIL", "TOTP"] as const, adminReview: false };
  const selected = { proofs: [...policy.proofs], adminReview: false };
  const now = new Date();
  const real = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", now, isolatedSource());
  const synthetic = await startMultiMethodRecovery(uniqueEmail("absent-multimethod"), "USER", selected, "pt-BR", now, isolatedSource());
  assert.match(real.requestId, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(synthetic.requestId, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(real.requestId.length, synthetic.requestId.length);
  assert.deepEqual(await getMultiMethodRecoveryState(real.requestId, real.requestKey, real.browserToken, "USER", selected),
    await getMultiMethodRecoveryState(synthetic.requestId, synthetic.requestKey, synthetic.browserToken, "USER", selected),
    "GET cannot enumerate a real unverified request");
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: synthetic.requestId } }), 0);

  const emailCode = (await queuedEmails(owner.email)).filter((message) => message.kind === "ACCOUNT_RECOVERY").at(-1)?.code;
  assert.match(emailCode ?? "", /^\d{6}$/u);
  await assert.rejects(verifyMultiMethodRecoveryEmail(real.requestId, real.requestKey, synthetic.browserToken, emailCode!, "USER"));
  await verifyMultiMethodRecoveryEmail(real.requestId, real.requestKey, real.browserToken, emailCode!, "USER");
  const beforeTotp = await getMultiMethodRecoveryState(real.requestId, real.requestKey, real.browserToken, "USER", selected);
  assert.equal(beforeTotp.emailVerified, true);
  assert.equal(beforeTotp.totpVerified, false);
  assert.equal(beforeTotp.status, "PENDING");
  await assert.rejects(consumeApprovedAccountRecovery(real.requestId, real.requestKey, "cannot-reset-after-email-alone", new Date(), "USER", real.browserToken));
  await verifyMultiMethodRecoveryTotp(real.requestId, real.requestKey, real.browserToken, totpAt(secret), "USER");
  assert.equal((await getMultiMethodRecoveryState(real.requestId, real.requestKey, real.browserToken, "USER", selected)).status, "APPROVED");

  const candidates = ["strong-multimethod-reset-pass-a", "strong-multimethod-reset-pass-b"];
  const results = await Promise.allSettled(candidates.map((password) =>
    consumeApprovedAccountRecovery(real.requestId, real.requestKey, password, new Date(), "USER", real.browserToken)));
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: real.requestId } })).status, "CONSUMED");
  const user = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { passwordHash: true, secondFactorMethod: true } });
  assert.equal((await Promise.all(candidates.map((password) => verifyPassword(user.passwordHash ?? "", password)))).filter(Boolean).length, 1);
  assert.equal(user.secondFactorMethod, "EMAIL");
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "REVOKED");
});

test("real PostgreSQL: independent ADMIN review plus TOTP requires verified replacement inbox before reset", integrationOptions, async () => {
  const secret = createTotpSecret();
  const owner = await createTestUser({ role: "ADMIN", label: "multimethod-admin-owner", totpSecret: secret });
  const reviewer = await createTestUser({ role: "ADMIN", label: "multimethod-admin-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const separateAdminPassword = "independent-administrator-privileged-secret";
  await prisma.administrativeCredential.create({ data: { userId: owner.id, passwordHash: await hashPassword(separateAdminPassword), status: "ACTIVE" } });
  const selected = { proofs: ["TOTP" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "ADMIN", selected, "pt-BR", new Date(), isolatedSource(), "Perdi acesso ao email");
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1);
  await assert.rejects(approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId));
  await requireStep("ADMIN TOTP proof", () => verifyMultiMethodRecoveryTotp(request.requestId, request.requestKey, request.browserToken, totpAt(secret), "ADMIN"));
  assert.equal((await getMultiMethodRecoveryState(request.requestId, request.requestKey, request.browserToken, "ADMIN", selected)).status, "PENDING");
  await requireStep("independent ADMIN approval", () => approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId));
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, "new-normal-admin-password-for-review", new Date(), "ADMIN", request.browserToken));
  const replacement = uniqueEmail("multimethod-admin-replacement");
  await requireStep("new mailbox challenge", () => startRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "ADMIN", replacement));
  const mailboxCode = (await queuedEmails(replacement)).filter((message) => message.kind === "RECOVERY_EMAIL_REBIND").at(-1)?.code;
  assert.match(mailboxCode ?? "", /^\d{6}$/u);
  await assert.rejects(verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "ADMIN", "000000"));
  await requireStep("new mailbox proof", () => verifyRecoveryNewMailbox(request.requestId, request.requestKey, request.browserToken, "ADMIN", mailboxCode!));
  await requireStep("admin normal credential reset", () => consumeApprovedAccountRecovery(request.requestId, request.requestKey, "new-normal-admin-password-for-review", new Date(), "ADMIN", request.browserToken));

  const stored = await prisma.user.findUniqueOrThrow({ where: { id: owner.id }, select: { email: true, emailNormalized: true, emailVerifiedAt: true, passwordHash: true, secondFactorMethod: true } });
  assert.equal(stored.email, replacement);
  assert.equal(stored.emailNormalized, replacement);
  assert.ok(stored.emailVerifiedAt);
  assert.equal(await verifyPassword(stored.passwordHash ?? "", "new-normal-admin-password-for-review"), true);
  assert.equal(stored.secondFactorMethod, "EMAIL");
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: owner.id } })).status, "REVOKED");
  const administrative = await prisma.administrativeCredential.findUniqueOrThrow({ where: { userId: owner.id }, select: { passwordHash: true } });
  assert.equal(await verifyPassword(administrative.passwordHash, separateAdminPassword), true);
  assert.equal(await prisma.emailOutboxMessage.count({ where: { recipientEmail: owner.email, kind: "RECOVERY_EMAIL_REBIND_NOTICE" } }), 1);
});

test("real PostgreSQL: reviewer demotion invalidates prior approval before reset", integrationOptions, async () => {
  const owner = await createTestUser({ label: "multimethod-demoted-owner" });
  const reviewer = await createTestUser({ role: "ADMIN", label: "multimethod-demoted-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const selected = { proofs: ["EMAIL" as const], adminReview: true };
  const request = await startMultiMethodRecovery(owner.email, "USER", selected, "pt-BR", new Date(), isolatedSource());
  const emailCode = (await queuedEmails(owner.email)).filter((message) => message.kind === "ACCOUNT_RECOVERY").at(-1)?.code;
  assert.ok(emailCode);
  await verifyMultiMethodRecoveryEmail(request.requestId, request.requestKey, request.browserToken, emailCode, "USER");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, request.requestId);
  await prisma.user.update({ where: { id: reviewer.id }, data: { role: "USER" } });
  await assert.rejects(consumeApprovedAccountRecovery(request.requestId, request.requestKey, "demoted-admin-must-not-authorize", new Date(), "USER", request.browserToken));
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: request.requestId } })).status, "APPROVED");
  assert.equal(await verifyPassword((await prisma.user.findUniqueOrThrow({ where: { id: owner.id } })).passwordHash ?? "", "demoted-admin-must-not-authorize"), false);
});
