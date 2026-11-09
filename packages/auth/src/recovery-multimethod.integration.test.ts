import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, seedAdminSessionWithElevation, uniqueEmail } from "./integration-fixtures";
import {
  getMultiMethodRecoveryState,
  startMultiMethodRecovery,
  startRecoveryNewMailbox,
  verifyMultiMethodRecoveryEmail,
  verifyMultiMethodRecoveryTotp,
  verifyRecoveryNewMailbox
} from "./recovery-methods";
import { approveAccountRecovery, consumeApprovedAccountRecovery, createTotpSecret } from "./security";
import { hashPassword, verifyPassword } from "./index";

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
