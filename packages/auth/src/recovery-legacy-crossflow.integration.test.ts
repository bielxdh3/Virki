import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation } from "./integration-fixtures";
import { startMultiMethodRecovery, verifyMultiMethodRecoveryTotp } from "./recovery-methods";
import {
  approveAccountRecovery, createTotpSecret, getAccountRecoveryRequestId,
  requestAccountRecovery, requestAdministrativeAccountRecovery, verifyAccountRecoveryEmail
} from "./security";

after(() => prisma.$disconnect());

function totpCode(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let value = 0;
  let count = 0;
  for (const digit of secret) {
    value = (value << 5) | alphabet.indexOf(digit);
    count += 5;
    if (count >= 8) {
      bytes.push((value >>> (count - 8)) & 255);
      count -= 8;
      value &= (1 << count) - 1;
    }
  }
  const step = Buffer.alloc(8);
  step.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(step).digest();
  const offset = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function oldMailboxRequest(email: string, role: "USER" | "ADMIN" = "USER") {
  if (role === "ADMIN") await requestAdministrativeAccountRecovery(email, "pt-BR");
  else await requestAccountRecovery(email, "pt-BR");
  const emailMessage = (await queuedEmails(email)).filter(row => row.kind === "ACCOUNT_RECOVERY").at(-1);
  const requestKey = requestKeyFromActionUrl(emailMessage?.actionUrl);
  const opened = await getAccountRecoveryRequestId(requestKey, new Date(), role);
  assert.ok(opened);
  assert.match(emailMessage?.code ?? "", /^\d{6}$/u);
  return { id: opened.id, key: requestKey, code: emailMessage!.code! };
}

async function ageCooldown(requestId: string) {
  await prisma.accountRecoveryRequest.update({
    where: { id: requestId }, data: { createdAt: new Date(Date.now() - 61_000) }
  });
}

async function totpRecovery(email: string, role: "USER" | "ADMIN") {
  const request = await startMultiMethodRecovery(email, role, { proofs: ["TOTP"], adminReview: true }, "pt-BR");
  assert.equal(await prisma.accountRecoveryRequest.count({ where: { id: request.requestId } }), 1,
    "strong recovery must persist, not return a synthetic browser capability");
  return request;
}

for (const role of ["USER", "ADMIN"] as const) {
  test(`real PostgreSQL ${role}: a TOTP-proven PENDING recovery vetoes legacy start and remains approvable`, integrationOptions, async () => {
    const secret = createTotpSecret();
    const owner = await createTestUser({ role, totpSecret: secret, label: "crossflow-strong-first" });
    const reviewer = await createTestUser({ role: "ADMIN", label: "crossflow-strong-reviewer" });
    const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
    const strong = await totpRecovery(owner.email, role);
    await verifyMultiMethodRecoveryTotp(strong.requestId, strong.requestKey, strong.browserToken, totpCode(secret), role);
    await ageCooldown(strong.requestId);
    const requested = await Promise.allSettled([
      role === "USER" ? requestAccountRecovery(owner.email, "pt-BR") : requestAdministrativeAccountRecovery(owner.email, "pt-BR"),
      role === "USER" ? requestAccountRecovery(owner.email, "pt-BR") : requestAdministrativeAccountRecovery(owner.email, "pt-BR")
    ]);
    assert.ok(requested.some(result => result.status === "fulfilled"),
      "at least one contender completes; a PostgreSQL serialization loser may reject safely");
    const rows = await prisma.accountRecoveryRequest.findMany({ where: { userId: owner.id } });
    assert.deepEqual(rows.map(row => row.id), [strong.requestId], "old mailbox cannot create a competing legacy request");
    assert.equal(rows[0]?.status, "PENDING");
    assert.ok(rows[0]?.recoveryTotpVerifiedAt);
    await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, strong.requestId);
    assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: strong.requestId } })).status, "APPROVED");
    await ageCooldown(strong.requestId);
    if (role === "USER") await requestAccountRecovery(owner.email, "pt-BR");
    else await requestAdministrativeAccountRecovery(owner.email, "pt-BR");
    assert.equal(await prisma.accountRecoveryRequest.count({ where: { userId: owner.id } }), 1, "APPROVED must also veto legacy");
  });

  test(`real PostgreSQL ${role}: an earlier unverified legacy cannot expire a subsequent TOTP proof`, integrationOptions, async () => {
    const secret = createTotpSecret();
    const owner = await createTestUser({ role, totpSecret: secret, label: "crossflow-legacy-first" });
    await createTestUser({ role: "ADMIN", label: "crossflow-other-reviewer" });
    const legacy = await oldMailboxRequest(owner.email, role);
    await ageCooldown(legacy.id);
    const strong = await totpRecovery(owner.email, role);
    await verifyMultiMethodRecoveryTotp(strong.requestId, strong.requestKey, strong.browserToken, totpCode(secret), role);
    await assert.rejects(verifyAccountRecoveryEmail(legacy.id, legacy.key, legacy.code, new Date(), role),
      "old mailbox must fail after independent TOTP proof");
    const [legacyRow, strongRow] = await Promise.all([
      prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: legacy.id } }),
      prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: strong.requestId } })
    ]);
    assert.equal(legacyRow.status, "PENDING");
    assert.equal(legacyRow.emailVerifiedAt, null, "failed legacy proof must not set verified state");
    assert.equal(strongRow.status, "PENDING");
    assert.ok(strongRow.recoveryTotpVerifiedAt);
  });
}

test("real PostgreSQL: an already EMAIL-verified legacy cannot win ADMIN approval over newer proven TOTP", integrationOptions, async () => {
  const secret = createTotpSecret();
  const owner = await createTestUser({ totpSecret: secret, label: "crossflow-approved-legacy" });
  const reviewer = await createTestUser({ role: "ADMIN", label: "crossflow-approval-reviewer" });
  const { sessionId } = await seedAdminSessionWithElevation(reviewer.id, "ACCOUNT_STATE_CHANGE");
  const legacy = await oldMailboxRequest(owner.email);
  await verifyAccountRecoveryEmail(legacy.id, legacy.key, legacy.code);
  await ageCooldown(legacy.id);
  const strong = await totpRecovery(owner.email, "USER");
  await verifyMultiMethodRecoveryTotp(strong.requestId, strong.requestKey, strong.browserToken, totpCode(secret), "USER");
  await assert.rejects(approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, legacy.id),
    "legacy email approval may not expire a stronger pending proof");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: strong.requestId } })).status, "PENDING");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: legacy.id } })).status, "PENDING");
  await approveAccountRecovery({ id: reviewer.id, role: "ADMIN" }, sessionId, strong.requestId);
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: strong.requestId } })).status, "APPROVED");
  assert.equal((await prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: legacy.id } })).status, "EXPIRED");
});

test("real PostgreSQL: concurrent legacy mailbox and owner TOTP proof cannot both win", integrationOptions, async () => {
  for (let attempt = 0; attempt < 3; attempt++) {
    const secret = createTotpSecret();
    const owner = await createTestUser({ totpSecret: secret, label: "crossflow-physical-race" });
    await createTestUser({ role: "ADMIN", label: "crossflow-physical-reviewer" });
    const legacy = await oldMailboxRequest(owner.email);
    await ageCooldown(legacy.id);
    const strong = await totpRecovery(owner.email, "USER");
    const [legacyResult, strongResult] = await Promise.allSettled([
      verifyAccountRecoveryEmail(legacy.id, legacy.key, legacy.code),
      verifyMultiMethodRecoveryTotp(strong.requestId, strong.requestKey, strong.browserToken, totpCode(secret), "USER")
    ]);
    assert.ok(legacyResult.status === "fulfilled" || strongResult.status === "fulfilled",
      "one of the competing account-locked proofs must complete");
    assert.ok(legacyResult.status === "rejected" || strongResult.status === "rejected",
      "serialized account lock must prevent both rival proofs from succeeding");
    const [oldRow, strongRow] = await Promise.all([
      prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: legacy.id } }),
      prisma.accountRecoveryRequest.findUniqueOrThrow({ where: { id: strong.requestId } })
    ]);
    if (strongResult.status === "fulfilled") {
      assert.equal(oldRow.emailVerifiedAt, null);
      assert.equal(strongRow.status, "PENDING");
      assert.ok(strongRow.recoveryTotpVerifiedAt);
    } else if (legacyResult.status === "fulfilled") {
      assert.equal(strongRow.status, "EXPIRED", "only a strong recovery with no verified factor may lose");
      assert.equal(strongRow.recoveryTotpVerifiedAt, null);
      assert.ok(oldRow.emailVerifiedAt);
    } else {
      assert.equal(strongRow.status, "PENDING");
      assert.equal(oldRow.emailVerifiedAt, null);
    }
  }
});
