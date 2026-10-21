import assert from "node:assert/strict";
import { createHmac, randomInt, randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails, requestKeyFromActionUrl, seedAdminSessionWithElevation } from "./integration-fixtures";
import { hashOidcIdentifier } from "./oidc-secrets";
import {
  approveAccountRecovery,
  consumeApprovedAccountRecovery,
  createTotpSecret,
  disableTotp,
  DEVICE_TRUST_TTL_MS,
  generateRecoveryCode,
  getAccountRecoveryRequestId,
  hashDeviceToken,
  hashRecoveryCode,
  LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT,
  LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT,
  type LoginCeremonyStart,
  requestAccountRecovery,
  regenerateRecoveryCodes,
  SecurityMutationError,
  startLoginCeremony,
  verifyAccountRecoveryEmail,
  verifyLoginEmailCode,
  verifyLoginRecoveryCode,
  verifyLoginTotpCode,
  verifyRecoveryCode,
  verifyTotpCode
} from "./security";

after(() => prisma.$disconnect());

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;
const LOGIN_CODE_KINDS = new Set(["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"]);

type CeremonyStart = Extract<LoginCeremonyStart, { kind: "CEREMONY" }>;

function ceremonyOf(start: LoginCeremonyStart): CeremonyStart {
  assert.equal(start.kind, "CEREMONY");
  return start as CeremonyStart;
}

// The newest login code mailed to the address; emails are read from the never-sent outbox.
async function latestLoginCode(email: string): Promise<string> {
  const code = (await queuedEmails(email)).filter((message) => LOGIN_CODE_KINDS.has(message.kind)).at(-1)?.code;
  if (!code) throw new Error("No login code was queued for the test user.");
  return code;
}

async function countLoginMails(email: string): Promise<number> {
  return (await queuedEmails(email)).filter((message) => LOGIN_CODE_KINDS.has(message.kind)).length;
}

async function countTrustedRows(userId: string, deviceToken: string): Promise<number> {
  return prisma.trustedDevice.count({ where: { userId, deviceIdHash: hashDeviceToken(deviceToken), status: "TRUSTED" } });
}

async function seedOidcArtifact(userId: string): Promise<void> {
  await prisma.oidcArtifact.create({
    data: { model: "AccessToken", idHash: `int-${randomUUID()}`, payloadCiphertext: "x", accountIdHash: hashOidcIdentifier(userId) }
  });
}

async function countOidcArtifacts(userId: string): Promise<number> {
  return prisma.oidcArtifact.count({ where: { accountIdHash: hashOidcIdentifier(userId) } });
}

async function waitForBlockedPostgresQuery(blockerPid: number, queryFragment: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const blocked = await prisma.$queryRaw<Array<{ waiters: number }>>`
      SELECT count(*)::int AS waiters
      FROM pg_stat_activity
      WHERE wait_event_type = 'Lock'
        AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
        AND query LIKE ${`%${queryFragment}%`}
    `;
    if ((blocked[0]?.waiters ?? 0) >= 1) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock wait on ${queryFragment}.`);
}

// Email-factor login from a device. An untrusted candidate token is replaced by the server, so the
// device token returned by startLoginCeremony is the one every later call must use.
async function completeEmailLogin(userId: string, email: string, when: Date, role?: "USER" | "ADMIN") {
  const ceremony = ceremonyOf(await startLoginCeremony(userId, undefined, "pt-BR", when, false, role));
  const result = await verifyLoginEmailCode(ceremony.ceremonyId, await latestLoginCode(email), ceremony.deviceToken, when, role);
  return { deviceToken: ceremony.deviceToken, result };
}

// Full MFA login for a TOTP account: emailed code, then the authenticator code.
async function completeEmailAndTotpLogin(user: { id: string; email: string }, secret: string, when: Date) {
  const ceremony = ceremonyOf(await startLoginCeremony(user.id, undefined, "pt-BR", when));
  const emailStep = await verifyLoginEmailCode(ceremony.ceremonyId, await latestLoginCode(user.email), ceremony.deviceToken, when);
  assert.deepEqual(emailStep, { requiresTotp: true, session: null });
  const session = await verifyLoginTotpCode(ceremony.ceremonyId, totpAt(secret, when), ceremony.deviceToken, when);
  return { deviceToken: ceremony.deviceToken, session };
}

// RFC 4648 base32 decoding for the secret produced by createTotpSecret().
function base32Decode(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of value) {
    buffer = ((buffer << 5) | alphabet.indexOf(char)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

// RFC 6238 code (HMAC-SHA1, 30 s step, 6 digits), computed independently of the production verifier.
function totpAt(secret: string, when: Date): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(when.getTime() / 1_000 / 30)));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

async function openLatestRecovery(email: string, now: Date) {
  const emails = (await queuedEmails(email)).filter((message) => message.kind === "ACCOUNT_RECOVERY");
  const latest = emails.at(-1);
  const requestKey = requestKeyFromActionUrl(latest?.actionUrl);
  const opened = await getAccountRecoveryRequestId(requestKey, now);
  assert.ok(opened, "the newest emailed recovery link opens");
  return { requestId: opened.id, requestKey, code: latest?.code };
}

test("a TOTP device is trusted only after the TOTP step completes", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "login-totp-trust" });
  const base = new Date();
  assert.notEqual(verifyTotpCode(secret, totpAt(secret, base), base), null, "the test-local TOTP matches the production verifier");

  const first = ceremonyOf(await startLoginCeremony(user.id, undefined, "pt-BR", base));
  assert.equal(first.factor, "EMAIL");
  assert.equal(first.newDevice, true);
  const emailStep = await verifyLoginEmailCode(first.ceremonyId, await latestLoginCode(user.email), first.deviceToken, base);
  assert.deepEqual(emailStep, { requiresTotp: true, session: null });
  assert.equal(await countTrustedRows(user.id, first.deviceToken), 0, "no trusted device before the full MFA");

  const secondAt = new Date(base.getTime() + 5_000);
  const second = ceremonyOf(await startLoginCeremony(user.id, first.deviceToken, "pt-BR", secondAt));
  assert.equal(second.factor, "EMAIL", "the same device still goes through the email step, not TOTP-only");
  await verifyLoginEmailCode(second.ceremonyId, await latestLoginCode(user.email), second.deviceToken, secondAt);
  const session = await verifyLoginTotpCode(second.ceremonyId, totpAt(secret, secondAt), second.deviceToken, secondAt);
  assert.ok(session.token);
  assert.equal(await countTrustedRows(user.id, second.deviceToken), 1, "the device is trusted after the TOTP step");

  // forceFreshProof skips the remembered grant so the TOTP-only ceremony for the trusted device is observed.
  const forced = ceremonyOf(await startLoginCeremony(user.id, second.deviceToken, "pt-BR", new Date(base.getTime() + 20_000), true));
  assert.equal(forced.factor, "TOTP", "a trusted TOTP device still requires TOTP and skips email");
});

test("an EMAIL-factor user keeps a remembered browser for 7 days", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-email-remember" });
  const base = new Date();
  const { deviceToken, result } = await completeEmailLogin(user.id, user.email, base);
  assert.ok(result.session);
  assert.equal(await countTrustedRows(user.id, deviceToken), 1);

  const remembered = await startLoginCeremony(user.id, deviceToken, "pt-BR", new Date(base.getTime() + DAY));
  assert.equal(remembered.kind, "SESSION");
});

test("an ADMIN never receives a remembered password-only session", integrationOptions, async () => {
  const admin = await createTestUser({ role: "ADMIN", label: "login-admin-remember" });
  const base = new Date();
  const { deviceToken, result } = await completeEmailLogin(admin.id, admin.email, base, "ADMIN");
  assert.ok(result.session);

  const again = await startLoginCeremony(admin.id, deviceToken, "pt-BR", new Date(base.getTime() + MINUTE), false, "ADMIN");
  assert.equal(again.kind, "CEREMONY");
});

test("login email ceremonies are capped per account even after a correct password", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-quota-account" });
  const base = new Date();
  let successes = 0;
  for (let i = 0; i < 30; i += 1) {
    try {
      await startLoginCeremony(user.id, undefined, "pt-BR", new Date(base.getTime() + i * 1_000));
      successes += 1;
    } catch (error) {
      assert.ok(error instanceof SecurityMutationError);
    }
  }
  assert.equal(successes, LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
  assert.equal(await countLoginMails(user.email), successes);
});

test("login email ceremonies are capped per trusted client source", integrationOptions, async () => {
  // A random host in TEST-NET-3 keeps the rate-limit window private to this run.
  const address = `203.0.113.${randomInt(10, 250)}`;
  const base = new Date();
  let successes = 0;
  let step = 0;
  for (let index = 0; index < 5; index += 1) {
    const user = await createTestUser({ label: `login-source-${index}` });
    for (let attempt = 0; attempt < LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT; attempt += 1) {
      step += 1;
      try {
        await startLoginCeremony(user.id, undefined, "pt-BR", new Date(base.getTime() + step * 1_000), false, undefined, address);
        successes += 1;
      } catch (error) {
        assert.ok(error instanceof SecurityMutationError);
      }
    }
  }
  assert.equal(successes, LOGIN_EMAIL_CEREMONY_SOURCE_LIMIT);
});

test("concurrent login ceremony starts cannot exceed the account quota", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-quota-race" });
  const base = new Date();
  const results = await Promise.allSettled(Array.from({ length: 20 }, () => startLoginCeremony(user.id, undefined, "pt-BR", base)));
  for (const result of results) {
    if (result.status === "rejected") assert.ok(result.reason instanceof SecurityMutationError);
  }
  const successes = results.filter((result) => result.status === "fulfilled").length;
  assert.ok(successes >= 1, "concurrent starts still let a legitimate ceremony through");
  assert.ok(successes <= LOGIN_EMAIL_CEREMONY_ACCOUNT_LIMIT);
  assert.equal(await countLoginMails(user.email), successes);
});

test("a repeated trusted-device start within 60 seconds reuses the pending ceremony", integrationOptions, async () => {
  const user = await createTestUser({ label: "login-reuse" });
  const base = new Date();
  const { deviceToken: token } = await completeEmailLogin(user.id, user.email, base);
  const mailsBefore = await countLoginMails(user.email);
  const at = (ms: number) => new Date(base.getTime() + ms);

  const first = ceremonyOf(await startLoginCeremony(user.id, token, "pt-BR", at(10_000), true));
  assert.equal(await countLoginMails(user.email), mailsBefore + 1);

  const reused = ceremonyOf(await startLoginCeremony(user.id, token, "pt-BR", at(30_000), true));
  assert.equal(reused.ceremonyId, first.ceremonyId);
  assert.equal(await countLoginMails(user.email), mailsBefore + 1, "a reused ceremony queues no new email");

  const fresh = ceremonyOf(await startLoginCeremony(user.id, token, "pt-BR", at(71_000), true));
  assert.notEqual(fresh.ceremonyId, first.ceremonyId);
  assert.equal(await countLoginMails(user.email), mailsBefore + 2);
});

test("an emailed proof does not spend the recovery-code verification budget", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "login-recovery" });
  const base = new Date();
  // The verification window of the earlier full login expires before the recovery attempt.
  const later = new Date(base.getTime() + 20 * MINUTE);
  const completed = await completeEmailAndTotpLogin(user, secret, base);
  assert.ok(completed.session.token);

  const recoveryCode = generateRecoveryCode();
  await prisma.recoveryCode.create({ data: { userId: user.id, codeHash: hashRecoveryCode(recoveryCode) } });
  await seedOidcArtifact(user.id);

  const ceremony = ceremonyOf(await startLoginCeremony(user.id, completed.deviceToken, "pt-BR", later, true));
  assert.equal(ceremony.factor, "TOTP");
  const challenge = await prisma.deviceChallenge.findUnique({ where: { ceremonyId: ceremony.ceremonyId }, select: { status: true, emailVerifiedAt: true } });
  assert.equal(challenge?.status, "VERIFIED");
  assert.equal(challenge?.emailVerifiedAt, null);

  assert.deepEqual(await verifyLoginRecoveryCode(ceremony.ceremonyId, "000000000000000000", ceremony.deviceToken, later), { kind: "EMAIL_REQUIRED" });
  assert.deepEqual(await verifyLoginEmailCode(ceremony.ceremonyId, await latestLoginCode(user.email), ceremony.deviceToken, later), { requiresTotp: true, session: null });

  // Successful proofs refund only their reservation; the three failed recovery guesses remain counted.
  for (let index = 0; index < 3; index += 1) {
    await assert.rejects(verifyLoginRecoveryCode(ceremony.ceremonyId, generateRecoveryCode(), ceremony.deviceToken, later), SecurityMutationError);
  }
  const recovered = await verifyLoginRecoveryCode(ceremony.ceremonyId, recoveryCode, ceremony.deviceToken, later);
  assert.ok(recovered.kind === "RECOVERED");
  assert.ok(recovered.session.token);
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  assert.equal((await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash: createRateLimitIdentifierHash(`login-verification-user:${user.id}`) } })).attempts, 3);

  const factor = await prisma.totpFactor.findUnique({ where: { userId: user.id }, select: { status: true } });
  assert.equal(factor?.status, "REVOKED");
  assert.equal(await prisma.recoveryCode.count({ where: { userId: user.id } }), 0);
  assert.equal(await countOidcArtifacts(user.id), 0);
});

test("disabling TOTP purges OIDC artifacts and revokes sessions for that account only", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "oidc-totp-disable" });
  const other = await createTestUser({ label: "oidc-totp-other" });
  const base = new Date();
  await seedOidcArtifact(user.id);
  await seedOidcArtifact(other.id);
  const session = await prisma.session.create({ data: { userId: user.id, tokenHash: `int-${randomUUID()}`, expiresAt: new Date(base.getTime() + DAY) }, select: { id: true } });

  await disableTotp(user.id, totpAt(secret, base), base);

  assert.equal(await countOidcArtifacts(user.id), 0);
  assert.equal(await countOidcArtifacts(other.id), 1);
  const stored = await prisma.session.findUniqueOrThrow({ where: { id: session.id }, select: { revokedAt: true } });
  assert.notEqual(stored.revokedAt, null);
});

test("recovery-code verification rechecks active account state under the account lock", integrationOptions, async () => {
  const user = await createTestUser({ label: "recovery-code-account-lock" });
  const code = generateRecoveryCode();
  const recoveryCode = await prisma.recoveryCode.create({ data: { userId: user.id, codeHash: hashRecoveryCode(code) }, select: { id: true } });
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR UPDATE`;
    locked();
    await gate;
    await transaction.user.update({ where: { id: user.id }, data: { accountStatus: "BLOCKED" } });
  }, { timeout: 10_000 });
  await ready;

  const verification = verifyRecoveryCode(user.id, code).then((ok) => ({ ok: true as const, value: ok }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, "FOR UPDATE");
  } finally {
    release();
  }
  await blocker;
  const outcome = await verification;
  assert.equal(outcome.ok, false, "a blocked account must not consume a recovery code");
  if (!outcome.ok) assert.ok(outcome.error instanceof SecurityMutationError);
  assert.equal((await prisma.recoveryCode.findUniqueOrThrow({ where: { id: recoveryCode.id }, select: { usedAt: true } })).usedAt, null);
});

test("recovery-code regeneration rechecks active account state under the account lock", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "recovery-code-regeneration-lock" });
  const now = new Date();
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR UPDATE`;
    locked();
    await gate;
    await transaction.user.update({ where: { id: user.id }, data: { accountStatus: "BLOCKED" } });
  }, { timeout: 10_000 });
  await ready;

  const regeneration = regenerateRecoveryCodes(user.id, totpAt(secret, now), now).then((codes) => ({ ok: true as const, codes }), (error: unknown) => ({ ok: false as const, error }));
  try {
    await waitForBlockedPostgresQuery(blockerPid, "FOR UPDATE");
  } finally {
    release();
  }
  await blocker;
  const outcome = await regeneration;
  assert.equal(outcome.ok, false, "a blocked account must not rotate recovery codes");
  if (!outcome.ok) assert.ok(outcome.error instanceof SecurityMutationError);
  assert.equal(await prisma.recoveryCode.count({ where: { userId: user.id } }), 0);
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id }, select: { lastUsedStep: true } })).lastUsedStep, null);
});

test("an approved account recovery purges OIDC artifacts for that account only", integrationOptions, async () => {
  const owner = await createTestUser({ label: "oidc-recovery-owner" });
  const other = await createTestUser({ label: "oidc-recovery-other" });
  const admin = await createTestUser({ role: "ADMIN", label: "oidc-recovery-admin" });
  await seedOidcArtifact(owner.id);
  await seedOidcArtifact(other.id);

  const start = new Date();
  const { sessionId } = await seedAdminSessionWithElevation(admin.id, "ACCOUNT_STATE_CHANGE", start);
  await requestAccountRecovery(owner.email, "pt-BR", start);
  const legit = await openLatestRecovery(owner.email, start);
  await verifyAccountRecoveryEmail(legit.requestId, legit.requestKey, legit.code ?? "", start);
  await approveAccountRecovery({ id: admin.id, role: "ADMIN" }, sessionId, legit.requestId, start);
  const approved = await openLatestRecovery(owner.email, start);
  await consumeApprovedAccountRecovery(approved.requestId, approved.requestKey, "integration-oidc-password-1", start);

  assert.equal(await countOidcArtifacts(owner.id), 0);
  assert.equal(await countOidcArtifacts(other.id), 1);
});


test("successful email and TOTP ceremonies preserve the shared verification failure budget", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "mfa-success-budget" });
  const base = new Date();
  for (let index = 0; index < 4; index += 1) await completeEmailAndTotpLogin(user, secret, new Date(base.getTime() + index * 60_000));
  assert.equal(await prisma.loginRateLimit.count({ where: { identifierHash: (await import("./rate-limit-config")).createRateLimitIdentifierHash(`login-verification-user:${user.id}`), attempts: { gt: 0 } } }), 0);
});

test("aged trusted-device tokens are revoked and cannot restore a remembered grant", integrationOptions, async () => {
  const user = await createTestUser({ label: "device-aged" });
  const base = new Date();
  const { deviceToken } = await completeEmailLogin(user.id, user.email, base);
  await prisma.trustedDevice.updateMany({ where: { userId: user.id }, data: { createdAt: new Date(base.getTime() - DEVICE_TRUST_TTL_MS), lastSeenAt: base } });
  const replay = ceremonyOf(await startLoginCeremony(user.id, deviceToken, "pt-BR", base));
  assert.equal(replay.newDevice, true);
  assert.notEqual(replay.deviceToken, deviceToken);
  const aged = await prisma.trustedDevice.findUniqueOrThrow({ where: { userId_deviceIdHash: { userId: user.id, deviceIdHash: hashDeviceToken(deviceToken) } } });
  assert.equal(aged.status, "REVOKED");
  assert.ok(aged.revokedAt);
  assert.equal(aged.rememberedUntil, null);
});

test("forced reauthentication on a remembered browser still requires MFA", integrationOptions, async () => {
  const user = await createTestUser({ label: "fresh-reauth" });
  const base = new Date();
  const { deviceToken } = await completeEmailLogin(user.id, user.email, base);
  const forced = ceremonyOf(await startLoginCeremony(user.id, deviceToken, "pt-BR", new Date(base.getTime() + 1000), true, "USER"));
  assert.equal(forced.factor, "EMAIL");
  await assert.rejects(verifyLoginTotpCode(forced.ceremonyId, "000000", forced.deviceToken, base, "USER"), SecurityMutationError);
});


test("failed email proofs remain limited across ceremonies after successful proofs", integrationOptions, async () => {
  const user = await createTestUser({ label: "mfa-failures-persist" });
  const base = new Date();
  const first = ceremonyOf(await startLoginCeremony(user.id, undefined, "pt-BR", base));
  const firstCode = await latestLoginCode(user.email);
  const firstWrong = firstCode === "000000" ? "000001" : "000000";
  for (let attempt = 0; attempt < 4; attempt += 1) await assert.rejects(verifyLoginEmailCode(first.ceremonyId, firstWrong, first.deviceToken, base), SecurityMutationError);
  await verifyLoginEmailCode(first.ceremonyId, await latestLoginCode(user.email), first.deviceToken, base);
  const { createRateLimitIdentifierHash } = await import("./rate-limit-config");
  const identifierHash = createRateLimitIdentifierHash(`login-verification-user:${user.id}`);
  assert.equal((await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash } })).attempts, 4, "successful proof preserves four failures");
  const second = ceremonyOf(await startLoginCeremony(user.id, undefined, "pt-BR", new Date(base.getTime() + 1000)));
  const secondCode = await latestLoginCode(user.email);
  await assert.rejects(verifyLoginEmailCode(second.ceremonyId, secondCode === "000000" ? "000001" : "000000", second.deviceToken, base), SecurityMutationError);
  assert.equal((await prisma.loginRateLimit.findUniqueOrThrow({ where: { identifierHash } })).attempts, 5, "failure on another ceremony reaches shared limit");
  await assert.rejects(verifyLoginEmailCode(second.ceremonyId, await latestLoginCode(user.email), second.deviceToken, base), SecurityMutationError);
});
