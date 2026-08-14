import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { after, before, beforeEach, test } from "node:test";
import { NextRequest } from "next/server";

import { getSessionByToken, hashPassword, hashSessionToken } from "@bielos/auth";
import { hasActiveSecurityElevation } from "@bielos/auth/administration";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { decryptEmailPayload } from "@bielos/auth/email";
import {
  confirmTotpEnrollment,
  consumeApprovedAccountRecovery,
  DEVICE_COOKIE_NAME,
  disableTotp,
  encryptTotpSecret,
  hashDeviceToken,
  invalidateRememberedLoginGrantsForUser,
  REMEMBERED_BROWSER_TTL_MS,
  revokeTrustedDevice,
  startLoginCeremony,
  startTotpEnrollment,
  verifyLoginEmailCode,
  verifyLoginTotpCode
} from "@bielos/auth/security";
import { prisma } from "@bielos/database";

import { POST as login } from "../../api/login/route";
import { POST as verify } from "../../api/login/verify/route";
import { POST as logout } from "../../api/logout/route";
import {
  revokeAllOtherCoreSessionRecords
} from "../security/session-service";
import {
  cleanCoreIntegrationTestData,
  disconnectCoreIntegrationTestDatabase
} from "./test-database";

const syntheticCredential = "replace-with-test-secret";
const syntheticTotpSecret = "JBSWY3DPEHPK3PXP";
const originalAccessRequired = process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED;
const originalRateLimitSecret = process.env.BIELOS_RATE_LIMIT_HASH_SECRET;
const originalHubUrl = process.env.NEXT_PUBLIC_HUB_URL;
const originalNodeEnv = process.env.NODE_ENV;
let passwordHash: string;

function currentTestNow(): Date {
  return new Date(Date.now() - 60 * 1000);
}

before(async () => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = syntheticCredential;
  process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
  passwordHash = await hashPassword(syntheticCredential);
});

beforeEach(async () => {
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "false";
  process.env.BIELOS_RATE_LIMIT_HASH_SECRET = syntheticCredential;
  process.env.NEXT_PUBLIC_HUB_URL = "https://hub.example.invalid";
  await cleanCoreIntegrationTestData();
  await prisma.emailOutboxMessage.deleteMany();
});

after(async () => {
  restoreEnvironmentVariable("CLOUDFLARE_ACCESS_JWT_REQUIRED", originalAccessRequired);
  restoreEnvironmentVariable("BIELOS_RATE_LIMIT_HASH_SECRET", originalRateLimitSecret);
  restoreEnvironmentVariable("NEXT_PUBLIC_HUB_URL", originalHubUrl);
  restoreEnvironmentVariable("NODE_ENV", originalNodeEnv);
  await cleanCoreIntegrationTestData();
  await prisma.emailOutboxMessage.deleteMany();
  await disconnectCoreIntegrationTestDatabase();
});

test("new TOTP browsers verify email first, and only completed TOTP establishes a seven-day grant", async () => {
  const user = await createUser("new-totp@example.invalid", "TOTP");
  const deviceToken = createDeviceToken();
  const now = currentTestNow();

  const start = asCeremony(await startLoginCeremony(user.id, deviceToken, "pt-BR", now));
  assert.equal(start.factor, "EMAIL");
  assert.equal(start.newDevice, true);

  const emailCode = await latestEmailCode("NEW_DEVICE_VERIFICATION");
  const emailResult = await verifyLoginEmailCode(start.ceremonyId, emailCode, now);
  assert.equal(emailResult.requiresTotp, true);
  assert.equal(emailResult.session, null);
  assert.equal((await rememberedGrant(user.id, deviceToken))?.rememberedUntil ?? null, null);

  const session = await verifyLoginTotpCode(
    start.ceremonyId,
    createTotpCode(syntheticTotpSecret, now),
    now
  );
  const grant = await rememberedGrant(user.id, deviceToken);
  assert.equal(grant?.rememberedUntil?.getTime(), now.getTime() + REMEMBERED_BROWSER_TTL_MS);
  assert.equal(grant?.strongVerifiedAt?.getTime(), now.getTime());
  assert.notEqual(await getSessionByToken(session.token), null);
});

test("email-factor browsers establish the grant only after valid email verification", async () => {
  const user = await createUser("email-factor@example.invalid", "EMAIL");
  const deviceToken = createDeviceToken();
  const now = currentTestNow();
  const start = asCeremony(await startLoginCeremony(user.id, deviceToken, "pt-BR", now));

  assert.equal(start.factor, "EMAIL");
  assert.equal((await rememberedGrant(user.id, deviceToken))?.rememberedUntil ?? null, null);
  await assert.rejects(verifyLoginEmailCode(start.ceremonyId, "000000", now));
  assert.equal(await rememberedGrant(user.id, deviceToken), null);

  const result = await verifyLoginEmailCode(start.ceremonyId, await latestEmailCode("NEW_DEVICE_VERIFICATION"), now);
  assert.equal(result.requiresTotp, false);
  assert.notEqual(result.session, null);
  assert.equal(await rememberedGrant(user.id, deviceToken) !== null, true);
});

test("trusted-device rows without a remembered grant fail closed after migration", async () => {
  const user = await createUser("migrated-row@example.invalid", "EMAIL");
  const deviceToken = createDeviceToken();
  await prisma.trustedDevice.create({
    data: {
      userId: user.id,
      deviceIdHash: hashDeviceToken(deviceToken),
      status: "TRUSTED"
    }
  });

  const response = await login(createLoginRequest(user.email, syntheticCredential, deviceToken));

  assert.equal(getLocation(response).searchParams.get("factor"), "email");
  assert.equal(getCookieValueOrNull(response, "bielos_session"), null);
  assert.equal((await rememberedGrant(user.id, deviceToken))?.rememberedUntil ?? null, null);
});

test("failed, expired, and replayed ceremonies establish no remembered trust", async () => {
  const user = await createUser("ceremony-failure@example.invalid", "TOTP");
  const deviceToken = createDeviceToken();
  const now = new Date("2026-08-05T12:00:00.000Z");

  const failed = asCeremony(await startLoginCeremony(user.id, deviceToken, "pt-BR", now));
  await assert.rejects(verifyLoginEmailCode(failed.ceremonyId, "000000", now));
  assert.equal(await rememberedGrant(user.id, deviceToken), null);

  const expired = asCeremony(await startLoginCeremony(user.id, deviceToken, "pt-BR", now));
  const expiredAt = new Date(now.getTime() + 10 * 60 * 1000 + 1);
  await assert.rejects(verifyLoginEmailCode(expired.ceremonyId, await latestEmailCode("NEW_DEVICE_VERIFICATION"), expiredAt));
  assert.equal(await rememberedGrant(user.id, deviceToken), null);

  const replayed = asCeremony(await startLoginCeremony(user.id, deviceToken, "pt-BR", now));
  const code = await latestEmailCode("NEW_DEVICE_VERIFICATION");
  const emailResult = await verifyLoginEmailCode(replayed.ceremonyId, code, now);
  assert.equal(emailResult.requiresTotp, true);
  await assert.rejects(verifyLoginEmailCode(replayed.ceremonyId, code, now));
  await assert.rejects(verifyLoginTotpCode(replayed.ceremonyId, "000000", now));
  assert.equal((await rememberedGrant(user.id, deviceToken))?.rememberedUntil ?? null, null);
});

test("ordinary logout revokes the session, clears only its cookie, and preserves the remembered browser", async () => {
  const user = await createUser("logout-preserve@example.invalid", "TOTP");
  const loginResult = await completeTotpRouteLogin(user.email);
  const grantBefore = await rememberedGrant(user.id, loginResult.deviceToken);
  assert.notEqual(grantBefore, null);

  const formData = new FormData();
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());
  const response = await logout(new NextRequest("https://hub.example.invalid/api/logout", {
    method: "POST",
    body: formData,
    headers: {
      cookie: `${cookieHeader("bielos_session", loginResult.sessionToken)}; ${cookieHeader(DEVICE_COOKIE_NAME, loginResult.deviceToken)}`
    }
  }));
  const setCookie = response.headers.get("set-cookie") ?? "";

  assert.equal(await getSessionByToken(loginResult.sessionToken), null);
  assert.match(setCookie, /^bielos_session=/);
  assert.equal(setCookie.includes(`${DEVICE_COOKIE_NAME}=;`), false);
  assert.equal(setCookie.includes("CF_Authorization"), false);
  assert.equal((await rememberedGrant(user.id, loginResult.deviceToken))?.rememberedUntil?.getTime(), grantBefore?.rememberedUntil?.getTime());
});

test("a valid remembered browser needs the password but skips email and TOTP without extending its absolute expiry", async () => {
  const user = await createUser("remembered-login@example.invalid", "TOTP");
  const first = await completeTotpRouteLogin(user.email);
  const grantBefore = await rememberedGrant(user.id, first.deviceToken);
  assert.notEqual(grantBefore, null);
  const emailCountBefore = await countEmailMessages();

  const rememberedResponse = await login(createLoginRequest(user.email, syntheticCredential, first.deviceToken));
  assert.equal(getLocation(rememberedResponse).pathname, "/");
  assert.equal(getLocation(rememberedResponse).search, "");
  assert.equal(await countEmailMessages(), emailCountBefore);
  const rememberedSession = getCookieValue(rememberedResponse, "bielos_session");
  assert.notEqual(await getSessionByToken(rememberedSession), null);
  assert.equal((await rememberedGrant(user.id, first.deviceToken))?.rememberedUntil?.getTime(), grantBefore?.rememberedUntil?.getTime());

  const invalidPassword = await login(createLoginRequest(user.email, "synthetic-wrong-password", first.deviceToken));
  assert.equal(getLocation(invalidPassword).pathname, "/login");
  assert.equal(getCookieValueOrNull(invalidPassword, "bielos_session"), null);
});

test("an expired known TOTP browser requires TOTP but not email, then rotates for a new absolute period", async () => {
  const user = await createUser("expired-totp@example.invalid", "TOTP");
  const first = await completeTotpRouteLogin(user.email);
  await prisma.trustedDevice.updateMany({
    where: { userId: user.id, deviceIdHash: hashDeviceToken(first.deviceToken) },
    data: { rememberedUntil: new Date(1), strongVerifiedAt: new Date(0) }
  });
  await prisma.totpFactor.update({ where: { userId: user.id }, data: { lastUsedStep: null } });
  const emailCountBefore = await countEmailMessages();

  const response = await login(createLoginRequest(user.email, syntheticCredential, first.deviceToken));
  assert.equal(getLocation(response).searchParams.get("factor"), "totp");
  assert.equal(await countEmailMessages(), emailCountBefore);

  const ceremony = getLocation(response).searchParams.get("ceremony") ?? "";
  const totpResponse = await verify(createVerifyRequest(ceremony, "totp", createTotpCode(syntheticTotpSecret, new Date())));
  assert.equal(getLocation(totpResponse).pathname, "/");
  const grant = await rememberedGrant(user.id, first.deviceToken);
  assert.equal(grant?.rememberedUntil !== null, true);
  assert.equal(grant?.strongVerifiedAt !== null, true);
  assert.equal(grant!.rememberedUntil!.getTime(), grant!.strongVerifiedAt!.getTime() + REMEMBERED_BROWSER_TTL_MS);
});

test("an expired known email-factor browser requires email verification", async () => {
  const user = await createUser("expired-email@example.invalid", "EMAIL");
  const first = await completeEmailRouteLogin(user.email);
  await prisma.trustedDevice.updateMany({
    where: { userId: user.id, deviceIdHash: hashDeviceToken(first.deviceToken) },
    data: { rememberedUntil: new Date(1), strongVerifiedAt: new Date(0) }
  });
  const response = await login(createLoginRequest(user.email, syntheticCredential, first.deviceToken));

  assert.equal(getLocation(response).searchParams.get("factor"), "email");
  const emailResponse = await verify(createVerifyRequest(
    getLocation(response).searchParams.get("ceremony") ?? "",
    "email",
    await latestEmailCode("EMAIL_TWO_FACTOR")
  ));
  assert.equal(getLocation(emailResponse).pathname, "/");
});

test("unknown, malformed, cross-user, and revoked device credentials use the new-device flow", async () => {
  const user = await createUser("device-fallback@example.invalid", "EMAIL");
  const unknown = await login(createLoginRequest(user.email, syntheticCredential, createDeviceToken()));
  assert.equal(getLocation(unknown).searchParams.get("factor"), "email");

  const malformed = await login(createLoginRequest(user.email, syntheticCredential, "malformed cookie"));
  assert.equal(getLocation(malformed).searchParams.get("factor"), "email");
  assert.notEqual(getCookieValueOrNull(malformed, DEVICE_COOKIE_NAME), null);

  const other = await createUser("other-device@example.invalid", "EMAIL");
  const otherToken = createDeviceToken();
  await createTrustedDevice(other.id, otherToken, new Date("2026-08-12T12:00:00.000Z"));
  const crossUser = await login(createLoginRequest(user.email, syntheticCredential, otherToken));
  assert.equal(getLocation(crossUser).searchParams.get("factor"), "email");

  const ownDevice = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));
  await revokeTrustedDevice(user.id, ownDevice.deviceKey);
  const revoked = await login(createLoginRequest(user.email, syntheticCredential, ownDevice.deviceToken));
  assert.equal(getLocation(revoked).searchParams.get("factor"), "email");
});

test("device revocation invalidates the grant and pending ceremony atomically", async () => {
  const user = await createUser("revoke-device@example.invalid", "EMAIL");
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));
  await prisma.deviceChallenge.create({
    data: {
      userId: user.id,
      ceremonyId: createDeviceToken(),
      deviceIdHash: hashDeviceToken(device.deviceToken),
      codeHash: "synthetic-code-hash",
      expiresAt: new Date("2026-08-06T12:00:00.000Z")
    }
  });

  await revokeTrustedDevice(user.id, device.deviceKey);
  const row = await prisma.trustedDevice.findUnique({ where: { deviceKey: device.deviceKey }, select: { status: true, rememberedUntil: true, strongVerifiedAt: true } });
  const challenge = await prisma.deviceChallenge.findFirst({ where: { userId: user.id }, select: { status: true } });
  assert.equal(row?.status, "REVOKED");
  assert.equal(row?.rememberedUntil, null);
  assert.equal(row?.strongVerifiedAt, null);
  assert.equal(challenge?.status, "REVOKED");
});

test("password recovery clears remembered grants, sessions, and in-flight ceremonies", async () => {
  const user = await createUser("recovery-invalidates@example.invalid", "EMAIL");
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));
  const token = "recovery-session-token";
  await prisma.session.create({ data: { userId: user.id, tokenHash: hashSessionToken(token), expiresAt: new Date("2026-08-12T12:00:00.000Z") } });
  const requestKey = createDeviceToken();
  await prisma.accountRecoveryRequest.create({
    data: {
      requestKey,
      userId: user.id,
      emailChallengeHash: "synthetic-code-hash",
      status: "APPROVED",
      expiresAt: new Date("2026-08-12T12:00:00.000Z")
    }
  });
  await prisma.deviceChallenge.create({
    data: {
      userId: user.id,
      ceremonyId: createDeviceToken(),
      deviceIdHash: hashDeviceToken(device.deviceToken),
      codeHash: "synthetic-code-hash",
      expiresAt: new Date("2026-08-06T12:00:00.000Z")
    }
  });

  await consumeApprovedAccountRecovery(requestKey, await awaitHashPassword("replacement-password"), new Date("2026-08-05T12:00:00.000Z"));
  assert.equal((await rememberedGrant(user.id, device.deviceToken))?.rememberedUntil ?? null, null);
  assert.equal(await getSessionByToken(token), null);
  assert.equal((await prisma.deviceChallenge.findFirst({ where: { userId: user.id }, select: { status: true } }))?.status, "REVOKED");
});

test("TOTP enrollment, replacement, and disable invalidate remembered trust", async () => {
  const user = await createUser("totp-invalidation@example.invalid", "TOTP");
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));

  const setup = await startTotpEnrollment(user.id, user.email);
  assert.equal((await rememberedGrant(user.id, device.deviceToken))?.rememberedUntil ?? null, null);
  const setupNow = new Date("2026-08-05T12:00:00.000Z");
  await confirmTotpEnrollment(user.id, createTotpCode(setup.secret, setupNow), setupNow);
  await createRememberedGrant(user.id, device.deviceToken, setupNow);
  await disableTotp(user.id);
  assert.equal((await rememberedGrant(user.id, device.deviceToken))?.rememberedUntil ?? null, null);
});

test("account deactivation and the exported account-state hook fail closed", async () => {
  const user = await createUser("account-state@example.invalid", "EMAIL");
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));
  await prisma.user.update({ where: { id: user.id }, data: { isActive: false, accountStatus: "BLOCKED" } });
  await invalidateRememberedLoginGrantsForUser(user.id);

  assert.equal((await rememberedGrant(user.id, device.deviceToken))?.rememberedUntil ?? null, null);
  await assert.rejects(startLoginCeremony(user.id, device.deviceToken, "pt-BR", new Date("2026-08-05T12:00:00.000Z")));
});

test("confirmed revoke-all sessions invalidates remembered trust but single-session logout does not", async () => {
  const user = await createUser("revoke-all@example.invalid", "EMAIL");
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date("2026-08-12T12:00:00.000Z"));
  const now = new Date("2026-08-05T12:00:00.000Z");
  const current = await createSessionRow(user.id, "current-session", now);
  const other = await createSessionRow(user.id, "other-session", now);

  const revokeResult = await revokeAllOtherCoreSessionRecords({ id: user.id }, current.id, true, now);
  assert.equal(revokeResult.revokedCount, 1);
  assert.equal((await rememberedGrant(user.id, device.deviceToken))?.rememberedUntil ?? null, null);
  assert.equal((await prisma.session.findUnique({ where: { id: other.id }, select: { revokedAt: true } }))?.revokedAt?.getTime(), now.getTime());
  assert.equal((await prisma.session.findUnique({ where: { id: current.id }, select: { revokedAt: true } }))?.revokedAt, null);
});

test("remembered login never creates or satisfies administrative elevation", async () => {
  const user = await createUser("admin-boundary@example.invalid", "EMAIL", "OWNER");
  const now = currentTestNow();
  const device = await createTrustedDevice(user.id, createDeviceToken(), new Date(now.getTime() + REMEMBERED_BROWSER_TTL_MS));
  const start = await startLoginCeremony(user.id, device.deviceToken, "pt-BR", now);

  assert.equal(start.kind, "SESSION");
  assert.equal(await prisma.securityElevation.count({ where: { userId: user.id } }), 0);
  const session = start.kind === "SESSION" ? await getSessionByToken(start.session.token) : null;
  assert.notEqual(session, null);
  assert.equal(await hasActiveSecurityElevation(user.id, session!.id, "ACCOUNT_STATE_CHANGE"), false);
});

test("remembered login audits contain no raw bearer values or factors", async () => {
  const user = await createUser("audit-boundary@example.invalid", "EMAIL");
  const deviceToken = createDeviceToken();
  const now = currentTestNow();
  await createTrustedDevice(user.id, deviceToken, new Date(now.getTime() + REMEMBERED_BROWSER_TTL_MS));
  const response = await login(createLoginRequest(user.email, syntheticCredential, deviceToken));
  const sessionToken = getCookieValue(response, "bielos_session");
  const audits = await prisma.auditLog.findMany({ select: { eventType: true, message: true, metadata: true, actorEmailHash: true } });
  const serialized = JSON.stringify(audits);

  assert.equal(getLocation(response).pathname, "/");
  assert.notEqual(sessionToken, "");
  assert.equal(serialized.includes(deviceToken), false);
  assert.equal(serialized.includes(sessionToken), false);
  assert.equal(serialized.includes(syntheticCredential), false);
  assert.equal(serialized.includes(syntheticTotpSecret), false);
});

async function completeTotpRouteLogin(email: string) {
  const response = await login(createLoginRequest(email, syntheticCredential));
  const deviceToken = getCookieValue(response, DEVICE_COOKIE_NAME);
  assert.equal(getLocation(response).searchParams.get("factor"), "email");
  const emailResponse = await verify(createVerifyRequest(
    getLocation(response).searchParams.get("ceremony") ?? "",
    "email",
    await latestEmailCode("NEW_DEVICE_VERIFICATION")
  ));
  const totpResponse = await verify(createVerifyRequest(
    getLocation(emailResponse).searchParams.get("ceremony") ?? "",
    "totp",
    createTotpCode(syntheticTotpSecret, new Date())
  ));
  return { deviceToken, sessionToken: getCookieValue(totpResponse, "bielos_session") };
}

async function completeEmailRouteLogin(email: string) {
  const response = await login(createLoginRequest(email, syntheticCredential));
  const deviceToken = getCookieValue(response, DEVICE_COOKIE_NAME);
  const sessionResponse = await verify(createVerifyRequest(
    getLocation(response).searchParams.get("ceremony") ?? "",
    "email",
    await latestEmailCode("NEW_DEVICE_VERIFICATION")
  ));
  return { deviceToken, sessionToken: getCookieValue(sessionResponse, "bielos_session") };
}

function createLoginRequest(email: string, password: string, deviceToken?: string): Request {
  const formData = new FormData();
  formData.set("email", email);
  formData.set("password", password);
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());
  return new Request("https://hub.example.invalid/api/login", {
    method: "POST",
    body: formData,
    headers: {
      "user-agent": "bielos-synthetic-trusted-browser-test",
      ...(deviceToken ? { cookie: cookieHeader(DEVICE_COOKIE_NAME, deviceToken) } : {})
    }
  });
}

function createVerifyRequest(ceremony: string, factor: string, code: string): Request {
  const formData = new FormData();
  formData.set(CSRF_FORM_FIELD_NAME, createCsrfToken());
  formData.set("ceremony", ceremony);
  formData.set("factor", factor);
  formData.set("code", code);
  return new Request("https://hub.example.invalid/api/login/verify", {
    method: "POST",
    body: formData,
    headers: { "user-agent": "bielos-synthetic-trusted-browser-test" }
  });
}

async function createUser(email: string, factor: "EMAIL" | "TOTP", role: "OWNER" | "MEMBER" = "MEMBER") {
  const user = await prisma.user.create({
    data: {
      email,
      emailNormalized: email,
      passwordHash,
      role,
      isActive: true,
      accountStatus: "ACTIVE",
      emailVerifiedAt: new Date("2026-08-01T00:00:00.000Z"),
      secondFactorMethod: factor,
      ...(factor === "TOTP"
        ? { totpFactor: { create: { secretCiphertext: encryptTotpSecret(syntheticTotpSecret), keyVersion: 1, status: "ACTIVE" } } }
        : {})
    },
    select: { id: true, email: true }
  });
  return user;
}

async function createTrustedDevice(userId: string, deviceToken: string, rememberedUntil: Date) {
  const strongVerifiedAt = new Date(rememberedUntil.getTime() - REMEMBERED_BROWSER_TTL_MS);
  const device = await prisma.trustedDevice.create({
    data: {
      userId,
      deviceIdHash: hashDeviceToken(deviceToken),
      status: "TRUSTED",
      rememberedUntil,
      strongVerifiedAt,
      lastSeenAt: strongVerifiedAt
    },
    select: { deviceKey: true, deviceIdHash: true }
  });
  return { ...device, deviceToken };
}

async function createRememberedGrant(userId: string, deviceToken: string, now: Date) {
  await prisma.trustedDevice.update({
    where: { userId_deviceIdHash: { userId, deviceIdHash: hashDeviceToken(deviceToken) } },
    data: { rememberedUntil: new Date(now.getTime() + REMEMBERED_BROWSER_TTL_MS), strongVerifiedAt: now }
  });
}

async function createSessionRow(userId: string, token: string, now: Date) {
  return prisma.session.create({
    data: { userId, tokenHash: hashSessionToken(token), expiresAt: new Date(now.getTime() + 60 * 60 * 1000) },
    select: { id: true }
  });
}

async function rememberedGrant(userId: string, deviceToken: string) {
  return prisma.trustedDevice.findUnique({
    where: { userId_deviceIdHash: { userId, deviceIdHash: hashDeviceToken(deviceToken) } },
    select: { rememberedUntil: true, strongVerifiedAt: true }
  });
}

async function latestEmailCode(kind: "NEW_DEVICE_VERIFICATION" | "EMAIL_TWO_FACTOR"): Promise<string> {
  const message = await prisma.emailOutboxMessage.findFirst({ where: { kind }, orderBy: { createdAt: "desc" }, select: { payload: true } });
  assert.notEqual(message, null);
  const payload = decryptEmailPayload(message!.payload);
  assert.equal(typeof payload.code, "string");
  return payload.code;
}

async function countEmailMessages(): Promise<number> {
  return prisma.emailOutboxMessage.count({ where: { kind: { in: ["NEW_DEVICE_VERIFICATION", "EMAIL_TWO_FACTOR"] } } });
}

function asCeremony(start: Awaited<ReturnType<typeof startLoginCeremony>>) {
  if (start.kind !== "CEREMONY") throw new Error("Expected security ceremony.");
  return start;
}

function createDeviceToken(): string {
  return randomBytes(32).toString("base64url");
}

function createTotpCode(secret: string, now: Date): string {
  const step = Math.floor(now.getTime() / 1000 / 30);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const decoded: number[] = [];
  for (const character of secret) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      decoded.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  const digest = createHmac("sha1", Buffer.from(decoded)).update(Buffer.from(step.toString(16).padStart(16, "0"), "hex")).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

function getLocation(response: Response): URL {
  return new URL(response.headers.get("location") ?? "https://invalid.example/");
}

function getCookieValue(response: Response, name: string): string {
  const value = getCookieValueOrNull(response, name);
  assert.notEqual(value, null);
  return value!;
}

function getCookieValueOrNull(response: Response, name: string): string | null {
  const setCookie = response.headers.get("set-cookie") ?? "";
  const match = setCookie.match(new RegExp(`${name}=([^;]+)`));
  return match?.[1] ?? null;
}

function cookieHeader(name: string, value: string): string {
  return `${name}=${value}`;
}

async function awaitHashPassword(value: string): Promise<string> {
  return hashPassword(value);
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}
