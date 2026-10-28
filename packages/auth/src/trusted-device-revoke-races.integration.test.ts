import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import {
  createTotpSecret,
  hashDeviceToken,
  LoginCeremonyStartError,
  revokeTrustedDevice,
  SecurityMutationError,
  startLoginCeremony,
  verifyLoginTotpCode
} from "./security";

after(() => prisma.$disconnect());

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
  throw new Error(`Timed out waiting for the action query to block on ${queryFragment}.`);
}

async function completesBeforeRelease(promise: Promise<unknown>, milliseconds = 5_000): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then(() => true, () => true),
      new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), milliseconds); })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

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

function totpAt(secret: string, when: Date): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(when.getTime() / 1_000 / 30)));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = ((digest[offset]! & 0x7f) << 24) | (digest[offset + 1]! << 16) | (digest[offset + 2]! << 8) | digest[offset + 3]!;
  return String(binary % 1_000_000).padStart(6, "0");
}

test("trusted-device revoke commits while login start waits on the User row", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "issue65-revoke-start-race" });
  const deviceToken = randomBytes(32).toString("base64url");
  const device = await prisma.trustedDevice.create({ data: { userId: user.id, deviceIdHash: hashDeviceToken(deviceToken) }, select: { deviceKey: true } });
  const now = new Date();
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    // NO KEY UPDATE still blocks the login path's FOR UPDATE revalidation, but
    // permits the revocation audit's FK key-share check to commit independently.
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR NO KEY UPDATE`;
    locked();
    await gate;
  }, { timeout: 15_000 });
  await ready;

  const starting = startLoginCeremony(user.id, deviceToken, "pt-BR", now, true, "USER")
    .then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error }));
  let revoking: Promise<{ ok: true } | { ok: false; error: unknown }> | undefined;
  let observedStartWait: boolean;
  let revokedBeforeRelease: boolean;
  try {
    await waitForBlockedPostgresQuery(blockerPid, "FOR UPDATE");
    observedStartWait = true;
    revoking = revokeTrustedDevice(user.id, device.deviceKey)
      .then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    revokedBeforeRelease = await completesBeforeRelease(revoking);
  } finally {
    release();
  }
  await blocker;
  const startOutcome = await starting;
  const revokeOutcome = revoking ? await revoking : null;

  assert.equal(observedStartWait, true, "login start was confirmed waiting on the held User row");
  assert.equal(revokedBeforeRelease, true, "device revocation must commit before the User row lock is released");
  assert.equal(revokeOutcome?.ok, true, "trusted-device revoke completed successfully");
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { deviceKey: device.deviceKey }, select: { status: true } })).status, "REVOKED");
  assert.equal(await prisma.deviceChallenge.count({ where: { userId: user.id, deviceIdHash: hashDeviceToken(deviceToken), status: { in: ["PENDING", "VERIFIED"] }, consumedAt: null } }), 0,
    "no live challenge remains on the revoked cookie");
  const loginStartFailure = startOutcome.ok
    ? null
    : startOutcome.error instanceof LoginCeremonyStartError
      ? startOutcome.error.stage
      : startOutcome.error instanceof Error
        ? startOutcome.error.name
        : typeof startOutcome.error;
  if (!startOutcome.ok) assert.fail(`login start completes after the account lock is released; failure=${loginStartFailure ?? "none"}`);
  assert.equal(startOutcome.value.kind, "CEREMONY");
  assert.notEqual(startOutcome.value.deviceToken, deviceToken, "the revoked cookie is replaced");
});

test("trusted-device revoke commits while TOTP verification waits on the User row", integrationOptions, async () => {
  const secret = createTotpSecret();
  const user = await createTestUser({ totpSecret: secret, label: "issue65-revoke-totp-race" });
  const deviceToken = randomBytes(32).toString("base64url");
  const device = await prisma.trustedDevice.create({ data: { userId: user.id, deviceIdHash: hashDeviceToken(deviceToken) }, select: { deviceKey: true } });
  const now = new Date();
  const start = await startLoginCeremony(user.id, deviceToken, "pt-BR", now, true, "USER");
  assert.equal(start.kind, "CEREMONY");
  const ceremony = start as Extract<typeof start, { kind: "CEREMONY" }>;
  const sessionsBefore = await prisma.session.count({ where: { userId: user.id } });
  let blockerPid = 0;
  let locked!: () => void;
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const blocker = prisma.$transaction(async (transaction) => {
    [{ pid: blockerPid }] = await transaction.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid() AS pid`;
    // NO KEY UPDATE blocks verification's FOR UPDATE account check while allowing
    // the revocation audit's FK key-share check to complete before verification resumes.
    await transaction.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${user.id} FOR NO KEY UPDATE`;
    locked();
    await gate;
  }, { timeout: 15_000 });
  await ready;

  const verification = verifyLoginTotpCode(ceremony.ceremonyId, totpAt(secret, now), deviceToken, now, "USER")
    .then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error }));
  let revoking: Promise<{ ok: true } | { ok: false; error: unknown }> | undefined;
  let observedVerifierWait: boolean;
  let revokedBeforeRelease: boolean;
  try {
    await waitForBlockedPostgresQuery(blockerPid, "FOR UPDATE");
    observedVerifierWait = true;
    revoking = revokeTrustedDevice(user.id, device.deviceKey)
      .then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    revokedBeforeRelease = await completesBeforeRelease(revoking);
  } finally {
    release();
  }
  await blocker;
  const verificationOutcome = await verification;
  const revokeOutcome = revoking ? await revoking : null;

  assert.equal(observedVerifierWait, true, "TOTP verification was confirmed waiting on the held User row");
  assert.equal(revokedBeforeRelease, true, "device revocation must commit before the User row lock is released");
  assert.equal(revokeOutcome?.ok, true, "trusted-device revoke completed successfully");
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { deviceKey: device.deviceKey }, select: { status: true } })).status, "REVOKED");
  const finalChallenge = await prisma.deviceChallenge.findUniqueOrThrow({ where: { ceremonyId: ceremony.ceremonyId }, select: { status: true, consumedAt: true } });
  assert.equal(finalChallenge.status, "REVOKED");
  assert.equal(verificationOutcome.ok, false, "TOTP proof loses after revoke commits while it waits");
  if (!verificationOutcome.ok) assert.ok(verificationOutcome.error instanceof SecurityMutationError);
  assert.equal(finalChallenge.consumedAt, null);
  assert.equal(await prisma.session.count({ where: { userId: user.id } }), sessionsBefore);
  assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id }, select: { lastUsedStep: true } })).lastUsedStep, null);
});
