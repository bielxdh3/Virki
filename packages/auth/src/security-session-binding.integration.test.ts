import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { after, test } from "node:test";
import { PrismaClient, prisma } from "@virki/database";
import { createTestUser, integrationOptions } from "./integration-fixtures";
import {
  confirmTotpEnrollment,
  disableTotp,
  hashDeviceToken,
  regenerateRecoveryCodes,
  revokeTrustedDevice,
  SecurityMutationError,
  startTotpEnrollment,
  type SecurityMutationSession
} from "./security";

after(() => prisma.$disconnect());

function totpAt(secret: string, at: Date): string {
  // Independently compute the RFC 6238 value, not via the production verifier.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let word = 0;
  const bytes: number[] = [];
  for (const letter of secret.replace(/=+$/u, "")) {
    const index = alphabet.indexOf(letter);
    assert.ok(index >= 0, "invalid fixture secret");
    word = (word << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((word >>> bits) & 0xff);
      word &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function actor(role: "USER" | "ADMIN") {
  const user = await createTestUser({ role, label: "bound-factor" });
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      tokenHash: randomBytes(32).toString("hex"),
      expiresAt: new Date(Date.now() + 10 * 60_000)
    },
    select: { id: true }
  });
  return { user, session: { id: session.id, role } satisfies SecurityMutationSession };
}

async function audits(userId: string, type: string) {
  return prisma.auditLog.count({ where: { actorUserId: userId, eventType: type, result: "SUCCESS" } });
}

for (const role of ["USER", "ADMIN"] as const) {
  test(`real PG: ${role} TOTP enrollment, confirm, recovery rotation and disable bind the initiating session`, integrationOptions, async () => {
    const { user, session } = await actor(role);
    const first = await startTotpEnrollment(user.id, user.email, session);
    assert.match(first.uri, /^otpauth:\/\/totp\//u);
    assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id } })).status, "PENDING");
    assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLMENT_STARTED"), 1);

    const now = new Date();
    const recovery = await confirmTotpEnrollment(user.id, totpAt(first.secret, now), now, session);
    assert.equal(recovery.length, 10);
    assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id } })).status, "ACTIVE");
    assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLED"), 1);

    // Future timestamps only advance the offline TOTP fixture, not PostgreSQL's
    // session clock. Both factors are still checked against a live DB session.
    const later = new Date(now.getTime() + 31_000);
    const replacement = await regenerateRecoveryCodes(user.id, totpAt(first.secret, later), later, session);
    assert.equal(replacement.length, 10);
    assert.equal(replacement.some((code) => recovery.includes(code)), false);
    assert.equal(await audits(user.id, "RECOVERY_CODES_REGENERATED"), 1);

    const final = new Date(now.getTime() + 62_000);
    await disableTotp(user.id, totpAt(first.secret, final), final, session);
    assert.equal((await prisma.totpFactor.findUniqueOrThrow({ where: { userId: user.id } })).status, "REVOKED");
    assert.equal((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).secondFactorMethod, "EMAIL");
    assert.equal(await prisma.recoveryCode.count({ where: { userId: user.id } }), 0);
    assert.notEqual((await prisma.session.findUniqueOrThrow({ where: { id: session.id } })).revokedAt, null);
    assert.equal(await audits(user.id, "SECOND_FACTOR_DISABLED"), 1);
    await assert.rejects(startTotpEnrollment(user.id, user.email, session), SecurityMutationError,
      "a session revoked by TOTP disable cannot enroll another factor");
    assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLMENT_STARTED"), 1);
  });

  test(`real PG: ${role} mismatched, expired, revoked and foreign sessions do not mutate TOTP or audit`, integrationOptions, async () => {
    const { user, session } = await actor(role);
    const opposite = role === "USER" ? "ADMIN" : "USER";
    await assert.rejects(
      startTotpEnrollment(user.id, user.email, { id: session.id, role: opposite }),
      SecurityMutationError, "a forged role must not authorize a factor mutation"
    );
    const foreign = await actor(role);
    await assert.rejects(
      startTotpEnrollment(user.id, user.email, foreign.session),
      SecurityMutationError, "a different user's valid session must not authorize this user"
    );
    await prisma.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    await assert.rejects(startTotpEnrollment(user.id, user.email, session), SecurityMutationError);
    await prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: null, expiresAt: new Date(Date.now() - 1_000) }
    });
    await assert.rejects(startTotpEnrollment(user.id, user.email, session), SecurityMutationError);
    assert.equal(await prisma.totpFactor.count({ where: { userId: user.id } }), 0);
    assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLMENT_STARTED"), 0);
  });
}

test("real PG: trusted device revoke is session/role scoped and commits one success audit", integrationOptions, async () => {
  const { user, session } = await actor("USER");
  const deviceKey = randomBytes(32).toString("base64url");
  const device = await prisma.trustedDevice.create({
    data: { userId: user.id, deviceKey, deviceIdHash: hashDeviceToken(randomBytes(32).toString("base64url")) }
  });
  await assert.rejects(
    revokeTrustedDevice(user.id, deviceKey, { ...session, role: "ADMIN" }),
    SecurityMutationError
  );
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).status, "TRUSTED");
  assert.equal(await audits(user.id, "TRUSTED_DEVICE_REVOKED"), 0);
  await revokeTrustedDevice(user.id, deviceKey, session);
  assert.equal((await prisma.trustedDevice.findUniqueOrThrow({ where: { id: device.id } })).status, "REVOKED");
  assert.equal(await audits(user.id, "TRUSTED_DEVICE_REVOKED"), 1);
});

test("real PG: TOTP enrollment rolls back factor and success audit when actor expires during an observed audit lock", integrationOptions, async () => {
  const migrationUrl = process.env.MIGRATION_DATABASE_URL;
  const runtimeUrl = process.env.VIRKI_INTEGRATION_DATABASE_URL;
  assert.ok(migrationUrl && runtimeUrl, "dedicated disposable PostgreSQL URLs are required");
  const migrator = new URL(migrationUrl);
  const runtime = new URL(runtimeUrl);
  assert.equal(migrator.hostname, "127.0.0.1");
  assert.equal(migrator.username, "virki_migrator");
  assert.equal(runtime.hostname, "127.0.0.1");
  assert.equal(runtime.username, "virki_runtime_test");
  assert.ok(["/virki_e2e_test", "/virki_integration_test"].includes(migrator.pathname),
    "the lock test must target a known disposable PostgreSQL fixture");
  assert.equal(runtime.pathname, migrator.pathname);
  assert.equal(runtime.port, migrator.port);

  const { user, session } = await actor("USER");
  const migrationDb = new PrismaClient({ datasources: { db: { url: migrationUrl } } });
  let release!: () => void;
  let locked!: () => void;
  let blockerPid = 0;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const ready = new Promise<void>((resolve) => { locked = resolve; });
  const holder = migrationDb.$transaction(async (tx) => {
    [{ pid: blockerPid }] = await tx.$queryRaw<Array<{ pid: number }>>`SELECT pg_backend_pid()::int AS pid`;
    // Only the isolated migrator can take this table-level lock. The real
    // runtime role cannot modify schema, and the runner owns both connections.
    await tx.$executeRawUnsafe('LOCK TABLE "AuditLog" IN ACCESS EXCLUSIVE MODE');
    locked();
    await gate;
  }, { timeout: 12_000 }).then(
    () => ({ ok: true as const, error: null }),
    (error: unknown) => ({ ok: false as const, error })
  );

  let outcome: Promise<{ ok: boolean; error: unknown }> | undefined;
  let observed = false;
  try {
    await Promise.race([
      ready,
      holder.then((result) => { throw result.error ?? Error("audit lock holder ended before readiness"); })
    ]);
    const expiresAt = new Date(Date.now() + 2_800);
    await prisma.session.update({ where: { id: session.id }, data: { expiresAt } });
    outcome = startTotpEnrollment(user.id, user.email, session).then(
      () => ({ ok: true, error: null }),
      (error: unknown) => ({ ok: false, error })
    );
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline) {
      const rows = await prisma.$queryRaw<Array<{ count: number }>>`
        SELECT count(*)::int AS count FROM pg_stat_activity
        WHERE wait_event_type = 'Lock'
          AND pg_blocking_pids(pid) @> ARRAY[${blockerPid}]::integer[]
          AND query LIKE '%INSERT%AuditLog%'
      `;
      if ((rows[0]?.count ?? 0) > 0) { observed = true; break; }
      await new Promise<void>((resolve) => setTimeout(resolve, 15));
    }
    assert.equal(observed, true, "the success audit INSERT must actually block in PostgreSQL");
    assert.ok(Date.now() < expiresAt.getTime(), "the actor must have been live when audit INSERT blocked");
    await new Promise<void>((resolve) => setTimeout(resolve, Math.max(0, expiresAt.getTime() - Date.now() + 120)));
    assert.ok(Date.now() >= expiresAt.getTime(), "expiry must occur while the audit write is blocked");
  } finally {
    release();
    await Promise.allSettled([holder, outcome]);
    await migrationDb.$disconnect();
  }
  assert.equal((await holder).ok, true);
  assert.equal((await outcome)?.ok, false);
  assert.ok((await outcome)?.error instanceof SecurityMutationError,
    "the final actor-session recheck, not a Prisma timeout, must fail the transaction");
  assert.equal(await prisma.totpFactor.count({ where: { userId: user.id } }), 0,
    "factor writes inside the failed transaction must roll back");
  assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLMENT_STARTED"), 0,
    "a failed transaction cannot persist a misleading success audit");

  await prisma.session.update({
    where: { id: session.id }, data: { expiresAt: new Date(Date.now() + 60_000) }
  });
  const live = await startTotpEnrollment(user.id, user.email, session);
  assert.match(live.uri, /^otpauth:\/\/totp\//u);
  assert.equal(await prisma.totpFactor.count({ where: { userId: user.id, status: "PENDING" } }), 1);
  assert.equal(await audits(user.id, "SECOND_FACTOR_ENROLLMENT_STARTED"), 1);
});
