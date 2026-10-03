import assert from "node:assert/strict";
import test from "node:test";
import {
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  getApprovedAccountRecoveryExpiry,
  getPendingAccountRecoveryQueueWhere,
  hashDeviceToken,
  hashRecoveryCode,
  hashSecurityCode,
  lockActiveRecoveryAccountInTransaction,
  lockAndExpireSiblingAccountRecoveriesInTransaction,
  revokeUserAuthenticationProofsInTransaction,
  verifySecurityCode,
  verifyTotpCode
} from "./security";

test("TOTP secrets are encrypted and never returned from ciphertext", () => {
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret, { NODE_ENV: "test" });
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, { NODE_ENV: "test" }), secret);
  assert.match(hashDeviceToken("opaque-device-token"), /^[a-f0-9]{64}$/);
});

test("TOTP confirmation accepts the RFC vector and rejects same-window replay", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const now = new Date(0);
  assert.equal(verifyTotpCode(secret, "282760", now, null), 0);
  assert.equal(verifyTotpCode(secret, "282760", now, 0), null);
  assert.equal(verifyTotpCode(secret, "000000", now, null), null);
});

test("short security codes use a keyed versioned digest while existing recovery codes remain compatible", () => {
  const env = { NODE_ENV: "test" };
  const stored = hashSecurityCode("123456", env);
  assert.match(stored, /^h2:[a-f0-9]{64}$/u);
  assert.equal(verifySecurityCode("123456", stored, env), true);
  assert.equal(verifySecurityCode("654321", stored, env), false);
  assert.equal(verifySecurityCode("123456", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", env), true);
  assert.equal(hashRecoveryCode("ab-cd"), hashRecoveryCode("AB CD"));
});

test("administrator recovery queue excludes requests at or past expiry", () => {
  const now = new Date("2026-10-02T12:00:00.000Z");

  assert.deepEqual(getPendingAccountRecoveryQueueWhere(now), {
    status: "PENDING",
    emailVerifiedAt: { not: null },
    expiresAt: { gt: now }
  });
});

test("approved account recovery gets a fresh completion window", () => {
  const approvedAt = new Date("2026-10-02T12:00:00.000Z");

  assert.equal(getApprovedAccountRecoveryExpiry(approvedAt).toISOString(), "2026-10-02T12:30:00.000Z");
});

test("recovery state transitions serialize on the active account row", async () => {
  let query = "";
  let values: unknown[] = [];
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray, ...parameters: unknown[]) => {
      query = strings.join("?");
      values = parameters;
      return [{ id: "user-a" }];
    }
  } as never;

  assert.equal(await lockActiveRecoveryAccountInTransaction(transaction, "user-a"), true);
  assert.match(query, /"isActive" = TRUE[\s\S]*"accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE/u);
  assert.deepEqual(values, ["user-a"]);
});

test("recovery completion locks per account and expires every pending or approved sibling", async () => {
  const operations: string[] = [];
  const requests = [
    { id: "current", userId: "user-a", status: "APPROVED" },
    { id: "pending", userId: "user-a", status: "PENDING" },
    { id: "approved", userId: "user-a", status: "APPROVED" },
    { id: "consumed", userId: "user-a", status: "CONSUMED" },
    { id: "other-user", userId: "user-b", status: "PENDING" }
  ];
  const transaction = {
    $queryRaw: async () => { operations.push("lock"); return []; },
    accountRecoveryRequest: {
      updateMany: async ({ where, data }: { where: { userId: string; id: { not: string }; status: { in: string[] } }; data: { status: string } }) => {
        operations.push("invalidate");
        let count = 0;
        for (const request of requests) {
          if (request.userId === where.userId && request.id !== where.id.not && where.status.in.includes(request.status)) {
            request.status = data.status;
            count += 1;
          }
        }
        return { count };
      }
    }
  } as never;

  await lockAndExpireSiblingAccountRecoveriesInTransaction(transaction, "user-a", "current");

  assert.deepEqual(operations, ["lock", "lock", "invalidate"]);
  assert.deepEqual(requests.map(({ id, status }) => [id, status]), [
    ["current", "APPROVED"],
    ["pending", "EXPIRED"],
    ["approved", "EXPIRED"],
    ["consumed", "CONSUMED"],
    ["other-user", "PENDING"]
  ]);
});

test("account deactivation revokes remembered devices and active login challenges", async () => {
  const now = new Date("2026-10-02T12:00:00.000Z");
  const devices = [
    { userId: "user-a", status: "TRUSTED", revokedAt: null as Date | null, rememberedUntil: new Date("2026-10-09T12:00:00.000Z") as Date | null, strongVerifiedAt: new Date("2026-10-02T11:00:00.000Z") as Date | null },
    { userId: "user-a", status: "REVOKED", revokedAt: now, rememberedUntil: null, strongVerifiedAt: null },
    { userId: "user-b", status: "TRUSTED", revokedAt: null, rememberedUntil: new Date("2026-10-09T12:00:00.000Z"), strongVerifiedAt: new Date("2026-10-02T11:00:00.000Z") }
  ];
  const challenges = [
    { userId: "user-a", status: "PENDING" },
    { userId: "user-a", status: "VERIFIED" },
    { userId: "user-a", status: "EXPIRED" },
    { userId: "user-b", status: "PENDING" }
  ];
  let expiredRecoveries: unknown;
  const transaction = {
    trustedDevice: {
      updateMany: async ({ where, data }: { where: { userId: string; status: string }; data: { status: string; revokedAt: Date; rememberedUntil: null; strongVerifiedAt: null } }) => {
        let count = 0;
        for (const device of devices) {
          if (device.userId === where.userId && device.status === where.status) {
            Object.assign(device, data);
            count += 1;
          }
        }
        return { count };
      }
    },
    deviceChallenge: {
      updateMany: async ({ where, data }: { where: { userId: string; status: { in: string[] } }; data: { status: string } }) => {
        for (const challenge of challenges) {
          if (challenge.userId === where.userId && where.status.in.includes(challenge.status)) challenge.status = data.status;
        }
        return { count: 0 };
      }
    },
    accountRecoveryRequest: {
      updateMany: async (args: unknown) => { expiredRecoveries = args; return { count: 2 }; }
    }
  } as never;

  await revokeUserAuthenticationProofsInTransaction(transaction, "user-a", now);

  assert.deepEqual(devices.map((device) => [device.status, device.revokedAt, device.rememberedUntil, device.strongVerifiedAt]), [
    ["REVOKED", now, null, null],
    ["REVOKED", now, null, null],
    ["TRUSTED", null, new Date("2026-10-09T12:00:00.000Z"), new Date("2026-10-02T11:00:00.000Z")]
  ]);
  assert.deepEqual(challenges.map(({ userId, status }) => [userId, status]), [
    ["user-a", "REVOKED"],
    ["user-a", "REVOKED"],
    ["user-a", "EXPIRED"],
    ["user-b", "PENDING"]
  ]);
  assert.deepEqual(expiredRecoveries, {
    where: { userId: "user-a", status: { in: ["PENDING", "APPROVED"] } },
    data: { status: "EXPIRED" }
  });
});
