import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { prisma } from "@virki/database";
import {
  createTotpSecret,
  canApproveAccountRecovery,
  consumeApprovedAccountRecovery,
  decryptTotpSecret,
  encryptTotpSecret,
  getLoginCeremonyFailureStage,
  getApprovedAccountRecoveryExpiry,
  getPendingAccountRecoveryQueueWhere,
  hashDeviceToken,
  hashEmailAddress,
  hashRecoveryCode,
  hashSecurityCode,
  isAccountRecoveryEligible,
  isPublicAccountRecoveryEligible,
  isValidRecoveryCodeInput,
  getAccountSecurityState,
  listTrustedDevices,
  LoginCeremonyStartError,
  SecurityMutationError,
  lockActiveLoginAccountInTransaction,
  lockActiveRecoveryAccountInTransaction,
  lockAndExpireSiblingAccountRecoveriesInTransaction,
  revokeUserAuthenticationProofsInTransaction,
  resolveLoginDeviceToken,
  verifySecurityCode,
  verifyLoginRecoveryCode,
  verifyTotpCode
} from "./security";

test("login ceremony diagnostics expose only fixed failure stages", () => {
  assert.equal(getLoginCeremonyFailureStage(new LoginCeremonyStartError("outbox-enqueue")), "outbox-enqueue");
  assert.equal(getLoginCeremonyFailureStage(new Error("private database detail")), undefined);
});

test("TOTP secrets are encrypted and never returned from ciphertext", () => {
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret, { NODE_ENV: "test" });
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, { NODE_ENV: "test" }), secret);
  assert.match(hashDeviceToken("opaque-device-token"), /^[a-f0-9]{64}$/);
});

test("TOTP ciphertexts reject shortened authentic GCM tags", () => {
  const env = { NODE_ENV: "test" };
  const parts = encryptTotpSecret(createTotpSecret(), env).split(":");
  parts[2] = Buffer.from(parts[2], "base64url").subarray(0, 4).toString("base64url");
  assert.throws(() => decryptTotpSecret(parts.join(":"), env));
});

test("login replaces an unknown caller-selected device token before it can be trusted", () => {
  const attackerToken = "A".repeat(48);
  const resolved = resolveLoginDeviceToken(attackerToken, null);

  assert.equal(resolved.isTrusted, false);
  assert.notEqual(resolved.deviceToken, attackerToken);
  assert.match(resolved.deviceToken, /^[A-Za-z0-9_-]{32,100}$/u);
});

test("login replaces revoked or malformed device tokens and reuses only an active trusted device", () => {
  const knownToken = "T".repeat(48);
  const revoked = resolveLoginDeviceToken(knownToken, { status: "TRUSTED", revokedAt: new Date() });
  const malformed = resolveLoginDeviceToken("bad", { status: "TRUSTED", revokedAt: null });
  const trusted = resolveLoginDeviceToken(knownToken, { status: "TRUSTED", revokedAt: null });

  assert.equal(revoked.isTrusted, false);
  assert.notEqual(revoked.deviceToken, knownToken);
  assert.equal(malformed.isTrusted, false);
  assert.notEqual(malformed.deviceToken, "bad");
  assert.deepEqual(trusted, { deviceToken: knownToken, isTrusted: true });
});

test("TOTP confirmation accepts the RFC vector and rejects same-window replay", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const now = new Date(0);
  assert.equal(verifyTotpCode(secret, "282760", now, null), 0);
  assert.equal(verifyTotpCode(`${secret}====`, "282760", now, null), 0);
  assert.equal(verifyTotpCode(secret, "282760", now, 0), null);
  assert.equal(verifyTotpCode(secret, "000000", now, null), null);
});

test("short security codes accept only the keyed versioned digest while recovery codes stay normalized", () => {
  const env = { NODE_ENV: "test" };
  const stored = hashSecurityCode("123456", env);
  assert.match(stored, /^h2:[a-f0-9]{64}$/u);
  assert.equal(verifySecurityCode("123456", stored, env), true);
  assert.equal(verifySecurityCode("654321", stored, env), false);
  // Unkeyed legacy SHA-256 code hashes are no longer accepted.
  assert.equal(verifySecurityCode("123456", "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", env), false);
  assert.equal(hashRecoveryCode("ab-cd"), hashRecoveryCode("AB CD"));
});

test("recovery-code format is checked before starting the email-proof step", () => {
  assert.equal(isValidRecoveryCodeInput("A1B2C3D4E5F6071829"), true);
  assert.equal(isValidRecoveryCodeInput("A1B2-C3D4-E5F6-0718-29"), true);
  assert.equal(isValidRecoveryCodeInput("A1B2C3D4E5F60718"), false);
  assert.equal(isValidRecoveryCodeInput("A1B2C3D4E5F60718XZ"), false);
});

test("login recovery rejects malformed input before email proof and counts it after email proof", async (context) => {
  const userId = "user-recovery-123";
  const ceremonyId = "ceremony-recovery-123456789";
  const deviceToken = "D".repeat(48);
  const email = "recovery-user@example.test";
  const emailNormalized = email.toLowerCase();
  const now = new Date("2026-10-19T12:00:00.000Z");
  const challenge = {
    id: "challenge-recovery-1",
    userId,
    deviceIdHash: hashDeviceToken(deviceToken),
    emailAddressHash: hashEmailAddress(emailNormalized),
    emailVerifiedAt: null as Date | null,
    requiresTotp: true,
    status: "VERIFIED",
    expiresAt: new Date(now.getTime() + 60_000),
    consumedAt: null,
    user: {
      email,
      emailNormalized,
      displayName: "Recovery user",
      role: "USER",
      isActive: true,
      accountStatus: "ACTIVE",
      secondFactorMethod: "TOTP",
      totpFactor: { id: "factor-recovery-1", status: "ACTIVE", lastUsedStep: null }
    }
  };
  const rateLimits = new Map<string, { attempts: number; windowStartedAt: Date; blockedUntil: Date | null; expiresAt: Date }>();
  let challengeUpdates = 0;
  let emailsQueued = 0;
  let recoveryLookups = 0;
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray) => strings.join("").includes('FROM "User"') ? [{ id: userId }] : [],
    deviceChallenge: {
      findUnique: async () => challenge,
      updateMany: async () => { challengeUpdates += 1; return { count: 1 }; }
    },
    loginRateLimit: {
      findUnique: async ({ where }: { where: { identifierHash: string } }) => rateLimits.get(where.identifierHash) ?? null,
      create: async ({ data }: { data: { identifierHash: string; attempts: number; windowStartedAt: Date; blockedUntil: Date | null; expiresAt: Date } }) => {
        const row = { ...data };
        rateLimits.set(data.identifierHash, row);
        return row;
      },
      update: async ({ where, data }: { where: { identifierHash: string }; data: Partial<{ attempts: number; windowStartedAt: Date; blockedUntil: Date | null; expiresAt: Date }> }) => {
        const row = rateLimits.get(where.identifierHash)!;
        Object.assign(row, data);
        return row;
      }
    },
    emailOutboxMessage: { upsert: async () => { emailsQueued += 1; return { id: "email-1" }; } },
    recoveryCode: { findFirst: async () => { recoveryLookups += 1; return null; } }
  };
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalTransaction);
  Object.defineProperty(prisma, "$transaction", {
    ...originalTransaction,
    value: async (operation: (value: never) => Promise<unknown>) => operation(transaction as never)
  });
  context.after(() => Object.defineProperty(prisma, "$transaction", originalTransaction));

  await assert.rejects(verifyLoginRecoveryCode(ceremonyId, "anything", deviceToken, now), SecurityMutationError);
  assert.equal(challengeUpdates, 0);
  assert.equal(emailsQueued, 0);
  assert.equal(rateLimits.size, 0);

  challenge.emailVerifiedAt = now;
  await assert.rejects(verifyLoginRecoveryCode(ceremonyId, "anything", deviceToken, now), SecurityMutationError);
  assert.equal(challengeUpdates, 0);
  assert.equal(emailsQueued, 0);
  assert.equal(rateLimits.size, 2);
  assert.deepEqual([...rateLimits.values()].map(({ attempts }) => attempts), [1, 1]);
  assert.equal(recoveryLookups, 0);
});

test("security counts exclude used recovery codes and devices beyond the trust lifetime", async () => {
  const now = new Date("2026-10-19T12:00:00.000Z");
  const userFindUnique = prisma.user.findUnique;
  const deviceFindMany = prisma.trustedDevice.findMany;
  let userQuery: unknown;
  let deviceQuery: unknown;
  prisma.user.findUnique = (async (args: unknown) => {
    userQuery = args;
    return { secondFactorMethod: "TOTP", emailVerifiedAt: now, totpFactor: { status: "ACTIVE", confirmedAt: now }, _count: { recoveryCodes: 4, trustedDevices: 2 } };
  }) as unknown as typeof userFindUnique;
  prisma.trustedDevice.findMany = (async (args: unknown) => {
    deviceQuery = args;
    return [];
  }) as typeof deviceFindMany;
  try {
    await getAccountSecurityState("user-1", now);
    await listTrustedDevices("user-1", now);
    const userSelect = (userQuery as { select: { _count: { select: Record<string, unknown> } } }).select;
    assert.deepEqual(userSelect._count.select.recoveryCodes, { where: { usedAt: null } });
    assert.deepEqual(userSelect._count.select.trustedDevices, {
      where: { status: "TRUSTED", revokedAt: null, createdAt: { gt: new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000) } }
    });
    assert.deepEqual((deviceQuery as { where: unknown }).where, {
      userId: "user-1",
      status: "TRUSTED",
      revokedAt: null,
      createdAt: { gt: new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000) }
    });
  } finally {
    prisma.user.findUnique = userFindUnique;
    prisma.trustedDevice.findMany = deviceFindMany;
  }
});

test("administrator recovery queue excludes requests at or past expiry", () => {
  const now = new Date("2026-10-02T12:00:00.000Z");

  assert.deepEqual(getPendingAccountRecoveryQueueWhere(now), {
    status: "PENDING",
    emailVerifiedAt: { not: null },
    expiresAt: { gt: now },
    user: { role: { in: ["USER", "ADMIN"] }, isActive: true, accountStatus: "ACTIVE" }
  });
  assert.deepEqual(getPendingAccountRecoveryQueueWhere(now, "admin-1"), {
    status: "PENDING",
    emailVerifiedAt: { not: null },
    expiresAt: { gt: now },
    user: { role: { in: ["USER", "ADMIN"] }, isActive: true, accountStatus: "ACTIVE", id: { not: "admin-1" } }
  });
});

test("recovery role policy isolates portal requests and requires a different active Admin to approve", () => {
  const activeUser = { id: "user-1", role: "USER", isActive: true, accountStatus: "ACTIVE" };
  const activeAdmin = { id: "admin-1", role: "ADMIN", isActive: true, accountStatus: "ACTIVE" };
  const reviewer = { id: "admin-2", role: "ADMIN" };

  assert.equal(isPublicAccountRecoveryEligible(activeUser), true);
  assert.equal(isPublicAccountRecoveryEligible(activeAdmin), false);
  assert.equal(isAccountRecoveryEligible(activeAdmin, "ADMIN"), true);
  assert.equal(isAccountRecoveryEligible(activeUser, "ADMIN"), false);
  assert.equal(isPublicAccountRecoveryEligible({ ...activeUser, isActive: false }), false);
  assert.equal(isPublicAccountRecoveryEligible({ ...activeUser, accountStatus: "SUSPENDED" }), false);
  assert.equal(canApproveAccountRecovery(reviewer, activeUser), true);
  assert.equal(canApproveAccountRecovery(reviewer, activeAdmin), true);
  assert.equal(canApproveAccountRecovery({ id: activeUser.id, role: "ADMIN" }, activeUser), false);
  assert.equal(canApproveAccountRecovery({ id: activeAdmin.id, role: "ADMIN" }, activeAdmin), false);
  assert.equal(canApproveAccountRecovery(reviewer, { ...activeAdmin, isActive: false }), false);
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
  assert.match(query, /"role" = \?::"UserRole"[\s\S]*"isActive" = TRUE[\s\S]*"accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE/u);
  assert.deepEqual(values, ["user-a", "USER"]);
  values = [];
  await lockActiveRecoveryAccountInTransaction(transaction, "admin-a", "ADMIN");
  assert.deepEqual(values, ["admin-a", "ADMIN"]);
});

test("approved password recovery changes the password and revokes access while preserving TOTP and recovery codes", async (context) => {
  type MutationArgs = { data?: Record<string, unknown> };
  const userId = "user-recovery-1";
  const requestId = "recovery-request-1";
  const requestKey = "R".repeat(32);
  const email = "recovery-user@example.test";
  const emailNormalized = email.toLowerCase();
  const now = new Date("2026-10-05T12:00:00.000Z");
  const totpFactor = { id: "totp-factor-1", userId, status: "ACTIVE", secretCiphertext: "encrypted-test-factor", keyVersion: 1, lastUsedStep: 123 };
  const recoveryCodes = [
    { id: "recovery-code-1", userId, codeHash: "recovery-hash-1", usedAt: null },
    { id: "recovery-code-2", userId, codeHash: "recovery-hash-2", usedAt: null }
  ];
  const user = {
    email,
    emailNormalized,
    displayName: "Recovery user",
    role: "USER",
    isActive: true,
    accountStatus: "ACTIVE",
    secondFactorMethod: "TOTP",
    totpFactor,
    recoveryCodes
  };
  const request = {
    id: requestId,
    requestKeyHash: createHash("sha256").update(requestKey, "utf8").digest("hex"),
    userId,
    emailAddressHash: createHash("sha256").update(emailNormalized, "utf8").digest("hex"),
    status: "APPROVED",
    expiresAt: new Date(now.getTime() + 60_000),
    user
  };
  const mfaOperations: string[] = [];
  const revocations = { sessions: 0, elevations: 0, devices: 0, challenges: 0, oidcArtifacts: 0 };
  let oidcAccountIdHash: unknown;
  let requestStatus = "APPROVED";
  let passwordHash = "old-password-hash";
  let userUpdateData: Record<string, unknown> | undefined;
  let auditEvent = "";

  const transaction = {
    $queryRaw: async (query: TemplateStringsArray) => query.join("").includes('FROM "User"') ? [{ id: userId }] : [],
    loginRateLimit: {
      findUnique: async () => null,
      create: async () => ({})
    },
    accountRecoveryRequest: {
      findUnique: async () => ({ ...request, status: requestStatus }),
      updateMany: async ({ data }: MutationArgs) => {
        if (data?.status === "CONSUMED") requestStatus = "CONSUMED";
        return { count: 1 };
      }
    },
    user: {
      update: async ({ data }: MutationArgs) => {
        userUpdateData = data;
        passwordHash = String(data?.passwordHash ?? "");
        return { id: userId };
      }
    },
    emailOutboxMessage: { upsert: async () => ({ id: "outbox-message-1" }) },
    session: {
      updateMany: async () => { revocations.sessions += 1; return { count: 1 }; }
    },
    securityElevation: {
      updateMany: async () => { revocations.elevations += 1; return { count: 1 }; }
    },
    trustedDevice: {
      updateMany: async () => { revocations.devices += 1; return { count: 1 }; }
    },
    deviceChallenge: {
      updateMany: async () => { revocations.challenges += 1; return { count: 1 }; }
    },
    oidcArtifact: {
      deleteMany: async ({ where }: { where: { accountIdHash?: unknown } }) => { revocations.oidcArtifacts += 1; oidcAccountIdHash = where.accountIdHash; return { count: 2 }; }
    },
    totpFactor: {
      updateMany: async () => { mfaOperations.push("totp-update"); return { count: 1 }; },
      deleteMany: async () => { mfaOperations.push("totp-delete"); return { count: 1 }; }
    },
    recoveryCode: {
      updateMany: async () => { mfaOperations.push("recovery-code-update"); return { count: 1 }; },
      deleteMany: async () => { mfaOperations.push("recovery-code-delete"); return { count: 1 }; }
    },
    auditLog: {
      create: async ({ data }: MutationArgs) => {
        auditEvent = String(data?.eventType ?? "");
        return { id: "audit-entry-1" };
      }
    }
  };

  const recoveryRequestDelegate = prisma.accountRecoveryRequest;
  const originalFindUnique = Object.getOwnPropertyDescriptor(recoveryRequestDelegate, "findUnique");
  const originalTransaction = Object.getOwnPropertyDescriptor(prisma, "$transaction");
  assert.ok(originalFindUnique && originalTransaction);
  Object.defineProperty(recoveryRequestDelegate, "findUnique", { ...originalFindUnique, value: async () => request });
  Object.defineProperty(prisma, "$transaction", {
    ...originalTransaction,
    value: async (operation: (value: never) => Promise<unknown>) => operation(transaction as never)
  });
  context.after(() => {
    Object.defineProperty(recoveryRequestDelegate, "findUnique", originalFindUnique);
    Object.defineProperty(prisma, "$transaction", originalTransaction);
  });

  await consumeApprovedAccountRecovery(requestId, requestKey, "new password for recovery", now);

  assert.equal(requestStatus, "CONSUMED");
  assert.notEqual(passwordHash, "old-password-hash");
  assert.deepEqual(Object.keys(userUpdateData ?? {}).sort(), ["emailVerifiedAt", "passwordHash"]);
  assert.equal(userUpdateData?.emailVerifiedAt, now);
  assert.deepEqual(revocations, { sessions: 1, elevations: 1, devices: 1, challenges: 1, oidcArtifacts: 1 });
  assert.equal(oidcAccountIdHash, createHash("sha256").update(userId, "utf8").digest("hex"));
  assert.deepEqual(mfaOperations, []);
  assert.equal(totpFactor.status, "ACTIVE");
  assert.equal(user.secondFactorMethod, "TOTP");
  assert.deepEqual(recoveryCodes, [
    { id: "recovery-code-1", userId, codeHash: "recovery-hash-1", usedAt: null },
    { id: "recovery-code-2", userId, codeHash: "recovery-hash-2", usedAt: null }
  ]);
  assert.equal(auditEvent, "ACCOUNT_RECOVERY_CONSUMED");
});

test("login verification locks the account under the role allowed by its current surface", async () => {
  let query = "";
  let values: unknown[] = [];
  const transaction = {
    $queryRaw: async (strings: TemplateStringsArray, ...parameters: unknown[]) => {
      query = strings.join("?");
      values = parameters;
      return [{ id: "admin-a" }];
    }
  } as never;

  assert.equal(await lockActiveLoginAccountInTransaction(transaction, "admin-a", "ADMIN"), true);
  assert.match(query, /"role" = \?::"UserRole"[\s\S]*"isActive" = TRUE[\s\S]*"accountStatus" = 'ACTIVE'[\s\S]*FOR UPDATE/u);
  assert.deepEqual(values, ["admin-a", "ADMIN"]);
  assert.equal(await lockActiveLoginAccountInTransaction(transaction, "user-a", "USER"), true);
  assert.deepEqual(values, ["user-a", "USER"]);
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
