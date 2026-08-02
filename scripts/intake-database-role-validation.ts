import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { createDatabaseIntakeRepository } from "../apps/intake/src/repository";
import { assertDisposableCoreTestDatabase } from "./core-test-database-safety.mjs";

const adminUrl = process.env.CORE_TEST_DATABASE_URL?.trim();
if (!adminUrl) {
  throw new Error("Intake database-role validation requires CORE_TEST_DATABASE_URL.");
}

assertDisposableCoreTestDatabase(adminUrl, {
  ...process.env,
  BIELOS_CORE_TEST_DATABASE_CONFIRM: "disposable"
});

const roleName = "bielos_intake_test";
const rolePassword = "intake-validation-only";
const admin = new PrismaClient({ datasources: { db: { url: adminUrl } } });
const restrictedUrl = new URL(adminUrl);
restrictedUrl.username = roleName;
restrictedUrl.password = rolePassword;
const restricted = new PrismaClient({
  datasources: { db: { url: restrictedUrl.toString() } }
});

async function main(): Promise<void> {
  try {
    await recreateRole();
    process.env.NODE_ENV = "test";

  const publicKey = `role-public-${Date.now()}`;
  const privateKey = `role-private-${Date.now()}`;
  await admin.moduleCatalog.create({
    data: {
      key: publicKey,
      name: "Role validation public module",
      visibility: "PUBLIC",
      requestable: true,
      runtimeAvailability: "AVAILABLE"
    }
  });
  await admin.moduleCatalog.create({
    data: {
      key: privateKey,
      name: "Role validation private module",
      visibility: "PRIVATE",
      requestable: true,
      runtimeAvailability: "AVAILABLE"
    }
  });

  for (const table of [
    "User",
    "Session",
    "Project",
    "ProjectAccess",
    "SecurityUnlock",
    "AuditLog",
    "AdministrativeCredential",
    "AdministrativeRecoveryCode",
    "SecurityElevation",
    "GymForgeParticipant",
    "GymForgeExercise",
    "GymForgeAttendance",
    "GymForgeWorkout",
    "GymForgeWorkoutSet",
    "GymForgeCompetition",
    "GymForgeCompetitionAssignment",
    "GymForgeCompetitionScoreCorrection",
    "ModuleCatalog"
  ]) {
    await expectDenied(`SELECT ${table}`, () =>
      restricted.$queryRawUnsafe(`SELECT 1 FROM "${table}" LIMIT 1`)
    );
  }

  for (const table of ["User", "Project", "AuditLog", "GymForgeParticipant"]) {
    await expectDenied(`UPDATE ${table}`, () =>
      restricted.$executeRawUnsafe(`UPDATE "${table}" SET "id" = "id"`)
    );
  }

  const repository = createDatabaseIntakeRepository(
    restricted as never,
    "https://public.example.invalid"
  );
  const publicModules = await repository.listPublicModules();
  assert.equal(publicModules.some((module) => module.key === publicKey), true);
  assert.equal(publicModules.some((module) => module.key === privateKey), false);

  const email = `role-validation-${Date.now()}@example.invalid`;
  await repository.submitApplication({
    emailNormalized: email,
    displayName: "Role validation",
    abuseIdentifierHash: createHash("sha256").update(email).digest("hex"),
    locale: "en",
    modules: [{ key: publicKey, reason: "Disposable role validation" }]
  });

  const application = await admin.accountApplication.findUniqueOrThrow({
    where: { emailNormalized: email },
    select: { id: true }
  });
  const publicModule = await admin.moduleCatalog.findUniqueOrThrow({
    where: { key: publicKey },
    select: { id: true }
  });
  await admin.applicationModuleDecision.updateMany({
    where: { applicationId: application.id, moduleId: publicModule.id },
    data: { status: "APPROVED" }
  });
  await admin.accountApplication.update({
    where: { id: application.id },
    data: { status: "APPROVED" }
  });

  const activationToken = `activation-${Date.now()}`;
  await admin.accountActivation.create({
    data: {
      applicationId: application.id,
      tokenHash: hashToken(activationToken),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      updatedAt: new Date()
    }
  });
  await repository.activateApplication(activationToken, "disposable-password-123");

  const activatedUser = await admin.user.findUniqueOrThrow({
    where: { emailNormalized: email },
    select: { id: true }
  });
    assert.equal(
      await admin.moduleAccessGrant.count({ where: { userId: activatedUser.id, moduleId: publicModule.id } }),
      1
    );
  } finally {
    await restricted.$disconnect();
    await admin.$executeRawUnsafe(`DROP ROLE IF EXISTS "${roleName}"`);
    await admin.$disconnect();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "Intake database-role validation failed.");
  process.exitCode = 1;
});

async function recreateRole(): Promise<void> {
  await admin.$executeRawUnsafe(`DROP ROLE IF EXISTS "${roleName}"`);
  await admin.$executeRawUnsafe(`CREATE ROLE "${roleName}" LOGIN PASSWORD '${rolePassword}'`);
  await admin.$executeRawUnsafe(`GRANT USAGE ON SCHEMA public TO "${roleName}"`);
  await admin.$executeRawUnsafe(
    `GRANT SELECT ON "IntakePublicModuleCatalog" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT SELECT ("id", "emailNormalized", "status") ON "AccountApplication" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT INSERT ("id", "emailNormalized", "displayName", "abuseIdentifierHash", "updatedAt") ON "AccountApplication" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT UPDATE ("status", "updatedAt") ON "AccountApplication" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT SELECT ("id", "applicationId", "moduleId", "createdAt") ON "ApplicationModuleDecision" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT INSERT ("id", "dedupeKey", "applicationId", "moduleId", "reason", "updatedAt") ON "ApplicationModuleDecision" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT SELECT ("id", "applicationId", "tokenHash", "expiresAt", "consumedAt") ON "ApplicationEmailVerification" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT INSERT ("id", "applicationId", "tokenHash", "expiresAt", "updatedAt") ON "ApplicationEmailVerification" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT UPDATE ("consumedAt", "updatedAt") ON "ApplicationEmailVerification" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT SELECT ("id", "idempotencyKey") ON "EmailOutboxMessage" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT INSERT ("id", "idempotencyKey", "kind", "recipientEmail", "locale", "payload", "availableAt", "updatedAt") ON "EmailOutboxMessage" TO "${roleName}"`
  );
  await admin.$executeRawUnsafe(
    `GRANT EXECUTE ON FUNCTION "bielos_intake_activate_application"(TEXT, TEXT, TEXT, TIMESTAMP(3)) TO "${roleName}"`
  );
}

async function expectDenied(label: string, action: () => Promise<unknown>): Promise<void> {
  try {
    await action();
  } catch {
    return;
  }
  throw new Error(`Restricted intake role unexpectedly allowed ${label}.`);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
