import assert from "node:assert/strict";

import { prisma } from "@bielos/database";

export async function assertCoreIntegrationTestDatabase(): Promise<void> {
  assert.equal(process.env.BIELOS_CORE_TEST_DATABASE_CONFIRM, "disposable");

  const rows = await prisma.$queryRaw<Array<{ databaseName: string }>>`
    SELECT current_database() AS "databaseName"
  `;

  assert.match(rows[0]?.databaseName ?? "", /test/i);
}

export async function cleanCoreIntegrationTestData(): Promise<void> {
  await assertCoreIntegrationTestDatabase();

  await prisma.$transaction([
    prisma.loginRateLimit.deleteMany(),
    prisma.auditLog.deleteMany(),
    prisma.securityUnlock.deleteMany(),
    prisma.session.deleteMany(),
    prisma.projectAccess.deleteMany(),
    prisma.project.deleteMany(),
    prisma.user.deleteMany()
  ]);
}

export async function disconnectCoreIntegrationTestDatabase(): Promise<void> {
  await prisma.$disconnect();
}
