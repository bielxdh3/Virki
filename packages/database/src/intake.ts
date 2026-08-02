import { PrismaClient } from "@prisma/client";

export function createRestrictedIntakeClient(
  databaseUrl = process.env.BIELOS_INTAKE_DATABASE_URL
): PrismaClient | null {
  const normalizedUrl = databaseUrl?.trim();
  if (!normalizedUrl) {
    return null;
  }

  return new PrismaClient({
    datasources: {
      db: { url: normalizedUrl }
    }
  });
}
