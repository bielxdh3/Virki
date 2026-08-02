import { PrismaClient } from "@prisma/client";

export { Prisma } from "@prisma/client";
export type { PrismaClient } from "@prisma/client";
export * from "./identity-access";
export { createRestrictedIntakeClient } from "./intake";

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
