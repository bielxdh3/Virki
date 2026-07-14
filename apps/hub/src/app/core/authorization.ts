import type { Prisma } from "@bielos/database";

export type CoreProjectPrincipal = {
  id: string;
  role: string;
};

export function isCoreAdministrator(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

export function getCoreProjectReadScope(
  principal: CoreProjectPrincipal
): Prisma.ProjectWhereInput {
  if (isCoreAdministrator(principal.role)) {
    return {};
  }

  return {
    OR: [
      { visibility: "PUBLIC" },
      {
        accesses: {
          some: {
            userId: principal.id
          }
        }
      }
    ]
  };
}

export function getCoreProjectWhere(userId: string, role: string): Prisma.ProjectWhereInput {
  return getCoreProjectReadScope({ id: userId, role });
}
