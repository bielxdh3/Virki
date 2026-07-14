import { prisma } from "@bielos/database";

import {
  getCoreProjectReadScope,
  isCoreAdministrator,
  type CoreProjectPrincipal
} from "../authorization";
import { isValidCoreResourceId } from "./validation";

export const CORE_PROJECT_READ_LIMIT = 100;

const safeProjectFields = {
  id: true,
  name: true,
  slug: true,
  description: true,
  visibility: true,
  status: true,
  updatedAt: true
} as const;

export async function listCoreProjectsForPrincipal(principal: CoreProjectPrincipal) {
  if (!(await isActivePrincipal(principal.id))) {
    return [];
  }

  const administrator = isCoreAdministrator(principal.role);

  return prisma.project.findMany({
    where: getCoreProjectReadScope(principal),
    select: {
      ...safeProjectFields,
      accesses: {
        where: administrator ? undefined : { userId: principal.id },
        select: {
          accessLevel: true,
          user: {
            select: {
              id: true,
              email: true,
              displayName: true,
              role: true,
              isActive: true
            }
          }
        },
        orderBy: { createdAt: "asc" },
        take: 100
      }
    },
    orderBy: [{ updatedAt: "desc" }, { name: "asc" }],
    take: CORE_PROJECT_READ_LIMIT
  });
}

export async function findCoreProjectForPrincipal(
  principal: CoreProjectPrincipal,
  projectId: string
) {
  if (!isValidCoreResourceId(projectId) || !(await isActivePrincipal(principal.id))) {
    return null;
  }

  return prisma.project.findFirst({
    where: {
      AND: [{ id: projectId }, getCoreProjectReadScope(principal)]
    },
    select: safeProjectFields
  });
}

async function isActivePrincipal(userId: string): Promise<boolean> {
  if (!isValidCoreResourceId(userId)) {
    return false;
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { isActive: true }
  });

  return user?.isActive === true;
}
