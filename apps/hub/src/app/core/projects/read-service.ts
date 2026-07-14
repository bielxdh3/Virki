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
  const persistedPrincipal = await getPersistedPrincipal(principal);

  if (!persistedPrincipal) {
    return [];
  }

  const administrator = isCoreAdministrator(persistedPrincipal.role);

  return prisma.project.findMany({
    where: getCoreProjectReadScope(persistedPrincipal),
    select: {
      ...safeProjectFields,
      accesses: {
        where: administrator ? undefined : { userId: persistedPrincipal.id },
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
  const persistedPrincipal = await getPersistedPrincipal(principal);

  if (!isValidCoreResourceId(projectId) || !persistedPrincipal) {
    return null;
  }

  return prisma.project.findFirst({
    where: {
      AND: [{ id: projectId }, getCoreProjectReadScope(persistedPrincipal)]
    },
    select: safeProjectFields
  });
}

async function getPersistedPrincipal(
  principal: CoreProjectPrincipal
): Promise<CoreProjectPrincipal | null> {
  if (!isValidCoreResourceId(principal.id)) {
    return null;
  }

  const user = await prisma.user.findUnique({
    where: { id: principal.id },
    select: { isActive: true, role: true }
  });

  if (!user?.isActive || user.role !== principal.role) {
    return null;
  }

  return { id: principal.id, role: user.role };
}
