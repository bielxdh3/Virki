import { prisma } from "@bielos/database";

import {
  getCoreProjectReadScope,
  isCoreAdministrator,
  type CoreProjectPrincipal
} from "../authorization";
import { isValidCoreResourceId } from "./validation";

export const CORE_PROJECT_READ_LIMIT = 100;
export const CORE_PROJECT_ACCESS_READ_LIMIT = 100;
export const CORE_PROJECT_ADMIN_USER_LIMIT = 200;

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

export async function findCoreProjectDetailForPrincipal(
  principal: CoreProjectPrincipal,
  projectId: string
) {
  const persistedPrincipal = await getPersistedPrincipal(principal);

  if (!isValidCoreResourceId(projectId) || !persistedPrincipal) {
    return null;
  }

  const administrator = isCoreAdministrator(persistedPrincipal.role);
  const where = {
    AND: [{ id: projectId }, getCoreProjectReadScope(persistedPrincipal)]
  };

  if (administrator) {
    const [project, activeUsers] = await Promise.all([
      prisma.project.findFirst({
        where,
        select: {
          ...safeProjectFields,
          accesses: {
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
            orderBy: [{ createdAt: "asc" }, { id: "asc" }],
            take: CORE_PROJECT_ACCESS_READ_LIMIT
          }
        }
      }),
      prisma.user.findMany({
        where: { isActive: true },
        select: { id: true, email: true, displayName: true, role: true },
        orderBy: [{ email: "asc" }, { id: "asc" }],
        take: CORE_PROJECT_ADMIN_USER_LIMIT
      })
    ]);

    if (!project) {
      return null;
    }

    return {
      ...project,
      administrator: true as const,
      effectiveAccess:
        persistedPrincipal.role === "OWNER" ? "GLOBAL_OWNER" as const : "GLOBAL_ADMIN" as const,
      activeUsers
    };
  }

  const project = await prisma.project.findFirst({
    where,
    select: {
      ...safeProjectFields,
      accesses: {
        where: { userId: persistedPrincipal.id },
        select: { accessLevel: true },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        take: 1
      }
    }
  });

  if (!project) {
    return null;
  }

  const effectiveAccess =
    project.accesses[0]?.accessLevel ??
    (project.visibility === "PUBLIC" ? "AUTHENTICATED" : null);

  if (!effectiveAccess) {
    return null;
  }

  return {
    id: project.id,
    name: project.name,
    slug: project.slug,
    description: project.description,
    visibility: project.visibility,
    status: project.status,
    updatedAt: project.updatedAt,
    administrator: false as const,
    effectiveAccess,
    accesses: [],
    activeUsers: []
  };
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
