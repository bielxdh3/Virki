import { type AuthenticatedUser } from "@bielos/auth";
import { requireSecurityElevation } from "@bielos/auth/administration";
import { createRequestKey, isAccessGrantActive, prisma, type Prisma } from "@bielos/database";

const REQUEST_COOLDOWN_MS = 24 * 60 * 60 * 1000;

type Principal = Pick<AuthenticatedUser, "id" | "role">;

export class ModuleAccessMutationError extends Error {
  constructor() {
    super("Module access mutation rejected.");
    this.name = "ModuleAccessMutationError";
  }
}

export async function listVisibleModules(principal: Principal) {
  const now = new Date();
  return prisma.moduleCatalog.findMany({
    where: {
      OR: [
        { visibility: "PUBLIC" },
        {
          accessGrants: {
            some: {
              userId: principal.id,
              status: "ACTIVE",
              OR: [{ accessDurationKind: "PERMANENT" }, { expiresAt: { gt: now } }]
            }
          }
        }
      ]
    },
    orderBy: { name: "asc" },
    take: 50,
    select: {
      id: true,
      key: true,
      name: true,
      visibility: true,
      runtimeAvailability: true,
      requestable: true,
      accessGrants: {
        where: { userId: principal.id },
        select: { status: true, accessDurationKind: true, expiresAt: true }
      },
      featurePermissions: {
        where: { status: "ACTIVE", requestable: true },
        select: {
          key: true,
          label: true,
          grants: {
            where: { userId: principal.id, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
            select: { expiresAt: true }
          }
        }
      }
    }
  });
}

export async function createModuleAccessRequest(
  principal: Principal,
  moduleKey: string,
  reason: string
): Promise<void> {
  if (!/^[a-z0-9-]{1,48}$/.test(moduleKey) || reason.trim().length < 1 || reason.length > 1_000) {
    throw new ModuleAccessMutationError();
  }
  const now = new Date();
  try {
    await prisma.$transaction(async (transaction) => {
      const persisted = await transaction.user.findUnique({ where: { id: principal.id }, select: { isActive: true } });
      if (!persisted?.isActive) throw new ModuleAccessMutationError();
      await lockTarget(transaction, `${principal.id}:${moduleKey}`);
      const module = await transaction.moduleCatalog.findUnique({ where: { key: moduleKey }, select: { id: true, visibility: true, requestable: true } });
      if (!module || module.visibility !== "PUBLIC" || !module.requestable) throw new ModuleAccessMutationError();
      const previous = await transaction.moduleAccessRequest.findFirst({
        where: { userId: principal.id, moduleId: module.id },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true, retryAfterAt: true, indefinitelyBlocked: true }
      });
      if (
        previous &&
        (previous.indefinitelyBlocked ||
          (previous.retryAfterAt && previous.retryAfterAt > now) ||
          previous.createdAt.getTime() + REQUEST_COOLDOWN_MS > now.getTime())
      ) {
        throw new ModuleAccessMutationError();
      }
      await transaction.moduleAccessRequest.create({
        data: {
          requestKey: createRequestKey(principal.id, module.id, now),
          userId: principal.id,
          moduleId: module.id,
          reason: reason.trim()
        }
      });
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ModuleAccessMutationError();
  }
}

export async function createFeaturePermissionRequest(
  principal: Principal,
  moduleKey: string,
  permissionKey: string,
  reason: string
): Promise<void> {
  if (!isKey(moduleKey) || !isKey(permissionKey) || reason.length > 1_000) throw new ModuleAccessMutationError();
  const now = new Date();
  try {
    await prisma.$transaction(async (transaction) => {
      const persisted = await transaction.user.findUnique({ where: { id: principal.id }, select: { isActive: true } });
      if (!persisted?.isActive) throw new ModuleAccessMutationError();
      await lockTarget(transaction, `${principal.id}:feature:${moduleKey}:${permissionKey}`);
      const module = await transaction.moduleCatalog.findUnique({ where: { key: moduleKey }, select: { id: true, visibility: true } });
      if (!module || module.visibility !== "PUBLIC") throw new ModuleAccessMutationError();
      const permission = await transaction.featurePermissionDeclaration.findUnique({
        where: { moduleId_key: { moduleId: module.id, key: permissionKey } },
        select: { id: true, status: true, requestable: true, module: { select: { visibility: true } } }
      });
      if (!permission || permission.status !== "ACTIVE" || !permission.requestable || permission.module.visibility !== "PUBLIC") {
        throw new ModuleAccessMutationError();
      }
      const previous = await transaction.featurePermissionRequest.findFirst({
        where: { userId: principal.id, permissionId: permission.id },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true, retryAfterAt: true, indefinitelyBlocked: true }
      });
      if (previous && (previous.indefinitelyBlocked || (previous.retryAfterAt && previous.retryAfterAt > now) || previous.createdAt.getTime() + REQUEST_COOLDOWN_MS > now.getTime())) {
        throw new ModuleAccessMutationError();
      }
      await transaction.featurePermissionRequest.create({
        data: { requestKey: createRequestKey(principal.id, permission.id, now), userId: principal.id, permissionId: permission.id, reason: reason.trim() || null }
      });
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ModuleAccessMutationError();
  }
}

export async function reviewModuleAccessRequest(input: {
  actor: Principal;
  sessionId: string;
  requestKey: string;
  approve: boolean;
  accessDurationKind: "PERMANENT" | "TEMPORARY";
  expiresAt: Date | null;
}): Promise<void> {
  await requireSecurityElevation(input.actor.id, input.sessionId, "MODULE_ACCESS_CHANGE");
  if (!isOwner(input.actor) || !isRequestKey(input.requestKey) || (input.accessDurationKind === "TEMPORARY" && !input.expiresAt) || (input.accessDurationKind === "PERMANENT" && input.expiresAt)) {
    throw new ModuleAccessMutationError();
  }
  try {
    await prisma.$transaction(async (transaction) => {
      await lockTarget(transaction, `request:${input.requestKey}`);
      const request = await transaction.moduleAccessRequest.findUnique({ where: { requestKey: input.requestKey }, select: { id: true, userId: true, moduleId: true, status: true } });
      const actor = await transaction.user.findUnique({ where: { id: input.actor.id }, select: { role: true, isActive: true } });
      if (!request || !actor?.isActive || actor.role !== "OWNER") throw new ModuleAccessMutationError();
      const status = input.approve ? "APPROVED" : "REJECTED";
      await transaction.moduleAccessRequest.update({ where: { id: request.id }, data: { status, reviewedByUserId: input.actor.id, decidedAt: new Date() } });
      if (input.approve) {
        await transaction.moduleAccessGrant.upsert({
          where: { userId_moduleId: { userId: request.userId, moduleId: request.moduleId } },
          update: { status: "ACTIVE", accessDurationKind: input.accessDurationKind, expiresAt: input.expiresAt, revokedAt: null, grantedByUserId: input.actor.id },
          create: { userId: request.userId, moduleId: request.moduleId, accessDurationKind: input.accessDurationKind, expiresAt: input.expiresAt, grantedByUserId: input.actor.id }
        });
      }
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ModuleAccessMutationError();
  }
}

export async function listPendingModuleRequests(actor: Principal) {
  await requirePersistedOwner(actor);
  return prisma.moduleAccessRequest.findMany({
    where: { status: "PENDING" },
    orderBy: { createdAt: "asc" },
    take: 50,
    select: {
      requestKey: true,
      reason: true,
      createdAt: true,
      user: { select: { emailNormalized: true } },
      module: { select: { key: true, name: true } }
    }
  });
}

export async function listPendingFeaturePermissionRequests(actor: Principal) {
  await requirePersistedOwner(actor);
  return prisma.featurePermissionRequest.findMany({
    where: { status: "PENDING" },
    orderBy: { createdAt: "asc" },
    take: 50,
    select: {
      requestKey: true,
      reason: true,
      createdAt: true,
      user: { select: { emailNormalized: true } },
      permission: { select: { key: true, label: true, module: { select: { key: true, name: true } } } }
    }
  });
}

export async function reviewFeaturePermissionRequest(input: {
  actor: Principal;
  sessionId: string;
  requestKey: string;
  approve: boolean;
  expiresAt: Date | null;
}): Promise<void> {
  await requireSecurityElevation(input.actor.id, input.sessionId, "FEATURE_PERMISSION_CHANGE");
  if (!isOwner(input.actor) || !isRequestKey(input.requestKey) || (input.expiresAt !== null && Number.isNaN(input.expiresAt.getTime()))) {
    throw new ModuleAccessMutationError();
  }
  try {
    await prisma.$transaction(async (transaction) => {
      await lockTarget(transaction, `feature-request:${input.requestKey}`);
      const [request, actor] = await Promise.all([
        transaction.featurePermissionRequest.findUnique({ where: { requestKey: input.requestKey }, select: { id: true, userId: true, permissionId: true } }),
        transaction.user.findUnique({ where: { id: input.actor.id }, select: { role: true, isActive: true } })
      ]);
      if (!request || !actor?.isActive || actor.role !== "OWNER") throw new ModuleAccessMutationError();
      await transaction.featurePermissionRequest.update({ where: { id: request.id }, data: { status: input.approve ? "APPROVED" : "REJECTED", reviewedByUserId: input.actor.id, decidedAt: new Date() } });
      if (input.approve) {
        await transaction.featurePermissionGrant.upsert({
          where: { userId_permissionId: { userId: request.userId, permissionId: request.permissionId } },
          update: { expiresAt: input.expiresAt, revokedAt: null, grantedByUserId: input.actor.id },
          create: { userId: request.userId, permissionId: request.permissionId, expiresAt: input.expiresAt, grantedByUserId: input.actor.id }
        });
      }
    }, { isolationLevel: "Serializable" });
  } catch {
    throw new ModuleAccessMutationError();
  }
}

export async function expireModuleAccessGrants(now = new Date()): Promise<number> {
  const result = await prisma.moduleAccessGrant.updateMany({ where: { status: "ACTIVE", accessDurationKind: "TEMPORARY", expiresAt: { lte: now } }, data: { status: "EXPIRED" } });
  return result.count;
}

export function hasActiveModuleGrant(grant: { status: "ACTIVE" | "EXPIRED" | "REVOKED"; accessDurationKind: "PERMANENT" | "TEMPORARY"; expiresAt: Date | null }, now = new Date()): boolean {
  return isAccessGrantActive(grant, now);
}

function isOwner(principal: Principal): boolean { return principal.role === "OWNER"; }
async function requirePersistedOwner(principal: Principal): Promise<void> {
  if (!isOwner(principal)) throw new ModuleAccessMutationError();
  const actor = await prisma.user.findUnique({ where: { id: principal.id }, select: { role: true, isActive: true } });
  if (!actor?.isActive || actor.role !== "OWNER") throw new ModuleAccessMutationError();
}
function isKey(value: string): boolean { return /^[a-z0-9][a-z0-9._-]{0,63}$/.test(value); }
function isRequestKey(value: string): boolean { return /^[a-f0-9]{64}$/.test(value); }
async function lockTarget(transaction: Prisma.TransactionClient, target: string): Promise<void> {
  await transaction.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`bielos-module:${target}`}, 0)) IS NULL AS "locked"`;
}
