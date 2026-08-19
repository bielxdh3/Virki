import { prisma } from "@bielos/database";

import {
  getSafeAuditActorState,
  getSafeAuditEventType,
  getSafeAuditResource,
  getSafeAuditResult,
  CORE_INFRASTRUCTURE_AUDIT_EVENT_TYPES,
  normalizeCoreAuditFilter,
  type CoreAuditFilter,
  type SafeAuditActorState,
  type SafeAuditResource,
  type SafeAuditResult
} from "./audit-view";

export const CORE_AUDIT_DISPLAY_LIMIT = 50;

type CoreAuditPrincipal = {
  id: string;
  role: string;
};

export type CoreAuditDisplay = {
  eventType: string;
  result: SafeAuditResult;
  resource: SafeAuditResource;
  actorState: SafeAuditActorState;
  createdAt: Date;
};

export async function listCoreAuditActivity(
  principal: CoreAuditPrincipal,
  requestedFilter: CoreAuditFilter | string = "activity"
): Promise<CoreAuditDisplay[]> {
  if (!isValidAuditPrincipal(principal)) {
    return [];
  }

  const persistedOwner = await prisma.user.findUnique({
    where: { id: principal.id },
    select: { role: true, isActive: true }
  });

  if (!persistedOwner?.isActive || persistedOwner.role !== "OWNER") {
    return [];
  }

  const filter = normalizeCoreAuditFilter(requestedFilter);

  const logs = await prisma.auditLog.findMany({
    select: {
      eventType: true,
      result: true,
      resource: true,
      actorUserId: true,
      createdAt: true
    },
    where: filter === "infrastructure"
      ? { eventType: { in: [...CORE_INFRASTRUCTURE_AUDIT_EVENT_TYPES] } }
      : { NOT: { eventType: "ACCESS_JWT_VALID", result: "SUCCESS" } },
    orderBy: { createdAt: "desc" },
    take: CORE_AUDIT_DISPLAY_LIMIT
  });

  return logs.map((log) => ({
    eventType: getSafeAuditEventType(log.eventType),
    result: getSafeAuditResult(log.result),
      resource: getSafeAuditResource(log.resource, log.eventType),
    actorState: getSafeAuditActorState(log.actorUserId),
    createdAt: log.createdAt
  }));
}

function isValidAuditPrincipal(principal: CoreAuditPrincipal): boolean {
  return principal.role === "OWNER" && principal.id.length > 0 && principal.id.length <= 128;
}
