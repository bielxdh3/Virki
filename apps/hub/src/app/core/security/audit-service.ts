import { prisma, type Prisma } from "@bielos/database";

import {
  getSafeAuditActorState,
  getSafeAuditEventType,
  getSafeAuditEventLabel,
  getSafeAuditCategory,
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
export const CORE_AUDIT_EXPORT_LIMIT = 500;
export const CORE_AUDIT_RETENTION_DAYS = readRetentionDays();

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

export type CoreAuditPageItem = CoreAuditDisplay & {
  id: string;
  eventLabel: string;
  category: ReturnType<typeof getSafeAuditCategory>;
};

export type CoreAuditPageOptions = {
  requestedFilter?: CoreAuditFilter | string;
  cursor?: string;
  category?: string;
  result?: string;
  event?: string;
  actor?: string;
  resource?: string;
  search?: string;
  from?: Date;
  to?: Date;
};

export type CoreAuditPage = {
  items: CoreAuditPageItem[];
  nextCursor: string | null;
  total: number;
  oldestAt: Date | null;
  newestAt: Date | null;
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

  const page = await listCoreAuditActivityPage(principal, { requestedFilter });
  return page.items.map(({ id: _id, eventLabel: _eventLabel, category: _category, ...item }) => item);
}

export function parseAuditDate(value: string | undefined, endOfDay = false): Date | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return undefined;
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(`${value}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z`);
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() !== year || date.getUTCMonth() + 1 !== month || date.getUTCDate() !== day ? undefined : date;
}

export async function listCoreAuditActivityPage(
  principal: CoreAuditPrincipal,
  options: CoreAuditPageOptions = {}
): Promise<CoreAuditPage> {
  if (!await isPersistedOwner(principal)) {
    return { items: [], nextCursor: null, total: 0, oldestAt: null, newestAt: null };
  }

  const where = buildAuditWhere(options);
  const cursor = decodeCursor(options.cursor);
  if (cursor) {
    where.AND = [
      ...(Array.isArray(where.AND) ? where.AND : where.AND ? [where.AND] : []),
      { OR: [{ createdAt: { lt: cursor.createdAt } }, { createdAt: cursor.createdAt, id: { lt: cursor.id } }] }
    ];
  }

  const [logs, total, oldest, newest] = await Promise.all([
    prisma.auditLog.findMany({
      select: { id: true, eventType: true, result: true, resource: true, actorUserId: true, createdAt: true },
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: CORE_AUDIT_DISPLAY_LIMIT + 1
    }),
    prisma.auditLog.count({ where: buildAuditWhere(options) }),
    prisma.auditLog.findFirst({ where: buildAuditWhere(options), orderBy: { createdAt: "asc" }, select: { createdAt: true } }),
    prisma.auditLog.findFirst({ where: buildAuditWhere(options), orderBy: { createdAt: "desc" }, select: { createdAt: true } })
  ]);

  const hasNext = logs.length > CORE_AUDIT_DISPLAY_LIMIT;
  const visible = hasNext ? logs.slice(0, CORE_AUDIT_DISPLAY_LIMIT) : logs;
  const last = visible.at(-1);
  return {
    items: visible.map((log) => ({
      id: log.id,
      eventType: getSafeAuditEventType(log.eventType),
      eventLabel: getSafeAuditEventLabel(log.eventType),
      category: getSafeAuditCategory(log.eventType, log.resource),
      result: getSafeAuditResult(log.result),
      resource: getSafeAuditResource(log.resource, log.eventType),
      actorState: getSafeAuditActorState(log.actorUserId),
      createdAt: log.createdAt
    })),
    nextCursor: hasNext && last ? encodeCursor({ id: last.id, createdAt: last.createdAt }) : null,
    total,
    oldestAt: oldest?.createdAt ?? null,
    newestAt: newest?.createdAt ?? null
  };
}

function buildAuditWhere(options: CoreAuditPageOptions): Prisma.AuditLogWhereInput {
  const filter = normalizeCoreAuditFilter(options.requestedFilter);
  const and: Prisma.AuditLogWhereInput[] = [
    filter === "infrastructure"
      ? { eventType: { in: [...CORE_INFRASTRUCTURE_AUDIT_EVENT_TYPES] } }
      : { NOT: { eventType: "ACCESS_JWT_VALID", result: "SUCCESS" } }
  ];
  const category = normalizeOption(options.category, ["auth", "account", "access", "project", "admin", "session", "system", "ops", "module", "other"] as const);
  if (category) and.push(getAuditCategoryWhere(category));
  const result = normalizeOption(options.result, ["SUCCESS", "FAILURE", "INFO"] as const);
  if (result) and.push({ result });
  const event = options.event?.trim();
  if (event && /^[A-Z0-9_]{1,80}$/.test(event)) and.push({ eventType: event });
  const actor = normalizeOption(options.actor, ["user", "system"] as const);
  if (actor === "user") and.push({ actorUserId: { not: null } });
  if (actor === "system") and.push({ actorUserId: null });
  const resource = normalizeOption(options.resource, ["hub", "access", "session", "project", "project-access", "application", "security", "system", "other"] as const);
  if (resource) and.push(getAuditResourceWhere(resource));
  const search = options.search?.trim();
  if (search && search.length <= 80 && /^[\w .:-]+$/u.test(search)) {
    and.push({ OR: [{ eventType: { contains: search, mode: "insensitive" } }, { resource: { contains: search, mode: "insensitive" } }] });
  }
  if (options.from || options.to) and.push({ createdAt: { ...(options.from ? { gte: options.from } : {}), ...(options.to ? { lte: options.to } : {}) } });
  return { AND: and };
}

function getAuditCategoryWhere(category: ReturnType<typeof getSafeAuditCategory>): Prisma.AuditLogWhereInput {
  const accountPrefixes = ["ACCOUNT_", "SECOND_FACTOR_", "RECOVERY_"];
  const modulePrefixes = ["GYMFORGE_", "MODULE_", "FEATURE_"];
  const prioritizedIdentityExclusions = ["AUTH_", "ACCESS_JWT_", "CORE_PROJECT_", "ADMIN_", ...modulePrefixes, "OWNER_", "AUDIT_"];
  const categoryWhere: Record<Exclude<ReturnType<typeof getSafeAuditCategory>, "other">, Prisma.AuditLogWhereInput> = {
    auth: { eventType: { startsWith: "AUTH_" } },
    access: { OR: [{ eventType: { startsWith: "ACCESS_JWT_" } }, { eventType: { startsWith: "CORE_PROJECT_ACCESS_" } }] },
    project: { AND: [{ eventType: { startsWith: "CORE_PROJECT_" } }, { NOT: { eventType: { startsWith: "CORE_PROJECT_ACCESS_" } } }] },
    admin: { eventType: { startsWith: "ADMIN_" } },
    module: { OR: modulePrefixes.map((prefix) => ({ eventType: { startsWith: prefix } })) },
    account: {
      OR: [
        ...accountPrefixes.map((prefix) => ({ eventType: { startsWith: prefix } })),
        { AND: [{ resource: { startsWith: "identity." } }, { NOT: { OR: prioritizedIdentityExclusions.map((prefix) => ({ eventType: { startsWith: prefix } })) } }] }
      ]
    },
    session: { AND: [{ NOT: { eventType: { startsWith: "AUTH_" } } }, { OR: [{ eventType: { contains: "SESSION" } }, { resource: "session" }] }] },
    ops: { OR: [{ eventType: { startsWith: "OWNER_" } }, { eventType: { startsWith: "AUDIT_" } }] },
    system: { resource: "system" }
  };
  if (category !== "other") return categoryWhere[category];
  return { NOT: { OR: Object.values(categoryWhere) } };
}

function getAuditResourceWhere(resource: SafeAuditResource): Prisma.AuditLogWhereInput {
  const knownResources: Prisma.AuditLogWhereInput[] = [
    { resource: "hub" },
    { resource: "session" },
    { resource: "core.project" },
    { resource: "core.project-access" },
    { resource: "system" },
    { resource: { startsWith: "identity." } },
    { resource: { startsWith: "gymforge." } }
  ];
  switch (resource) {
    case "hub":
    case "access":
      return { resource: "hub" };
    case "session":
      return { resource: "session" };
    case "project":
      return { resource: "core.project" };
    case "project-access":
      return { resource: "core.project-access" };
    case "application":
      return { OR: [{ resource: { in: ["identity.application", "identity.module", "identity.permission"] } }, { resource: { startsWith: "gymforge." } }] };
    case "security":
      return { resource: { in: ["identity.admin", "identity.elevation", "identity.recovery", "identity.2fa", "identity.device"] } };
    case "system":
      return { resource: "system" };
    case "other":
      return { NOT: { OR: knownResources } };
  }
}

async function isPersistedOwner(principal: CoreAuditPrincipal): Promise<boolean> {
  if (!isValidAuditPrincipal(principal)) return false;
  const persistedOwner = await prisma.user.findUnique({ where: { id: principal.id }, select: { role: true, isActive: true } });
  return Boolean(persistedOwner?.isActive && persistedOwner.role === "OWNER");
}

function normalizeOption<T extends readonly string[]>(value: string | undefined, choices: T): T[number] | undefined {
  return choices.includes(value as T[number]) ? value as T[number] : undefined;
}

function encodeCursor(cursor: { id: string; createdAt: Date }): string {
  return Buffer.from(JSON.stringify({ id: cursor.id, createdAt: cursor.createdAt.toISOString() }), "utf8").toString("base64url");
}

function decodeCursor(value: string | undefined): { id: string; createdAt: Date } | null {
  if (!value || value.length > 300) return null;
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as { id?: unknown; createdAt?: unknown };
    if (typeof parsed.id !== "string" || parsed.id.length > 128 || typeof parsed.createdAt !== "string") return null;
    const createdAt = new Date(parsed.createdAt);
    return Number.isNaN(createdAt.getTime()) ? null : { id: parsed.id, createdAt };
  } catch {
    return null;
  }
}

function isValidAuditPrincipal(principal: CoreAuditPrincipal): boolean {
  return principal.role === "OWNER" && principal.id.length > 0 && principal.id.length <= 128;
}

function readRetentionDays(): number {
  const parsed = Number.parseInt(process.env.AUDIT_LOG_RETENTION_DAYS ?? "180", 10);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 3650 ? parsed : 180;
}
