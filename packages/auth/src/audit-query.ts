import type { Prisma } from "@virki/database";

export const AUDIT_PAGE_SIZE = 50;
export const AUDIT_CATEGORIES = ["AUTH", "ACCOUNT", "ADMIN", "PROJECT", "SSO", "SECURITY", "ACCESS", "AUTHORIZATION", "CSRF", "RATE", "AUDIT", "LEGACY"] as const;
export type AuditSearchParams = Record<string, string | string[] | undefined>;
export type AuditFilters = { q: string; event: string; category: string; result: string; actor: string; actorRole: "" | "ADMIN" | "USER" | "SYSTEM"; resource: string; id: string; from: string; to: string; sort: "newest" | "oldest"; page: number };
export class AuditFilterError extends Error {
  constructor() { super("Filtros inválidos. Use identificadores seguros e um intervalo de até 366 dias (UTC−4)."); }
}
export function parseAuditFilters(params: AuditSearchParams): AuditFilters {
  const read = (key: string, pattern: RegExp, fallback = ""): string => {
    const value = params[key];
    if (value === undefined || value === "") return fallback;
    if (typeof value !== "string" || !pattern.test(value)) throw new AuditFilterError();
    return value;
  };
  const from = read("from", /^\d{4}-\d{2}-\d{2}$/u);
  const to = read("to", /^\d{4}-\d{2}-\d{2}$/u);
  for (const date of [from, to].filter(Boolean)) {
    const parsed = new Date(`${date}T04:00:00Z`);
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== date || date < "2000-01-01" || date > "2100-12-31") throw new AuditFilterError();
  }
  if (Boolean(from) !== Boolean(to) || (from && (from > to || Date.parse(to) - Date.parse(from) > 365 * 86400000))) throw new AuditFilterError();
  const category = read("category", /^[A-Z_]{2,24}$/u);
  if (category && !(AUDIT_CATEGORIES as readonly string[]).includes(category)) throw new AuditFilterError();
  const page = Number(read("page", /^[1-9]\d{0,3}$/u, "1"));
  if (page > 1000) throw new AuditFilterError();
  return {
    q: read("q", /^[A-Za-z0-9_.-]{1,80}$/u),
    event: read("event", /^[A-Z0-9_]{3,80}$/u), category,
    result: read("result", /^(SUCCESS|FAILURE|DENIED|INFO)$/u),
    actor: read("actor", /^(system|identified|[a-f0-9]{8,64})$/u),
    actorRole: read("actorRole", /^(ADMIN|USER|SYSTEM)$/u) as AuditFilters["actorRole"],
    resource: read("resource", /^[A-Za-z0-9_.-]{1,80}$/u),
    id: read("id", /^[A-Za-z0-9_.-]{8,80}$/u), from, to,
    sort: read("sort", /^(newest|oldest)$/u, "newest") as AuditFilters["sort"], page
  };
}
export function buildAuditQuery(filters: AuditFilters) {
  const where: Prisma.AuditLogWhereInput = {
    ...(filters.event ? { eventType: filters.event } : {}),
    ...(filters.category ? { category: filters.category } : {}),
    ...(filters.result ? { result: filters.result } : {}),
    ...(filters.actorRole === "SYSTEM" ? { actorRole: null, actorUserId: null, actorEmailHash: null } : filters.actorRole ? { actorRole: filters.actorRole } : {}),
    ...(filters.resource ? { resource: filters.resource } : {}),
    ...(filters.id ? { id: filters.id } : {}),
    ...(filters.actor === "system" ? { actorUserId: null, actorEmailHash: null } : filters.actor === "identified" ? { OR: [{ actorUserId: { not: null } }, { actorEmailHash: { not: null } }] } : filters.actor ? { actorRef: { startsWith: filters.actor } } : {}),
    ...(filters.from ? { createdAt: { gte: new Date(`${filters.from}T04:00:00Z`), lt: new Date(Date.parse(`${filters.to}T04:00:00Z`) + 86400000) } } : {})
  };
  const prefix = filters.q.replaceAll("_", "\\_");
  if (prefix) where.AND = [{ OR: [
    { eventType: { startsWith: prefix.toUpperCase() } }, { action: { startsWith: prefix.toLowerCase() } },
    { actorRef: { startsWith: prefix.toLowerCase() } }, { resource: { startsWith: prefix } }, { id: { startsWith: prefix } }
  ] }];
  const direction = filters.sort === "oldest" ? "asc" as const : "desc" as const;
  return { where, orderBy: [{ createdAt: direction }, { id: direction }], skip: (filters.page - 1) * AUDIT_PAGE_SIZE, take: AUDIT_PAGE_SIZE + 1 };
}
export function auditPageHref(filters: AuditFilters, page: number): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries({ ...filters, page })) if (value !== "" && !(key === "page" && value === 1)) params.set(key, String(value));
  return `/admin/audit?${params.toString()}`;
}
