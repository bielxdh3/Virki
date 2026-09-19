import { NextResponse, type NextRequest } from "next/server";

import { prisma } from "@bielos/database";
import { getCurrentSession } from "../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getLocale } from "../../../locale";
import { getCoreProjectDetailPath } from "../../../core/projects/detail-policy";
import { listCoreProjectsForPrincipal } from "../../../core/projects/read-service";
import { listVisibleModules } from "../../../core/modules/service";

export const dynamic = "force-dynamic";

type CommandItem = { label: string; hint: string; href: string; score: number };

export async function GET(request: NextRequest) {
  const access = await validateHubCloudflareAccess(request.headers, "core-command-palette");
  if (!isCloudflareAccessAllowed(access)) return NextResponse.json({ items: [] }, { status: 403 });
  const session = await getCurrentSession();
  if (!session) return NextResponse.json({ items: [] }, { status: 401 });

  const query = (request.nextUrl.searchParams.get("q") ?? "").trim().slice(0, 80);
  if (query.length < 1) return NextResponse.json({ items: [] }, { headers: { "cache-control": "no-store" } });
  const normalized = query.toLocaleLowerCase();
  const pt = (await getLocale()) === "pt-BR";
  const items: CommandItem[] = [];

  try {
    const projects = await listCoreProjectsForPrincipal(session.user);
    for (const project of projects) {
      const label = project.name;
      const score = rank(label, normalized);
      if (score < 0) continue;
      const href = getCoreProjectDetailPath(project.id);
      if (href) items.push({ label, hint: pt ? `Projeto · ${projectStatusLabel(project.status, true)}` : `Project · ${projectStatusLabel(project.status, false)}`, href, score });
    }

    const modules = await listVisibleModules(session.user);
    for (const module of modules) {
      const score = rank(`${module.name} ${module.key}`, normalized);
      if (score < 0) continue;
      items.push({ label: module.name, hint: pt ? `Módulo · ${runtimeLabel(module.runtimeAvailability, true)}` : `Module · ${runtimeLabel(module.runtimeAvailability, false)}`, href: "/core/modules", score });
    }

    if (session.user.role === "OWNER") {
      const users = await prisma.user.findMany({
        where: { isActive: true, OR: [{ emailNormalized: { contains: query.toLowerCase() } }, { displayName: { contains: query, mode: "insensitive" } }] },
        select: { emailNormalized: true, displayName: true },
        orderBy: { emailNormalized: "asc" },
        take: 10
      });
      for (const user of users) {
        const label = user.displayName ?? user.emailNormalized ?? (pt ? "Pessoa" : "Person");
        items.push({ label, hint: pt ? "Pessoa · pedidos" : "Person · requests", href: "/core/applications", score: rank(`${label} ${user.emailNormalized ?? ""}`, normalized) });
      }
      items.push(...maybeStatic(pt, normalized, [
        { label: pt ? "Auditoria" : "Audit", hint: pt ? "Histórico filtrado" : "Filtered history", href: `/core/security?search=${encodeURIComponent(query)}#audit` },
        { label: pt ? "Sessões" : "Sessions", hint: pt ? "Sessões ativas" : "Active sessions", href: "/core/security#sessions" }
      ]));
    }
    items.push(...maybeStatic(pt, normalized, [
      { label: pt ? "Saúde" : "Health", hint: pt ? "Estado dos projetos" : "Project status", href: "/core/health" },
      { label: pt ? "Recuperação" : "Recovery", hint: pt ? "Backup e restore" : "Backup and restore", href: "/core/recovery" },
      { label: pt ? "Módulos" : "Modules", hint: pt ? "Catálogo e pedidos" : "Catalog and requests", href: "/core/modules" }
    ]));
  } catch {
    return NextResponse.json({ items: [] }, { headers: { "cache-control": "no-store" } });
  }

  const seen = new Set<string>();
  const ranked = items
    .sort((left, right) => right.score - left.score || left.label.localeCompare(right.label, pt ? "pt-BR" : "en"))
    .filter((item) => {
      const key = `${item.href}\u0000${item.label}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 30)
    .map(({ label, hint, href }) => ({ label, hint, href }));
  return NextResponse.json({ items: ranked }, { headers: { "cache-control": "no-store" } });
}

function rank(value: string, query: string): number {
  const normalized = value.toLocaleLowerCase();
  if (!normalized.includes(query)) return -1;
  return normalized.startsWith(query) ? 100 - normalized.length : 50 - normalized.indexOf(query);
}

function projectStatusLabel(value: string, pt: boolean): string {
  return (pt
    ? { PLANNED: "Planejado", RESERVED: "Reservado", ACTIVE: "Ativo", PAUSED: "Pausado", ARCHIVED: "Arquivado" }
    : { PLANNED: "Planned", RESERVED: "Reserved", ACTIVE: "Active", PAUSED: "Paused", ARCHIVED: "Archived" })[value as "PLANNED" | "RESERVED" | "ACTIVE" | "PAUSED" | "ARCHIVED"] ?? (pt ? "Indisponível" : "Unavailable");
}

function runtimeLabel(value: string, pt: boolean): string {
  return (pt
    ? { AVAILABLE: "Disponível", UNAVAILABLE: "Indisponível", INERT: "Inerte" }
    : { AVAILABLE: "Available", UNAVAILABLE: "Unavailable", INERT: "Inert" })[value as "AVAILABLE" | "UNAVAILABLE" | "INERT"] ?? (pt ? "Indisponível" : "Unavailable");
}

function maybeStatic(pt: boolean, query: string, entries: Array<{ label: string; hint: string; href: string }>): CommandItem[] {
  return entries.flatMap((entry) => {
    const score = rank(`${entry.label} ${entry.hint}`, query);
    return score < 0 ? [] : [{ ...entry, score }];
  });
}
