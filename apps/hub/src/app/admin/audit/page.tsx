import { formatAuditEmailReference } from "@bielos/auth";
import { prisma } from "@bielos/database";
import { requireAdminPage } from "../../../lib/admin-page";

export const dynamic = "force-dynamic";

type SearchParams = Promise<{ cursor?: string; event?: string }>;

export default async function AuditPage({ searchParams }: { searchParams: SearchParams }) {
  await requireAdminPage();
  const params = await searchParams;
  const cursor = params.cursor && /^[A-Za-z0-9_-]{8,80}$/u.test(params.cursor) ? params.cursor : undefined;
  const event = params.event && /^[A-Z0-9_]{3,80}$/u.test(params.event) ? params.event : undefined;
  const logs = await prisma.auditLog.findMany({
    where: event ? { eventType: event } : undefined,
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    take: 51,
    select: { id: true, eventType: true, result: true, resource: true, message: true, metadata: true, createdAt: true, actor: { select: { email: true, displayName: true } }, actorEmailHash: true }
  });
  const hasNext = logs.length > 50;
  const items = logs.slice(0, 50);
  const nextCursor = hasNext ? items.at(-1)?.id : undefined;
  const eventTypes = await prisma.auditLog.findMany({ distinct: ["eventType"], select: { eventType: true }, orderBy: { eventType: "asc" }, take: 100 });
  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Auditoria</h1><p>Eventos de identidade, autenticação, segurança, acessos e conexões.</p></div></header>
    <form method="get" className="form-stack"><label>Tipo de evento<select name="event" defaultValue={event ?? ""}><option value="">Todos</option>{eventTypes.map(({ eventType }) => <option key={eventType} value={eventType}>{eventType}</option>)}</select></label><button type="submit">Filtrar</button></form>
    <section className="surface"><h2>Eventos recentes</h2>{items.length === 0 ? <p className="muted">Nenhum evento encontrado.</p> : <div className="row-list">{items.map((item) => {
      const metadata = safeAuditMetadata(item.metadata);
      const actor = item.actor?.displayName || item.actor?.email || (item.actorEmailHash ? `Conta ${formatAuditEmailReference(item.actorEmailHash)}` : "Sistema");
      return <article className="list-row" key={item.id}><div className="row-main"><strong>{item.createdAt.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })} · {actor} · {safeAuditMessage(item.message, item.eventType)} · {item.result === "SUCCESS" ? "✓" : item.result}</strong><span>{item.eventType}{item.resource ? ` · ${item.resource.slice(0, 80)}` : ""} · evento {item.id}</span><details><summary>Detalhes seguros</summary><pre>{JSON.stringify(metadata, null, 2)}</pre></details></div></article>;
    })}</div>}
      <nav className="pagination" aria-label="Paginação da auditoria">{cursor && <a className="button-secondary" href={`/admin/audit${event ? `?event=${encodeURIComponent(event)}` : ""}`}>Mais recentes</a>}{nextCursor && <a className="button-secondary" href={`/admin/audit?${event ? `event=${encodeURIComponent(event)}&` : ""}cursor=${encodeURIComponent(nextCursor)}`}>Mais antigos</a>}</nav>
    </section>
  </main>;
}

function safeAuditMetadata(value: unknown): unknown {
  if (!value || typeof value !== "object") return null;
  const forbidden = /password|secret|token|cookie|authorization|credential|recovery|totp|private|payload|code/i;
  const result: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (forbidden.test(key)) continue;
    if (entry === null || typeof entry === "boolean" || typeof entry === "number") result[key] = entry;
    else if (typeof entry === "string") result[key] = entry.slice(0, 300);
    else if (Array.isArray(entry)) result[key] = entry.slice(0, 20).map((child) => safeAuditMetadata(child));
    else if (typeof entry === "object") result[key] = safeAuditMetadata(entry);
  }
  return result;
}

function safeAuditMessage(value: string | null, fallback: string): string {
  if (!value) return fallback;
  if (/(password|secret|token|cookie|authorization|recovery|totp|code)\s*[:=]\s*\S+/iu.test(value) || /\bBearer\s+\S+/iu.test(value) || /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/u.test(value)) {
    return "Detalhe ocultado por política de segurança.";
  }
  return value.slice(0, 160);
}
