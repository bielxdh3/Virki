import { hashAuditIdentifier, safePersistedAuditMetadata, safeAuditState } from "@virki/auth";
import { AUDIT_CATEGORIES, auditPageHref, type AuditFilters } from "@virki/auth/audit-query";
import { DISPLAY_TIME_ZONE_LABEL, formatDateTime } from "@virki/auth/date-time";
import type { Prisma } from "@virki/database";

export const auditSelect = {
  id: true, eventType: true, result: true, resource: true, createdAt: true,
  actorUserId: true, actorEmailHash: true, actorRef: true, actorRole: true, category: true, severity: true, action: true, reason: true,
  schemaVersion: true, requestId: true, sessionRef: true, deviceRef: true, targetRef: true, service: true, route: true, method: true, networkProvenance: true,
  beforeState: true, afterState: true, metadata: true
} satisfies Prisma.AuditLogSelect;
export type AuditRow = Prisma.AuditLogGetPayload<{ select: typeof auditSelect }>;
const outcomes: Record<string, string> = { SUCCESS: "Sucesso", FAILURE: "Falha", DENIED: "Negado", INFO: "Informação" };
const safeIdentifier = (value: string | null) => value && /^[A-Za-z0-9_.-]{1,100}$/u.test(value) ? value : "Indisponível";
const safeRef = (value: string | null) => value && /^[a-f0-9]{64}$/u.test(value) ? value : null;

export function AuditView({ filters, rows, hasNext }: { filters: AuditFilters; rows: AuditRow[]; hasNext: boolean }) {
  const activeCount = Object.entries(filters).filter(([key, value]) => !["page", "sort"].includes(key) && value !== "").length;
  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Auditoria</h1><p>Investigue eventos por identificadores seguros. Horários em {DISPLAY_TIME_ZONE_LABEL}.</p></div></header>
    <form method="get" action="/admin/audit" className="form-stack audit-filters" aria-label="Filtros da auditoria">
      <label>Busca por prefixo<input name="q" type="search" defaultValue={filters.q} maxLength={80} pattern={"[A-Za-z0-9_.\\-]+"} aria-describedby="audit-search-help" /></label>
      <p className="muted" id="audit-search-help">Tipo, ação, referência da conta, recurso ou ID do evento. Use letras, números, ponto, hífen e sublinhado. Nunca insira e-mails ou segredos.</p>
      <details open={activeCount > (filters.q ? 1 : 0)}><summary>Filtros avançados</summary><div className="audit-filter-grid">
        <label>Tipo de evento<input name="event" defaultValue={filters.event} maxLength={80} pattern="[A-Z0-9_]+" /></label>
        <label>Categoria<select name="category" defaultValue={filters.category}><option value="">Todas</option>{AUDIT_CATEGORIES.map((category) => <option key={category}>{category}</option>)}</select></label>
        <label>Resultado<select name="result" defaultValue={filters.result}><option value="">Todos</option>{Object.entries(outcomes).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
        <label>Papel do ator<select name="actorRole" defaultValue={filters.actorRole}><option value="">Todos</option><option value="ADMIN">Administrador (ADMIN)</option><option value="USER">Usuário (USER)</option><option value="SYSTEM">Sistema sem conta identificada (SYSTEM)</option></select></label>
        <label>Referência do ator<input name="actor" defaultValue={filters.actor} maxLength={64} aria-describedby="audit-actor-help" /></label>
        <p className="muted" id="audit-actor-help">Use system (sem ator identificado), identified (conta identificada) ou o prefixo hexadecimal da referência (mínimo 8 caracteres).</p>
        <label>Recurso exato<input name="resource" defaultValue={filters.resource} maxLength={80} /></label>
        <label>ID exato do evento<input name="id" defaultValue={filters.id} maxLength={80} /></label>
        <label>Data inicial (UTC−4)<input name="from" type="date" defaultValue={filters.from} min="2000-01-01" max="2100-12-31" /></label>
        <label>Data final (UTC−4)<input name="to" type="date" defaultValue={filters.to} min="2000-01-01" max="2100-12-31" /></label>
        <p className="muted">Informe as duas datas para limitar a busca a até 366 dias, incluindo a data final.</p>
      </div></details>
      <label>Ordenação<select name="sort" defaultValue={filters.sort}><option value="newest">Mais recentes primeiro</option><option value="oldest">Mais antigos primeiro</option></select></label>
      <div className="form-actions"><button className="button-primary" type="submit">Buscar eventos</button><a className="button-secondary" href="/admin/audit">Limpar filtros</a></div>
    </form>
    <section className="surface" aria-labelledby="audit-results"><h2 id="audit-results">Eventos de segurança</h2>
      <p role="status">{rows.length} evento(s) nesta página · página {filters.page} · {activeCount} filtro(s) ativo(s){hasNext ? " · há mais eventos" : ""}.</p>
      {rows.length === 0 ? <p className="muted">{activeCount ? "Nenhum evento corresponde aos filtros. Ajuste a busca ou limpe os filtros." : "Nenhum evento disponível."}</p> : <div className="row-list">{rows.map((row) => {
        const actorRef = safeRef(row.actorRef) ?? (row.actorUserId ? hashAuditIdentifier(row.actorUserId) : row.actorEmailHash ? hashAuditIdentifier(row.actorEmailHash) : null);
        const eventType = safeIdentifier(row.eventType);
        const details = {
          versao: row.schemaVersion, categoria: safeIdentifier(row.category), gravidade: safeIdentifier(row.severity), motivo: safeIdentifier(row.reason),
          papelVerificado: row.actorRole === "ADMIN" || row.actorRole === "USER" ? row.actorRole : "Indisponível",
          ator: actorRef, alvo: safeRef(row.targetRef), sessao: safeRef(row.sessionRef), dispositivo: safeRef(row.deviceRef),
          requisicao: row.requestId && /^[a-f0-9-]{36}$/u.test(row.requestId) ? row.requestId : null,
          servico: safeIdentifier(row.service), rota: row.route && /^\/[a-zA-Z0-9/_.:-]{0,100}$/u.test(row.route) ? row.route : null, metodo: safeIdentifier(row.method),
          rede: "Indisponível", antes: safeAuditState(row.beforeState), depois: safeAuditState(row.afterState), metadados: safePersistedAuditMetadata(row.metadata)
        };
        return <article className="list-row audit-event" key={row.id}><div className="row-main">
          <div className="audit-event-heading"><time dateTime={row.createdAt.toISOString()}>{formatDateTime(row.createdAt)}</time><strong>{safeIdentifier(row.action ?? eventType)}</strong><span className={row.result === "FAILURE" || row.result === "DENIED" ? "form-error" : ""}>{outcomes[row.result] ?? "Indisponível"}</span></div>
          <span>{actorRef ? `Conta ${actorRef.slice(0, 12)}` : "Sem ator identificado"} · recurso {safeIdentifier(row.resource)}</span>
          <span>{eventType} · evento {safeIdentifier(row.id)}</span>
          <details><summary>Detalhes seguros · {safeIdentifier(row.id)}</summary><pre>{JSON.stringify(details, null, 2)}</pre></details>
        </div></article>;
      })}</div>}
      <nav className="pagination" aria-label="Paginação da auditoria">{filters.page > 1 && <a className="button-secondary" href={auditPageHref(filters, filters.page - 1)}>Página anterior</a>}{hasNext && filters.page < 1000 && <a className="button-secondary" href={auditPageHref(filters, filters.page + 1)}>Próxima página</a>}</nav>
      {filters.page === 1000 && hasNext && <p>Limite de paginação atingido. Restrinja o intervalo ou os filtros.</p>}
    </section>
  </main>;
}
