import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { getActivityInboxEvents } from "../capabilities";
import type { ActivityEvent } from "../capabilities";

export const dynamic = "force-dynamic";

function severityLabel(severity: ActivityEvent["severity"], locale: "pt-BR" | "en"): string {
  return (locale === "pt-BR"
    ? { info: "Informação", warning: "Atenção", critical: "Crítico" }
    : { info: "Information", warning: "Warning", critical: "Critical" })[severity];
}

export default async function CoreActivityPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-activity"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const pt = locale === "pt-BR";
  const events = getActivityInboxEvents();
  return (
    <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/health">
      <div className="core-projects-workspace">
        <header className="top-statusbar"><a href="/core/health">{pt ? "Saúde" : "Health"}</a><div className="top-actions"><span className="status-pill">{pt ? "Atividade" : "Activity"}</span><LanguageSelector locale={locale} label={pt ? "Idioma" : "Language"} returnTo="/core/activity" /></div></header>
        <section className="identity-panel"><p className="eyebrow">BielOS Core</p><h1>{pt ? "Atividade" : "Activity"}</h1><p>{pt ? "Exceções autorizadas, sem copiar logs de módulos." : "Authorized exceptions without copying module logs."}</p></section>
        {events.length === 0 ? <div className="capability-empty" role="status"><strong>{pt ? "Tudo limpo" : "All clear"}</strong><span>{pt ? "Nenhum módulo declarou eventos que precisam de atenção." : "No module has declared events that need attention."}</span></div> : <section className="capability-event-list">{events.map((event) => <a className="capability-event" href={event.href} key={event.id}><span className={`status-pill state-${event.severity}`}>{severityLabel(event.severity, locale)}</span><div><strong>{event.type}</strong><span>{event.source} · {event.occurredAt}</span></div></a>)}</section>}
      </div>
    </CoreShell>
  );
}
