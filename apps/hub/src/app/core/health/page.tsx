import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { getCoreHealthCards } from "../capabilities";
import { getCoreOperationsSnapshot } from "../operations";
import type { HealthState } from "../capabilities";

export const dynamic = "force-dynamic";

function healthStateLabel(state: HealthState, locale: "pt-BR" | "en"): string {
  return (locale === "pt-BR"
    ? { healthy: "Saudável", unknown: "Desconhecido", stale: "Desatualizado", unavailable: "Indisponível" }
    : { healthy: "Healthy", unknown: "Unknown", stale: "Stale", unavailable: "Unavailable" })[state];
}

export default async function CoreHealthPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-health"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const pt = locale === "pt-BR";
  const cards = getCoreHealthCards(await getCoreOperationsSnapshot(), locale);
  return (
    <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/health">
      <div className="core-projects-workspace">
        <header className="top-statusbar"><a href="/">{pt ? "Hub" : "Hub"}</a><div className="top-actions"><span className="status-pill">{pt ? "Saúde" : "Health"}</span><LanguageSelector locale={locale} label={pt ? "Idioma" : "Language"} returnTo="/core/health" /></div></header>
        <section className="identity-panel"><p className="eyebrow">BielOS Core</p><h1>{pt ? "Saúde" : "Health"}</h1><p>{pt ? "Estado mínimo, com fonte e frescor visíveis." : "Minimal status with source and freshness visible."}</p></section>
        <nav className="surface-link-row" aria-label={pt ? "Operações" : "Operations"}>
          <a className="button-secondary" href="/core/activity">{pt ? "Atividade" : "Activity"}</a>
          <a className="button-secondary" href="/core/recovery">{pt ? "Recuperação" : "Recovery"}</a>
          <a className="button-secondary" href="/core/automation">{pt ? "Automações" : "Automations"}</a>
        </nav>
        <section className="capability-card-grid" aria-label={pt ? "Saúde dos projetos" : "Project health"}>
          {cards.map((card) => (
            <article className="capability-card" key={card.id}>
              <div className="capability-card-heading"><div><p className="eyebrow">{card.source}</p><h2>{card.name}</h2></div><span className={`status-pill state-${card.state}`}>{healthStateLabel(card.state, locale)}</span></div>
              <p>{card.summary}</p>
              <dl className="capability-facts"><div><dt>{pt ? "Fonte" : "Source"}</dt><dd>{card.source}</dd></div><div><dt>{pt ? "Observado" : "Observed"}</dt><dd><time dateTime={card.observedAt}>{card.freshness}</time></dd></div></dl>
              <details><summary>{pt ? "Detalhes" : "Details"}</summary><ul>{card.details.map((detail) => <li key={detail}>{detail}</li>)}</ul></details>
            </article>
          ))}
        </section>
      </div>
    </CoreShell>
  );
}
