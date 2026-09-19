import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { getRecoveryCards } from "../capabilities";
import type { RecoveryCard } from "../capabilities";

export const dynamic = "force-dynamic";

function recoveryStateLabel(state: RecoveryCard["state"], locale: "pt-BR" | "en"): string {
  return (locale === "pt-BR"
    ? { verified: "Verificado", unknown: "Desconhecido", unavailable: "Indisponível" }
    : { verified: "Verified", unknown: "Unknown", unavailable: "Unavailable" })[state];
}

export default async function CoreRecoveryPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-recovery"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const pt = locale === "pt-BR";
  const cards = getRecoveryCards(locale);
  return (
    <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/health">
      <div className="core-projects-workspace">
        <header className="top-statusbar"><a href="/core/health">{pt ? "Saúde" : "Health"}</a><div className="top-actions"><span className="status-pill">{pt ? "Recuperação" : "Recovery"}</span><LanguageSelector locale={locale} label={pt ? "Idioma" : "Language"} returnTo="/core/recovery" /></div></header>
        <section className="identity-panel"><p className="eyebrow">BielOS Core</p><h1>{pt ? "Recuperação" : "Recovery"}</h1><p>{pt ? "O que pode ser recuperado agora?" : "What can be recovered now?"}</p></section>
        <section className="capability-card-grid" aria-label={pt ? "Estado de recuperação" : "Recovery status"}>
          {cards.map((card) => (
            <article className="capability-card" key={card.id}>
              <div className="capability-card-heading"><div><p className="eyebrow">{card.source}</p><h2>{card.name}</h2></div><span className={`status-pill state-${card.state}`}>{recoveryStateLabel(card.state, locale)}</span></div>
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
