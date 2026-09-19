import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { AUTOMATION_RECIPES } from "../capabilities";

export const dynamic = "force-dynamic";

export default async function CoreAutomationPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-automation"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const pt = locale === "pt-BR";
  return (
    <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/health">
      <div className="core-projects-workspace">
        <header className="top-statusbar"><a href="/core/health">{pt ? "Saúde" : "Health"}</a><div className="top-actions"><span className="status-pill">{pt ? "Automações" : "Automations"}</span><LanguageSelector locale={locale} label={pt ? "Idioma" : "Language"} returnTo="/core/automation" /></div></header>
        <section className="identity-panel"><p className="eyebrow">BielOS Core</p><h1>{pt ? "Automações" : "Automations"}</h1><p>{pt ? "Receitas explícitas e limitadas; nenhum script livre." : "Explicit bounded recipes; no unrestricted scripting."}</p></section>
        <section className="capability-card-grid" aria-label={pt ? "Receitas" : "Recipes"}>
          {AUTOMATION_RECIPES.map((recipe) => <article className="capability-card" key={recipe.id}><div className="capability-card-heading"><div><p className="eyebrow">v{recipe.version}</p><h2>{pt ? "Avisar recuperação desatualizada" : "Surface stale recovery"}</h2></div><span className="status-pill state-unavailable">{pt ? "Bloqueada" : "Blocked"}</span></div><dl className="capability-facts"><div><dt>{pt ? "Gatilho" : "Trigger"}</dt><dd>{pt ? "Recuperação desatualizada" : recipe.trigger}</dd></div><div><dt>{pt ? "Ação" : "Action"}</dt><dd>{pt ? "Criar exceção na atividade" : recipe.action}</dd></div><div><dt>{pt ? "Alvo" : "Target"}</dt><dd>{pt ? "Módulo autorizado" : recipe.target}</dd></div></dl><p>{pt ? "Requer provedor declarado e scheduler limitado." : recipe.reason}</p></article>)}
        </section>
      </div>
    </CoreShell>
  );
}
