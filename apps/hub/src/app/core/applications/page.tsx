import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { reissueCoreApplicationActivation, reviewCoreApplication } from "./actions";
import { listPendingApplications } from "./service";

export const dynamic = "force-dynamic";

const copy = {
  "pt-BR": {
    title: "Solicitações de conta",
    back: "Voltar ao hub",
    language: "Idioma",
    intro: "Verifique o e-mail antes de revisar. Aprovações ficam pendentes até a ativação única.",
    empty: "Nenhuma solicitação pendente.",
    applicant: "Candidato",
    modules: "Módulos",
    reason: "Motivo informado",
    decision: "Decisão",
    approve: "Aprovar",
    reject: "Rejeitar",
    internalReason: "Motivo interno",
    userMessage: "Mensagem visível ao usuário (opcional)",
    duration: "Duração",
    permanent: "Permanente",
    temporary: "Temporário",
    expires: "Expira em",
    review: "Salvar decisão",
    reissue: "Reemitir ativação",
    pending: "Pendente",
    verified: "E-mail verificado",
    approved: "Aprovado",
    partial: "Aprovado parcialmente",
    rejected: "Rejeitado",
    activated: "Ativado"
  },
  en: {
    title: "Account applications",
    back: "Back to hub",
    language: "Language",
    intro: "Email verification comes before review. Approvals remain pending until one-time activation.",
    empty: "No pending applications.",
    applicant: "Applicant",
    modules: "Modules",
    reason: "Applicant reason",
    decision: "Decision",
    approve: "Approve",
    reject: "Reject",
    internalReason: "Internal reason",
    userMessage: "User-visible message (optional)",
    duration: "Duration",
    permanent: "Permanent",
    temporary: "Temporary",
    expires: "Expires at",
    review: "Save decision",
    reissue: "Reissue activation",
    pending: "Pending",
    verified: "Email verified",
    approved: "Approved",
    partial: "Partially approved",
    rejected: "Rejected",
    activated: "Activated"
  }
} as const;

export default async function CoreApplicationsPage() {
  const access = await validateHubCloudflareAccess(await headers(), "core-applications");
  if (!isCloudflareAccessAllowed(access)) {
    forbidden();
  }
  const session = await getCurrentSession();
  if (!session) {
    redirect("/login");
  }
  if (session.user.role !== "OWNER") {
    forbidden();
  }
  const locale = await getLocale();
  const t = copy[locale];
  const applications = await listPendingApplications(session.user);
  const csrfToken = createCsrfToken();

  return (
    <CoreShell variant="standalone" locale={locale} role={session.user.role} activePath="/core/applications"><div className="core-projects-workspace">
        <header className="top-statusbar">
          <a href="/">{t.back}</a>
          <LanguageSelector locale={locale} label={t.language} />
        </header>
        <section className="identity-panel">
          <p className="eyebrow">BielOS Core</p>
          <h1>{t.title}</h1>
          <p>{t.intro}</p>
        </section>
        {applications.length === 0 ? (
          <p className="core-project-empty">{t.empty}</p>
        ) : (
          <section className="core-project-list" aria-label={t.title}>
            {applications.map((application) => (
              <article className="core-project-card" key={application.id}>
                <div className="core-project-card-main">
                  <div className="core-project-title-row">
                    <div>
                      <span className="core-project-slug">{application.status}</span>
                      <h2>{application.displayName || application.emailNormalized}</h2>
                      <p>{application.emailNormalized}</p>
                    </div>
                  </div>
                  <div className="core-project-list">
                    {application.moduleDecisions.map((decision) => (
                      <form action={reviewCoreApplication} method="post" className="core-project-card" key={decision.id}>
                        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                        <input type="hidden" name="applicationId" value={application.id} />
                        <input type="hidden" name="moduleDecisionId" value={decision.id} />
                        <strong>{decision.moduleId}</strong>
                        <span>{t.reason}: {decision.reason}</span>
                        <label>{t.decision}<select name="decision" defaultValue={decision.status === "APPROVED" ? "APPROVED" : "REJECTED"}><option value="APPROVED">{t.approve}</option><option value="REJECTED">{t.reject}</option></select></label>
                        <label>{t.internalReason}<textarea name="internalReason" maxLength={1000} defaultValue={decision.internalReason ?? ""} /></label>
                        <label>{t.userMessage}<textarea name="userVisibleMessage" maxLength={500} defaultValue={decision.userVisibleMessage ?? ""} /></label>
                        <label>{t.duration}<select name="accessDurationKind" defaultValue={decision.accessDurationKind}><option value="PERMANENT">{t.permanent}</option><option value="TEMPORARY">{t.temporary}</option></select></label>
                        <label>{t.expires}<input type="datetime-local" name="accessExpiresAt" /></label>
                        <button type="submit">{t.review}</button>
                      </form>
                    ))}
                  </div>
                  {(application.status === "APPROVED" || application.status === "PARTIALLY_APPROVED") && (
                    <form action={reissueCoreApplicationActivation} method="post">
                      <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                      <input type="hidden" name="applicationId" value={application.id} />
                      <button type="submit">{t.reissue}</button>
                    </form>
                  )}
                </div>
              </article>
            ))}
          </section>
        )}
      </div>
    </CoreShell>
  );
}
