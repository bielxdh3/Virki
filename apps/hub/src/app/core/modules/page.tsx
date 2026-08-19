import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { requestCoreFeaturePermission, requestCoreModule, reviewCoreFeaturePermissionRequest, reviewCoreModuleRequest } from "./actions";
import { listPendingFeaturePermissionRequests, listPendingModuleRequests, listVisibleModules } from "./service";

export const dynamic = "force-dynamic";

export default async function CoreModulesPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-modules"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const portuguese = locale === "pt-BR";
  const t = portuguese ? {
    catalogLabel: "Catálogo de módulos",
    requestReason: "Motivo",
    optionalReason: "Motivo opcional",
    request: "Solicitar",
    requestPermission: "Solicitar permissão",
    granted: "Concedida",
    requestable: "Solicitável",
    grantedOnly: "Somente concedido",
    administration: "Administração de solicitações",
    noPending: "Nenhuma solicitação pendente.",
    decision: "Decisão",
    approve: "Aprovar",
    reject: "Rejeitar",
    duration: "Duração",
    permanent: "Permanente",
    temporary: "Temporário",
    expires: "Expira em",
    save: "Salvar"
  } : {
    catalogLabel: "Module catalog",
    requestReason: "Reason",
    optionalReason: "Optional reason",
    request: "Request",
    requestPermission: "Request permission",
    granted: "Granted",
    requestable: "Requestable",
    grantedOnly: "Granted only",
    administration: "Request administration",
    noPending: "No pending requests.",
    decision: "Decision",
    approve: "Approve",
    reject: "Reject",
    duration: "Duration",
    permanent: "Permanent",
    temporary: "Temporary",
    expires: "Expires at",
    save: "Save"
  };
  const modules = await listVisibleModules(session.user);
  const pendingModuleRequests = session.user.role === "OWNER" ? await listPendingModuleRequests(session.user) : [];
  const pendingFeatureRequests = session.user.role === "OWNER" ? await listPendingFeaturePermissionRequests(session.user) : [];
  const csrfToken = createCsrfToken();

  return (
    <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/modules"><div className="core-projects-workspace">
      <header className="top-statusbar"><a href="/">{portuguese ? "Voltar ao hub" : "Back to hub"}</a><LanguageSelector locale={locale} label={portuguese ? "Idioma" : "Language"} /></header>
      <section className="identity-panel"><p className="eyebrow">BielOS Core</p><h1>{portuguese ? "Catálogo de módulos" : "Module catalog"}</h1><p>{portuguese ? "Acesso e runtime são estados separados." : "Access and runtime are separate states."}</p></section>
      <section className="core-project-list" aria-label={t.catalogLabel}>
        {modules.map((module) => {
          const grant = module.accessGrants[0];
          const granted = grant?.status === "ACTIVE" && (grant.accessDurationKind === "PERMANENT" || (grant.expiresAt && grant.expiresAt > new Date()));
          return <article className="core-project-card" key={module.key}><div className="core-project-card-main"><span className="core-project-slug">{module.runtimeAvailability}</span><h2>{module.name}</h2><p>{granted ? t.granted : module.requestable ? t.requestable : t.grantedOnly}</p>
            {!granted && module.visibility === "PUBLIC" && module.requestable ? <form action={requestCoreModule} method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="moduleKey" value={module.key} /><label>{t.requestReason}<textarea required name="reason" maxLength={1000} /></label><button type="submit">{t.request}</button></form> : null}
            {module.featurePermissions.map((permission) => <form action={requestCoreFeaturePermission} method="post" key={permission.key}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="moduleKey" value={module.key} /><input type="hidden" name="permissionKey" value={permission.key} /><strong>{permission.label}</strong>{permission.grants[0] ? <span>{t.granted}</span> : <><label>{t.optionalReason}<input name="reason" maxLength={1000} /></label><button type="submit">{t.requestPermission}</button></>}</form>)}
          </div></article>;
        })}
      </section>
      {session.user.role === "OWNER" ? <section className="panel"><h2>{t.administration}</h2>
        {pendingModuleRequests.length === 0 && pendingFeatureRequests.length === 0 ? <p>{t.noPending}</p> : null}
        {pendingModuleRequests.map((request) => <form action={reviewCoreModuleRequest} method="post" key={request.requestKey}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={request.requestKey} /><strong>{request.module.name}</strong><span>{request.user.emailNormalized}</span><p>{request.reason}</p><label>{t.decision}<select name="decision"><option value="APPROVED">{t.approve}</option><option value="REJECTED">{t.reject}</option></select></label><label>{t.duration}<select name="accessDurationKind"><option value="PERMANENT">{t.permanent}</option><option value="TEMPORARY">{t.temporary}</option></select></label><label>{t.expires}<input type="datetime-local" name="expiresAt" /></label><button type="submit">{t.save}</button></form>)}
        {pendingFeatureRequests.map((request) => <form action={reviewCoreFeaturePermissionRequest} method="post" key={request.requestKey}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={request.requestKey} /><strong>{request.permission.module.name}: {request.permission.label}</strong><span>{request.user.emailNormalized}</span><p>{request.reason}</p><label>{t.decision}<select name="decision"><option value="APPROVED">{t.approve}</option><option value="REJECTED">{t.reject}</option></select></label><label>{t.expires}<input type="datetime-local" name="expiresAt" /></label><button type="submit">{t.save}</button></form>)}
      </section> : null}
    </div></CoreShell>
  );
}
