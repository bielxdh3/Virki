import { createCsrfToken } from "@bielos/auth/csrf";
import { getCurrentSession } from "../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getLocale } from "../../../locale";
import { LanguageSelector } from "../../../language-selector";
import { getAdministrativeCredentialState, listActiveSecurityElevations } from "@bielos/auth/administration";
import { listPendingAccountRecoveries } from "@bielos/auth/security";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { AdminSecurityPanel } from "../admin-panel";
import { CoreShell } from "../../shell";
import { approveRecoveryAction } from "../../../recover/actions";
import { CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

export const dynamic = "force-dynamic";

export default async function AdministrativeSecurityPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-administrative-security"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  if (session.user.role !== "OWNER") forbidden();
  const locale = await getLocale();
  const [credential, elevations, recoveries] = await Promise.all([getAdministrativeCredentialState(session.user.id), listActiveSecurityElevations(session.user, session.id), listPendingAccountRecoveries(session.user)]);
  const csrfToken = createCsrfToken();
  return <CoreShell variant="standalone" locale={locale} role={session.user.role} activePath="/core/security/admin"><div className="core-security-workspace"><header className="top-statusbar"><a href="/core/security">{locale === "pt-BR" ? "Voltar à segurança" : "Back to security"}</a><LanguageSelector locale={locale} label={locale === "pt-BR" ? "Idioma" : "Language"} returnTo="/core/security/admin" /></header><header className="core-security-intro"><p className="eyebrow">BielOS Core</p><h1>{locale === "pt-BR" ? "Segurança administrativa" : "Administrative security"}</h1><p>{locale === "pt-BR" ? "Credencial administrativa separada e elevação vinculada à sessão." : "Separate administrative credential and session-bound elevation."}</p></header><AdminSecurityPanel csrfToken={csrfToken} credentialConfigured={credential?.status === "ACTIVE"} activeElevations={elevations} /><section className="panel"><h2>{locale === "pt-BR" ? "Aprovações de recuperação de conta" : "Account recovery approvals"}</h2>{recoveries.length === 0 ? <p>{locale === "pt-BR" ? "Nenhuma." : "None."}</p> : <ul>{recoveries.map((item) => <li key={item.requestKey}><span>{item.user.displayName ?? item.user.emailNormalized}</span><form action={approveRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={item.requestKey} /><button type="submit">{locale === "pt-BR" ? "Aprovar recuperação" : "Approve recovery"}</button></form></li>)}</ul>}</section></div></CoreShell>;
}
