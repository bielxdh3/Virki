import { createCsrfToken } from "@bielos/auth/csrf";
import { getAccountSecurityState, listTrustedDevices } from "@bielos/auth/security";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getLocale } from "../../../locale";
import { LanguageSelector } from "../../../language-selector";
import { AccountSecurityPanel, TrustedDeviceList } from "../account-security-panel";
import { CoreShell } from "../../shell";

export const dynamic = "force-dynamic";

export default async function AccountSecurityPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-account-security"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const locale = await getLocale();
  const [state, devices] = await Promise.all([getAccountSecurityState(session.user.id), listTrustedDevices(session.user.id)]);
  const csrfToken = createCsrfToken();
  return <CoreShell variant="docked" locale={locale} role={session.user.role} activePath="/core/security/account"><div className="core-security-workspace"><header className="top-statusbar"><a href="/core/security">{locale === "pt-BR" ? "Voltar à segurança" : "Back to security"}</a><LanguageSelector locale={locale} label={locale === "pt-BR" ? "Idioma" : "Language"} returnTo="/core/security/account" /></header><header className="core-security-intro"><p className="eyebrow">BielOS Core</p><h1>{locale === "pt-BR" ? "Segurança da conta" : "Account security"}</h1><p>{locale === "pt-BR" ? "Gerencie seu segundo fator e os dispositivos confiáveis." : "Manage your second factor and trusted devices."}</p></header><AccountSecurityPanel csrfToken={csrfToken} totpActive={state?.totpStatus === "ACTIVE"} recoveryCodeCount={state?.recoveryCodeCount ?? 0} /><TrustedDeviceList csrfToken={csrfToken} devices={devices} locale={locale} /></div></CoreShell>;
}
