import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getLocale } from "../locale";
import { LanguageSelector } from "../language-selector";
import { completeRecoveryAction, requestRecoveryAction, verifyRecoveryAction } from "./actions";

export const dynamic = "force-dynamic";
const copy = { "pt-BR": { title: "Recuperar conta", note: "Se houver uma conta elegível, enviaremos instruções para o e-mail verificado.", email: "E-mail", request: "Enviar instruções", code: "Código", verify: "Verificar e-mail", password: "Nova senha", complete: "Concluir recuperação", pending: "A recuperação aguarda aprovação administrativa.", error: "Não foi possível concluir esta etapa.", language: "Idioma" }, en: { title: "Recover account", note: "If an eligible account exists, instructions will be sent to its verified email.", email: "Email", request: "Send instructions", code: "Code", verify: "Verify email", password: "New password", complete: "Complete recovery", pending: "Recovery is waiting for administrative approval.", error: "This step could not be completed.", language: "Language" } } satisfies Record<BielosLocale, Record<string, string>>;

export default async function RecoverPage({ searchParams }: { searchParams?: Promise<{ request?: string; sent?: string; verified?: string; error?: string }> }) {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "account-recovery-page"))) forbidden();
  const params = await searchParams;
  const locale = await getLocale();
  const t = copy[locale];
  const csrfToken = createCsrfToken();
  const requestKey = params?.request ?? "";
  return <main className="login-screen"><section className="login-window" aria-label={t.title}><div className="login-language"><LanguageSelector locale={locale} label={t.language} /></div><h1>{t.title}</h1><p>{t.note}</p><form className="login-form" action={requestRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><label>{t.email}<input type="email" name="email" autoComplete="email" required /></label><button type="submit">{t.request}</button></form>{params?.sent ? <p role="status">{t.note}</p> : null}{requestKey ? <><form className="login-form" action={verifyRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={requestKey} /><label>{t.code}<input name="code" inputMode="numeric" pattern="[0-9]{6}" required /></label><button type="submit">{t.verify}</button></form><p>{t.pending}</p><form className="login-form" action={completeRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={requestKey} /><label>{t.password}<input type="password" name="newPassword" minLength={12} autoComplete="new-password" required /></label><button type="submit">{t.complete}</button></form></> : null}{params?.error ? <p className="login-error" role="alert">{t.error}</p> : null}</section></main>;
}
