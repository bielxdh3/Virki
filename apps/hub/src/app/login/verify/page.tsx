import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";

export const dynamic = "force-dynamic";

const copy = {
  "pt-BR": { title: "Verificação de segurança", email: "Informe o código enviado por e-mail.", totp: "Informe o código do aplicativo autenticador.", code: "Código", submit: "Continuar", error: "Não foi possível validar este código.", language: "Idioma" },
  en: { title: "Security verification", email: "Enter the code sent by email.", totp: "Enter the code from your authenticator app.", code: "Code", submit: "Continue", error: "This code could not be verified.", language: "Language" }
} satisfies Record<BielosLocale, Record<string, string>>;

export default async function LoginVerificationPage({ searchParams }: { searchParams?: Promise<{ ceremony?: string; factor?: string; error?: string }> }) {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "hub-login-verification-page"))) forbidden();
  if (await getCurrentSession()) redirect("/");
  const params = await searchParams;
  const ceremony = params?.ceremony ?? "";
  const factor = params?.factor === "totp" ? "totp" : "email";
  const locale = await getLocale();
  const t = copy[locale];
  const csrfToken = createCsrfToken();
  return <main className="login-screen"><section className="login-window" aria-label={t.title}><div className="login-language"><LanguageSelector locale={locale} label={t.language} /></div><div className="login-brand"><img src="/hub-mark.svg" alt="" /><div><p className="eyebrow">hub.biel.dev.br</p><h1>BielOS Hub</h1></div></div><form className="login-form" action="/api/login/verify" method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="ceremony" value={ceremony} /><input type="hidden" name="factor" value={factor} /><p>{factor === "totp" ? t.totp : t.email}</p><label>{t.code}<input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>{params?.error ? <p className="login-error" role="alert">{t.error}</p> : null}<button type="submit">{t.submit}</button></form></section></main>;
}
