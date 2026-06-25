import type { BielosLocale } from "@bielos/ui";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getLocale } from "../locale";
import { LanguageSelector } from "../language-selector";

export const dynamic = "force-dynamic";

type LoginPageProps = {
  searchParams?: Promise<{
    error?: string;
  }>;
};

const copy = {
  "pt-BR": {
    loginLabel: "Login interno BielOS",
    language: "Idioma",
    identity: "Identidade de acesso",
    passphrase: "Senha",
    error: "E-mail ou senha inválidos.",
    unlock: "Desbloquear hub",
    note: "O acesso interno é obrigatório antes do hub privado abrir."
  },
  en: {
    loginLabel: "BielOS internal login",
    language: "Language",
    identity: "Access identity",
    passphrase: "Passphrase",
    error: "Invalid email or password.",
    unlock: "Unlock hub",
    note: "Internal access is required before the private hub can open."
  }
} satisfies Record<BielosLocale, Record<string, string>>;

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "hub-login-page");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();
  const params = await searchParams;

  if (session) {
    redirect("/");
  }

  const locale = await getLocale();
  const t = copy[locale];
  const csrfToken = createCsrfToken();

  return (
    <main className="login-screen">
      <section className="login-window" aria-label={t.loginLabel}>
        <div className="login-language">
          <LanguageSelector locale={locale} label={t.language} returnTo="/login" />
        </div>
        <div className="login-brand">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <p className="eyebrow">hub.biel.dev.br</p>
            <h1>BielOS Hub</h1>
          </div>
        </div>

        <form className="login-form" action="/api/login" method="post">
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <label>
            {t.identity}
            <input type="email" name="email" autoComplete="email" required />
          </label>
          <label>
            {t.passphrase}
            <input type="password" name="password" autoComplete="current-password" required />
          </label>
          {params?.error ? (
            <p className="login-error" role="alert">
              {t.error}
            </p>
          ) : null}
          <button type="submit">{t.unlock}</button>
        </form>

        <p className="login-note">{t.note}</p>
      </section>
    </main>
  );
}
