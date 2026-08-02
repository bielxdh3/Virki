import type { BielosLocale } from "@bielos/ui";
import { getLocale } from "../locale";
import { LanguageSelector } from "../language-selector";
import { ApplyForm } from "./apply-form";

const copy = {
  "pt-BR": {
    title: "Solicitar acesso",
    description: "Envie uma solicitação para os módulos públicos disponíveis. A análise só começa após a verificação do e-mail.",
    back: "Voltar ao BielOS",
    language: "Idioma",
    unavailable: "As solicitações públicas estão temporariamente indisponíveis.",
    modules: "Módulos públicos requestáveis",
    reason: "Explique o motivo do acesso",
    email: "E-mail",
    displayName: "Nome (opcional)",
    submit: "Enviar solicitação",
    gymforge: "GymForge",
    aip: "AIP",
    rootark: "root.ark",
    runtimeAvailable: "Runtime disponível",
    runtimeUnavailable: "Runtime ainda indisponível"
  },
  en: {
    title: "Request access",
    description: "Submit a request for public requestable modules. Review starts only after email verification.",
    back: "Back to BielOS",
    language: "Language",
    unavailable: "Public requests are temporarily unavailable.",
    modules: "Public requestable modules",
    reason: "Explain why you need access",
    email: "Email",
    displayName: "Name (optional)",
    submit: "Submit request",
    gymforge: "GymForge",
    aip: "AIP",
    rootark: "root.ark",
    runtimeAvailable: "Runtime available",
    runtimeUnavailable: "Runtime not available yet"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const modules = [
  { key: "gymforge", name: "GymForge", available: true },
  { key: "aip", name: "AIP", available: false },
  { key: "rootark", name: "root.ark", available: false }
] as const;

export default async function ApplyPage() {
  const locale = await getLocale();
  const t = copy[locale];
  const intakeUrl = process.env.NEXT_PUBLIC_INTAKE_URL?.trim() ?? "";

  return (
    <main className="os-screen">
      <section className="desktop-shell apply-shell" aria-label={t.title}>
        <header className="top-bar">
          <a href="/" className="brand-lockup">
            <img src="/bielos-mark.svg" alt="" className="brand-mark" />
            <span>{t.back}</span>
          </a>
          <LanguageSelector locale={locale} label={t.language} />
        </header>
        <section className="apply-panel">
          <p className="eyebrow">biel.dev.br/apply</p>
          <h1>{t.title}</h1>
          <p className="description">{t.description}</p>
          {!intakeUrl && <p className="apply-unavailable">{t.unavailable}</p>}
          <ApplyForm locale={locale} copy={t} modules={modules} apiUrl={intakeUrl} />
        </section>
      </section>
    </main>
  );
}
