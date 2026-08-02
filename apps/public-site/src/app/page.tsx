import type { BielosLocale } from "@bielos/ui";
import { getLocale } from "./locale";
import { LanguageSelector } from "./language-selector";

const publicProjects = {
  "pt-BR": [
    {
      name: "BielOS Core",
      description: "Interface central e ponto de entrada público do projeto BielOS.",
      status: "Público"
    },
    {
      name: "L-vault",
      description: "Espaço reservado para futuras ferramentas pessoais.",
      status: "Reservado"
    },
    {
      name: "root.ark",
      description: "Espaço reservado para futuros fluxos de arquivo.",
      status: "Reservado"
    },
    {
      name: "H-vault",
      description: "Espaço reservado para futura organização de dados.",
      status: "Reservado"
    },
    {
      name: "GymForge",
      description: "Aplicação privada disponível no hub autenticado; a expansão de recursos permanece congelada.",
      status: "Privado"
    }
  ],
  en: [
    {
      name: "BielOS Core",
      description: "Core interface and public entry point for the BielOS project.",
      status: "Public"
    },
    {
      name: "L-vault",
      description: "Reserved module space for future personal tooling.",
      status: "Reserved"
    },
    {
      name: "root.ark",
      description: "Reserved module space for future archive workflows.",
      status: "Reserved"
    },
    {
      name: "H-vault",
      description: "Reserved module space for future organized storage.",
      status: "Reserved"
    },
    {
      name: "GymForge",
      description: "Private application available in the authenticated hub; further feature expansion remains frozen.",
      status: "Private"
    }
  ]
} satisfies Record<BielosLocale, Array<{ name: string; description: string; status: string }>>;

const copy = {
  "pt-BR": {
    shellLabel: "Página pública BielOS",
    statusLabel: "Status público",
    status: "Status público disponível",
    description:
      "Um hub pessoal em estilo sistema operacional para projetos, ferramentas, arquivos, automação e laboratórios técnicos.",
    enterHub: "Entrar no hub",
    apply: "Solicitar acesso",
    projectsLabel: "Projetos públicos",
    footerStatus: "Status geral: disponível",
    footerSurface: "Superfície pública apenas",
    language: "Idioma"
  },
  en: {
    shellLabel: "BielOS public landing",
    statusLabel: "Public status",
    status: "Public status available",
    description:
      "A personal operating-system-style hub for projects, tools, archives, automation, and technical labs.",
    enterHub: "Enter hub",
    apply: "Request access",
    projectsLabel: "Public projects",
    footerStatus: "Generic status: available",
    footerSurface: "Public surface only",
    language: "Language"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const hubUrl = process.env.NEXT_PUBLIC_HUB_URL ?? "https://hub.biel.dev.br";

export default async function PublicLandingPage() {
  const locale = await getLocale();
  const t = copy[locale];

  return (
    <main className="os-screen">
      <section className="desktop-shell" aria-label={t.shellLabel}>
        <header className="top-bar">
          <div className="brand-lockup">
            <img src="/bielos-mark.svg" alt="" className="brand-mark" />
            <span>BielOS</span>
          </div>
          <div className="top-actions">
            <LanguageSelector locale={locale} label={t.language} />
            <div className="status-pill" aria-label={t.statusLabel}>
              <span className="pulse" />
              {t.status}
            </div>
          </div>
        </header>

        <section className="hero-panel">
          <div className="terminal-strip">
            <span />
            <span />
            <span />
          </div>
          <p className="eyebrow">biel.dev.br</p>
          <h1>BielOS</h1>
          <p className="description">{t.description}</p>
          <div className="public-actions">
            <a className="enter-button" href={hubUrl}>{t.enterHub}</a>
            <a className="secondary-button" href="/apply">{t.apply}</a>
          </div>
        </section>

        <section className="project-grid" aria-label={t.projectsLabel}>
          {publicProjects[locale].map((project) => (
            <article className="project-card" key={project.name}>
              <div>
                <p className="card-kicker">{project.status}</p>
                <h2>{project.name}</h2>
              </div>
              <p>{project.description}</p>
            </article>
          ))}
        </section>

        <footer className="status-line">
          <span>{t.footerStatus}</span>
          <span>{t.footerSurface}</span>
        </footer>
      </section>
    </main>
  );
}
