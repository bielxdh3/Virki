import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../lib/cloudflare-access";
import { getCurrentSession } from "../lib/auth";
import { getLocale } from "./locale";
import { LanguageSelector } from "./language-selector";

export const dynamic = "force-dynamic";

const copy = {
  "pt-BR": {
    privateHub: "Hub privado",
    navLabel: "Navegação BielOS",
    primary: "Principal",
    overview: "Visão geral",
    modules: "Módulos",
    security: "Segurança",
    ops: "Ops",
    status: "Status",
    running: "Em execução",
    protected: "Protegido",
    language: "Idioma",
    logout: "Sair",
    systemIdentity: "Identidade do sistema",
    workspace: "Workspace",
    hero:
      "Workspace pessoal para projetos, ferramentas, arquivos, automação e laboratórios técnicos. Os módulos ficam bloqueados até cada um ter seu próprio desenho de segurança e dados.",
    session: "Sessão",
    active: "Ativa",
    overviewTitle: "Sessão, segurança e stack local",
    coreOnly: "Core apenas",
    unlocked: "Desbloqueada",
    identity: "Identidade",
    role: "Papel",
    operations: "Operações",
    localStack: "Stack local",
    twoLayers: "Duas camadas",
    quickActions: "Ações rápidas",
    safe: "Seguro",
    viewModules: "Ver módulos",
    viewDeployment: "Ver status do deploy",
    coreReserved: "Core e áreas reservadas",
    sensitive: "Sensível",
    internal: "Interno",
    planned: "Planejado",
    openFoundation: "Abrir fundação",
    reservedModules: "Módulos reservados",
    futureWork: "Trabalho futuro de módulos ainda não está ativo",
    noIngestion: "A ingestão de dados privados ainda é específica por módulo e não está habilitada por este shell."
  },
  en: {
    privateHub: "Private Hub",
    navLabel: "BielOS navigation",
    primary: "Primary",
    overview: "Overview",
    modules: "Modules",
    security: "Security",
    ops: "Ops",
    status: "Status",
    running: "Running",
    protected: "Protected",
    language: "Language",
    logout: "Log out",
    systemIdentity: "System identity",
    workspace: "Workspace",
    hero:
      "Personal workspace for projects, tools, archives, automation, and technical labs. Modules stay locked until each one has its own security and data design.",
    session: "Session",
    active: "Active",
    overviewTitle: "Session, security, and local stack",
    coreOnly: "Core only",
    unlocked: "Unlocked",
    identity: "Identity",
    role: "Role",
    operations: "Operations",
    localStack: "Local stack",
    twoLayers: "Two layers",
    quickActions: "Quick Actions",
    safe: "Safe",
    viewModules: "View modules",
    viewDeployment: "View deployment status",
    coreReserved: "Core and reserved areas",
    sensitive: "Sensitive",
    internal: "Internal",
    planned: "Planned",
    openFoundation: "Open foundation",
    reservedModules: "Reserved modules",
    futureWork: "Future module work is not active yet",
    noIngestion: "Private data ingestion is still module-specific and is not enabled by this shell."
  }
} satisfies Record<BielosLocale, Record<string, string>>;

function getModuleCards(locale: BielosLocale) {
  const pt = locale === "pt-BR";

  return [
    {
      name: "BielOS Core",
      shortName: "BC",
      description: pt
        ? "Shell central do workspace e placeholder do registro de módulos."
        : "Core workspace shell and module registry placeholder.",
      status: pt ? "Shell apenas" : "Shell only",
      sensitivity: "internal"
    },
    {
      name: "L-vault",
      shortName: "LV",
      description: pt
        ? "Área de vault privado planejada. Armazenamento e ingestão não estão habilitados."
        : "Planned private vault area. No storage or ingestion is enabled.",
      status: pt ? "Bloqueado" : "Locked",
      sensitivity: "sensitive"
    },
    {
      name: "root.ark",
      shortName: "RA",
      description: pt
        ? "Área de arquivo planejada. Documentos e registros não são aceitos."
        : "Planned archive area. No documents or records are accepted.",
      status: pt ? "Bloqueado" : "Locked",
      sensitivity: "sensitive"
    },
    {
      name: "H-vault",
      shortName: "HV",
      description: pt
        ? "Área sensível planejada. Nenhum dado de saúde ou privado existe aqui."
        : "Planned sensitive vault area. No health or private data exists here.",
      status: pt ? "Bloqueado" : "Locked",
      sensitivity: "sensitive"
    },
    {
      name: "GymForge",
      shortName: "GF",
      description: pt
        ? "Fundação de competição de academia com acesso fechado. Tracking e uploads não estão habilitados."
        : "Gated gym competition foundation. Tracking and uploads are not enabled.",
      status: pt ? "Fundação" : "Foundation",
      sensitivity: "internal",
      href: "/gymforge"
    }
  ];
}

export default async function HubDashboardPage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "hub-dashboard");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const locale = await getLocale();
  const t = copy[locale];
  const moduleCards = getModuleCards(locale);
  const reservedModules = moduleCards;
  const csrfToken = createCsrfToken();
  const deploymentStatus = [
    { label: locale === "pt-BR" ? "Site público" : "Public site", value: locale === "pt-BR" ? "Disponível" : "Available" },
    { label: "Hub", value: t.protected },
    { label: "Tunnel", value: locale === "pt-BR" ? "Gerenciado" : "Managed" },
    { label: locale === "pt-BR" ? "Dados de módulos" : "Module data", value: locale === "pt-BR" ? "Não montado" : "Not mounted" }
  ];
  const securityLayers = [
    {
      name: "Cloudflare Access",
      description:
        locale === "pt-BR"
          ? "Verificação externa antes do hub ser alcançado."
          : "External access check before the hub is reached.",
      state: locale === "pt-BR" ? "Primeira" : "First"
    },
    {
      name: "BielOS Internal Auth",
      description:
        locale === "pt-BR"
          ? "Sessão local da aplicação para o hub privado."
          : "Local application session for the private hub.",
      state: locale === "pt-BR" ? "Segunda" : "Second"
    }
  ];

  return (
    <main className="hub-shell">
      <aside className="os-dock" aria-label={t.navLabel}>
        <div className="dock-identity">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <strong>BielOS</strong>
            <span>{t.privateHub}</span>
          </div>
        </div>

        <nav className="dock-nav" aria-label={t.primary}>
          <a href="#overview" aria-label={t.overview}>
            <span aria-hidden="true">01</span>
            <strong>{t.overview}</strong>
          </a>
          <a href="#modules" aria-label={t.modules}>
            <span aria-hidden="true">02</span>
            <strong>{t.modules}</strong>
          </a>
          <a href="#security" aria-label={t.security}>
            <span aria-hidden="true">03</span>
            <strong>{t.security}</strong>
          </a>
          <a href="#ops" aria-label={t.ops}>
            <span aria-hidden="true">04</span>
            <strong>{t.ops}</strong>
          </a>
        </nav>

        <div className="dock-footer">
          <span>{t.status}</span>
          <strong>{t.running}</strong>
        </div>
      </aside>

      <section className="hub-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>hub.biel.dev.br</span>
            <span>{t.protected}</span>
          </div>
          <div className="top-actions">
            <LanguageSelector locale={locale} label={t.language} />
            <form action="/api/logout" method="post">
              <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
              <button className="icon-command" type="submit" aria-label={t.logout}>
                <span>{t.logout}</span>
              </button>
            </form>
          </div>
        </header>

        <section className="identity-panel anchor-section" id="overview" aria-label={t.systemIdentity}>
          <div>
            <p className="eyebrow">BielOS Hub</p>
            <h1>{t.workspace}</h1>
            <p>{t.hero}</p>
          </div>
          <div className="identity-meter" aria-label="Core readiness">
            <span>{t.session}</span>
            <strong>{t.active}</strong>
          </div>
        </section>

        <div className="section-heading">
          <div>
            <p className="eyebrow">Overview</p>
            <h2>{t.overviewTitle}</h2>
          </div>
          <span>{t.coreOnly}</span>
        </div>

        <section className="dashboard-grid" aria-label="BielOS Hub">
          <article className="panel session-panel">
            <div className="panel-title">
              <span>{t.session}</span>
              <strong className="status-pill is-active">{t.unlocked}</strong>
            </div>
            <div className="session-avatar" aria-hidden="true">
              {session.user.email.slice(0, 2).toUpperCase()}
            </div>
            <dl className="detail-list">
              <div>
                <dt>{t.identity}</dt>
                <dd>{session.user.email}</dd>
              </div>
              <div>
                <dt>{t.role}</dt>
                <dd>{session.user.role}</dd>
              </div>
            </dl>
          </article>

          <article className="panel deployment-panel anchor-section" id="ops">
            <div className="panel-title">
              <span>{t.operations}</span>
              <strong className="status-pill">{t.localStack}</strong>
            </div>
            <div className="status-list">
              {deploymentStatus.map((item) => (
                <div key={item.label}>
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </article>

          <article className="panel security-panel anchor-section" id="security">
            <div className="panel-title">
              <span>{t.security}</span>
              <strong className="status-pill is-guarded">{t.twoLayers}</strong>
            </div>
            <div className="layer-stack">
              {securityLayers.map((layer) => (
                <div className="layer-item" key={layer.name}>
                  <span>{layer.state}</span>
                  <div>
                    <strong>{layer.name}</strong>
                    <p>{layer.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="panel quick-actions">
            <div className="panel-title">
              <span>{t.quickActions}</span>
              <strong className="status-pill">{t.safe}</strong>
            </div>
            <div className="action-stack">
              <a href="#modules">{t.viewModules}</a>
              <a href="#ops">{t.viewDeployment}</a>
              <form action="/api/logout" method="post">
                <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                <button type="submit">{t.logout}</button>
              </form>
            </div>
          </article>
        </section>

        <section className="module-window anchor-section" id="modules" aria-label="Module grid">
          <div className="window-titlebar">
            <div>
              <span>Modules</span>
              <strong>{t.coreReserved}</strong>
            </div>
          </div>

          <div className="module-grid">
            {moduleCards.map((module) => (
              <article
                className={`module-card ${
                  module.sensitivity === "sensitive" ? "is-sensitive" : ""
                }`}
                key={module.name}
              >
                <div className="module-card-header">
                  <span className="module-icon">{module.shortName}</span>
                  <span className="module-class">
                    {module.sensitivity === "sensitive" ? t.sensitive : t.internal}
                  </span>
                </div>
                <h2>{module.name}</h2>
                <p>{module.description}</p>
                <div className="module-tags">
                  <span className="is-reserved">{module.status}</span>
                  <span>{t.planned}</span>
                </div>
                {"href" in module ? <a href={module.href}>{t.openFoundation}</a> : null}
              </article>
            ))}
          </div>
        </section>

        <section className="reserved-strip" aria-label="Reserved modules">
          <div>
            <p className="eyebrow">{t.reservedModules}</p>
            <h2>{t.futureWork}</h2>
            <p>{t.noIngestion}</p>
          </div>
          <div className="reserved-list">
            {reservedModules.map((module) => (
              <span key={module.name}>{module.name}</span>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
