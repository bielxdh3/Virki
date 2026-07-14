import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import {
  hubRegistry,
  type BielosLocale,
  type HubRegistryItemId
} from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../lib/cloudflare-access";
import { getCurrentSession } from "../lib/auth";
import { getLocale } from "./locale";
import { LanguageSelector } from "./language-selector";
import { getCoreOperationsSnapshot } from "./core/operations";

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
      "Workspace pessoal para projetos, segurança, operações e aplicações privadas. GymForge está disponível; módulos reservados permanecem inertes.",
    session: "Sessão",
    active: "Ativa",
    overviewTitle: "Sessão, segurança e stack local",
    coreOnly: "Core apenas",
    unlocked: "Desbloqueada",
    identity: "Identidade",
    role: "Papel",
    operations: "Operações",
    localStack: "Stack local",
    liveChecks: "Verificações nesta requisição",
    verified: "Verificado",
    unknown: "Desconhecido",
    configuredArchitecture: "Arquitetura configurada",
    configured: "Configurado",
    manualChecks: "Validação externa",
    manual: "Manual",
    hubRequest: "Processo do hub responde",
    databaseQuery: "Consulta mínima ao banco",
    authenticatedSession: "Sessão autenticada válida",
    publicSurface: "Site público separado",
    privateSurface: "Hub privado em duas camadas",
    loopbackPorts: "Portas de origem em loopback",
    containerHealth: "Saúde dos containers",
    externalRoutes: "Respostas dos domínios externos",
    migrationState: "Estado de migrações",
    honestStatus: "Sem telemetria simulada",
    twoLayers: "Duas camadas",
    quickActions: "Ações rápidas",
    safe: "Seguro",
    viewModules: "Ver módulos",
    viewProjects: "Abrir projetos",
    viewSecurity: "Gerenciar sessões",
    viewDeployment: "Ver status do deploy",
    registryTitle: "Core, aplicações e módulos reservados",
    coreWorkspace: "Workspace Core",
    availableApplications: "Aplicações disponíveis",
    sensitive: "Sensível",
    internal: "Interno",
    planned: "Planejado",
    available: "Disponível",
    reserved: "Reservado",
    open: "Abrir",
    reservedModules: "Módulos reservados",
    futureWork: "Módulos futuros permanecem inertes",
    noIngestion: "Os módulos reservados não possuem rotas ou ingestão. Aplicações existentes mantêm seus próprios limites privados."
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
      "Personal workspace for projects, security, operations, and private applications. GymForge is available; reserved modules remain inert.",
    session: "Session",
    active: "Active",
    overviewTitle: "Session, security, and local stack",
    coreOnly: "Core only",
    unlocked: "Unlocked",
    identity: "Identity",
    role: "Role",
    operations: "Operations",
    localStack: "Local stack",
    liveChecks: "Checks in this request",
    verified: "Verified",
    unknown: "Unknown",
    configuredArchitecture: "Configured architecture",
    configured: "Configured",
    manualChecks: "External validation",
    manual: "Manual",
    hubRequest: "Hub process responds",
    databaseQuery: "Minimal database query",
    authenticatedSession: "Authenticated session valid",
    publicSurface: "Separate public site",
    privateSurface: "Two-layer private hub",
    loopbackPorts: "Loopback origin ports",
    containerHealth: "Container health",
    externalRoutes: "External domain responses",
    migrationState: "Migration state",
    honestStatus: "No simulated telemetry",
    twoLayers: "Two layers",
    quickActions: "Quick Actions",
    safe: "Safe",
    viewModules: "View modules",
    viewProjects: "Open projects",
    viewSecurity: "Manage sessions",
    viewDeployment: "View deployment status",
    registryTitle: "Core, applications, and reserved modules",
    coreWorkspace: "Core workspace",
    availableApplications: "Available applications",
    sensitive: "Sensitive",
    internal: "Internal",
    planned: "Planned",
    available: "Available",
    reserved: "Reserved",
    open: "Open",
    reservedModules: "Reserved modules",
    futureWork: "Future modules remain inert",
    noIngestion: "Reserved modules have no routes or ingestion. Existing applications retain their own private boundaries."
  }
} satisfies Record<BielosLocale, Record<string, string>>;

function getRegistryDescriptions(locale: BielosLocale): Record<HubRegistryItemId, string> {
  const pt = locale === "pt-BR";

  return {
    "bielos-core": pt
      ? "Workspace privado para projetos, segurança pessoal e operações seguras."
      : "Private workspace for projects, personal security, and safe operations.",
    "core-projects": pt
      ? "Projetos autorizados, ciclo de vida e controle de acesso."
      : "Authorized projects, lifecycle, and access control.",
    "core-security": pt
      ? "Sessões pessoais com revogação segura e escopo por usuário."
      : "Personal sessions with safe user-scoped revocation.",
    "core-operations": pt
      ? "Estado verificável do hub e referências operacionais seguras."
      : "Verifiable hub state and safe operational references.",
    gymforge: pt
      ? "Aplicação privada de academia com presença, treinos, rankings, competições e pontuação."
      : "Private gym application with attendance, workouts, rankings, competitions, and scoring.",
    lvault: pt
      ? "Vault privado reservado, sem rota, armazenamento ou ingestão."
      : "Reserved private vault with no route, storage, or ingestion.",
    rootark: pt
      ? "Compartimentos zero-knowledge reservados; runtime permanece bloqueado."
      : "Reserved zero-knowledge compartments; runtime remains blocked.",
    hvault: pt
      ? "Área sensível reservada, sem dados ou runtime."
      : "Reserved sensitive area with no data or runtime."
  };
}

function getRegistryName(id: HubRegistryItemId, fallback: string, locale: BielosLocale): string {
  if (locale !== "pt-BR") {
    return fallback;
  }

  const names: Partial<Record<HubRegistryItemId, string>> = {
    "core-projects": "Workspace de projetos",
    "core-security": "Segurança e sessões",
    "core-operations": "Operações"
  };

  return names[id] ?? fallback;
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
  const registryDescriptions = getRegistryDescriptions(locale);
  const registryGroups = [
    {
      id: "core",
      title: t.coreWorkspace,
      items: hubRegistry.filter((item) => item.category === "core")
    },
    {
      id: "application",
      title: t.availableApplications,
      items: hubRegistry.filter((item) => item.category === "application")
    },
    {
      id: "reserved",
      title: t.reservedModules,
      items: hubRegistry.filter((item) => item.category === "reserved")
    }
  ] as const;
  const reservedModules = hubRegistry.filter((item) => item.category === "reserved");
  const csrfToken = createCsrfToken();
  const operationsSnapshot = await getCoreOperationsSnapshot();
  const liveChecks = [
    { label: t.hubRequest, state: operationsSnapshot.hubRequest },
    { label: t.databaseQuery, state: operationsSnapshot.database },
    { label: t.authenticatedSession, state: operationsSnapshot.authenticatedSession }
  ];
  const configuredArchitecture = [
    t.publicSurface,
    t.privateSurface,
    t.loopbackPorts
  ];
  const manualChecks = [
    t.containerHealth,
    t.externalRoutes,
    t.migrationState
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
          <img src="/hub-mark.svg" alt="" width={64} height={64} />
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
              <strong className="status-pill">{t.honestStatus}</strong>
            </div>
            <div className="core-operations-groups">
              <section>
                <h3>{t.liveChecks}</h3>
                <div className="status-list">
                  {liveChecks.map((item) => (
                    <div key={item.label}>
                      <span>{item.label}</span>
                      <strong className={item.state === "verified" ? "is-verified" : "is-unknown"}>
                        {item.state === "verified" ? t.verified : t.unknown}
                      </strong>
                    </div>
                  ))}
                </div>
              </section>
              <section>
                <h3>{t.configuredArchitecture}</h3>
                <div className="status-list">
                  {configuredArchitecture.map((label) => (
                    <div key={label}>
                      <span>{label}</span>
                      <strong>{t.configured}</strong>
                    </div>
                  ))}
                </div>
              </section>
              <section>
                <h3>{t.manualChecks}</h3>
                <div className="status-list">
                  {manualChecks.map((label) => (
                    <div key={label}>
                      <span>{label}</span>
                      <strong className="is-unknown">{t.manual}</strong>
                    </div>
                  ))}
                </div>
              </section>
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
              <a href="/core/projects">{t.viewProjects}</a>
              <a href="/core/security">{t.viewSecurity}</a>
              <a href="#ops">{t.viewDeployment}</a>
              <form action="/api/logout" method="post">
                <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                <button type="submit">{t.logout}</button>
              </form>
            </div>
          </article>
        </section>

        <section className="module-window anchor-section" id="modules" aria-label={t.registryTitle}>
          <div className="window-titlebar">
            <div>
              <span>Registry</span>
              <strong>{t.registryTitle}</strong>
            </div>
          </div>

          <div className="hub-registry-groups">
            {registryGroups.map((group) => (
              <section className="hub-registry-group" key={group.id} aria-labelledby={`registry-${group.id}`}>
                <div className="hub-registry-heading">
                  <h2 id={`registry-${group.id}`}>{group.title}</h2>
                  <span>{group.items.length}</span>
                </div>

                <div className="module-grid">
                  {group.items.map((item) => (
                    <article
                      className={`module-card ${
                        item.sensitivity === "sensitive" ? "is-sensitive" : ""
                      } ${item.status !== "reserved" ? "is-active" : ""}`}
                      key={item.id}
                    >
                      <div className="module-card-header">
                        <span className="module-icon">{item.shortName}</span>
                        <span className="module-class">
                          {item.sensitivity === "sensitive" ? t.sensitive : t.internal}
                        </span>
                      </div>
                      <h2>{getRegistryName(item.id, item.name, locale)}</h2>
                      <p>{registryDescriptions[item.id]}</p>
                      <div className="module-tags">
                        <span className={item.status === "reserved" ? "is-reserved" : "is-active"}>
                          {item.status === "active"
                            ? t.active
                            : item.status === "available"
                              ? t.available
                              : t.reserved}
                        </span>
                        <span>{group.title}</span>
                      </div>
                      {"href" in item ? <a href={item.href}>{t.open}</a> : null}
                    </article>
                  ))}
                </div>
              </section>
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
