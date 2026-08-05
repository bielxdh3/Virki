import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getCurrentSession } from "../../../lib/auth";
import { getLocale } from "../../locale";
import { LanguageSelector } from "../../language-selector";
import { CoreShell } from "../shell";
import { isCoreAdministrator } from "../authorization";
import { createCoreProject } from "./actions";
import { getCoreProjectDetailPath } from "./detail-policy";
import { CoreProjectAdminControls } from "./project-admin-controls";
import {
  CORE_PROJECT_READ_LIMIT,
  listCoreProjectsForPrincipal
} from "./read-service";

export const dynamic = "force-dynamic";

const PROJECT_LIMIT = CORE_PROJECT_READ_LIMIT;

const copy = {
  "pt-BR": {
    privateHub: "Hub privado",
    navLabel: "Navegação BielOS Core",
    primary: "Principal",
    returnHub: "Voltar ao hub",
    projects: "Projetos",
    protected: "Protegido",
    language: "Idioma",
    workspace: "Workspace de projetos",
    eyebrow: "BielOS Core",
    intro: "Projetos autorizados, ciclo de vida e acesso em uma visão privada e compacta.",
    projectCount: "projetos visíveis",
    adminTools: "Administração",
    createProject: "Criar projeto",
    createSummary: "Novo projeto",
    name: "Nome",
    slug: "Slug",
    description: "Descrição",
    optional: "opcional",
    visibility: "Visibilidade",
    status: "Status",
    access: "Acesso",
    updated: "Atualizado",
    save: "Salvar alterações",
    create: "Criar projeto",
    edit: "Editar projeto",
    archive: "Arquivar",
    archiveProject: "Arquivar projeto",
    archiveConfirm: "Confirmo que este projeto ficará somente leitura.",
    noDelete: "A exclusão permanente não está disponível.",
    empty: "Nenhum projeto disponível para esta conta.",
    emptyAdmin: "Crie o primeiro projeto pelo controle de administração acima.",
    emptyMember: "Um administrador pode conceder acesso a projetos internos.",
    archived: "Arquivado",
    archivedNote: "Projeto preservado em modo somente leitura.",
    public: "Público no hub",
    internal: "Interno",
    sensitive: "Sensível",
    planned: "Planejado",
    reserved: "Reservado",
    active: "Ativo",
    paused: "Pausado",
    viewer: "Visualizador",
    editor: "Editor",
    owner: "Responsável",
    administrator: "Administrador",
    authenticated: "Usuário autenticado",
    actions: "Ações administrativas",
    editDetails: "Editar metadados",
    accessDetails: "Gerenciar acesso",
    grantAccess: "Conceder ou alterar acesso",
    selectUser: "Selecionar usuário",
    accessLevel: "Nível de acesso",
    applyAccess: "Aplicar acesso",
    currentAccess: "Acessos atuais",
    noAccess: "Nenhum acesso explícito adicional.",
    inactiveUser: "Inativo",
    activeUser: "Ativo",
    revokeAccess: "Revogar",
    accessLimit: "Até 100 acessos exibidos por projeto.",
    archiveDetails: "Área de arquivamento",
    slugHint: "Letras minúsculas, números e hífens simples.",
    limitNote: "Lista limitada aos 100 projetos mais recentes.",
    openProject: "Abrir projeto"
  },
  en: {
    privateHub: "Private Hub",
    navLabel: "BielOS Core navigation",
    primary: "Primary",
    returnHub: "Back to hub",
    projects: "Projects",
    protected: "Protected",
    language: "Language",
    workspace: "Project workspace",
    eyebrow: "BielOS Core",
    intro: "Authorized projects, lifecycle, and access in a compact private view.",
    projectCount: "visible projects",
    adminTools: "Administration",
    createProject: "Create project",
    createSummary: "New project",
    name: "Name",
    slug: "Slug",
    description: "Description",
    optional: "optional",
    visibility: "Visibility",
    status: "Status",
    access: "Access",
    updated: "Updated",
    save: "Save changes",
    create: "Create project",
    edit: "Edit project",
    archive: "Archive",
    archiveProject: "Archive project",
    archiveConfirm: "I understand this project will become read-only.",
    noDelete: "Permanent deletion is not available.",
    empty: "No projects are available to this account.",
    emptyAdmin: "Create the first project from the administration control above.",
    emptyMember: "An administrator can grant access to internal projects.",
    archived: "Archived",
    archivedNote: "Project preserved in read-only mode.",
    public: "Hub public",
    internal: "Internal",
    sensitive: "Sensitive",
    planned: "Planned",
    reserved: "Reserved",
    active: "Active",
    paused: "Paused",
    viewer: "Viewer",
    editor: "Editor",
    owner: "Owner",
    administrator: "Administrator",
    authenticated: "Authenticated user",
    actions: "Administrative actions",
    editDetails: "Edit metadata",
    accessDetails: "Manage access",
    grantAccess: "Grant or change access",
    selectUser: "Select user",
    accessLevel: "Access level",
    applyAccess: "Apply access",
    currentAccess: "Current access",
    noAccess: "No additional explicit access.",
    inactiveUser: "Inactive",
    activeUser: "Active",
    revokeAccess: "Revoke",
    accessLimit: "Up to 100 access rows are shown per project.",
    archiveDetails: "Archive area",
    slugHint: "Lowercase letters, numbers, and single hyphens.",
    limitNote: "List limited to the 100 most recently updated projects.",
    openProject: "Open project"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const visibilityValues = ["PUBLIC", "INTERNAL", "SENSITIVE"] as const;
const statusValues = ["PLANNED", "RESERVED", "ACTIVE", "PAUSED"] as const;

function getVisibilityLabel(value: string, t: (typeof copy)[BielosLocale]): string {
  const labels: Record<string, string> = {
    PUBLIC: t.public,
    INTERNAL: t.internal,
    SENSITIVE: t.sensitive
  };

  return labels[value] ?? value;
}

function getStatusLabel(value: string, t: (typeof copy)[BielosLocale]): string {
  const labels: Record<string, string> = {
    PLANNED: t.planned,
    RESERVED: t.reserved,
    ACTIVE: t.active,
    PAUSED: t.paused,
    ARCHIVED: t.archived
  };

  return labels[value] ?? value;
}

function getAccessLabel(
  accessLevel: string | undefined,
  visibility: string,
  isAdministrator: boolean,
  t: (typeof copy)[BielosLocale]
): string {
  if (isAdministrator) {
    return t.administrator;
  }

  const labels: Record<string, string> = {
    VIEWER: t.viewer,
    EDITOR: t.editor,
    OWNER: t.owner
  };

  return accessLevel ? (labels[accessLevel] ?? accessLevel) : visibility === "PUBLIC" ? t.authenticated : t.viewer;
}

function formatUpdatedAt(value: Date, locale: BielosLocale): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(value);
}

export default async function CoreProjectsPage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "core-projects");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const locale = await getLocale();
  const t = copy[locale];
  const isAdministrator = isCoreAdministrator(session.user.role);
  const csrfToken = createCsrfToken();
  const projects = await listCoreProjectsForPrincipal(session.user);
  const activeUsers = isAdministrator
    ? await prisma.user.findMany({
        where: { isActive: true },
        select: { id: true, email: true, displayName: true, role: true },
        orderBy: { email: "asc" },
        take: 200
      })
    : [];

  return (
    <CoreShell
      variant="docked"
      locale={locale}
      role={session.user.role}
      activePath="/core/projects"
      className="core-projects-shell"
      footer={<><span>{t.projects}</span><strong>{projects.length} / {PROJECT_LIMIT}</strong></>}
    >
      <div className="core-projects-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>BielOS Core</span>
            <span>{t.protected}</span>
          </div>
          <div className="top-actions">
            <a className="button-ghost core-back-link" href="/">
              {t.returnHub}
            </a>
            <LanguageSelector locale={locale} label={t.language} returnTo="/core/projects" />
          </div>
        </header>

        <header className="core-projects-intro">
          <div>
            <p className="eyebrow">{t.eyebrow}</p>
            <h1>{t.workspace}</h1>
            <p>{t.intro}</p>
          </div>
          <div className="core-projects-count" aria-label={`${projects.length} ${t.projectCount}`}>
            <strong>{projects.length}</strong>
            <span>{t.projectCount}</span>
          </div>
        </header>

        {isAdministrator ? (
          <section className="core-admin-strip anchor-section" id="administration" aria-labelledby="core-admin-heading">
            <div className="core-admin-strip-heading">
              <div>
                <p className="eyebrow">{t.adminTools}</p>
                <h2 id="core-admin-heading">{t.createProject}</h2>
              </div>
              <span className="status-pill is-guarded">OWNER / ADMIN</span>
            </div>
            <details className="admin-drawer core-project-drawer">
              <summary>{t.createSummary}</summary>
              <form className="compact-form core-project-form" action={createCoreProject}>
                <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                <label>
                  <span>{t.name}</span>
                  <input name="name" required minLength={2} maxLength={80} autoComplete="off" />
                </label>
                <label>
                  <span>{t.slug}</span>
                  <input
                    name="slug"
                    required
                    minLength={3}
                    maxLength={64}
                    pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
                    aria-describedby="core-create-slug-hint"
                    autoComplete="off"
                  />
                  <small id="core-create-slug-hint">{t.slugHint}</small>
                </label>
                <label className="core-project-description-field">
                  <span>{t.description} ({t.optional})</span>
                  <textarea name="description" maxLength={500} rows={3} />
                </label>
                <label>
                  <span>{t.visibility}</span>
                  <select name="visibility" defaultValue="INTERNAL">
                    {visibilityValues.map((value) => (
                      <option key={value} value={value}>{getVisibilityLabel(value, t)}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>{t.status}</span>
                  <select name="status" defaultValue="PLANNED">
                    {statusValues.map((value) => (
                      <option key={value} value={value}>{getStatusLabel(value, t)}</option>
                    ))}
                  </select>
                </label>
                <div className="button-row core-project-form-actions">
                  <button className="button-primary" type="submit">{t.create}</button>
                </div>
              </form>
            </details>
          </section>
        ) : null}

        <section className="core-projects-section anchor-section" id="projects" aria-labelledby="core-projects-heading">
          <div className="section-heading core-projects-heading">
            <div>
              <p className="eyebrow">{t.workspace}</p>
              <h2 id="core-projects-heading">{t.projects}</h2>
            </div>
            <span>{projects.length} / {PROJECT_LIMIT}</span>
          </div>

          {projects.length === 0 ? (
            <div className="core-project-empty">
              <strong>{t.empty}</strong>
              <span>{isAdministrator ? t.emptyAdmin : t.emptyMember}</span>
            </div>
          ) : (
            <div className="core-project-list">
              {projects.map((project) => {
                const archived = project.status === "ARCHIVED";
                const accessLabel = getAccessLabel(
                  project.accesses[0]?.accessLevel,
                  project.visibility,
                  isAdministrator,
                  t
                );

                return (
                  <article className={`core-project-card${archived ? " is-archived" : ""}`} key={project.id}>
                    <div className="core-project-card-main">
                      <div className="core-project-title-row">
                        <div>
                          <span className="core-project-slug">/{project.slug}</span>
                          <h3>{project.name}</h3>
                        </div>
                        <span className={`status-pill core-project-status status-${project.status.toLowerCase()}`}>
                          {getStatusLabel(project.status, t)}
                        </span>
                      </div>

                      {project.description ? <p className="core-project-description">{project.description}</p> : null}

                      <dl className="core-project-meta">
                        <div>
                          <dt>{t.visibility}</dt>
                          <dd>{getVisibilityLabel(project.visibility, t)}</dd>
                        </div>
                        <div>
                          <dt>{t.access}</dt>
                          <dd>{accessLabel}</dd>
                        </div>
                        <div>
                          <dt>{t.updated}</dt>
                          <dd>{formatUpdatedAt(project.updatedAt, locale)}</dd>
                        </div>
                      </dl>

                      <a className="button-ghost core-project-open" href={getCoreProjectDetailPath(project.id) ?? "/core/projects"}>
                        {t.openProject}
                      </a>

                      {archived ? <p className="core-project-archived-note">{t.archivedNote}</p> : null}
                    </div>

                    {isAdministrator && !archived ? (
                      <CoreProjectAdminControls
                        project={project}
                        activeUsers={activeUsers}
                        actorRole={session.user.role}
                        copy={t}
                      />
                    ) : null}
                  </article>
                );
              })}
            </div>
          )}
          <p className="core-project-limit-note">{t.limitNote}</p>
        </section>
      </div>
    </CoreShell>
  );
}
