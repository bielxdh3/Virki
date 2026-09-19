import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, notFound, redirect } from "next/navigation";

import { getCurrentSession } from "../../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../../lib/cloudflare-access";
import { LanguageSelector } from "../../../language-selector";
import { getLocale } from "../../../locale";
import { CoreShell } from "../../shell";
import {
  canShowCoreProjectMutationControls,
  CORE_PROJECT_DETAIL_COPY,
  getCoreProjectDetailPath
} from "../detail-policy";
import {
  getCoreProjectActionFeedback,
  getCoreProjectFeedbackMessage
} from "../feedback";
import { CoreProjectAdminControls, type CoreProjectAdminCopy } from "../project-admin-controls";
import { findCoreProjectDetailForPrincipal } from "../read-service";

export const dynamic = "force-dynamic";

const adminCopy = {
  "pt-BR": {
    name: "Nome",
    slug: "Slug",
    description: "Descrição",
    optional: "opcional",
    visibility: "Visibilidade",
    status: "Status",
    save: "Salvar alterações",
    archiveProject: "Arquivar projeto",
    archiveConfirm: "Confirmo que este projeto ficará somente leitura.",
    noDelete: "A exclusão permanente não está disponível.",
    public: "Público no hub",
    internal: "Interno",
    sensitive: "Sensível",
    planned: "Planejado",
    reserved: "Reservado",
    active: "Ativo",
    paused: "Pausado",
    unavailable: "Indisponível",
    viewer: "Visualizador",
    editor: "Editor",
    owner: "Responsável do projeto",
    editDetails: "Editar metadados",
    accessDetails: "Gerenciar acesso e responsável",
    selectUser: "Selecionar usuário",
    accessLevel: "Nível de acesso no projeto",
    ownerHelp: "Define o responsável deste projeto; não altera o papel global do usuário.",
    accessElevationHelp: "Antes de aplicar ou revogar acesso, confirme a operação na Segurança administrativa e volte aqui.",
    accessElevationLink: "Abrir Segurança administrativa",
    applyAccess: "Aplicar acesso",
    currentAccess: "Acessos atuais",
    noAccess: "Nenhum acesso explícito adicional.",
    inactiveUser: "Inativo",
    activeUser: "Ativo",
    revokeAccess: "Revogar",
    accessLimit: "Até 100 acessos exibidos por projeto.",
    archiveDetails: "Área de arquivamento"
  },
  en: {
    name: "Name",
    slug: "Slug",
    description: "Description",
    optional: "optional",
    visibility: "Visibility",
    status: "Status",
    save: "Save changes",
    archiveProject: "Archive project",
    archiveConfirm: "I understand this project will become read-only.",
    noDelete: "Permanent deletion is not available.",
    public: "Hub public",
    internal: "Internal",
    sensitive: "Sensitive",
    planned: "Planned",
    reserved: "Reserved",
    active: "Active",
    paused: "Paused",
    unavailable: "Unavailable",
    viewer: "Viewer",
    editor: "Editor",
    owner: "Project owner",
    editDetails: "Edit metadata",
    accessDetails: "Manage access and project owner",
    selectUser: "Select user",
    accessLevel: "Project access level",
    ownerHelp: "Defines this project's responsible owner; it does not change the user's global role.",
    accessElevationHelp: "Before applying or revoking access, confirm the operation in Administrative security and return here.",
    accessElevationLink: "Open Administrative security",
    applyAccess: "Apply access",
    currentAccess: "Current access",
    noAccess: "No additional explicit access.",
    inactiveUser: "Inactive",
    activeUser: "Active",
    revokeAccess: "Revoke",
    accessLimit: "Up to 100 access rows are shown per project.",
    archiveDetails: "Archive area"
  }
} satisfies Record<BielosLocale, CoreProjectAdminCopy>;

function visibilityLabel(value: string, locale: BielosLocale): string {
  const t = CORE_PROJECT_DETAIL_COPY[locale];
  return ({ PUBLIC: t.public, INTERNAL: t.internal, SENSITIVE: t.sensitive })[value] ?? t.unavailable;
}

function statusLabel(value: string, locale: BielosLocale): string {
  const t = CORE_PROJECT_DETAIL_COPY[locale];
  return ({
    PLANNED: t.planned,
    RESERVED: t.reserved,
    ACTIVE: t.active,
    PAUSED: t.paused,
    ARCHIVED: t.archivedStatus
  })[value] ?? t.unavailable;
}

function accessLabel(value: string, locale: BielosLocale): string {
  const t = CORE_PROJECT_DETAIL_COPY[locale];
  return ({
    VIEWER: t.viewer,
    EDITOR: t.editor,
    OWNER: t.owner,
    GLOBAL_OWNER: t.globalOwner,
    GLOBAL_ADMIN: t.globalAdmin,
    AUTHENTICATED: t.authenticated
  })[value] ?? t.unavailable;
}

function formatUpdatedAt(value: Date, locale: BielosLocale): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "long",
    timeStyle: "short"
  }).format(value);
}

export default async function CoreProjectDetailPage({
  params,
  searchParams
}: {
  params: Promise<{ projectId: string }>;
  searchParams?: Promise<{ status?: string; error?: string }>;
}) {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "core-project-detail");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();
  if (!session) redirect("/login");

  const { projectId } = await params;
  const project = await findCoreProjectDetailForPrincipal(session.user, projectId);
  if (!project) notFound();

  const feedback = getCoreProjectActionFeedback(await searchParams);
  const locale = await getLocale();
  const t = CORE_PROJECT_DETAIL_COPY[locale];
  const detailPath = getCoreProjectDetailPath(project.id) ?? "/core/projects";
  const archived = project.status === "ARCHIVED";

  return (
    <CoreShell
      variant="docked"
      locale={locale}
      role={session.user.role}
      activePath="/core/projects"
      className={`core-project-detail-shell${archived ? " is-archived" : ""}`}
      footer={<><span>{t.access}</span><strong>{accessLabel(project.effectiveAccess, locale)}</strong></>}
    >
      <div className="core-project-detail-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>BielOS Core</span>
            <span>{t.protected}</span>
          </div>
          <div className="top-actions">
            <a className="button-ghost core-back-link" href="/core/projects">{t.returnProjects}</a>
            <a className="button-ghost core-back-link" href="/">{t.returnHub}</a>
            <LanguageSelector locale={locale} label={t.language} returnTo={detailPath} />
          </div>
        </header>

        {feedback ? (
          <p
            className={`core-project-feedback is-${feedback.kind}`}
            role={feedback.kind === "error" ? "alert" : "status"}
          >
            {getCoreProjectFeedbackMessage(feedback, t)}
          </p>
        ) : null}

        <section className="core-project-detail-card anchor-section" id="project" aria-labelledby="project-title">
          <header className="core-project-detail-header">
            <div>
              <p className="eyebrow">{t.eyebrow}</p>
              <span className="core-project-slug">/{project.slug}</span>
              <h1 id="project-title">{project.name}</h1>
            </div>
            <span className={`status-pill core-project-status status-${project.status.toLowerCase()}`}>
              {statusLabel(project.status, locale)}
            </span>
          </header>

          <div className="core-project-detail-description">
            <h2>{t.description}</h2>
            <p>{project.description ?? t.noDescription}</p>
          </div>

          <dl className="core-project-detail-meta">
            <div><dt>{t.visibility}</dt><dd>{visibilityLabel(project.visibility, locale)}</dd></div>
            <div><dt>{t.status}</dt><dd>{statusLabel(project.status, locale)}</dd></div>
            <div><dt>{t.access}</dt><dd>{accessLabel(project.effectiveAccess, locale)}</dd></div>
            <div><dt>{t.updated}</dt><dd>{formatUpdatedAt(project.updatedAt, locale)}</dd></div>
          </dl>

          {archived ? (
            <div className="core-project-detail-archived" role="status">
              <strong>{t.archived}</strong>
              <span>{t.archivedNote}</span>
            </div>
          ) : null}
        </section>

        {project.administrator && canShowCoreProjectMutationControls(true, project.status) ? (
          <section className="core-project-detail-admin anchor-section" id="administration" aria-labelledby="project-admin-title">
            <div className="section-heading">
              <div><p className="eyebrow">{t.administration}</p><h2 id="project-admin-title">{t.administration}</h2></div>
            </div>
            <CoreProjectAdminControls
              project={project}
              activeUsers={project.activeUsers}
              actorRole={session.user.role}
              copy={adminCopy[locale]}
              returnToDetail
            />
          </section>
        ) : null}
      </div>
    </CoreShell>
  );
}
