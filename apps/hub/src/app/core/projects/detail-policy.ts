import type { BielosLocale } from "@bielos/ui";

import { isValidCoreResourceId } from "./validation";

export const CORE_PROJECT_DETAIL_COPY = {
  "pt-BR": {
    privateHub: "Hub privado",
    navLabel: "Navegação do projeto",
    primary: "Principal",
    returnHub: "Voltar ao hub",
    returnProjects: "Voltar aos projetos",
    projects: "Projetos",
    protected: "Protegido",
    language: "Idioma",
    eyebrow: "Workspace privado",
    description: "Descrição",
    noDescription: "Nenhuma descrição registrada.",
    visibility: "Visibilidade",
    status: "Status",
    access: "Seu acesso efetivo",
    updated: "Última atualização",
    archived: "Somente leitura",
    archivedNote: "Este projeto está arquivado e permanece disponível apenas para consulta.",
    public: "Público no hub",
    internal: "Interno",
    sensitive: "Sensível",
    planned: "Planejado",
    reserved: "Reservado",
    active: "Ativo",
    paused: "Pausado",
    archivedStatus: "Arquivado",
    viewer: "Visualizador",
    editor: "Editor",
    owner: "Responsável",
    globalOwner: "OWNER global",
    globalAdmin: "ADMIN global",
    authenticated: "Usuário autenticado",
    administration: "Administração do projeto"
  },
  en: {
    privateHub: "Private Hub",
    navLabel: "Project navigation",
    primary: "Primary",
    returnHub: "Back to hub",
    returnProjects: "Back to projects",
    projects: "Projects",
    protected: "Protected",
    language: "Language",
    eyebrow: "Private workspace",
    description: "Description",
    noDescription: "No description has been recorded.",
    visibility: "Visibility",
    status: "Status",
    access: "Your effective access",
    updated: "Last updated",
    archived: "Read only",
    archivedNote: "This project is archived and remains available for reference only.",
    public: "Hub public",
    internal: "Internal",
    sensitive: "Sensitive",
    planned: "Planned",
    reserved: "Reserved",
    active: "Active",
    paused: "Paused",
    archivedStatus: "Archived",
    viewer: "Viewer",
    editor: "Editor",
    owner: "Owner",
    globalOwner: "Global OWNER",
    globalAdmin: "Global ADMIN",
    authenticated: "Authenticated user",
    administration: "Project administration"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

export function getCoreProjectDetailPath(projectId: string): string | null {
  return isValidCoreResourceId(projectId)
    ? `/core/projects/${encodeURIComponent(projectId)}`
    : null;
}

export function canShowCoreProjectMutationControls(
  administrator: boolean,
  status: string
): boolean {
  return administrator && status !== "ARCHIVED";
}
