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
    unavailable: "Indisponível",
    viewer: "Visualizador",
    editor: "Editor",
    owner: "Responsável",
    globalOwner: "Responsável global",
    globalAdmin: "Administrador global",
    authenticated: "Usuário autenticado",
    administration: "Administração do projeto",
    actionError: "Não foi possível concluir a ação.",
    feedbackCreated: "Projeto criado.",
    feedbackUpdated: "Projeto atualizado.",
    feedbackArchived: "Projeto arquivado.",
    feedbackAccessGranted: "Acesso concedido. A lista abaixo mostra o estado persistido.",
    feedbackAccessChanged: "Acesso alterado. A lista abaixo mostra o estado persistido.",
    feedbackAccessUnchanged: "Nenhuma alteração foi necessária; o estado persistido já correspondia ao pedido.",
    feedbackAccessRevoked: "Acesso revogado. A lista abaixo mostra o estado persistido.",
    feedbackElevation: "Acesso não alterado: a elevação administrativa necessária está ausente ou expirada.",
    feedbackProjectCreate: "Projeto não criado: a operação foi rejeitada.",
    feedbackProjectUpdate: "Projeto não atualizado: a operação foi rejeitada.",
    feedbackProjectArchive: "Projeto não arquivado: a operação foi rejeitada.",
    feedbackProjectAccess: "Acesso não alterado: a operação foi rejeitada pelas regras do projeto."
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
    unavailable: "Unavailable",
    viewer: "Viewer",
    editor: "Editor",
    owner: "Owner",
    globalOwner: "Global owner",
    globalAdmin: "Global administrator",
    authenticated: "Authenticated user",
    administration: "Project administration",
    actionError: "The action could not be completed.",
    feedbackCreated: "Project created.",
    feedbackUpdated: "Project updated.",
    feedbackArchived: "Project archived.",
    feedbackAccessGranted: "Access granted. The list below shows the persisted state.",
    feedbackAccessChanged: "Access changed. The list below shows the persisted state.",
    feedbackAccessUnchanged: "No change was needed; the persisted state already matched the request.",
    feedbackAccessRevoked: "Access revoked. The list below shows the persisted state.",
    feedbackElevation: "Access was not changed: the required administrative elevation is missing or expired.",
    feedbackProjectCreate: "Project was not created: the operation was rejected.",
    feedbackProjectUpdate: "Project was not updated: the operation was rejected.",
    feedbackProjectArchive: "Project was not archived: the operation was rejected.",
    feedbackProjectAccess: "Access was not changed: the project rules rejected the operation."
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
