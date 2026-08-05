import type { BielosLocale } from "@bielos/ui";

export type CoreNavigationItemId =
  | "hub"
  | "projects"
  | "security"
  | "account-security"
  | "modules"
  | "administrative-security"
  | "applications";

export type CoreNavigationItem = {
  id: CoreNavigationItemId;
  href: string;
  label: string;
};

const copy = {
  "pt-BR": {
    label: "Navegação BielOS Core",
    hub: "Hub",
    projects: "Projetos",
    security: "Segurança pessoal",
    accountSecurity: "Segurança da conta",
    modules: "Catálogo de módulos",
    administrativeSecurity: "Segurança administrativa",
    applications: "Solicitações de conta"
  },
  en: {
    label: "BielOS Core navigation",
    hub: "Hub",
    projects: "Projects",
    security: "Personal security",
    accountSecurity: "Account security",
    modules: "Module catalog",
    administrativeSecurity: "Administrative security",
    applications: "Account applications"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const definitions = [
  { id: "hub", href: "/", copyKey: "hub", ownerOnly: false },
  { id: "projects", href: "/core/projects", copyKey: "projects", ownerOnly: false },
  { id: "security", href: "/core/security", copyKey: "security", ownerOnly: false },
  { id: "account-security", href: "/core/security/account", copyKey: "accountSecurity", ownerOnly: false },
  { id: "modules", href: "/core/modules", copyKey: "modules", ownerOnly: false },
  { id: "administrative-security", href: "/core/security/admin", copyKey: "administrativeSecurity", ownerOnly: true },
  { id: "applications", href: "/core/applications", copyKey: "applications", ownerOnly: true }
] as const;

export function getCoreNavigationLabel(locale: BielosLocale): string {
  return copy[locale].label;
}

export function getCoreNavigationItems(locale: BielosLocale, role: string): CoreNavigationItem[] {
  return definitions
    .filter((item) => item.ownerOnly !== true || role === "OWNER")
    .map((item) => ({ id: item.id, href: item.href, label: copy[locale][item.copyKey] }));
}
