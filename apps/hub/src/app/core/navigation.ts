import type { BielosLocale } from "@bielos/ui";

export type CoreNavigationItemId =
  | "hub"
  | "operations"
  | "projects"
  | "security"
  | "audit"
  | "account-security"
  | "modules"
  | "administrative-security"
  | "applications";

export type CoreNavigationItem = {
  id: CoreNavigationItemId;
  href: string;
  label: string;
  kind: "route" | "section";
  activePath: string;
};

const copy = {
  "pt-BR": {
    label: "Navegação BielOS Core",
    hub: "Hub",
    operations: "Ops",
    projects: "Projetos",
    security: "Pessoal",
    audit: "Audit",
    accountSecurity: "Conta",
    modules: "Módulos",
    administrativeSecurity: "Admin",
    applications: "Pedidos"
  },
  en: {
    label: "BielOS Core navigation",
    hub: "Hub",
    operations: "Ops",
    projects: "Projects",
    security: "Personal",
    audit: "Audit",
    accountSecurity: "Account",
    modules: "Modules",
    administrativeSecurity: "Admin",
    applications: "Requests"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const definitions = [
  { id: "hub", href: "/", copyKey: "hub", kind: "route", activePath: "/", ownerOnly: false },
  { id: "operations", href: "/core/health", copyKey: "operations", kind: "route", activePath: "/core/health", ownerOnly: false },
  { id: "projects", href: "/core/projects", copyKey: "projects", kind: "route", activePath: "/core/projects", ownerOnly: false },
  { id: "security", href: "/core/security", copyKey: "security", kind: "route", activePath: "/core/security", ownerOnly: false },
  { id: "audit", href: "/core/security#audit", copyKey: "audit", kind: "section", activePath: "/core/security", ownerOnly: true },
  { id: "account-security", href: "/core/security/account", copyKey: "accountSecurity", kind: "route", activePath: "/core/security/account", ownerOnly: false },
  { id: "modules", href: "/core/modules", copyKey: "modules", kind: "route", activePath: "/core/modules", ownerOnly: false },
  { id: "administrative-security", href: "/core/security/admin", copyKey: "administrativeSecurity", kind: "route", activePath: "/core/security/admin", ownerOnly: true },
  { id: "applications", href: "/core/applications", copyKey: "applications", kind: "route", activePath: "/core/applications", ownerOnly: true }
] as const;

export function getCoreNavigationLabel(locale: BielosLocale): string {
  return copy[locale].label;
}

export function getCoreNavigationItems(locale: BielosLocale, role: string): CoreNavigationItem[] {
  return definitions
    .filter((item) => item.ownerOnly !== true || role === "OWNER")
    .map((item) => ({
      id: item.id,
      href: item.href,
      label: copy[locale][item.copyKey],
      kind: item.kind,
      activePath: item.activePath
    }));
}
