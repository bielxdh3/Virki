export {
  DEFAULT_LOCALE,
  LOCALE_COOKIE_NAME,
  LOCALE_OPTIONS,
  SUPPORTED_LOCALES,
  isSupportedLocale
} from "./i18n";
export type { BielosLocale } from "./i18n";

export type HubRegistryCategory = "core" | "application" | "reserved";
export type HubRegistrySensitivity = "internal" | "sensitive";
export type HubRegistryStatus = "active" | "available" | "reserved";
export type HubRegistryItemId =
  | "bielos-core"
  | "core-projects"
  | "core-security"
  | "core-operations"
  | "gymforge"
  | "lvault"
  | "rootark"
  | "hvault";

export type HubRegistryItem = {
  id: HubRegistryItemId;
  name: string;
  shortName: string;
  category: HubRegistryCategory;
  status: HubRegistryStatus;
  sensitivity: HubRegistrySensitivity;
  href?: string;
};

export const hubRegistry = [
  {
    id: "bielos-core",
    name: "BielOS Core",
    shortName: "BC",
    category: "core",
    status: "active",
    sensitivity: "internal",
    href: "/core/projects"
  },
  {
    id: "core-projects",
    name: "Project Workspace",
    shortName: "PW",
    category: "core",
    status: "active",
    sensitivity: "internal",
    href: "/core/projects"
  },
  {
    id: "core-security",
    name: "Security & Sessions",
    shortName: "SS",
    category: "core",
    status: "active",
    sensitivity: "sensitive",
    href: "/core/security"
  },
  {
    id: "core-operations",
    name: "Operations",
    shortName: "OP",
    category: "core",
    status: "active",
    sensitivity: "internal",
    href: "/#ops"
  },
  {
    id: "gymforge",
    name: "GymForge",
    shortName: "GF",
    category: "application",
    status: "available",
    sensitivity: "internal",
    href: "/gymforge"
  },
  {
    id: "lvault",
    name: "L-vault",
    shortName: "LV",
    category: "reserved",
    status: "reserved",
    sensitivity: "sensitive"
  },
  {
    id: "rootark",
    name: "root.ark",
    shortName: "RA",
    category: "reserved",
    status: "reserved",
    sensitivity: "sensitive"
  },
  {
    id: "hvault",
    name: "H-vault",
    shortName: "HV",
    category: "reserved",
    status: "reserved",
    sensitivity: "internal"
  }
] as const satisfies readonly HubRegistryItem[];

export const moduleCatalog = hubRegistry.filter(
  (item) => item.category === "reserved"
);
