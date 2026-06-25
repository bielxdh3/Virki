export type ModuleSensitivity = "internal" | "sensitive";
export {
  DEFAULT_LOCALE,
  LOCALE_COOKIE_NAME,
  LOCALE_OPTIONS,
  SUPPORTED_LOCALES,
  isSupportedLocale
} from "./i18n";
export type { BielosLocale } from "./i18n";

export type ModuleSummary = {
  name: string;
  shortName: string;
  slug: "lvault" | "rootark" | "hvault" | "gymforge";
  description: string;
  status: string;
  sensitivity: ModuleSensitivity;
};

export const moduleCatalog: ModuleSummary[] = [
  {
    name: "L-vault",
    shortName: "LV",
    slug: "lvault",
    description: "Reserved space for a future lightweight vault module.",
    status: "Reserved",
    sensitivity: "sensitive"
  },
  {
    name: "root.ark",
    shortName: "RA",
    slug: "rootark",
    description: "Reserved space for future archival and root knowledge flows.",
    status: "Reserved",
    sensitivity: "sensitive"
  },
  {
    name: "H-vault",
    shortName: "HV",
    slug: "hvault",
    description: "Reserved space for a future organized storage module.",
    status: "Reserved",
    sensitivity: "internal"
  },
  {
    name: "GymForge",
    shortName: "GF",
    slug: "gymforge",
    description: "Reserved space for future training and progression tooling.",
    status: "Reserved",
    sensitivity: "internal"
  }
];
