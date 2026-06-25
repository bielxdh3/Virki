export const LOCALE_COOKIE_NAME = "bielos_locale";

export const SUPPORTED_LOCALES = ["pt-BR", "en"] as const;

export type BielosLocale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: BielosLocale = "pt-BR";

export const LOCALE_OPTIONS: Array<{ value: BielosLocale; label: string }> = [
  { value: "pt-BR", label: "Português" },
  { value: "en", label: "English" }
];

export function isSupportedLocale(value: string | undefined): value is BielosLocale {
  return SUPPORTED_LOCALES.includes(value as BielosLocale);
}

