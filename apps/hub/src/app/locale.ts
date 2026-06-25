import { DEFAULT_LOCALE, LOCALE_COOKIE_NAME, isSupportedLocale } from "@bielos/ui";
import type { BielosLocale } from "@bielos/ui";
import { cookies } from "next/headers";

export async function getLocale(): Promise<BielosLocale> {
  const cookieStore = await cookies();
  const cookieValue = cookieStore.get(LOCALE_COOKIE_NAME)?.value;

  return isSupportedLocale(cookieValue) ? cookieValue : DEFAULT_LOCALE;
}

