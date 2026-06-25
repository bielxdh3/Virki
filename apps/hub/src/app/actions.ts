"use server";

import { LOCALE_COOKIE_NAME, isSupportedLocale } from "@bielos/ui";
import { cookies } from "next/headers";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

function safeReturnPath(value: FormDataEntryValue | null): string {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//") ? value : "/";
}

async function getCookieDomain(): Promise<string | undefined> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("host")?.split(":")[0];

  return host === "biel.dev.br" || host === "hub.biel.dev.br" ? ".biel.dev.br" : undefined;
}

export async function setLocalePreference(formData: FormData) {
  const locale = formData.get("locale");

  if (typeof locale === "string" && isSupportedLocale(locale)) {
    const cookieStore = await cookies();
    cookieStore.set(LOCALE_COOKIE_NAME, locale, {
      httpOnly: false,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      domain: await getCookieDomain(),
      maxAge: 60 * 60 * 24 * 365
    });
  }

  redirect(safeReturnPath(formData.get("returnTo")));
}
