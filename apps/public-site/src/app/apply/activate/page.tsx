import type { BielosLocale } from "@bielos/ui";
import { ActivateApplication } from "../activate-application";
import { getLocale } from "../../locale";

export default async function ActivatePage() {
  const base = process.env.NEXT_PUBLIC_INTAKE_URL?.trim() ?? "";
  const endpoint = base ? `${base.replace(/\/$/, "")}/activate` : "";
  const locale: BielosLocale = await getLocale();
  return <ActivateApplication endpoint={endpoint} locale={locale} />;
}
