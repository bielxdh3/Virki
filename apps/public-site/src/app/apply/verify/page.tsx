import type { BielosLocale } from "@bielos/ui";
import { VerifyApplication } from "../verify-application";
import { getLocale } from "../../locale";

export default async function VerifyPage() {
  const base = process.env.NEXT_PUBLIC_INTAKE_URL?.trim() ?? "";
  const endpoint = base ? `${base.replace(/\/$/, "")}/verify` : "";
  const locale: BielosLocale = await getLocale();
  return <VerifyApplication endpoint={endpoint} locale={locale} />;
}
