import { VerifyApplication } from "../verify-application";

export default function VerifyPage() {
  const base = process.env.NEXT_PUBLIC_INTAKE_URL?.trim() ?? "";
  const endpoint = base ? `${base.replace(/\/$/, "")}/verify` : "";
  return <VerifyApplication endpoint={endpoint} />;
}
