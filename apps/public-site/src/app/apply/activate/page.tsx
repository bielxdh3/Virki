import { ActivateApplication } from "../activate-application";

export default function ActivatePage() {
  const base = process.env.NEXT_PUBLIC_INTAKE_URL?.trim() ?? "";
  const endpoint = base ? `${base.replace(/\/$/, "")}/activate` : "";
  return <ActivateApplication endpoint={endpoint} />;
}
