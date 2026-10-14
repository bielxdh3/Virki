import { requireAdminPage } from "../../../lib/admin-page";
import { createSessionCsrfToken } from "../../../lib/session-csrf";
import { AccessView } from "./access-view";

export const dynamic = "force-dynamic";

export default async function AccessPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  await requireAdminPage();
  return AccessView({ searchParams, csrf: await createSessionCsrfToken("admin-access") });
}
