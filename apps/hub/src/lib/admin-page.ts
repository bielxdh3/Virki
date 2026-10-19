import { cache } from "react";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "./auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "./cloudflare-access";
import { getSurface, trustedReturnTo } from "./surface";
import { isAdminRequestAllowed, isAdminRole } from "./admin-policy";
import { recordSecurityDenial } from "./audit-denial";

type AdminSession = NonNullable<Awaited<ReturnType<typeof getCurrentSession>>>;

// Layouts are skipped on partial (RSC) renders, so every admin page must run this
// itself before reading data. cache() keeps one Access audit row per request when
// the layout and the page both call it during a full render.
export const requireAdminPage = cache(async (): Promise<AdminSession> => {
  const requestHeaders = await headers();
  const surface = getSurface(requestHeaders);
  const accessValid = isCloudflareAccessAllowed(await validateHubCloudflareAccess(requestHeaders, "admin-page"));
  if (!isAdminRequestAllowed(surface, accessValid)) forbidden();
  const session = await getCurrentSession();
  if (!session) {
    const returnTo = trustedReturnTo(requestHeaders, surface) ?? "/admin/accounts";
    redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
  }
  if (!isAdminRole(session.user.role)) { await recordSecurityDenial(requestHeaders, "admin-page", "role", session); forbidden(); }
  return session;
});
