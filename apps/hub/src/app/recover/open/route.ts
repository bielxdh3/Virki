import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { getAccountRecoveryRequestId } from "@virki/auth/security";
import { getSurface, getSurfaceBaseUrl } from "../../../lib/surface";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { clearMultiMethodRecoveryCookies, setRecoveryCandidateCookie, setRecoveryCookie } from "../recovery-cookie";
import { requiresRecoveryLinkSwitch } from "../recovery-switch";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown" || (surface === "local" && process.env.NODE_ENV === "production")) return new NextResponse("Not found", { status: 404, headers: privateHeaders() });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "account-recovery-link"))) return new NextResponse("Forbidden", { status: 403, headers: privateHeaders() });
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  if (!baseUrl) return new NextResponse("Service Unavailable", { status: 503, headers: privateHeaders() });
  const expectedRole = surface === "hub" ? "ADMIN" : "USER";
  const requestKey = new URL(request.url).searchParams.get("request") ?? "";
  const recovery = await getAccountRecoveryRequestId(requestKey, new Date(), expectedRole);
  const destination = new URL("/recover", baseUrl);
  if (!recovery) {
    destination.searchParams.set("error", "1");
    return NextResponse.redirect(destination, { status: 303, headers: privateHeaders() });
  }
  destination.searchParams.set("requestId", recovery.id);
  const response = NextResponse.redirect(destination, { status: 303, headers: privateHeaders() });
  let mustSwitch: boolean;
  try {
    mustSwitch = await requiresRecoveryLinkSwitch(await cookies(), recovery.id, expectedRole);
  } catch {
    // Fail closed on indeterminate database state; never replace the old key.
    return new NextResponse("Service Unavailable", { status: 503, headers: privateHeaders() });
  }
  if (mustSwitch) {
    destination.searchParams.set("switch", "1");
    const confirmation = NextResponse.redirect(destination, { status: 303, headers: privateHeaders() });
    setRecoveryCandidateCookie(confirmation.cookies, requestKey, recovery.expiresAt);
    return confirmation;
  }
  setRecoveryCookie(response.cookies, requestKey, recovery.expiresAt);
  // Adopting a legacy link must not leave stale modern browser/intent hints
  // attached to the new, unrelated request key.
  clearMultiMethodRecoveryCookies(response.cookies);
  return response;
}

function privateHeaders(): HeadersInit {
  return { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };
}
