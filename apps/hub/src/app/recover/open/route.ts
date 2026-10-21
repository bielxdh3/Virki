import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { getAccountRecoveryRequestId } from "@virki/auth/security";
import { getSurface, getSurfaceBaseUrl } from "../../../lib/surface";
import { requiresRecoveryRequestSwitch } from "../../../lib/recovery";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { RECOVERY_COOKIE_NAME } from "../../../lib/recovery";
import { setRecoveryCandidateCookie, setRecoveryCookie } from "../recovery-cookie";

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
  const activeKey = (await cookies()).get(RECOVERY_COOKIE_NAME)?.value;
  const activeRecovery = activeKey ? await getAccountRecoveryRequestId(activeKey, new Date(), expectedRole) : null;
  if (requiresRecoveryRequestSwitch(activeRecovery?.id, recovery.id)) {
    destination.searchParams.set("switch", "1");
    const confirmation = NextResponse.redirect(destination, { status: 303, headers: privateHeaders() });
    setRecoveryCandidateCookie(confirmation.cookies, requestKey, recovery.expiresAt);
    return confirmation;
  }
  setRecoveryCookie(response.cookies, requestKey, recovery.expiresAt);
  return response;
}

function privateHeaders(): HeadersInit {
  return { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };
}
