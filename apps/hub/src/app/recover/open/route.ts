import { NextResponse } from "next/server";
import { getAccountRecoveryRequestId } from "@virki/auth/security";
import { getSurface, getSurfaceBaseUrl } from "../../../lib/surface";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { setRecoveryCandidateCookie } from "../recovery-cookie";

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
  // Merely opening a legacy GET must NEVER adopt/clear an authorizing bearer:
  // the HTTP 303 could be held until another tab finishes a modern TOTP proof.
  // The later Set-Cookie would silently destroy its only browser-bound pair.
  // Candidate-only discovery is non-authorizing; an explicit CSRF-guarded POST
  // must subsequently adopt the link, even when the browser had no old key.
  destination.searchParams.set("switch", "1");
  const confirmation = NextResponse.redirect(destination, { status: 303, headers: privateHeaders() });
  setRecoveryCandidateCookie(confirmation.cookies, requestKey, recovery.expiresAt);
  return confirmation;
}

function privateHeaders(): HeadersInit {
  return { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };
}
