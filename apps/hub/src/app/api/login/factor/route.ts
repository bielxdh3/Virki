import { NextResponse } from "next/server";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@virki/auth/csrf";
import { DEVICE_COOKIE_NAME, selectLoginBackupFactor } from "@virki/auth/security";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, hasSameOrigin, safeReturnTo } from "../../../../lib/surface";
import { readBoundedFormData } from "../../../../lib/request-form";
import { recordSecurityDenial } from "../../../../lib/audit-denial";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-login-factor-selection"))) {
    return new NextResponse("Forbidden", { status: 403 });
  }
  if (!hasSameOrigin(request.headers)) {
    await recordSecurityDenial(request.headers, "login-factor-origin", "csrf");
    return new NextResponse("Forbidden", { status: 403 });
  }
  const form = await readBoundedFormData(request);
  if (!form) return new NextResponse("Bad Request", { status: 400 });
  if (!validateCsrfToken(read(form, CSRF_FORM_FIELD_NAME), { scope: "login-factor-selection" }).valid) {
    await recordSecurityDenial(request.headers, "login-factor-csrf", "csrf");
    return new NextResponse("Forbidden", { status: 403 });
  }
  const deviceToken = readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME);
  if (!deviceToken) return new NextResponse("Forbidden", { status: 403 });
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  if (!baseUrl) return new NextResponse("Service Unavailable", { status: 503, headers: { "cache-control": "no-store" } });
  const ceremony = read(form, "ceremony");
  const destination = new URL("/login/verify", baseUrl);
  destination.searchParams.set("ceremony", ceremony);
  const returnTo = safeReturnTo(read(form, "returnTo"), surface);
  if (returnTo) destination.searchParams.set("returnTo", returnTo);
  if (read(form, "reauth") === "1") destination.searchParams.set("reauth", "1");
  try {
    await selectLoginBackupFactor(ceremony, deviceToken, surface === "hub" ? "ADMIN" : surface === "portal" ? "USER" : undefined);
    destination.searchParams.set("factor", "backup");
  } catch {
    destination.searchParams.set("factor", "totp");
    destination.searchParams.set("error", "1");
  }
  return NextResponse.redirect(destination, { status: 303 });
}

function read(form: FormData, key: string): string {
  const value = form.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator >= 0 && pair.slice(0, separator).trim() === name) return pair.slice(separator + 1).trim();
  }
  return undefined;
}
