import { NextResponse } from "next/server";
import {
  authenticateUserWithRateLimit,
  createAuditRequestMetadata,
  hashAuditEmail,
  normalizeEmail,
  getSessionCookieOptions,
  SESSION_COOKIE_NAME,
  writeAuditLog
} from "@bielos/auth";
import { DEVICE_COOKIE_NAME, startLoginCeremony } from "@bielos/auth/security";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { getSurface, getSurfaceBaseUrl, safeReturnTo } from "../../../lib/surface";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const surface = getSurface(request.headers);
  if (surface === "unknown") return new NextResponse("Not found", { status: 404 });
  if (surface === "hub" && !isCloudflareAccessAllowed(await validateHubCloudflareAccess(request.headers, "admin-login-api"))) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const formData = await request.formData();
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const returnTo = safeReturnTo(getFormString(formData, "returnTo"));
  const baseUrl = getSurfaceBaseUrl(request.headers, request.url);
  const failureRedirectUrl = new URL("/login", baseUrl);
  const defaultPath = surface === "hub" ? "/admin/accounts" : "/";
  const successUrl = new URL(returnTo ?? defaultPath, baseUrl);

  const email = String(formData.get("email") ?? "");
  const password = String(formData.get("password") ?? "");
  const rateLimitIdentifier = normalizeEmail(email);
  const auditMetadata = createAuditRequestMetadata(request.headers, "hub-login");
  const actorEmailHash = rateLimitIdentifier ? hashAuditEmail(rateLimitIdentifier) : undefined;

  const authentication = await authenticateUserWithRateLimit(email, password);
  const user = authentication.user;

  if (!user) {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorEmailHash,
      resource: "hub",
      message:
        authentication.failureMode === "rate-limited"
          ? "Login rate limit reached."
          : authentication.failureMode === "limiter-unavailable"
            ? "Login rate limit unavailable."
            : "Login failed.",
      metadata: auditMetadata
    });
    return redirectToLogin(failureRedirectUrl, true, returnTo);
  }

  let ceremony;
  try {
    ceremony = await startLoginCeremony(
      user.id,
      readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME),
      "pt-BR"
    );
  } catch {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_FAILURE",
      result: "FAILURE",
      actorUserId: user.id,
      actorEmailHash: hashAuditEmail(user.email),
      resource: "hub",
      message: "Security verification unavailable.",
      metadata: auditMetadata
    });
    return redirectToLogin(failureRedirectUrl, true, returnTo);
  }

  if (ceremony.kind === "SESSION") {
    await writeAuditLog({
      eventType: "AUTH_LOGIN_SUCCESS",
      result: "SUCCESS",
      actorUserId: user.id,
      actorEmailHash: hashAuditEmail(user.email),
      resource: "hub",
      message: "Remembered-browser login succeeded.",
      metadata: { ...auditMetadata, rememberedBrowser: true }
    });
    const response = NextResponse.redirect(successUrl, { status: 303 });
    response.cookies.set(SESSION_COOKIE_NAME, ceremony.session.token, getSessionCookieOptions(ceremony.session.expiresAt));
    return response;
  }

  await writeAuditLog({
    eventType: "AUTH_LOGIN_SUCCESS",
    result: "INFO",
    actorUserId: user.id,
    actorEmailHash: hashAuditEmail(user.email),
    resource: "hub",
    message: "Password accepted; security verification pending.",
    metadata: auditMetadata
  });
  const verifyUrl = new URL("/login/verify", baseUrl);
  verifyUrl.searchParams.set("ceremony", ceremony.ceremonyId);
  verifyUrl.searchParams.set("factor", ceremony.factor.toLowerCase());
  if (returnTo) verifyUrl.searchParams.set("returnTo", returnTo);
  const response = NextResponse.redirect(verifyUrl, { status: 303 });
  if (readCookie(request.headers.get("cookie"), DEVICE_COOKIE_NAME) !== ceremony.deviceToken) {
    response.cookies.set(DEVICE_COOKIE_NAME, ceremony.deviceToken, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 180 * 24 * 60 * 60
    });
  }

  return response;
}

function redirectToLogin(url: URL, failed: boolean, returnTo: string | null) {
  if (failed) {
    url.searchParams.set("error", "1");
  }
  if (returnTo) url.searchParams.set("returnTo", returnTo);

  return NextResponse.redirect(url, { status: 303 });
}

function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) {
    return undefined;
  }

  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0 || pair.slice(0, separator).trim() !== name) {
      continue;
    }
    return pair.slice(separator + 1).trim();
  }

  return undefined;
}
