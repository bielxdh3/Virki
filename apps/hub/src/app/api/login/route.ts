import { NextResponse } from "next/server";
import {
  authenticateUserWithRateLimit,
  createAuditRequestMetadata,
  hashAuditEmail,
  normalizeEmail,
  writeAuditLog
} from "@bielos/auth";
import { DEVICE_COOKIE_NAME, startLoginCeremony } from "@bielos/auth/security";
import { CSRF_FORM_FIELD_NAME, validateCsrfToken } from "@bielos/auth/csrf";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../lib/cloudflare-access";
import { createHubRedirectUrl } from "../../../lib/hub-redirect";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const accessResult = await validateHubCloudflareAccess(request.headers, "hub-login-api");

  if (!isCloudflareAccessAllowed(accessResult)) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  const formData = await request.formData();
  const csrfResult = validateCsrfToken(getFormString(formData, CSRF_FORM_FIELD_NAME));

  if (!csrfResult.valid) {
    return new NextResponse("Forbidden", { status: 403 });
  }

  let failureRedirectUrl: URL;

  try {
    failureRedirectUrl = createHubRedirectUrl("/login", request.url);
  } catch {
    return new NextResponse("Service unavailable", { status: 503 });
  }

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
    return redirectToLogin(failureRedirectUrl, true);
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
    return redirectToLogin(failureRedirectUrl, true);
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
  const verifyUrl = createHubRedirectUrl("/login/verify", request.url);
  verifyUrl.searchParams.set("ceremony", ceremony.ceremonyId);
  verifyUrl.searchParams.set("factor", ceremony.factor.toLowerCase());
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

function redirectToLogin(url: URL, failed: boolean) {
  if (failed) {
    url.searchParams.set("error", "1");
  }

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
