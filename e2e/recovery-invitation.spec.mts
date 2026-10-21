import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { hashPassword, hashSessionToken, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { hashEmailAddress, hashRecoveryRequestKey, requestAccountRecovery } from "@virki/auth/security";
// @ts-expect-error The disposable-database guard is a JavaScript safety helper without a declaration file.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";
// @ts-expect-error The LOW-05 diagnostics helper is a JavaScript test-only redaction boundary.
import { classifyLow05NavigationError, classifyLow05Url, describeLow05Response } from "../scripts/e2e/low05-diagnostics.mjs";

const portalUrl = process.env.VIRKI_E2E_HUB_MODE === "production" ? "https://portal.localhost" : "https://portal.localhost:3001";
const sessionCookieName = getSessionCookieName({ NODE_ENV: process.env.VIRKI_E2E_HUB_MODE === "production" ? "production" : "development" });
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();

function hasLow05NoStoreDirectives(value: string): boolean {
  const directives = new Set(value.toLowerCase().split(",").map((directive) => directive.trim()));
  return ["no-store", "max-age=0", "must-revalidate"].every((directive) => directives.has(directive)) && !directives.has("public");
}

async function goBackToProtectedPage(page: import("@playwright/test").Page): Promise<{ status: number; cacheControl: string }> {
  const protectedDocumentResponse = page.waitForResponse((response) => {
    const request = response.request();
    const url = new URL(response.url());
    return request.frame() === page.mainFrame() && request.isNavigationRequest() && request.resourceType() === "document" && request.method() === "GET" &&
      url.origin === new URL(portalUrl).origin && url.pathname === "/account/security";
  }, { timeout: 15_000 });
  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(`${portalUrl}/account/security`);
  const response = await protectedDocumentResponse;
  return { status: response.status(), cacheControl: await response.headerValue("cache-control") ?? "" };
}

test.skip(!e2eDatabaseUrl, "Recovery/invitation E2E requires an explicit disposable PostgreSQL fixture.");

type AuthFixture = { admin: { id: string }; user: { id: string; email: string; password: string } };

test("public recovery form gives known and unknown addresses the same browser response", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_PORTAL_URL = portalUrl;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.localhost";
  const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
  if (!fixturePath) throw new Error("Recovery/invitation E2E fixture path is unavailable.");
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(fixturePath, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const unknownEmail = `${randomUUID()}@unknown.e2e.invalid`;
  const responses: Array<{ url: string; httpStatus: number; body: string; status: string; heading: string }> = [];
  try {
    const knownRequestCountBefore = await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } });
    const knownMessageCountBefore = await database.emailOutboxMessage.count({ where: { recipientEmail: fixture.user.email, kind: "ACCOUNT_RECOVERY" } });
    for (const email of [fixture.user.email, unknownEmail]) {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.goto(`${portalUrl}/recover`);
        await page.getByLabel("E-mail", { exact: true }).fill(email);
        const actionResponsePromise = page.waitForResponse((response) => {
          const responseUrl = new URL(response.url());
          return response.request().method() === "POST" && responseUrl.origin === new URL(portalUrl).origin && responseUrl.pathname === "/recover";
        });
        await page.getByRole("button", { name: "Enviar instruções", exact: true }).click();
        const actionResponse = await actionResponsePromise;
        await expect(page).toHaveURL(`${portalUrl}/recover?sent=1`);
        const status = page.getByRole("status");
        await expect(status).toHaveText("Se a conta puder ser recuperada, você receberá instruções no e-mail cadastrado.");
        responses.push({
          url: new URL(page.url()).pathname + new URL(page.url()).search,
          httpStatus: actionResponse.status(),
          body: await page.locator("main").innerText(),
          status: await status.innerText(),
          heading: await page.getByRole("heading", { level: 1 }).innerText()
        });
      } finally {
        await context.close();
      }
    }
    expect(responses[0]).toEqual(responses[1]);
    const knownRequestCountAfter = await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } });
    const knownMessageCountAfter = await database.emailOutboxMessage.count({ where: { recipientEmail: fixture.user.email, kind: "ACCOUNT_RECOVERY" } });
    expect(knownRequestCountAfter).toBe(knownRequestCountBefore + 1);
    expect(knownMessageCountAfter).toBe(knownMessageCountBefore + 1);
    expect(await database.accountRecoveryRequest.count({ where: { emailAddressHash: hashEmailAddress(unknownEmail) } })).toBe(0);
    expect(await database.emailOutboxMessage.count({ where: { recipientEmail: unknownEmail, kind: "ACCOUNT_RECOVERY" } })).toBe(0);
  } finally {
    await database.$disconnect();
  }
});

test("invitation purpose survives URL spoofing and activates a USER once with onboarding copy", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_PORTAL_URL = portalUrl;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.localhost";
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  let sessionId: string | undefined;
  try {
    const { provisionInvitedUserAccount } = await import("@virki/auth/account-invitation");
    const email = `${randomUUID()}.invited@e2e.invalid`;
    const expiresAt = new Date(Date.now() + 10 * 60_000);
    const session = await database.session.create({
      data: { userId: fixture.admin.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")), expiresAt },
      select: { id: true }
    });
    sessionId = session.id;
    await database.securityElevation.create({
      data: {
        userId: fixture.admin.id,
        sessionId,
        requestKey: randomBytes(24).toString("base64url"),
        protocolVersion: 1,
        scope: "ACCOUNT_STATE_CHANGE",
        challengeHash: "e2e-fixture",
        status: "ACTIVE",
        expiresAt
      }
    });
    await provisionInvitedUserAccount({ id: fixture.admin.id }, sessionId, { email, displayName: "E2E Invitee" });
    const account = await database.user.findUnique({ where: { emailNormalized: email }, select: { id: true, passwordHash: true } });
    expect(account).not.toBeNull();
    const message = await database.emailOutboxMessage.findFirst({ where: { recipientEmail: email, kind: "ACCOUNT_INVITATION" }, select: { payload: true } });
    expect(message).not.toBeNull();
    if (!account || !message) throw new Error("Invitation E2E fixture was not created.");
    const actionUrl = decryptEmailPayload(message.payload).actionUrl;
    if (!actionUrl || new URL(actionUrl).origin !== portalUrl) throw new Error("Invitation E2E link is invalid.");
    const spoofedUrl = new URL(actionUrl);
    spoofedUrl.searchParams.set("purpose", "RECOVERY");
    const page = await context.newPage();
    await page.goto(spoofedUrl.toString());
    await expect(page.getByRole("heading", { level: 1, name: "Ativar sua conta", exact: true })).toBeVisible();
    await expect(page.getByText("Bem-vindo ao Virki! Defina uma senha para ativar sua conta. O convite é válido por 72 horas e pode ser usado uma vez.", { exact: true })).toBeVisible();
    const passwordInput = page.getByLabel("Criar senha", { exact: true });
    await expect(passwordInput).toHaveAttribute("minlength", "12");
    const password = `Invite-${randomBytes(24).toString("base64url")}`;
    await passwordInput.fill(password);
    await page.getByRole("button", { name: "Ativar conta", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/login?invited=1`);
    await expect(page.getByRole("status")).toContainText("Conta ativada");
    const activated = await database.user.findUnique({ where: { id: account.id }, select: { passwordHash: true, emailVerifiedAt: true, accountStatus: true } });
    expect(activated?.passwordHash).toBeTruthy();
    expect(activated?.emailVerifiedAt).not.toBeNull();
    expect(activated?.accountStatus).toBe("ACTIVE");
    expect(await verifyPassword(activated!.passwordHash!, password)).toBe(true);
    expect(await database.accountRecoveryRequest.count({ where: { userId: account.id, purpose: "INVITATION", status: "CONSUMED" } })).toBe(1);

    await page.goto(actionUrl);
    await expect(page.locator('p.form-error[role="alert"]')).toContainText("Não foi possível abrir este link.");
    await expect(page.getByLabel("Criar senha", { exact: true })).toHaveCount(0);
    expect(await database.user.findUnique({ where: { id: account.id }, select: { passwordHash: true } })).toEqual({ passwordHash: activated?.passwordHash });
  } finally {
    if (sessionId) await database.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    await context.close();
    await database.$disconnect();
  }
});

test("approved USER recovery keeps recovery copy and rejects a short password on the server", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery/invitation E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_PORTAL_URL = portalUrl;
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.localhost";
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  try {
    const email = `${randomUUID()}.recovery@e2e.invalid`;
    const originalPassword = `Original-${randomBytes(24).toString("base64url")}`;
    const user = await database.user.create({ data: {
      email, emailNormalized: email, displayName: "E2E Recovery User", passwordHash: await hashPassword(originalPassword),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date()
    }, select: { id: true, passwordHash: true } });
    await requestAccountRecovery(email, "pt-BR");
    const message = await database.emailOutboxMessage.findFirst({ where: { recipientEmail: email, kind: "ACCOUNT_RECOVERY" }, orderBy: { createdAt: "desc" }, select: { payload: true } });
    if (!message) throw new Error("USER recovery E2E email is unavailable.");
    const actionUrl = decryptEmailPayload(message.payload).actionUrl;
    if (!actionUrl || new URL(actionUrl).origin !== portalUrl) throw new Error("USER recovery E2E link is invalid.");
    const requestKey = new URL(actionUrl).searchParams.get("request");
    if (!requestKey) throw new Error("USER recovery E2E key is unavailable.");
    const recovery = await database.accountRecoveryRequest.findUnique({ where: { requestKeyHash: hashRecoveryRequestKey(requestKey) }, select: { id: true } });
    if (!recovery) throw new Error("USER recovery E2E record is unavailable.");
    const approvedAt = new Date();
    await database.accountRecoveryRequest.update({ where: { id: recovery.id }, data: {
      status: "APPROVED", emailVerifiedAt: approvedAt, reviewedByUserId: fixture.admin.id, approvedAt
    } });

    const page = await context.newPage();
    await page.goto(actionUrl);
    await expect(page.getByRole("heading", { level: 1, name: "Recuperar conta", exact: true })).toBeVisible();
    await expect(page.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    const passwordInput = page.getByLabel("Nova senha", { exact: true });
    await expect(passwordInput).toHaveAttribute("minlength", "12");
    await expect(passwordInput).toHaveAttribute("pattern", "[^\\u0000-\\u001f\\u007f-\\u009f]{12,256}");
    await passwordInput.evaluate((input) => { (input as HTMLInputElement).form!.noValidate = true; });
    await passwordInput.fill("short");
    await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/recover?requestId=${recovery.id}`);
    await expect(page.locator('p.form-error[role="alert"]')).toContainText("pelo menos 12 caracteres");
    expect(await database.user.findUnique({ where: { id: user.id }, select: { passwordHash: true } })).toEqual({ passwordHash: user.passwordHash });

    const newPassword = `Recovered-${randomBytes(24).toString("base64url")}`;
    await page.getByLabel("Nova senha", { exact: true }).fill(newPassword);
    await page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(page).toHaveURL(`${portalUrl}/login?recovered=1`);
    const recovered = await database.user.findUnique({ where: { id: user.id }, select: { passwordHash: true } });
    expect(recovered?.passwordHash).not.toBeNull();
    expect(await verifyPassword(recovered!.passwordHash!, newPassword)).toBe(true);
    expect(await verifyPassword(recovered!.passwordHash!, originalPassword)).toBe(false);
    expect(await database.accountRecoveryRequest.findUnique({ where: { id: recovery.id }, select: { status: true, purpose: true, emailVerifiedAt: true } })).toMatchObject({ status: "CONSUMED", purpose: "RECOVERY", emailVerifiedAt: approvedAt });
  } finally {
    await context.close();
    await database.$disconnect();
  }
});

test("USER TOTP confirmation hides the enrollment secret and recovery codes after success", async ({ browser }) => {
  test.setTimeout(90_000);
  if (!e2eDatabaseUrl) throw new Error("TOTP E2E database is unavailable.");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  const fixture = JSON.parse(await (await import("node:fs/promises")).readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as AuthFixture;
  const database = new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } });
  const context = await browser.newContext();
  await context.addInitScript(() => {
    const recordLifecycleEvent = (keyPrefix: string | null, type: "pagehide" | "pageshow", persisted: boolean) => {
      if (!keyPrefix) return;
      const storageKey = `${keyPrefix}-lifecycle-events`;
      const current = JSON.parse(window.sessionStorage.getItem(storageKey) ?? "[]") as Array<{ type: string; persisted: boolean }>;
      current.push({ type, persisted });
      window.sessionStorage.setItem(storageKey, JSON.stringify(current));
    };
    window.addEventListener("pagehide", (event) => {
      const keyPrefix = window.location.pathname === "/account/security"
        ? "virki-low05-security"
        : window.location.pathname === "/"
          ? "virki-low05-portal"
          : null;
      if (!keyPrefix) return;
      window.sessionStorage.setItem(`${keyPrefix}-pagehide-persisted`, String(event.persisted));
      recordLifecycleEvent(keyPrefix, "pagehide", event.persisted);
    });
    window.addEventListener("pageshow", (event) => {
      const keyPrefix = window.location.pathname === "/account/security"
        ? "virki-low05-security"
        : window.location.pathname === "/"
          ? "virki-low05-portal"
          : null;
      if (!keyPrefix) return;
      window.sessionStorage.setItem(`${keyPrefix}-pageshow-persisted`, String(event.persisted));
      recordLifecycleEvent(keyPrefix, "pageshow", event.persisted);
    });
  });
  const page = await context.newPage();
  const low05NavigationResponses: Array<Record<string, unknown>> = [];
  const low05NavigationFailures: Array<Record<string, string>> = [];
  page.on("response", (response) => {
    const request = response.request();
    if (!request.isNavigationRequest()) return;
    const summary = describeLow05Response(response, response.url(), portalUrl) as Record<string, unknown> & { route: { origin: string; route: string } };
    if (summary.route.origin !== "portal" || !["account-security", "login", "root"].includes(summary.route.route)) return;
    const method = request.method().toUpperCase();
    low05NavigationResponses.push({ method: ["GET", "HEAD", "POST"].includes(method) ? method : "other", ...summary });
  });
  page.on("requestfailed", (request) => {
    if (!request.isNavigationRequest()) return;
    const route = classifyLow05Url(request.url(), portalUrl);
    if (route.origin !== "portal" || !["account-security", "login"].includes(route.route)) return;
    low05NavigationFailures.push({ route: route.route, error: classifyLow05NavigationError(request.failure()?.errorText) });
  });
  let sessionId: string | undefined;
  try {
    await context.clearCookies();
    expect((await context.cookies(portalUrl)).some(({ name }) => name === sessionCookieName)).toBe(false);
    const initialUrl = classifyLow05Url(portalUrl + "/account/security", portalUrl);
    let unauthenticatedResponse: import("@playwright/test").Response | null = null;
    let navigationError = "none";
    try {
      unauthenticatedResponse = await page.goto(portalUrl + "/account/security", { waitUntil: "domcontentloaded" });
    } catch (error) {
      navigationError = classifyLow05NavigationError(error);
    }
    const loginFormPresent = await page.getByLabel("E-mail", { exact: true }).count().then((count) => count > 0).catch(() => false);
    const securityHeadingPresent = await page.getByRole("heading", { level: 1, name: "Segurança", exact: true }).count().then((count) => count > 0).catch(() => false);
    const genericErrorPagePresent = await page.getByRole("heading", { name: /^(404|500|internal server error|application error)/iu }).count().then((count) => count > 0).catch(() => false);
    const navigationEvidence = {
      initialUrl,
      finalUrl: classifyLow05Url(page.url(), portalUrl),
      requestBoundary: {
        origin: portalUrl.startsWith("https://portal.localhost") ? "portal" : "other",
        scheme: portalUrl.startsWith("https://") ? "https" : "other",
        originHasExplicitPort: Boolean(new URL(portalUrl).port),
        productionHubMode: process.env.VIRKI_E2E_HUB_MODE === "production"
      },
      gotoResponse: unauthenticatedResponse ? { method: "GET", ...describeLow05Response(unauthenticatedResponse, unauthenticatedResponse.url(), portalUrl) } : null,
      nextProxyMatcherExecuted: low05NavigationResponses.some((response) =>
        (response.route as { route?: string }).route === "account-security" && response.requestIdPresent === true
      ),
      redirectChain: low05NavigationResponses,
      failedNavigationRequests: low05NavigationFailures,
      navigationError,
      page: { loginFormPresent, securityHeadingPresent, genericErrorPagePresent }
    };
    if (process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true") {
      console.log(`LOW-05 unauthenticated navigation: ${JSON.stringify(navigationEvidence)}`);
    }
    expect(navigationError).toBe("none");
    expect(low05NavigationResponses[0]?.status).toBe(307);
    expect(low05NavigationResponses[0]?.requestIdPresent).toBe(true);
    expect(navigationEvidence.finalUrl).toEqual({ origin: "portal", route: "login", returnTo: "account-security" });
    await page.getByLabel("E-mail", { exact: true }).fill(fixture.user.email);
    await page.getByLabel("Senha", { exact: true }).fill(fixture.user.password);
    const loginResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/login" && response.request().method() === "POST");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();
    const loginResponse = await loginResponsePromise;
    if (loginResponse.status() !== 303) throw new Error("E2E USER login did not create an email verification challenge.");
    const loginLocation = loginResponse.headers().location;
    if (!loginLocation) throw new Error("E2E USER login did not return a verification destination.");
    const verificationUrl = new URL(loginLocation, portalUrl);
    const ceremonyId = verificationUrl.searchParams.get("ceremony");
    if (verificationUrl.pathname !== "/login/verify" || verificationUrl.searchParams.get("factor") !== "email" || !ceremonyId) {
      const fixtureUserState = await database.user.findUnique({
        where: { id: fixture.user.id },
        select: { passwordHash: true, role: true, isActive: true, accountStatus: true, secondFactorMethod: true }
      });
      const factor = verificationUrl.searchParams.get("factor");
      const loginEvidence = {
        status: loginResponse.status(),
        destination: verificationUrl.pathname === "/login/verify" ? "login-verify" : verificationUrl.pathname === "/login" ? "login" : "other",
        factor: factor === "email" || factor === "totp" ? factor : "other",
        ceremonyPresent: Boolean(ceremonyId),
        errorPresent: verificationUrl.searchParams.has("error"),
        role: fixtureUserState?.role ?? "missing",
        active: fixtureUserState?.isActive ?? false,
        accountStatus: fixtureUserState?.accountStatus ?? "missing",
        secondFactorMethod: fixtureUserState?.secondFactorMethod ?? "none",
        passwordMatchesStoredHash: fixtureUserState?.passwordHash ? await verifyPassword(fixtureUserState.passwordHash, fixture.user.password) : false
      };
      if (process.env.VIRKI_E2E_LOW05_DIAGNOSTICS === "true") console.log(`LOW-05 login classification: ${JSON.stringify(loginEvidence)}`);
      throw new Error("E2E USER login did not request the expected email factor.");
    }
    await page.waitForURL((url) => url.pathname === "/login/verify" && url.searchParams.get("ceremony") === ceremonyId);
    const verificationMessage = await database.emailOutboxMessage.findFirst({
      where: {
        idempotencyKey: "security-ceremony:" + ceremonyId,
        recipientEmail: fixture.user.email,
        kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] }
      },
      select: { payload: true }
    });
    if (!verificationMessage) throw new Error("E2E USER email verification message is unavailable.");
    const emailCode = decryptEmailPayload(verificationMessage.payload).code;
    if (!/^\d{6}$/u.test(emailCode ?? "")) throw new Error("E2E USER email verification message is invalid.");
    await page.getByLabel("Código", { exact: true }).fill(emailCode!);
    await page.getByRole("button", { name: "Continuar", exact: true }).click();
    await page.waitForURL((url) => url.pathname === "/account/security");
    const sessionCookie = (await context.cookies(portalUrl)).find(({ name }) => name === sessionCookieName);
    if (!sessionCookie) throw new Error("E2E USER session cookie was not created after email verification.");
    const activeSession = await database.session.findFirst({
      where: { userId: fixture.user.id, tokenHash: hashSessionToken(sessionCookie.value) },
      select: { id: true }
    });
    if (!activeSession) throw new Error("E2E USER session was not persisted after email verification.");
    sessionId = activeSession.id;

    const securityResponse = await page.reload();
    const securityCacheControl = await securityResponse?.headerValue("cache-control") ?? "";
    const securityResponseIsNoStore = /(?:^|,)\s*no-store(?:,|$)/iu.test(securityCacheControl);
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(securityCacheControl).toBe("private, no-store, max-age=0, must-revalidate");
    } else if (!securityResponseIsNoStore) {
      // Next's development server replaces Proxy response headers with this value; the production policy is
      // checked at the Proxy boundary, while browser BFCache proof requires a production-mode server.
      expect(securityCacheControl).toBe("no-cache, must-revalidate");
      console.log("LOW-05 production BFCache proof unavailable: isolated E2E uses Next development mode.");
    }
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const actionResponses: Array<Promise<{ status: number; cacheControl: string }>> = [];
    page.on("response", (response) => {
      if (response.request().method() === "POST" && new URL(response.url()).origin === new URL(portalUrl).origin) {
        actionResponses.push(response.headerValue("cache-control").then((cacheControl) => ({ status: response.status(), cacheControl: cacheControl ?? "" })));
      }
    });
    const factorSection = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Autenticação multifator", exact: true }) });
    await factorSection.getByLabel("Senha atual", { exact: true }).fill(fixture.user.password);
    const beginActionIndex = actionResponses.length;
    await factorSection.getByRole("button", { name: "Configurar aplicativo autenticador", exact: true }).click();
    const secretElement = factorSection.locator("code");
    await expect(secretElement).toHaveCount(1);
    const secret = (await secretElement.textContent())?.trim() ?? "";
    if (!/^[A-Z2-7]+=*$/u.test(secret)) throw new Error("E2E TOTP enrollment secret was invalid.");
    const beginAction = (await Promise.all(actionResponses))[beginActionIndex];
    if (!beginAction) throw new Error("E2E TOTP enrollment action response was not observed.");
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(hasLow05NoStoreDirectives(beginAction.cacheControl)).toBe(true);
    }
    const code = currentTotpCode(secret);
    await factorSection.getByLabel("Código atual do aplicativo", { exact: true }).fill(code);
    const activateActionIndex = actionResponses.length;
    await factorSection.getByRole("button", { name: "Ativar TOTP", exact: true }).click();
    await expect(factorSection.getByRole("heading", { name: "Códigos de recuperação — exibidos uma vez", exact: true })).toBeVisible();
    const codes = await factorSection.locator("section[aria-live='polite'] li code").allTextContents();
    if (codes.length !== 10 || codes.some((recoveryCode) => !/^[A-Z0-9-]{8,32}$/u.test(recoveryCode))) {
      throw new Error("E2E TOTP recovery codes were invalid.");
    }
    const activateAction = (await Promise.all(actionResponses))[activateActionIndex];
    if (!activateAction) throw new Error("E2E TOTP activation action response was not observed.");
    if (process.env.VIRKI_E2E_HUB_MODE === "production") {
      expect(hasLow05NoStoreDirectives(activateAction.cacheControl)).toBe(true);
    }
    const sensitiveValues = [fixture.user.password, emailCode!, secret, code, ...codes];
    const visibleState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(visibleState.dom).toBe(true);
    expect(visibleState.accessibility).toBe(true);
    expect(visibleState.history).toBe(false);
    expect(visibleState.storage).toBe(false);
    expect(await database.recoveryCode.count({ where: { userId: fixture.user.id, usedAt: null } })).toBe(10);

    await page.goto(`${portalUrl}/?history-probe=low05`);
    await expect(page).toHaveURL(`${portalUrl}/?history-probe=low05`);
    const historyBackResponse = await goBackToProtectedPage(page);
    expect(historyBackResponse.status).toBe(200);
    expect(historyBackResponse.cacheControl).toBe("private, no-store, max-age=0, must-revalidate");
    const browserCacheEvidence = await page.evaluate(() => {
      type NotRestoredReasonTree = { reasons?: Array<{ reason: string }>; children?: NotRestoredReasonTree[] };
      type NavigationWithNotRestoredReasons = PerformanceNavigationTiming & { notRestoredReasons?: NotRestoredReasonTree | null };
      const navigation = performance.getEntriesByType("navigation")[0] as NavigationWithNotRestoredReasons | undefined;
      const collectReasons = (tree: NotRestoredReasonTree | null | undefined): string[] => tree
        ? [...(tree.reasons ?? []).map(({ reason }) => reason), ...(tree.children ?? []).flatMap(collectReasons)]
        : [];
      return {
        pagehidePersisted: window.sessionStorage.getItem("virki-low05-security-pagehide-persisted"),
        pageshowPersisted: window.sessionStorage.getItem("virki-low05-security-pageshow-persisted"),
        lifecycleEvents: JSON.parse(window.sessionStorage.getItem("virki-low05-security-lifecycle-events") ?? "[]") as Array<{ type: string; persisted: boolean }>,
        notRestoredReasons: collectReasons(navigation?.notRestoredReasons)
      };
    });
    console.log(`LOW-05 browser history probe: cache-control=${securityCacheControl || "unobserved"}; pagehide.persisted=${browserCacheEvidence.pagehidePersisted ?? "unobserved"}; pageshow.persisted=${browserCacheEvidence.pageshowPersisted ?? "unobserved"}; lifecycle=${JSON.stringify(browserCacheEvidence.lifecycleEvents)}; notRestoredReasons=${browserCacheEvidence.notRestoredReasons.join(",") || "none"}`);
    console.log(`LOW-05 production browser: chromium=${browser.version()}; document-cache-control=${securityCacheControl}; begin-action-cache-control=${beginAction.cacheControl}; recovery-action-cache-control=${activateAction.cacheControl}`);
    expect(browserCacheEvidence.pagehidePersisted).not.toBeNull();
    expect(browserCacheEvidence.pageshowPersisted).not.toBeNull();
    expect(browserCacheEvidence.lifecycleEvents.some(({ type }) => type === "pagehide")).toBe(true);
    expect(browserCacheEvidence.lifecycleEvents.some(({ type }) => type === "pageshow")).toBe(true);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const backState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(backState.dom).toBe(false);
    expect(backState.accessibility).toBe(false);
    expect(backState.history).toBe(false);
    expect(backState.storage).toBe(false);
    expect(backState.forms).toBe(false);
    await page.goForward({ waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(`${portalUrl}/?history-probe=low05`);
    const repeatHistoryBackResponse = await goBackToProtectedPage(page);
    expect(repeatHistoryBackResponse.status).toBe(200);
    expect(repeatHistoryBackResponse.cacheControl).toBe("private, no-store, max-age=0, must-revalidate");
    const repeatBackState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(repeatBackState.dom).toBe(false);
    expect(repeatBackState.accessibility).toBe(false);
    expect(repeatBackState.history).toBe(false);
    expect(repeatBackState.storage).toBe(false);
    expect(repeatBackState.forms).toBe(false);

    await page.reload();
    await expect(factorSection.getByText("Aplicativo autenticador (TOTP) ativo.", { exact: true })).toBeVisible();
    const reloadState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(reloadState.dom).toBe(false);
    expect(reloadState.accessibility).toBe(false);
    expect(reloadState.history).toBe(false);
    expect(reloadState.storage).toBe(false);
    expect(reloadState.forms).toBe(false);

    await page.goto(`${portalUrl}/`);
    await expect(page.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();
    const logoutResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/logout" && response.request().method() === "POST");
    await page.getByRole("button", { name: "Sair", exact: true }).click();
    const logoutResponse = await logoutResponsePromise;
    await page.waitForURL((url) => url.pathname === "/login");
    const logoutEvidence = describeLow05Response(logoutResponse, logoutResponse.url(), portalUrl);
    console.log(`LOW-05 logout response: ${JSON.stringify({ method: "POST", ...logoutEvidence })}`);
    expect(logoutResponse.status()).toBe(303);
    expect(logoutEvidence.cacheControl).toBe("no-store");
    expect((await context.cookies(portalUrl)).some(({ name }) => name === sessionCookieName)).toBe(false);
    expect((await database.session.findUnique({ where: { id: sessionId }, select: { revokedAt: true } }))?.revokedAt).not.toBeNull();

    await page.goBack({ waitUntil: "networkidle" });
    const logoutBackEvidence = await page.evaluate(() => ({
      path: window.location.pathname,
      navigationType: (window.performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type ?? "unknown",
      bodyChildCount: document.body.childElementCount,
      protectedContentCount: document.querySelectorAll("[data-protected-page-content]").length,
      protectedContentHasChildren: Array.from(document.querySelectorAll("[data-protected-page-content]"), (element) => element.childElementCount > 0),
      portalPagehidePersisted: window.sessionStorage.getItem("virki-low05-portal-pagehide-persisted"),
      portalPageshowPersisted: window.sessionStorage.getItem("virki-low05-portal-pageshow-persisted"),
      lifecycleEvents: JSON.parse(window.sessionStorage.getItem("virki-low05-portal-lifecycle-events") ?? "[]") as Array<{ type: string; persisted: boolean }>
    }));
    const postLogoutLoginFormPresent = await page.getByLabel("E-mail", { exact: true }).count().then((count) => count > 0).catch(() => false);
    const authenticatedPortalHeadingPresent = await page.getByRole("heading", { level: 1, name: "Projetos", exact: true }).count().then((count) => count > 0).catch(() => false);
    const logoutButtonPresent = await page.getByRole("button", { name: "Sair", exact: true }).count().then((count) => count > 0).catch(() => false);
    console.log(`LOW-05 post-logout history: ${JSON.stringify({ ...logoutBackEvidence, route: classifyLow05Url(page.url(), portalUrl), loginFormPresent: postLogoutLoginFormPresent, authenticatedPortalHeadingPresent, logoutButtonPresent, recentNavigationResponses: low05NavigationResponses.slice(-6) })}`);
    await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
    expect(logoutBackEvidence.path).toBe("/login");
    expect(logoutBackEvidence.lifecycleEvents.some(({ type }) => type === "pagehide")).toBe(true);
    expect(authenticatedPortalHeadingPresent).toBe(false);
    expect(logoutButtonPresent).toBe(false);
    const loggedOutState = await inspectSensitiveBrowserState(page, sensitiveValues);
    expect(loggedOutState.dom).toBe(false);
    expect(loggedOutState.accessibility).toBe(false);
    expect(loggedOutState.history).toBe(false);
    expect(loggedOutState.storage).toBe(false);
    expect(loggedOutState.forms).toBe(false);
  } finally {
    if (sessionId) await database.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
    await context.close();
    await database.$disconnect();
  }
});

async function inspectSensitiveBrowserState(page: import("@playwright/test").Page, sensitiveValues: string[]) {
  const html = await page.content();
  const accessibleSnapshot = await page.locator("body").ariaSnapshot();
  const pageState = await page.evaluate(() => ({
    history: JSON.stringify(window.history.state ?? null),
    storage: [window.localStorage, window.sessionStorage].flatMap((storage) => Object.keys(storage).map((key) => storage.getItem(key) ?? "")).join("\n"),
    forms: Array.from(document.forms).flatMap((form) => Array.from(form.elements).map((element) => "value" in element ? String(element.value ?? "") : "")).join("\n"),
    dom: document.documentElement.outerHTML
  }));
  const containsValue = (text: string) => sensitiveValues.some((value) => value.length > 0 && text.includes(value));
  return {
    dom: containsValue(html) || containsValue(pageState.dom),
    accessibility: containsValue(accessibleSnapshot),
    history: containsValue(pageState.history),
    storage: containsValue(pageState.storage),
    forms: containsValue(pageState.forms)
  };
}

function currentTotpCode(secret: string, now = Date.now()): string {
  const key = decodeBase32(secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of value.replace(/=+$/u, "")) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error("TOTP E2E secret is invalid.");
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  return Buffer.from(bytes);
}
