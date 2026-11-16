import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { PrismaClient } from "@virki/database";

// @ts-expect-error The shared safety helper is JavaScript without a declaration.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const hubUrl = "https://hub.localhost:3001";
const portalUrl = "https://portal.localhost:3001";
const sessionCookieName = getSessionCookieName({ NODE_ENV: "development" });

type Actor = { id: string; email: string; password: string; deviceToken: string };
type Fixture = { user: Actor; recoveryReviewer: Actor };

let fixture: Fixture;
let database: PrismaClient;

test.beforeAll(async () => {
  if (process.env.VIRKI_E2E_NATIVE_HUB !== "required" ||
      process.env.VIRKI_E2E_HUB_MODE === "production" ||
      process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("Native Hub browser gate was not explicitly isolated.");
  }
  const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL;
  const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
  if (!databaseUrl || !fixturePath || !existsSync(fixturePath)) {
    throw new Error("Native Hub browser gate requires the seeded disposable PostgreSQL fixture.");
  }
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  if (new URL(databaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("Native Hub browser gate refuses a non-E2E database.");
  }
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isFixture(value)) throw new Error("Native Hub browser fixture is incomplete.");
  fixture = value;
  database = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
});

test.afterAll(async () => { await database?.$disconnect(); });

test("NATIVE HUB: unauthenticated login/recovery reachable but admin data denied without Access JWT", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    const login = await page.goto(`${hubUrl}/login`);
    expect(login?.status()).toBe(200);
    expect(login?.request().headers()["cf-access-jwt-assertion"]).toBeUndefined();
    await expect(page.getByRole("heading", { level: 1, name: "Entrar" })).toBeVisible();

    const recovery = await page.goto(`${hubUrl}/recover`);
    expect(recovery?.status()).toBe(200);
    expect(recovery?.request().headers()["cf-access-jwt-assertion"]).toBeUndefined();
    await expect(page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();

    // Do not confuse rendering a form with authorizing its real Server Action.
    // An unknown identity gets the non-enumerating synthetic flow without
    // creating an actual account recovery in the disposable PostgreSQL.
    await page.getByLabel("E-mail da conta", { exact: true }).fill(`${randomUUID()}@unknown.e2e.invalid`);
    await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    const recoveryPost = page.waitForResponse((response) => new URL(response.url()).origin === hubUrl &&
      new URL(response.url()).pathname === "/recover" && response.request().method() === "POST" &&
      Boolean(response.request().headers()["next-action"]));
    await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    const recoveryAttempt = await recoveryPost;
    expect(recoveryAttempt.status()).toBeGreaterThanOrEqual(200);
    expect(recoveryAttempt.status()).toBeLessThan(400);
    expect(recoveryAttempt.request().headers()["cf-access-jwt-assertion"]).toBeUndefined();
    await expect(page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]{43}$/u);
    const requestId = new URL(page.url()).searchParams.get("requestId")!;
    expect(await database.accountRecoveryRequest.findUnique({ where: { id: requestId } })).toBeNull();

    const deniedPending = page.waitForResponse((response) => response.url() === `${hubUrl}/admin/accounts` && response.request().method() === "GET");
    await page.goto(`${hubUrl}/admin/accounts`);
    const denied = await deniedPending;
    expect(denied?.status()).toBe(307);
    expect(denied?.headers().location).toBe(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await expect(page.getByRole("heading", { name: "Contas", exact: true })).toHaveCount(0);
    expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(false);

    const forged = await browser.newContext({ extraHTTPHeaders: { "cf-access-jwt-assertion": "forged-access-assertion" } });
    try {
      const forgedPage = await forged.newPage();
      const deniedAgainPending = forgedPage.waitForResponse((response) => response.url() === `${hubUrl}/admin/accounts` && response.request().method() === "GET");
      await forgedPage.goto(`${hubUrl}/admin/accounts`);
      const deniedAgain = await deniedAgainPending;
      expect(deniedAgain?.status()).toBe(307);
      await expect(forgedPage).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      expect((await forged.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(false);
    } finally {
      await forged.close();
    }
  } finally {
    await context.close();
  }
});

test("NATIVE HUB: legitimate USER credentials and authenticated Portal USER cannot enter admin", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`${hubUrl}/login`);
    await enterPassword(page, fixture.user);
    await expect(page).toHaveURL((url) => url.origin === hubUrl && url.pathname === "/login" && url.searchParams.get("error") === "1");
    expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(false);

    // A real Portal login issues a valid USER session. Copy its cookie to the
    // Hub deliberately to test the server-side role check, not just DNS scope.
    await page.goto(`${portalUrl}/login`);
    await enterPassword(page, fixture.user);
    if (new URL(page.url()).pathname === "/login/verify") {
      await completeEmailMfa(page, fixture.user);
    }
    await expect(page.getByRole("heading", { level: 1, name: "Projetos" })).toBeVisible();
    const portalCookie = (await context.cookies(portalUrl)).find((cookie) => cookie.name === sessionCookieName);
    expect(portalCookie?.value).toBeTruthy();
    await context.addCookies([{ name: sessionCookieName, value: portalCookie!.value, url: hubUrl,
      httpOnly: true, secure: true, sameSite: "Lax" }]);
    const response = await page.goto(`${hubUrl}/admin/accounts`);
    expect(response?.status()).toBe(403);
    await expect(page.getByRole("heading", { name: "Contas", exact: true })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("NATIVE HUB: ADMIN password plus genuine queued MFA grants scoped session, CSRF remains required", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await enterPassword(page, fixture.recoveryReviewer);
    await expect(page).toHaveURL((url) => url.origin === hubUrl && url.pathname === "/login/verify" && url.searchParams.get("factor") === "email");
    expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(false);
    await completeEmailMfa(page, fixture.recoveryReviewer);
    await expect(page).toHaveURL(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(true);

    // Playwright's Node APIRequestContext does not inherit Chromium's
    // private host-resolver-rules for hub.localhost in isolated Docker. Send
    // this genuine CSRF-negative request from the browser's same-origin
    // network stack instead; keep both the actual POST and HTTP 403 asserted.
    const invalidCsrfResponse = page.waitForResponse((response) =>
      response.url() === `${hubUrl}/api/login` && response.request().method() === "POST");
    const invalidCsrfStatus = await page.evaluate(async (email) => {
      const response = await fetch("/api/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email })
      });
      return response.status;
    }, fixture.recoveryReviewer.email);
    const invalidCsrf = await invalidCsrfResponse;
    // Request.headers() deliberately omits some browser-managed headers;
    // allHeaders() is required to inspect the actual Origin on the wire.
    const actualRequestHeaders = await invalidCsrf.request().allHeaders();
    expect(actualRequestHeaders.origin).toBe(hubUrl);
    expect(invalidCsrf.status()).toBe(403);
    expect(invalidCsrfStatus).toBe(403);

    await page.goto(`${hubUrl}/admin/security`);
    await expect(page.getByRole("heading", { level: 1, name: "Segurança", exact: true })).toBeVisible();
    const credential = page.locator("section.surface").filter({ has: page.getByRole("heading", { name: "Credencial administrativa", exact: true }) });
    const sendRecovery = credential.getByRole("button", { name: "Enviar código de recuperação por e-mail" });
    await expect(sendRecovery).toBeVisible();
    const recoveryForm = sendRecovery.locator("xpath=ancestor::form");
    const ceremonyBefore = await database.securityElevation.count({
      where: { userId: fixture.recoveryReviewer.id, scope: "ADMIN_CREDENTIAL_EMAIL_RECOVERY" }
    });
    const outboxBefore = await database.emailOutboxMessage.count({
      where: { recipientEmail: fixture.recoveryReviewer.email, kind: "ADMIN_EMAIL_VERIFICATION" }
    });
    const adminCredentialBefore = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: fixture.recoveryReviewer.id }, select: { keyVersion: true, passwordHash: true }
    });

    await recoveryForm.locator('input[name="normalPassword"]').fill(fixture.recoveryReviewer.password);
    await recoveryForm.locator('input[name="csrfToken"]').evaluate((input) => {
      (input as HTMLInputElement).value = "invalid-native-hub-csrf";
    });
    const csrfActionResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/admin/security" &&
      response.request().method() === "POST" && Boolean(response.request().headers()["next-action"]));
    await sendRecovery.click();
    expect((await csrfActionResponse).status(), "genuine ADMIN Server Action must reject forged session CSRF").toBe(403);
    expect(await database.securityElevation.count({
      where: { userId: fixture.recoveryReviewer.id, scope: "ADMIN_CREDENTIAL_EMAIL_RECOVERY" }
    })).toBe(ceremonyBefore);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: fixture.recoveryReviewer.email, kind: "ADMIN_EMAIL_VERIFICATION" }
    })).toBe(outboxBefore);

    // A valid native ADMIN request must then reach the real service/outbox,
    // proving this was not a blanket 403 from a hidden Access dependency.
    await page.goto(`${hubUrl}/admin/security`);
    const validSend = page.getByRole("button", { name: "Enviar código de recuperação por e-mail" });
    await validSend.locator("xpath=ancestor::form").locator('input[name="normalPassword"]').fill(fixture.recoveryReviewer.password);
    const validActionResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/admin/security" &&
      response.request().method() === "POST" && Boolean(response.request().headers()["next-action"]));
    await validSend.click();
    expect((await validActionResponse).status()).toBe(200);
    const confirmRecovery = page.getByRole("button", { name: "Confirmar código e trocar senha" });
    await expect(confirmRecovery).toBeVisible();
    const requestKey = await confirmRecovery.locator("xpath=ancestor::form").locator('input[name="requestKey"]').inputValue();
    expect(requestKey.length).toBeGreaterThan(10);
    const issued = await database.securityElevation.findUniqueOrThrow({ where: { requestKey } });
    expect(issued).toMatchObject({ userId: fixture.recoveryReviewer.id, status: "PENDING", scope: "ADMIN_CREDENTIAL_EMAIL_RECOVERY" });
    expect(await database.securityElevation.count({
      where: { userId: fixture.recoveryReviewer.id, scope: "ADMIN_CREDENTIAL_EMAIL_RECOVERY" }
    })).toBe(ceremonyBefore + 1);
    expect(await database.emailOutboxMessage.count({
      where: { recipientEmail: fixture.recoveryReviewer.email, kind: "ADMIN_EMAIL_VERIFICATION",
        idempotencyKey: `admin-elevation:${requestKey}` }
    })).toBe(1);
    const adminCredentialAfter = await database.administrativeCredential.findUniqueOrThrow({
      where: { userId: fixture.recoveryReviewer.id }, select: { keyVersion: true, passwordHash: true }
    });
    expect(adminCredentialAfter).toEqual(adminCredentialBefore);

    // Even an authentic ADMIN session must not grant the Portal USER surface.
    const adminCookie = (await context.cookies(hubUrl)).find((cookie) => cookie.name === sessionCookieName)!;
    await context.addCookies([{ name: sessionCookieName, value: adminCookie.value, url: portalUrl,
      httpOnly: true, secure: true, sameSite: "Lax" }]);
    const portal = await page.goto(`${portalUrl}/`);
    expect(portal?.status()).toBe(403);
    await expect(page.getByRole("heading", { name: "Projetos", exact: true })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

async function enterPassword(page: Page, account: Actor): Promise<void> {
  await page.getByLabel("E-mail", { exact: true }).fill(account.email);
  await page.getByLabel("Senha", { exact: true }).fill(account.password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
}

async function completeEmailMfa(page: Page, account: Actor): Promise<void> {
  const url = new URL(page.url());
  const ceremony = url.searchParams.get("ceremony");
  if (!ceremony || url.searchParams.get("factor") !== "email") {
    throw new Error("Genuine emailed second-factor ceremony was not started.");
  }
  const item = await database.emailOutboxMessage.findFirst({
    where: { recipientEmail: account.email, idempotencyKey: `security-ceremony:${ceremony}`,
      kind: { in: ["EMAIL_TWO_FACTOR", "NEW_DEVICE_VERIFICATION"] } },
    select: { payload: true }
  });
  if (!item) throw new Error("Genuine MFA message missing from the disposable PostgreSQL outbox.");
  const code = decryptEmailPayload(item.payload).code;
  expect(code).toMatch(/^\d{6}$/u);
  await page.getByLabel("Código", { exact: true }).fill(code!);
  await page.getByRole("button", { name: "Continuar", exact: true }).click();
  await expect(page).not.toHaveURL((current) => current.pathname === "/login/verify");
}

function isFixture(value: unknown): value is Fixture {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return ["user", "recoveryReviewer"].every((key) => {
    const actor = record[key];
    return actor && typeof actor === "object" && ["id", "email", "password", "deviceToken"].every((field) =>
      typeof (actor as Record<string, unknown>)[field] === "string" &&
      Boolean((actor as Record<string, string>)[field]));
  });
}
