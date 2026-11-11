import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { hashPassword, hashSessionToken } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { createTotpSecret, encryptTotpSecret, generateRecoveryCode, hashRecoveryCode } from "@virki/auth/security";
import { PrismaClient } from "@virki/database";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

// @ts-expect-error The shared disposable database guard is an untyped JavaScript module.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const productionHub = process.env.VIRKI_E2E_HUB_MODE === "production";
const portal = productionHub ? "https://portal.localhost" : "https://portal.localhost:3001";
const hub = productionHub ? "https://hub.localhost" : "https://hub.localhost:3001";
const sessionCookie = getSessionCookieName({ NODE_ENV: productionHub ? "production" : "development" });
const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();

test.skip(!databaseUrl || !fixturePath || !existsSync(fixturePath),
  "Physical BACKUP login E2E requires the seeded, disposable Linux PostgreSQL fixture.");

type Role = "USER" | "ADMIN";
type Owner = { id: string; email: string; password: string; codes: string[]; originalSessionId: string };

function disposableDatabase(): PrismaClient {
  if (!databaseUrl || !fixturePath || !existsSync(fixturePath) ||
      process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("BACKUP browser E2E requires the isolated, confirmed database fixture.");
  }
  assertDisposableCoreTestDatabase(databaseUrl, process.env);
  if (new URL(databaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("BACKUP browser E2E refuses a non-disposable database name.");
  }
  return new PrismaClient({ datasources: { db: { url: databaseUrl } } });
}

async function createOwnedTotpAccount(database: PrismaClient, role: Role): Promise<Owner> {
  const email = `backup-login-${role.toLowerCase()}-${randomUUID()}@e2e.invalid`;
  const password = randomBytes(32).toString("base64url");
  const codes = Array.from({ length: 3 }, () => generateRecoveryCode());
  const secret = createTotpSecret();
  const user = await database.user.create({
    data: {
      email, emailNormalized: email, displayName: "Owned BACKUP login browser fixture",
      passwordHash: await hashPassword(password), role, isActive: true,
      accountStatus: "ACTIVE", emailVerifiedAt: new Date(), secondFactorMethod: "TOTP",
      totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(secret), keyVersion: 1,
        confirmedAt: new Date(), status: "ACTIVE"
      } },
      recoveryCodes: { create: codes.map((code) => ({ codeHash: hashRecoveryCode(code) })) }
    }, select: { id: true }
  });
  // A separate existing session must survive one-time backup login.
  const existing = await database.session.create({
    data: {
      userId: user.id, tokenHash: hashSessionToken(randomBytes(32).toString("base64url")),
      authenticationMethods: ["pwd", "otp", "mfa"], expiresAt: new Date(Date.now() + 600_000)
    }, select: { id: true }
  });
  return { id: user.id, email, password, codes, originalSessionId: existing.id };
}

async function newPage(browser: Browser, role: Role): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext(); // No trusted-device or session cookie: a genuinely new device.
  const page = await context.newPage();
  if (role === "ADMIN") await addCloudflareAccessHeader(page);
  return { context, page };
}

async function passwordToTotp(page: Page, owner: Owner, role: Role): Promise<string> {
  const origin = role === "ADMIN" ? hub : portal;
  await page.goto(`${origin}/login`);
  await page.getByLabel("E-mail", { exact: true }).fill(owner.email);
  await page.getByLabel("Senha", { exact: true }).fill(owner.password);
  const response = page.waitForResponse((item) =>
    item.url() === `${origin}/api/login` && item.request().method() === "POST");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  expect((await response).status()).toBe(303);
  await expect(page).toHaveURL((url) => url.origin === origin && url.pathname === "/login/verify" &&
    url.searchParams.get("factor") === "totp" && Boolean(url.searchParams.get("ceremony")));
  return new URL(page.url()).searchParams.get("ceremony")!;
}

async function assertRoleIsolation(browser: Browser, database: PrismaClient, owner: Owner, role: Role): Promise<void> {
  const oppositeRole = role === "USER" ? "ADMIN" : "USER";
  const { context, page } = await newPage(browser, oppositeRole);
  const origin = oppositeRole === "ADMIN" ? hub : portal;
  try {
    await page.goto(`${origin}/login`);
    await page.getByLabel("E-mail", { exact: true }).fill(owner.email);
    await page.getByLabel("Senha", { exact: true }).fill(owner.password);
    const response = page.waitForResponse((item) =>
      item.url() === `${origin}/api/login` && item.request().method() === "POST");
    await page.getByRole("button", { name: "Entrar", exact: true }).click();
    expect((await response).status()).toBe(303);
    await expect(page).toHaveURL((url) => url.origin === origin && url.pathname === "/login" &&
      url.searchParams.get("error") === "1");
    expect((await context.cookies(origin)).some((cookie) => cookie.name === sessionCookie)).toBe(false);
    expect(await database.deviceChallenge.count({ where: { userId: owner.id } })).toBe(0);
  } finally {
    await context.close();
  }
}

async function verifyBackupJourney(browser: Browser, role: Role): Promise<void> {
  const database = disposableDatabase();
  const contexts: BrowserContext[] = [];
  const origin = role === "ADMIN" ? hub : portal;
  try {
    const owner = await createOwnedTotpAccount(database, role);
    const baselineFactor = await database.totpFactor.findUniqueOrThrow({
      where: { userId: owner.id },
      select: { status: true, secretCiphertext: true, keyVersion: true, confirmedAt: true, lastUsedStep: true }
    });
    expect(baselineFactor.status).toBe("ACTIVE");
    const baselineSessions = await database.session.count({ where: { userId: owner.id } });
    const originalMessages = await database.emailOutboxMessage.count({ where: { recipientEmail: owner.email } });
    await assertRoleIsolation(browser, database, owner, role);

    const first = await newPage(browser, role);
    contexts.push(first.context);
    expect((await first.context.cookies(origin)).some((cookie) => cookie.name === sessionCookie)).toBe(false);
    const ceremony = await passwordToTotp(first.page, owner, role);
    const verifyUrl = new URL(first.page.url());
    const initialChallenge = await database.deviceChallenge.findUniqueOrThrow({
      where: { ceremonyId: ceremony },
      select: { userId: true, factorChoice: true, status: true, emailVerifiedAt: true, consumedAt: true }
    });
    expect(initialChallenge).toMatchObject({ userId: owner.id, factorChoice: "TOTP", status: "VERIFIED",
      emailVerifiedAt: null, consumedAt: null });
    expect(await database.emailOutboxMessage.count({ where: { recipientEmail: owner.email } })).toBe(originalMessages);
    await expect(first.page.getByRole("button", { name: "Entrar com um código reserva" })).toBeVisible();
    // A forged URL cannot select EMAIL over a persisted TOTP challenge.
    await first.page.goto(`${origin}/login/verify?ceremony=${encodeURIComponent(ceremony)}&factor=email`);
    await expect(first.page.locator('form[action="/api/login/verify"] input[name="factor"]')).toHaveValue("totp");

    const selectionForm = first.page.locator('form[action="/api/login/factor"]');
    await expect(selectionForm.locator('input[name="csrfToken"]')).toHaveValue(/^v2\./u);
    await selectionForm.locator('input[name="csrfToken"]').evaluate((element) => {
      (element as HTMLInputElement).value = "forged-backup-selection-csrf";
    });
    const deniedSelection = first.page.waitForResponse((response) => response.url() === `${origin}/api/login/factor` &&
      response.request().method() === "POST");
    await selectionForm.getByRole("button", { name: "Entrar com um código reserva" }).click();
    expect((await deniedSelection).status()).toBe(403);
    expect((await database.deviceChallenge.findUniqueOrThrow({ where: { ceremonyId: ceremony } })).factorChoice).toBe("TOTP");

    await first.page.goto(verifyUrl.href);
    const switchResponse = first.page.waitForResponse((response) => response.url() === `${origin}/api/login/factor` &&
      response.request().method() === "POST");
    await first.page.getByRole("button", { name: "Entrar com um código reserva" }).click();
    expect((await switchResponse).status()).toBe(303);
    await expect(first.page).toHaveURL((url) => url.origin === origin && url.pathname === "/login/verify" &&
      url.searchParams.get("ceremony") === ceremony && url.searchParams.get("factor") === "backup");
    await expect(first.page.getByText("Seu autenticador continuará ativo.", { exact: false })).toBeVisible();
    expect((await database.deviceChallenge.findUniqueOrThrow({ where: { ceremonyId: ceremony } })).factorChoice).toBe("BACKUP");
    // The server must retain BACKUP even when the client changes the query string to TOTP.
    const backupUrl = first.page.url();
    await first.page.goto(`${origin}/login/verify?ceremony=${encodeURIComponent(ceremony)}&factor=totp`);
    await expect(first.page.locator('form[action="/api/login/verify"] input[name="factor"]')).toHaveValue("backup");

    const verifyForm = first.page.locator('form[action="/api/login/verify"]');
    await expect(verifyForm.locator('input[name="csrfToken"]')).toHaveValue(/^v2\./u);
    await verifyForm.locator('input[name="code"]').fill(owner.codes[0]!);
    await verifyForm.locator('input[name="csrfToken"]').evaluate((element) => {
      (element as HTMLInputElement).value = "forged-backup-verification-csrf";
    });
    const deniedVerification = first.page.waitForResponse((response) => response.url() === `${origin}/api/login/verify` &&
      response.request().method() === "POST");
    await verifyForm.getByRole("button", { name: "Continuar" }).click();
    expect((await deniedVerification).status()).toBe(403);
    expect(await database.recoveryCode.count({ where: { userId: owner.id, usedAt: null } })).toBe(3);
    expect(await database.session.count({ where: { userId: owner.id } })).toBe(baselineSessions);

    await first.page.goto(backupUrl);
    await expect(first.page.locator('form[action="/api/login/verify"] input[name="factor"]')).toHaveValue("backup");
    await first.page.locator('form[action="/api/login/verify"] input[name="code"]').fill(owner.codes[0]!);
    const accepted = first.page.waitForResponse((response) => response.url() === `${origin}/api/login/verify` &&
      response.request().method() === "POST");
    await first.page.getByRole("button", { name: "Continuar" }).click();
    expect((await accepted).status()).toBe(303);
    await expect(first.page).toHaveURL((url) => url.origin === origin &&
      url.pathname === (role === "ADMIN" ? "/admin/accounts" : "/"));
    await expect(first.page.getByRole("heading", { level: 1, name: role === "ADMIN" ? "Contas" : "Projetos" })).toBeVisible();
    const sessionCookies = (await first.context.cookies(origin)).filter((cookie) => cookie.name === sessionCookie);
    expect(sessionCookies).toHaveLength(1);
    expect(sessionCookies[0]).toMatchObject({ domain: new URL(origin).hostname, httpOnly: true, path: "/" });

    const activeSessions = await database.session.findMany({
      where: { userId: owner.id, revokedAt: null, id: { not: owner.originalSessionId } },
      select: { authenticationMethods: true }
    });
    expect(activeSessions).toHaveLength(1);
    expect(activeSessions[0]!.authenticationMethods).toEqual(["pwd", "otp", "mfa", "backup"]);
    expect((await database.session.findUniqueOrThrow({ where: { id: owner.originalSessionId } })).revokedAt).toBeNull();
    expect(await database.totpFactor.findUniqueOrThrow({
      where: { userId: owner.id },
      select: { status: true, secretCiphertext: true, keyVersion: true, confirmedAt: true, lastUsedStep: true }
    })).toEqual(baselineFactor);
    expect(await database.recoveryCode.count({ where: { userId: owner.id, usedAt: null } })).toBe(2);
    expect((await database.recoveryCode.findFirstOrThrow({
      where: { userId: owner.id, codeHash: hashRecoveryCode(owner.codes[0]!) }, select: { usedAt: true }
    })).usedAt).not.toBeNull();
    expect((await database.recoveryCode.findMany({ where: { userId: owner.id, usedAt: null }, select: { codeHash: true } }))
      .map(({ codeHash }) => codeHash).sort()).toEqual(owner.codes.slice(1).map(hashRecoveryCode).sort());
    expect(await database.emailOutboxMessage.count({ where: { recipientEmail: owner.email } })).toBe(originalMessages);
    expect(await database.auditLog.count({
      where: { actorUserId: owner.id, eventType: "DEVICE_VERIFIED", result: "SUCCESS",
        message: "One-time backup code accepted for login." }
    })).toBe(1);

    // A spent code must also fail a *new* ceremony on another new device.
    const replay = await newPage(browser, role);
    contexts.push(replay.context);
    const replayCeremony = await passwordToTotp(replay.page, owner, role);
    expect(replayCeremony).not.toBe(ceremony);
    await replay.page.getByRole("button", { name: "Entrar com um código reserva" }).click();
    await expect(replay.page).toHaveURL((url) => url.pathname === "/login/verify" &&
      url.searchParams.get("ceremony") === replayCeremony && url.searchParams.get("factor") === "backup");
    await replay.page.locator('form[action="/api/login/verify"] input[name="code"]').fill(owner.codes[0]!);
    const deniedReplay = replay.page.waitForResponse((response) => response.url() === `${origin}/api/login/verify` &&
      response.request().method() === "POST");
    await replay.page.getByRole("button", { name: "Continuar" }).click();
    expect((await deniedReplay).status()).toBe(303);
    await expect(replay.page).toHaveURL((url) => url.pathname === "/login/verify" && url.searchParams.get("error") === "1");
    expect((await replay.context.cookies(origin)).some((cookie) => cookie.name === sessionCookie)).toBe(false);
    expect(await database.session.count({ where: { userId: owner.id } })).toBe(baselineSessions + 1);
    expect(await database.recoveryCode.count({ where: { userId: owner.id, usedAt: null } })).toBe(2);
  } finally {
    const closed = await Promise.allSettled(contexts.map((context) => context.close()));
    await database.$disconnect();
    expect(closed.every((result) => result.status === "fulfilled")).toBe(true);
    // AuditLog has a RESTRICT actor FK: the entire disposable DB is removed by the runner.
  }
}

test("USER password + BACKUP completes real HTTPS Portal login on a new device and consumes one code", async ({ browser }) => {
  test.setTimeout(180_000);
  await verifyBackupJourney(browser, "USER");
});

test("ADMIN password + BACKUP completes real HTTPS Access-protected Hub login with no email-only bypass", async ({ browser }) => {
  test.setTimeout(180_000);
  await verifyBackupJourney(browser, "ADMIN");
});
