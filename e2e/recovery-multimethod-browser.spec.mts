import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { PrismaClient } from "@virki/database";
// @ts-expect-error The disposable PostgreSQL guard is an audited JavaScript helper without declarations.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const productionMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const portalUrl = productionMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();

// The E2E global-setup creates owner-labelled fixtures on a private disposable
// database. This suite never provisions identities in shared/production data.
test.skip(!e2eDatabaseUrl || !fixturePath, "requires the isolated E2E database and fixture");

type Actor = { id: string; email: string };
type Fixture = { user: Actor; admin: Actor; recoveryReviewer: Actor };
type RecoveryCookie = { name: string; domain: string; path: string; httpOnly: boolean; secure: boolean; sameSite: string; value: string };

async function requireFixture(): Promise<{ fixture: Fixture; database: PrismaClient }> {
  if (!e2eDatabaseUrl || !fixturePath || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("A confirmed owned disposable E2E database is required.");
  }
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, { ...process.env, NODE_ENV: "test" });
  const parsed: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!parsed || typeof parsed !== "object") throw new Error("Missing E2E account fixture.");
  const value = parsed as Record<string, unknown>;
  for (const role of ["user", "admin", "recoveryReviewer"] as const) {
    const actor = value[role];
    if (!actor || typeof actor !== "object" || typeof (actor as Actor).id !== "string" ||
        typeof (actor as Actor).email !== "string") throw new Error("Invalid E2E account fixture.");
  }
  return { fixture: value as Fixture, database: new PrismaClient({ datasources: { db: { url: e2eDatabaseUrl } } }) };
}

async function openRecovery(browser: Browser, surface: "portal" | "hub") {
  const context = await browser.newContext();
  const page = await context.newPage();
  if (surface === "hub") await addCloudflareAccessHeader(page);
  const base = surface === "portal" ? portalUrl : hubUrl;
  await page.goto(`${base}/recover`);
  return { context, page, base };
}

async function startSelectedTotpEmail(page: Page, email: string): Promise<string> {
  await page.getByLabel("E-mail da conta", { exact: true }).fill(email);
  await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
  await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
  await expect(page).toHaveURL(/\/recover\?requestId=[A-Za-z0-9_-]+$/u);
  const publicRequestId = new URL(page.url()).searchParams.get("requestId") ?? "";
  expect(publicRequestId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  await expect(page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toBeVisible();
  return publicRequestId;
}

async function assertBoundCookies(context: BrowserContext, base: string, requestId: string): Promise<void> {
  const cookies = await context.cookies(base);
  const host = new URL(base).hostname;
  const names = [productionMode ? "__Host-virki_recovery" : "virki_recovery_v2",
    productionMode ? "__Host-virki_recovery_browser" : "virki_recovery_browser",
    productionMode ? "__Host-virki_recovery_intent" : "virki_recovery_intent"];
  for (const name of names) {
    const cookie = cookies.find((candidate) => candidate.name === name) as RecoveryCookie | undefined;
    expect(cookie, `${name} must be issued only by the selected recovery host`).toBeDefined();
    expect(cookie!.domain).toBe(host);
    expect(cookie!.path).toBe("/");
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.sameSite).toBe("Lax");
    expect(cookie!.secure).toBe(productionMode);
    expect(cookie!.value.length).toBeGreaterThan(0);
  }
  expect(cookies.find((cookie) => cookie.name === names[2])?.value).toBe(`${requestId}.TOTP_EMAIL`);
  expect(cookies.some((cookie) => cookie.name === "virki_recovery" && cookie.value.length > 0)).toBe(false,
    "legacy path-scoped recovery cookie must not remain active");
}

test("real and nonexistent USER TOTP+EMAIL requests expose equivalent pre-proof HTTP state and scoped cookies", async ({ browser }) => {
  test.setTimeout(120_000);
  const { fixture, database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  try {
    const before = await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } });
    const totalBefore = await database.accountRecoveryRequest.count();
    const real = await openRecovery(browser, "portal");
    contexts.push(real.context);
    const knownId = await startSelectedTotpEmail(real.page, fixture.user.email);
    await assertBoundCookies(real.context, real.base, knownId);

    const synthetic = await openRecovery(browser, "portal");
    contexts.push(synthetic.context);
    const absentEmail = `absent-${randomUUID()}@e2e.invalid`;
    const syntheticId = await startSelectedTotpEmail(synthetic.page, absentEmail);
    await assertBoundCookies(synthetic.context, synthetic.base, syntheticId);
    expect(syntheticId).not.toBe(knownId);
    expect((await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } }))).toBe(before + 1);
    expect(await database.accountRecoveryRequest.count()).toBe(totalBefore + 1,
      "the nonexistent account must not cause an additional database recovery request");
    const otherContext = await browser.newContext();
    contexts.push(otherContext);
    const stolenPage = await otherContext.newPage();
    await stolenPage.goto(`${portalUrl}/recover?requestId=${encodeURIComponent(knownId)}`);
    await expect(stolenPage.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toHaveCount(0,
      "an unbound browser must not see or claim another browser's recovery ceremony");
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await database.$disconnect();
  }
});

test("recovery form rejects a tampered CSRF token without minting capability cookies or mutating requests", async ({ browser }) => {
  const { fixture, database } = await requireFixture();
  const { context, page, base } = await openRecovery(browser, "portal");
  try {
    const before = await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } });
    await page.getByLabel("E-mail da conta", { exact: true }).fill(fixture.user.email);
    await page.locator('input[name="method"][value="TOTP_EMAIL"]').check();
    await page.locator('form input[name="csrfToken"]').first().evaluate((input) => {
      (input as HTMLInputElement).value = "invalid-tampered-csrf";
    });
    const denied = page.waitForResponse((response) => response.request().method() === "POST" &&
      new URL(response.url()).origin === base && new URL(response.url()).pathname === "/recover");
    await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
    expect((await denied).status()).toBe(403);
    expect(await database.accountRecoveryRequest.count({ where: { userId: fixture.user.id } })).toBe(before);
    const cookies = await context.cookies(base);
    expect(cookies.some((cookie) => cookie.name.includes("recovery") && Boolean(cookie.value))).toBe(false);
  } finally {
    await context.close();
    await database.$disconnect();
  }
});

test("Hub ADMIN recovery requires synthetic Access and never exposes a Portal ADMIN method", async ({ browser }) => {
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  try {
    const blocked = await browser.newContext();
    contexts.push(blocked);
    const noAccess = await blocked.newPage();
    const blockedResponse = await noAccess.goto(`${hubUrl}/recover`);
    expect(blockedResponse?.status()).toBe(403);

    const portal = await openRecovery(browser, "portal");
    contexts.push(portal.context);
    await expect(portal.page.getByRole("heading", { level: 1, name: "Recuperar conta" })).toBeVisible();
    await expect(portal.page.getByRole("heading", { name: "Recuperar acesso administrativo" })).toHaveCount(0);
    for (const method of ["TOTP_EMAIL", "EMAIL_ADMIN", "TOTP_ADMIN"] as const) {
      await expect(portal.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(1);
    }
    for (const method of ["PASSKEY_EMAIL", "PASSKEY_TOTP", "PASSKEY_ADMIN"] as const) {
      await expect(portal.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(
        process.env.VIRKI_E2E_PASSKEYS === "true" ? 1 : 0);
    }

    const hub = await openRecovery(browser, "hub");
    contexts.push(hub.context);
    await expect(hub.page.getByRole("heading", { level: 1, name: "Recuperar acesso administrativo" })).toBeVisible();
    for (const method of ["TOTP_EMAIL", "EMAIL_ADMIN", "TOTP_ADMIN"] as const) {
      await expect(hub.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(1);
    }
    for (const method of ["PASSKEY_EMAIL", "PASSKEY_TOTP", "PASSKEY_ADMIN"] as const) {
      await expect(hub.page.locator(`input[name="method"][value="${method}"]`)).toHaveCount(
        process.env.VIRKI_E2E_ADMIN_PASSKEYS === "true" ? 1 : 0);
    }
    expect((await hub.context.cookies(hubUrl)).filter((cookie) => cookie.name.includes("recovery") && cookie.value.length > 0)).toHaveLength(0,
      "merely viewing the ADMIN recovery form must not issue an authorizing recovery capability");
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await database.$disconnect();
  }
});
