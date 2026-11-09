import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { hashPassword, verifyPassword } from "@virki/auth";
import { getSessionCookieName } from "@virki/auth/constants";
import { decryptEmailPayload } from "@virki/auth/email";
import { createTotpSecret, encryptTotpSecret } from "@virki/auth/security";
// @ts-expect-error This reviewed JS guard has no separate type declaration.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const productionMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const portalUrl = productionMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE?.trim();

// The E2E global-setup creates owner-labelled fixtures on a private disposable
// database. This suite never provisions identities in shared/production data.
test.skip((!e2eDatabaseUrl || !fixturePath) && process.env.VIRKI_E2E_REQUIRE_RECOVERY !== "true",
  "requires isolated E2E resources; VIRKI_E2E_REQUIRE_RECOVERY=true makes this a mandatory gate");

type Actor = { id: string; email: string };
type Fixture = { user: Actor; admin: Actor; recoveryReviewer: Actor };
type RecoveryCookie = { name: string; domain: string; path: string; httpOnly: boolean; secure: boolean; sameSite: string; value: string };

async function requireFixture(): Promise<{ fixture: Fixture; database: PrismaClient }> {
  if (!e2eDatabaseUrl || !fixturePath || process.env.VIRKI_CORE_TEST_DATABASE_CONFIRM !== "disposable") {
    throw new Error("A confirmed owned disposable E2E database is required.");
  }
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  if (new URL(e2eDatabaseUrl).pathname !== "/virki_e2e_test") {
    throw new Error("Recovery browser tests require the dedicated E2E database name.");
  }
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
  const selectedPost = page.waitForResponse((response) => response.request().method() === "POST" &&
    new URL(response.url()).pathname === "/recover");
  await page.getByRole("button", { name: "Solicitar recuperação", exact: true }).click();
  const postResponse = await selectedPost;
  const setCookieHeaders = (await postResponse.headersArray()).filter((header) => header.name.toLowerCase() === "set-cookie").map((header) => header.value);
  const cookieNames = productionMode
    ? ["__Host-virki_recovery", "__Host-virki_recovery_browser", "__Host-virki_recovery_intent"]
    : ["virki_recovery_v2", "virki_recovery_browser", "virki_recovery_intent"];
  for (const name of cookieNames) {
    const issued = setCookieHeaders.find((header) => header.startsWith(`${name}=`));
    expect(issued, `server must issue ${name} in this recovery response`).toBeDefined();
    expect(/(?:^|;)\s*Domain=/iu.test(issued!), "recovery cookie must be host-only without a Domain attribute").toBe(false);
  }
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
  expect(cookies.some((cookie) => cookie.name === "virki_recovery" && cookie.value.length > 0),
    "legacy path-scoped recovery cookie must not remain active").toBe(false);
}

function totpAt(secret: string, at = new Date()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const character of secret) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("Invalid test TOTP secret.");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at.getTime() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("USER TOTP+EMAIL: real/synthetic parity, independent HTTP proofs, one-time reset and scoped cookies", async ({ browser }) => {
  test.setTimeout(120_000);
  const { database } = await requireFixture();
  const contexts: BrowserContext[] = [];
  const ownedEmail = `${randomUUID()}.multimethod@e2e.invalid`;
  let ownedUserId: string | undefined;
  try {
    const totpSecret = createTotpSecret();
    // The global E2E fixture is reused by other serial suites. Create a
    // unique owner-labelled account instead, so an earlier recovery request's
    // cooldown cannot silently turn the supposedly real case synthetic.
    const ownedUser = await database.user.create({ data: {
      email: ownedEmail, emailNormalized: ownedEmail, displayName: "Owned multi-method E2E fixture",
      passwordHash: await hashPassword(randomBytes(24).toString("base64url")),
      role: "USER", isActive: true, accountStatus: "ACTIVE", emailVerifiedAt: new Date(),
      secondFactorMethod: "TOTP",
      totpFactor: { create: {
        secretCiphertext: encryptTotpSecret(totpSecret), keyVersion: 1,
        status: "ACTIVE", confirmedAt: new Date()
      } }
    }, select: { id: true } });
    ownedUserId = ownedUser.id;
    const totalBefore = await database.accountRecoveryRequest.count();
    const real = await openRecovery(browser, "portal");
    contexts.push(real.context);
    const knownId = await startSelectedTotpEmail(real.page, ownedEmail);
    await assertBoundCookies(real.context, real.base, knownId);
    const realPreProof = (await real.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim();
    const realVisiblePage = (await real.page.locator("main").innerText()).trim();

    const synthetic = await openRecovery(browser, "portal");
    contexts.push(synthetic.context);
    const absentEmail = `absent-${randomUUID()}@e2e.invalid`;
    const syntheticId = await startSelectedTotpEmail(synthetic.page, absentEmail);
    await assertBoundCookies(synthetic.context, synthetic.base, syntheticId);
    const syntheticPreProof = (await synthetic.page.locator('section[aria-label="Confirmação de identidade"]').innerText()).trim();
    expect(syntheticPreProof,
      "known and unknown account requests must show the same pre-proof state and text").toBe(realPreProof);
    expect((await synthetic.page.locator("main").innerText()).trim(),
      "the complete visible pre-proof page must not enumerate the selected account").toBe(realVisiblePage);
    expect(syntheticId).not.toBe(knownId);
    expect((await database.accountRecoveryRequest.count({ where: { userId: ownedUserId } }))).toBe(1);
    expect(await database.accountRecoveryRequest.count(),
      "the nonexistent account must not cause an additional database recovery request").toBe(totalBefore + 1);
    const otherContext = await browser.newContext();
    contexts.push(otherContext);
    const stolenPage = await otherContext.newPage();
    await stolenPage.goto(`${portalUrl}/recover?requestId=${encodeURIComponent(knownId)}`);
    await expect(stolenPage.locator('[aria-label="E-mail cadastrado"] input[name="code"]'),
      "an unbound browser must not see or claim another browser's recovery ceremony").toHaveCount(0);

    const message = await database.emailOutboxMessage.findFirst({
      where: { recipientEmail: ownedEmail, kind: "ACCOUNT_RECOVERY" },
      orderBy: { createdAt: "desc" }, select: { payload: true }
    });
    const emailCode = message ? decryptEmailPayload(message.payload).code : undefined;
    expect(emailCode).toMatch(/^\d{6}$/u);
    const emailStage = real.page.locator('[aria-label="E-mail cadastrado"]');
    await emailStage.locator('input[name="code"]').fill(emailCode!);
    await emailStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.locator('[aria-label="E-mail cadastrado"]')).toContainText("Confirmado.");

    const totpStage = real.page.locator('[aria-label="Aplicativo autenticador"]');
    await totpStage.locator('input[name="code"]').fill(totpAt(totpSecret));
    await totpStage.getByRole("button", { name: "Confirmar", exact: true }).click();
    await expect(real.page.getByText("Defina uma nova senha para finalizar a recuperação.", { exact: false })).toBeVisible();
    // Preserve an already-rendered second completion form and the original
    // cookies, then replay its actual Server Action POST after first consume.
    const stalePage = await real.context.newPage();
    await stalePage.goto(real.page.url());
    const staleResetCandidate = `stale-e2e-${randomUUID()}-password`;
    await stalePage.getByLabel("Nova senha", { exact: true }).fill(staleResetCandidate);
    const priorRecoveryCookies = (await real.context.cookies(portalUrl)).filter((cookie) => cookie.name.includes("recovery"));
    const resetCandidate = `multimethod-e2e-${randomUUID()}-password`;
    await real.page.getByLabel("Nova senha", { exact: true }).fill(resetCandidate);
    await real.page.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(real.page).toHaveURL(`${portalUrl}/account/security?recovered=password`);
    const recovered = await database.user.findUniqueOrThrow({ where: { id: ownedUserId } });
    expect(await verifyPassword(recovered.passwordHash ?? "", resetCandidate)).toBe(true);
    expect(recovered.secondFactorMethod).toBe("EMAIL");
    expect((await database.totpFactor.findUniqueOrThrow({ where: { userId: ownedUserId } })).status).toBe("REVOKED");
    expect((await database.accountRecoveryRequest.findUniqueOrThrow({ where: { id: knownId } })).status).toBe("CONSUMED");
    expect(await database.session.count({ where: { userId: ownedUserId, revokedAt: null, expiresAt: { gt: new Date() } } })).toBe(1);
    const finalCookies = await real.context.cookies(portalUrl);
    expect(finalCookies.some((cookie) => cookie.name === getSessionCookieName({ NODE_ENV: productionMode ? "production" : "development" }) && Boolean(cookie.value))).toBe(true);
    expect(finalCookies.some((cookie) => cookie.name.includes("recovery") && Boolean(cookie.value))).toBe(false);
    await real.context.addCookies(priorRecoveryCookies);
    await stalePage.getByRole("button", { name: "Concluir recuperação", exact: true }).click();
    await expect(stalePage).toHaveURL(new RegExp(`/recover\\?requestId=${knownId}&error=1`),
      { timeout: 15_000 });
    const afterReplay = await database.user.findUniqueOrThrow({ where: { id: ownedUserId } });
    expect(await verifyPassword(afterReplay.passwordHash ?? "", resetCandidate)).toBe(true);
    expect(await verifyPassword(afterReplay.passwordHash ?? "", staleResetCandidate)).toBe(false);
    await real.page.goto(`${portalUrl}/recover?requestId=${encodeURIComponent(knownId)}`);
    await expect(real.page.locator('[aria-label="E-mail cadastrado"] input[name="code"]')).toHaveCount(0);
  } finally {
    // One browser's close failure cannot skip isolated DB cleanup/disconnect.
    const contextResults = await Promise.allSettled(contexts.map((context) => context.close()));
    try {
      if (ownedUserId) {
        await database.session.deleteMany({ where: { userId: ownedUserId } });
        await database.accountRecoveryRequest.deleteMany({ where: { userId: ownedUserId } });
        await database.emailOutboxMessage.deleteMany({ where: { recipientEmail: ownedEmail } });
        await database.totpFactor.deleteMany({ where: { userId: ownedUserId } });
        await database.user.deleteMany({ where: { id: ownedUserId, email: ownedEmail } });
      }
    } finally {
      await database.$disconnect();
    }
    expect(contextResults.every((result) => result.status === "fulfilled"),
      "every isolated browser context must close successfully").toBe(true);
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
    expect((await hub.context.cookies(hubUrl)).filter((cookie) => cookie.name.includes("recovery") && cookie.value.length > 0),
      "merely viewing the ADMIN recovery form must not issue an authorizing recovery capability").toHaveLength(0);
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await database.$disconnect();
  }
});
