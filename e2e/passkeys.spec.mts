import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { getSessionCookieName } from "@virki/auth/constants";
import { hashSessionToken } from "@virki/auth";
import { PrismaClient } from "@virki/database";

// @ts-expect-error The isolated safety guard is a plain JavaScript module.
import { assertDisposableCoreTestDatabase } from "../scripts/core-test-database-safety.mjs";

const url = "https://portal.localhost:3001";
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
const databaseUrl = process.env.VIRKI_E2E_DATABASE_URL;
const enabled = process.env.VIRKI_E2E_PASSKEYS === "true";
test.skip(!enabled || !fixturePath || !existsSync(fixturePath) || !databaseUrl, "Explicit isolated Linux WebAuthn test gate and database fixture required.");

test("USER virtual authenticator: register, discoverable login, credential inventory, revoke and deny replay", async ({ browser }) => {
  test.setTimeout(120_000);
  assertDisposableCoreTestDatabase(databaseUrl!, { ...process.env, NODE_ENV: "test" });
  const fixture: { user: { id: string; email: string; password: string } } = JSON.parse(await readFile(fixturePath!, "utf8"));
  const context = await browser.newContext();
  const db = new PrismaClient({ datasources: { db: { url: databaseUrl! } } });
  let browserSessionId: string | undefined;
  try {
    const browserSessionToken = randomBytes(32).toString("base64url");
    const browserSession = await db.session.create({ data: {
      userId: fixture.user.id,
      tokenHash: hashSessionToken(browserSessionToken),
      expiresAt: new Date(Date.now() + 15 * 60_000),
      authenticationMethods: ["pwd", "otp", "mfa"]
    } });
    browserSessionId = browserSession.id;
    await context.addCookies([{
      name: getSessionCookieName({ NODE_ENV: "development" }), value: browserSessionToken, url,
      httpOnly: true, secure: true, sameSite: "Lax"
    }]);

    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true
    } });
    try {
      await page.goto(`${url}/account/security`);
      await expect(page.getByRole("heading", { name: /Passkeys/ })).toBeVisible();
      await page.getByLabel("Senha atual para autorizar alterações").fill(fixture.user.password);
      await page.getByLabel("Nome da passkey").fill("Chave virtual E2E");
      await page.getByRole("button", { name: "Adicionar passkey" }).click();
      await expect(page.getByText("Chave virtual E2E", { exact: true })).toBeVisible({ timeout: 25_000 });
      const credentials = await db.passkeyCredential.findMany({ where: { userId: fixture.user.id, revokedAt: null, name: "Chave virtual E2E" } });
      expect(credentials).toHaveLength(1);
      // A post-enrollment server-rendered reload must list the *local* RP
      // credential, not silently query the production portal RP instead.
      await page.reload();
      await expect(page.getByText("Chave virtual E2E", { exact: true })).toBeVisible();

      await context.clearCookies();
      await page.goto(`${url}/login`);
      await expect(page.getByRole("button", { name: "Entrar com passkey" })).toBeVisible();
      await page.getByRole("button", { name: "Entrar com passkey" }).click();
      await expect(page).toHaveURL(`${url}/`, { timeout: 25_000 });
      const sessionCookie = (await context.cookies(url)).find(cookie => cookie.name === getSessionCookieName({ NODE_ENV: "development" }));
      expect(sessionCookie).toBeDefined();
      const issued = await db.session.findFirstOrThrow({ where: { tokenHash: hashSessionToken(sessionCookie!.value) } });
      expect(issued.authenticationMethods).toEqual(["webauthn"]);

      // Force an account-selected allowCredentials ceremony to exercise the
      // password-assisted fallback for non-discoverable security keys.
      await context.clearCookies();
      await page.goto(`${url}/login`);
      await page.getByLabel("E-mail (opcional, para selecionar uma chave não detectável)").fill(fixture.user.email);
      await page.getByLabel("Senha para selecionar a chave cadastrada").fill(fixture.user.password);
      await page.getByRole("button", { name: "Entrar com passkey" }).click();
      await expect(page).toHaveURL(`${url}/`, { timeout: 25_000 });
      const assistedCookie = (await context.cookies(url)).find(cookie => cookie.name === getSessionCookieName({ NODE_ENV: "development" }));
      expect(assistedCookie).toBeDefined();
      const assistedSession = await db.session.findFirstOrThrow({ where: { tokenHash: hashSessionToken(assistedCookie!.value) } });
      expect(assistedSession.authenticationMethods).toEqual(["pwd", "webauthn"]);

      await page.goto(`${url}/account/security`);
      await page.getByLabel("Senha atual para autorizar alterações").fill(fixture.user.password);
      await page.getByRole("button", { name: "Revogar Chave virtual E2E" }).click();
      await expect(page.getByText("Chave virtual E2E", { exact: true })).toHaveCount(0);
      const revoked = await db.passkeyCredential.findUniqueOrThrow({ where: { id: credentials[0]!.id } });
      expect(revoked.revokedAt).not.toBeNull();

      await context.clearCookies();
      await page.goto(`${url}/login`);
      await page.getByRole("button", { name: "Entrar com passkey" }).click();
      await expect(page.locator('section[aria-label="Entrar com passkey"] p[role="alert"]')).toContainText("passkey não foi validada");
    } finally {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
    }
  } finally {
    if (browserSessionId) await db.session.updateMany({ where: { id: browserSessionId, revokedAt: null }, data: { revokedAt: new Date() } }).catch(() => {});
    await context.close();
    await db.$disconnect();
  }
});
