import { expect, test, type Page, type Response } from "@playwright/test";
import { getSessionCookieName } from "@virki/auth/constants";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const publicUrl = "http://127.0.0.1:3000";
const productionHubMode = process.env.VIRKI_E2E_HUB_MODE === "production";
const portalUrl = productionHubMode ? "https://portal.localhost" : "https://portal.localhost:3001";
const hubUrl = productionHubMode ? "https://hub.localhost" : "https://hub.localhost:3001";
const sessionCookieName = getSessionCookieName({ NODE_ENV: productionHubMode ? "production" : process.env.NODE_ENV });

async function expectPublicDocumentScripts(page: Page, response: Response | null): Promise<string> {
  if (!response) throw new Error("Expected a public document response.");
  const scriptPolicy = response.headers()["content-security-policy"]?.split(";").map((value) => value.trim()).find((value) => value.startsWith("script-src "));
  const nonce = scriptPolicy?.match(/'nonce-([^']+)'/u)?.[1];
  if (!nonce) throw new Error("Expected a per-document script nonce.");
  expect(scriptPolicy).not.toContain("'unsafe-inline'");
  // Inspect scripts emitted in the document, not nodes added later by Next development tooling.
  const inlineNonces = await page.evaluate((html) => Array.from(new DOMParser().parseFromString(html, "text/html").querySelectorAll<HTMLScriptElement>("script:not([src])"), (script) => script.nonce || script.getAttribute("nonce")), await response.text());
  expect(inlineNonces.length).toBeGreaterThan(0);
  expect(inlineNonces.every((value) => value === nonce)).toBe(true);
  return nonce;
}

function expectHubDocumentSecurityHeaders(response: Response | null): void {
  if (!response) throw new Error("Expected a Hub document response.");
  const headers = response.headers();
  expect(headers["x-powered-by"]).toBeUndefined();
  const scriptPolicy = headers["content-security-policy"]?.split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith("script-src "));
  expect(scriptPolicy).toBeTruthy();
  expect(scriptPolicy).toMatch(/'nonce-[A-Za-z0-9+/=]+'/u);
  expect(scriptPolicy).toContain("'strict-dynamic'");
  expect(scriptPolicy).not.toContain("'unsafe-inline'");
}

for (const viewport of [
  { name: "desktop", width: 1365, height: 900 },
  { name: "mobile", width: 375, height: 812 }
]) {
  test(`public Entrar reaches the portal login screen at ${viewport.name}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport });
    try {
      const page = await context.newPage();
      const publicResponse = await page.goto(publicUrl);
      expect(publicResponse?.status()).toBe(200);
      expect(publicResponse?.headers()["x-powered-by"]).toBeUndefined();
      await expectPublicDocumentScripts(page, publicResponse);
      await expect(page).toHaveTitle("Virki");
      await expect(page.locator("html")).toHaveAttribute("lang", "pt-BR");

      const enterLink = page.getByRole("link", { name: "Entrar", exact: true });
      await expect(enterLink).toHaveAttribute("href", portalUrl);
      await enterLink.click();

      await expect(page).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
      await expect(page.getByRole("heading", { level: 1, name: "Entrar", exact: true })).toBeVisible();
      await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Senha", { exact: true })).toBeVisible();
      await expect(page.getByRole("link", { name: "Recuperar conta", exact: true })).toBeVisible();
    } finally {
      await context.close();
    }
  });

  test(`direct unauthenticated portal entry redirects to login at ${viewport.name}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport });
    try {
      const page = await context.newPage();
      const portalResponse = await page.goto(`${portalUrl}/`);
      expect(portalResponse?.status()).toBe(200);
      expectHubDocumentSecurityHeaders(portalResponse);

      await expect(page).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
      await expect(page.getByRole("heading", { level: 1, name: "Entrar", exact: true })).toBeVisible();
      await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Senha", { exact: true })).toBeVisible();
    } finally {
      await context.close();
    }
  });

  test(`unauthenticated Hub admin entry redirects to login at ${viewport.name}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport });
    try {
      const page = await context.newPage();
      await addCloudflareAccessHeader(page);
      let adminResponse: import("@playwright/test").Response | undefined;
      page.on("response", (response) => {
        if (response.url() === `${hubUrl}/admin/accounts` && response.request().method() === "GET") adminResponse = response;
      });
      const loginResponse = await page.goto(`${hubUrl}/admin/accounts`);

      expect(Boolean(adminResponse?.request().headers()["cf-access-jwt-assertion"])).toBe(true);
      expect(adminResponse?.headers()["x-powered-by"]).toBeUndefined();
      expectHubDocumentSecurityHeaders(loginResponse);
      const accessReason = adminResponse?.headers()["x-virki-e2e-access-reason"] ?? "not-reported";
      const accessKid = adminResponse?.headers()["x-virki-e2e-access-kid"] ?? "not-reported";
      await expect.soft(adminResponse?.status(), `Cloudflare Access rejected the E2E assertion (${accessReason}; kid=${accessKid}).`).toBe(307);
      await expect.soft(adminResponse?.headers().location).toBe(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      await expect.soft(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      await expect.soft(page.getByRole("heading", { name: "Contas", exact: true })).toHaveCount(0);
      await expect.soft(page.getByRole("link", { name: "Acessos", exact: true })).toHaveCount(0);
      expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === sessionCookieName)).toBe(false);
      await expect(page.getByRole("heading", { level: 1, name: "Entrar", exact: true })).toBeVisible();
      await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Senha", { exact: true })).toBeVisible();
    } finally {
      await context.close();
    }
  });
}

test("public not-found document renders normally with fresh script nonces", async ({ page }) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", () => runtimeErrors.push("page error"));
  page.on("console", (message) => {
    if (message.type() === "error" && /content security policy|refused to execute|refused to apply/iu.test(message.text())) runtimeErrors.push("CSP error");
  });
  const response = await page.goto(`${publicUrl}/missing-public-page`);
  expect(response?.status()).toBe(404);
  expect(response?.headers()["x-powered-by"]).toBeUndefined();
  const cspDirectives = response?.headers()["content-security-policy"]?.split(";").map((value) => value.trim());
  // This isolated E2E server runs in development, where Next's overlay injects
  // inline styles. The production-image smoke enforces strict style-src 'self'.
  expect(cspDirectives).toContain("style-src 'self' 'unsafe-inline'");
  expect(cspDirectives?.find((directive) => directive.startsWith("script-src "))).not.toContain("'unsafe-inline'");
  await expect(page.getByRole("heading", { name: "Virki", exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { level: 1, name: "404", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Voltar ao início", exact: true })).toHaveAttribute("href", "/");
  expect(await page.locator('link[rel~="stylesheet"]').count()).toBeGreaterThan(0);
  expect(await page.locator("body").evaluate((body) => getComputedStyle(body).fontFamily)).toContain("Inter");
  await expect(page.locator("body")).toBeVisible();
  const nonce = await expectPublicDocumentScripts(page, response);
  const reloaded = await page.reload();
  expect(reloaded?.status()).toBe(404);
  expect(await expectPublicDocumentScripts(page, reloaded)).not.toBe(nonce);
  expect(runtimeErrors).toEqual([]);
});

test("isolated ingress ignores forged forwarding headers and rejects a forged Access assertion", async ({ browser }) => {
  const portalContext = await browser.newContext({
    extraHTTPHeaders: {
      "x-forwarded-host": "attacker.invalid",
      "x-forwarded-proto": "http"
    }
  });
  try {
    const page = await portalContext.newPage();
    let protectedResponse: import("@playwright/test").Response | undefined;
    page.on("response", (response) => {
      if (response.url() === `${portalUrl}/account/security`) protectedResponse = response;
    });
    await page.goto(`${portalUrl}/account/security`);
    await expect(page).toHaveURL(`${portalUrl}/login?returnTo=%2Faccount%2Fsecurity`);
    expect(protectedResponse?.status()).toBe(307);
    expect(protectedResponse?.headers().location).toBe(`${portalUrl}/login?returnTo=%2Faccount%2Fsecurity`);
  } finally {
    await portalContext.close();
  }

  const hubContext = await browser.newContext({
    extraHTTPHeaders: {
      "cf-access-jwt-assertion": "forged-synthetic-assertion",
      "x-forwarded-host": "attacker.invalid",
      "x-forwarded-proto": "http"
    }
  });
  try {
    const page = await hubContext.newPage();
    const response = await page.goto(`${hubUrl}/login`);
    expect(response?.status()).toBe(403);
    await expect(page.getByRole("heading", { name: "Entrar", exact: true })).toHaveCount(0);
  } finally {
    await hubContext.close();
  }
});
