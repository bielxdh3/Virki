import { expect, test } from "@playwright/test";
import { SESSION_COOKIE_NAME } from "@virki/auth/constants";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const publicUrl = "http://127.0.0.1:3000";
const portalUrl = "https://portal.localhost:3001";
const hubUrl = "https://hub.localhost:3001";

for (const viewport of [
  { name: "desktop", width: 1365, height: 900 },
  { name: "mobile", width: 375, height: 812 }
]) {
  test(`public Entrar reaches the portal login screen at ${viewport.name}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport });
    try {
      const page = await context.newPage();
      await page.goto(publicUrl);

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
      await page.goto(`${portalUrl}/`);

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
      await page.goto(`${hubUrl}/admin/accounts`);

      expect(Boolean(adminResponse?.request().headers()["cf-access-jwt-assertion"])).toBe(true);
      const accessReason = adminResponse?.headers()["x-virki-e2e-access-reason"] ?? "not-reported";
      const accessKid = adminResponse?.headers()["x-virki-e2e-access-kid"] ?? "not-reported";
      await expect.soft(adminResponse?.status(), `Cloudflare Access rejected the E2E assertion (${accessReason}; kid=${accessKid}).`).toBe(307);
      await expect.soft(adminResponse?.headers().location).toBe(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      await expect.soft(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      await expect.soft(page.getByRole("heading", { name: "Contas", exact: true })).toHaveCount(0);
      await expect.soft(page.getByRole("link", { name: "Acessos", exact: true })).toHaveCount(0);
      expect((await context.cookies(hubUrl)).some((cookie) => cookie.name === SESSION_COOKIE_NAME)).toBe(false);
      await expect(page.getByRole("heading", { level: 1, name: "Entrar", exact: true })).toBeVisible();
      await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Senha", { exact: true })).toBeVisible();
    } finally {
      await context.close();
    }
  });
}

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
