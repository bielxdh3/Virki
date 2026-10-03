import { expect, test } from "@playwright/test";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token";

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
      await page.goto(`${hubUrl}/admin/accounts`);

      await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
      await expect(page.getByRole("heading", { level: 1, name: "Entrar", exact: true })).toBeVisible();
      await expect(page.getByLabel("E-mail", { exact: true })).toBeVisible();
      await expect(page.getByLabel("Senha", { exact: true })).toBeVisible();
    } finally {
      await context.close();
    }
  });
}
