import { expect, test } from "@playwright/test";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const surfaces = [
  { name: "Portal", url: "https://portal.localhost:3001" },
  { name: "Hub", url: "https://hub.localhost:3001" }
] as const;

for (const surface of surfaces) {
  test(`${surface.name} password visibility remains interactive after hydration and login errors`, async ({ browser }) => {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      if (surface.name === "Hub") await addCloudflareAccessHeader(page);
      const applicationErrors = new Set<string>();
      page.on("console", (message) => {
        const text = message.text();
        const location = message.location();
        // Next's dev overlay injects inline styles that conflict with the app's nonce-only CSP.
        const nextDevtoolsStyleViolation = text.startsWith("Applying inline style violates the following Content Security Policy directive 'style-src ")
          && location.url.includes("/node_modules/next/dist/compiled/next-devtools/");
        if (nextDevtoolsStyleViolation) return;
        if (message.type() === "error" || /hydration|server-rendered html/iu.test(text)) {
          applicationErrors.add(`${location.url}:${location.lineNumber}`);
        }
      });

      await page.goto(`${surface.url}/login?error=1`);
      const form = page.locator("form").filter({ has: page.getByLabel("Senha", { exact: true }) });
      const password = page.getByLabel("Senha", { exact: true });
      const toggle = page.locator(".password-field button[type='button']");
      const submits: string[] = [];
      page.on("request", (request) => {
        if (request.url().includes("/api/login")) submits.push(request.url());
      });

      await expect(page.getByRole("alert")).toHaveText("E-mail ou senha inválidos.");
      await password.fill("synthetic-login-password");
      await expect(password).toHaveAttribute("type", "password");
      await expect(toggle).toHaveAttribute("aria-label", "Mostrar senha");
      await expect(toggle).toHaveAttribute("aria-pressed", "false");

      await toggle.click();
      await expect(password).toHaveAttribute("type", "text");
      await expect(password).toHaveValue("synthetic-login-password");
      await expect(page.getByRole("button", { name: "Ocultar senha", exact: true })).toHaveAttribute("aria-pressed", "true");

      await toggle.focus();
      await page.keyboard.press("Enter");
      await expect(password).toHaveAttribute("type", "password");
      await expect(password).toHaveValue("synthetic-login-password");
      await expect(page.getByRole("button", { name: "Mostrar senha", exact: true })).toHaveAttribute("aria-pressed", "false");

      await page.keyboard.press("Space");
      await expect(password).toHaveAttribute("type", "text");
      await expect(password).toHaveValue("synthetic-login-password");
      await expect(form).toBeVisible();
      expect(submits).toHaveLength(0);
      expect(new URL(page.url()).pathname).toBe("/login");
      expect([...applicationErrors]).toEqual([]);
    } finally {
      await context.close();
    }
  });
}
