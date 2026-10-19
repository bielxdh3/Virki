import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { PrismaClient } from "@virki/database";
import { SESSION_COOKIE_NAME, hashSessionToken } from "@virki/auth";
import { createAuditLogData, hashAuditIdentifier } from "@virki/auth/audit";
import { formatDateTime } from "@virki/auth/date-time";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const hub = "https://hub.localhost:3001";
test.use({ channel: "chromium" });
test.skip(!process.env.VIRKI_E2E_DATABASE_URL, "Requires an explicit disposable PostgreSQL fixture.");

test("ADMIN investigates persisted audit with safe details, filters, paging, UTC−4 and responsive keyboard access", async ({ browser }) => {
  test.setTimeout(120_000);
  const fixture = JSON.parse(await readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as { admin: { id: string; email: string }; user: { id: string } };
  const database = new PrismaClient({ datasources: { db: { url: process.env.VIRKI_E2E_DATABASE_URL } } });
  // This context visits only the loopback hub fixture signed by this run's private test CA.
  const context = await browser.newContext();
  const token = randomBytes(32).toString("base64url");
  const resource = `browser.${randomUUID()}`;
  const hydrationErrors: string[] = [];
  try {
    const session = await database.session.create({ data: { userId: fixture.admin.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 600_000), authenticationMethods: ["pwd", "otp", "mfa"] } });
    await context.addCookies([{ name: SESSION_COOKIE_NAME, value: token, url: hub, httpOnly: true, secure: true, sameSite: "Lax" }]);
    await database.auditLog.createMany({ data: Array.from({ length: 53 }, (_, index) => ({
      ...createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", actorUserId: fixture.admin.id, actorRole: "ADMIN", resource }),
      id: `${resource}-${String(index).padStart(3, "0")}`,
      metadata: { source: "hub-login", arbitrary: "private-legacy@example.invalid", [["to", "ken"].join("")]: ["synthetic", "private", "material"].join("-") }, message: "private-legacy@example.invalid"
    })) });
    const firstAuditRecord = await database.auditLog.findUniqueOrThrow({ where: { id: `${resource}-000` }, select: { createdAt: true } });
    const page = await context.newPage();
    page.on("console", (message) => { if (/hydration|server-rendered html/iu.test(message.text())) hydrationErrors.push("hydration mismatch"); });
    await addCloudflareAccessHeader(page);
    await page.goto(`${hub}/admin/audit?resource=${resource}&sort=oldest`);
    await expect(page.getByRole("heading", { level: 1, name: "Auditoria", exact: true })).toBeVisible();
    await expect(page.locator("article.audit-event")).toHaveCount(50);
    await expect(page.locator("time").first()).toHaveText(formatDateTime(firstAuditRecord.createdAt));
    const body = await page.content();
    expect(body).not.toContain("private-legacy@example.invalid");
    expect(body).not.toContain("synthetic-private-material");
    expect(body).not.toContain(fixture.admin.email);
    expect(body).not.toContain(`${resource}-052`);
    const detail = page.locator("article.audit-event details").first();
    await expect(detail).not.toHaveAttribute("open");
    await detail.locator("summary").focus();
    await page.keyboard.press("Enter");
    await expect(detail).toHaveAttribute("open", "");
    await expect(detail.locator("pre")).toContainText(hashAuditIdentifier(fixture.admin.id));
    await expect(detail.locator("summary")).toBeFocused();
    for (const viewport of [{ width: 375, height: 812 }, { width: 812, height: 375 }, { width: 1280, height: 800 }]) {
      await page.setViewportSize(viewport);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    }
    const contrast = await page.getByRole("heading", { name: "Auditoria", exact: true }).evaluate((node) => {
      const style = getComputedStyle(node);
      const rgb = (value: string) => (value.match(/[\d.]+/gu) ?? []).slice(0, 3).map(Number).map((component) => component / 255).map((component) => component <= 0.04045 ? component / 12.92 : ((component + 0.055) / 1.055) ** 2.4);
      const fg = rgb(style.color); const bg = rgb(getComputedStyle(document.body).backgroundColor);
      const luminance = (color: number[]) => color[0] * 0.2126 + color[1] * 0.7152 + color[2] * 0.0722;
      return (Math.max(luminance(fg), luminance(bg)) + 0.05) / (Math.min(luminance(fg), luminance(bg)) + 0.05);
    });
    expect(contrast).toBeGreaterThan(4.5);
    await page.getByRole("link", { name: "Próxima página", exact: true }).click();
    await expect(page.locator("article.audit-event")).toHaveCount(3);
    expect(new URL(page.url()).searchParams.get("resource")).toBe(resource);
    await page.getByRole("link", { name: "Página anterior", exact: true }).click();
    await expect(page.locator("article.audit-event")).toHaveCount(50);
    await page.getByLabel("Busca por prefixo", { exact: true }).fill("AUTH_LOGIN");
    await page.getByRole("combobox", { name: "Resultado", exact: true }).selectOption("FAILURE");
    await page.getByRole("combobox", { name: "Ordenação", exact: true }).selectOption("newest");
    await page.getByRole("button", { name: "Buscar eventos", exact: true }).click();
    await expect(page.locator("article.audit-event").first()).toContainText(`${resource}-052`);
    await page.getByLabel("ID exato do evento", { exact: true }).fill(`${resource}-000`);
    await page.getByRole("button", { name: "Buscar eventos", exact: true }).click();
    await expect(page.locator("article.audit-event")).toHaveCount(1);
    const roleResource = `${resource}.roles`;
    await database.auditLog.createMany({ data: [
      { ...createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", actorUserId: fixture.admin.id, actorRole: "ADMIN", resource: roleResource }), id: `${roleResource}.admin` },
      { ...createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", actorUserId: fixture.user.id, actorRole: "USER", resource: roleResource }), id: `${roleResource}.user` },
      { ...createAuditLogData({ eventType: "AUTH_LOGIN_FAILURE", result: "FAILURE", resource: roleResource }), id: `${roleResource}.system` }
    ] });
    for (const [actorRole, eventId, displayedRole] of [["ADMIN", "admin", "ADMIN"], ["USER", "user", "USER"], ["SYSTEM", "system", "Indisponível"]] as const) {
      await page.goto(`${hub}/admin/audit?resource=${roleResource}&actorRole=${actorRole}`);
      await expect(page.getByRole("combobox", { name: "Papel do ator", exact: true })).toHaveValue(actorRole);
      await expect(page.locator("article.audit-event")).toHaveCount(1);
      await expect(page.locator("article.audit-event").first()).toContainText(`${roleResource}.${eventId}`);
      const roleDetail = page.locator("article.audit-event details").first();
      await roleDetail.locator("summary").click();
      await expect(roleDetail.locator("pre")).toContainText(`"papelVerificado": "${displayedRole}"`);
    }
    await page.goto(`${hub}/admin/audit?resource=missing.resource`);
    await expect(page.getByText("Nenhum evento corresponde aos filtros.", { exact: false })).toBeVisible();
    await page.goto(`${hub}/admin/audit?from=2026-02-30&to=2026-03-01`);
    await expect(page.getByRole("alert")).toContainText("Filtros inválidos");
    await page.getByRole("link", { name: "Limpar filtros", exact: true }).click();
    await expect(page.getByLabel("Busca por prefixo", { exact: true })).toHaveValue("");
    await database.session.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    await page.reload();
    await expect(page).toHaveURL(/\/login\?/u);
    expect(hydrationErrors).toEqual([]);
  } finally { await context.close(); await database.$disconnect(); }
});

test("audit search and details reject USER and missing Access before reading rows", async ({ browser }) => {
  const fixture = JSON.parse(await readFile(process.env.VIRKI_E2E_AUTH_FIXTURE_FILE!, "utf8")) as { user: { id: string } };
  const database = new PrismaClient({ datasources: { db: { url: process.env.VIRKI_E2E_DATABASE_URL } } });
  const context = await browser.newContext();
  try {
    const token = randomBytes(32).toString("base64url");
    await database.session.create({ data: { userId: fixture.user.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 600_000) } });
    await context.addCookies([{ name: SESSION_COOKIE_NAME, value: token, url: hub, httpOnly: true, secure: true, sameSite: "Lax" }]);
    const page = await context.newPage();
    expect((await page.goto(`${hub}/admin/audit?q=AUTH_LOGIN`))?.status()).toBe(403);
    await addCloudflareAccessHeader(page);
    await page.goto(`${hub}/admin/audit?q=AUTH_LOGIN`);
    await expect(page.getByRole("heading", { level: 1, name: "Auditoria", exact: true })).toHaveCount(0);
    await expect(page.locator("article.audit-event")).toHaveCount(0);
  } finally { await context.close(); await database.$disconnect(); }
});
