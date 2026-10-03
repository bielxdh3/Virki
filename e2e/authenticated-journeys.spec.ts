import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { expect, test, type BrowserContext } from "@playwright/test";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token";

const portalUrl = "https://portal.localhost:3001";
const hubUrl = "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.BIELOS_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.BIELOS_E2E_AUTH_FIXTURE_FILE;
const hasFixture = Boolean(fixturePath && existsSync(fixturePath));

test.skip(!e2eDatabaseUrl || !hasFixture, "Authenticated E2E requires an explicit disposable E2E database and its global-setup fixture.");

type AccountFixture = {
  email: string;
  password: string;
  deviceToken: string;
};

type AuthFixture = {
  user: AccountFixture;
  admin: AccountFixture;
  projectName: string;
  projectLaunchUrl: string;
  ungrantedProjectName: string;
  disabledProjectName: string;
};

let fixture: AuthFixture;
let deviceCookieName: string;
let sessionCookieName: string;

test.beforeAll(async () => {
  if (!fixturePath) throw new Error("Authenticated E2E fixture path is unavailable.");
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isAuthFixture(value)) throw new Error("Authenticated E2E fixture is invalid.");
  fixture = value;

  const [{ DEVICE_COOKIE_NAME }, { SESSION_COOKIE_NAME }] = await Promise.all([
    import("@bielos/auth/security"),
    import("@bielos/auth")
  ]);
  deviceCookieName = DEVICE_COOKIE_NAME;
  sessionCookieName = SESSION_COOKIE_NAME;
});

test("USER can sign in and sees only the granted enabled project", async ({ browser }) => {
  const context = await browser.newContext();
  try {
    await rememberDevice(context, portalUrl, fixture.user.deviceToken);
    const page = await context.newPage();
    await page.goto(`${portalUrl}/`);
    await expect(page).toHaveURL(`${portalUrl}/login?returnTo=%2F`);
    await signIn(page, fixture.user);

    await expect(page).toHaveURL(`${portalUrl}/`);
    await expect(page.getByRole("heading", { level: 1, name: "Projetos", exact: true })).toBeVisible();
    const projectLink = page.getByRole("link", { name: fixture.projectName });
    await expect(projectLink).toBeVisible();
    await expect(projectLink).toHaveAttribute("href", fixture.projectLaunchUrl);
    await expect(page.getByText(fixture.ungrantedProjectName, { exact: true })).toHaveCount(0);
    await expect(page.getByText(fixture.disabledProjectName, { exact: true })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("ADMIN can sign in to a protected page, navigate, and have the session revoked on logout", async ({ browser }) => {
  const context = await browser.newContext();
  try {
    await rememberDevice(context, hubUrl, fixture.admin.deviceToken);
    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
    await signIn(page, fixture.admin);

    await expect(page).toHaveURL(`${hubUrl}/admin/accounts`);
    await expect(page.getByRole("heading", { level: 1, name: "Contas", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Acessos", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/admin/access`);
    await expect(page.getByRole("heading", { level: 1, name: "Acessos", exact: true })).toBeVisible();
    await expect(page.getByText(`E2E User → ${fixture.projectName}`, { exact: true })).toBeVisible();

    const sessionCookie = (await context.cookies(hubUrl)).find((cookie) => cookie.name === sessionCookieName);
    expect(sessionCookie?.value).toBeTruthy();
    if (!sessionCookie) throw new Error("Authenticated E2E session cookie was not created.");

    const accesslessContext = await browser.newContext();
    try {
      await accesslessContext.addCookies([{
        name: sessionCookieName,
        value: sessionCookie.value,
        url: hubUrl,
        httpOnly: true,
        secure: true,
        sameSite: "Lax"
      }]);
      const accesslessPage = await accesslessContext.newPage();
      const response = await accesslessPage.goto(`${hubUrl}/admin/accounts`);
      expect(response?.status()).toBe(403);
    } finally {
      await accesslessContext.close();
    }

    await page.getByRole("button", { name: "Sair", exact: true }).click();
    await expect(page).toHaveURL(`${hubUrl}/login`);

    await context.addCookies([{
      name: sessionCookieName,
      value: sessionCookie.value,
      url: hubUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Lax"
    }]);
    await page.goto(`${hubUrl}/admin/accounts`);
    await expect(page).toHaveURL(`${hubUrl}/login?returnTo=%2Fadmin%2Faccounts`);
  } finally {
    await context.close();
  }
});

async function rememberDevice(context: BrowserContext, url: string, deviceToken: string): Promise<void> {
  await context.addCookies([{
    name: deviceCookieName,
    value: deviceToken,
    url,
    httpOnly: true,
    secure: true,
    sameSite: "Lax"
  }]);
}

async function signIn(page: import("@playwright/test").Page, account: AccountFixture): Promise<void> {
  await page.getByLabel("E-mail", { exact: true }).fill(account.email);
  await page.getByLabel("Senha", { exact: true }).fill(account.password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
}

function isAuthFixture(value: unknown): value is AuthFixture {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  const isAccount = (account: unknown): account is AccountFixture => {
    if (!account || typeof account !== "object") return false;
    const record = account as Record<string, unknown>;
    return typeof record.email === "string" && typeof record.password === "string" && typeof record.deviceToken === "string";
  };
  return isAccount(candidate.user) && isAccount(candidate.admin) && typeof candidate.projectName === "string" &&
    typeof candidate.projectLaunchUrl === "string" && new URL(candidate.projectLaunchUrl).hostname.endsWith(".invalid") &&
    typeof candidate.ungrantedProjectName === "string" && typeof candidate.disabledProjectName === "string";
}
