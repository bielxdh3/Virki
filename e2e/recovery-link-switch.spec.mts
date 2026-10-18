import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { addCloudflareAccessHeader } from "../scripts/e2e/access-token.mts";

const hubUrl = "https://hub.localhost:3001";
const e2eDatabaseUrl = process.env.VIRKI_E2E_DATABASE_URL?.trim();
const fixturePath = process.env.VIRKI_E2E_AUTH_FIXTURE_FILE;
test.skip(!e2eDatabaseUrl || !fixturePath, "Recovery switch E2E requires the explicit disposable database and global-setup fixture.");

type FixtureAccount = { id: string; email: string };
type AuthFixture = { admin: FixtureAccount; recoveryReviewer: FixtureAccount };
let fixture: AuthFixture;

test.beforeAll(async () => {
  if (!fixturePath || !e2eDatabaseUrl) throw new Error("Recovery switch E2E fixture is unavailable.");
  const { assertDisposableCoreTestDatabase } = await import("../scripts/core-test-database-safety.mjs");
  assertDisposableCoreTestDatabase(e2eDatabaseUrl, process.env);
  const value: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (!isFixture(value)) throw new Error("Recovery switch E2E fixture is invalid.");
  fixture = value;
});

test("approved ADMIN recovery link switch activates only the confirmed candidate", async ({ browser }) => {
  test.setTimeout(45_000);
  if (!e2eDatabaseUrl) throw new Error("Recovery switch E2E database is unavailable.");
  process.env.DATABASE_URL = e2eDatabaseUrl;
  process.env.VIRKI_HUB_URL = hubUrl;
  process.env.VIRKI_HUB_HOSTNAME = "hub.localhost";

  const [{ prisma }, { getAccountRecoveryState, hashRecoveryRequestKey, requestAdministrativeAccountRecovery }, { decryptEmailPayload }] = await Promise.all([
    import("@virki/database"),
    import("@virki/auth/security"),
    import("@virki/auth/email")
  ]);
  const context = await browser.newContext();
  try {
    const requestLink = async (account: FixtureAccount) => {
      await requestAdministrativeAccountRecovery(account.email, "pt-BR");
      const message = await prisma.emailOutboxMessage.findFirst({
        where: { recipientEmail: account.email, kind: "ACCOUNT_RECOVERY" },
        orderBy: { createdAt: "desc" },
        select: { id: true, payload: true }
      });
      if (!message) throw new Error("Recovery switch E2E message is unavailable.");
      const actionUrl = decryptEmailPayload(message.payload).actionUrl;
      if (!actionUrl || new URL(actionUrl).origin !== hubUrl) throw new Error("Recovery switch E2E link is invalid.");
      const requestKey = new URL(actionUrl).searchParams.get("request");
      if (!requestKey || !/^[A-Za-z0-9_-]{32,100}$/u.test(requestKey)) throw new Error("Recovery switch E2E key is invalid.");
      const recovery = await prisma.accountRecoveryRequest.findFirst({
        where: { userId: account.id, requestKeyHash: hashRecoveryRequestKey(requestKey) },
        select: { id: true }
      });
      if (!recovery) throw new Error("Recovery switch E2E record is unavailable.");
      return { actionUrl, requestKey, requestId: recovery.id };
    };

    const first = await requestLink(fixture.admin);
    const candidate = await requestLink(fixture.recoveryReviewer);
    const reviewedAt = new Date();
    await prisma.accountRecoveryRequest.update({
      where: { id: candidate.requestId },
      data: { status: "APPROVED", emailVerifiedAt: reviewedAt, reviewedByUserId: fixture.admin.id, approvedAt: reviewedAt }
    });

    const page = await context.newPage();
    await addCloudflareAccessHeader(page);
    await page.goto(first.actionUrl);
    await expect(page.getByLabel("Código de verificação", { exact: true })).toBeVisible();
    const firstActive = (await context.cookies(hubUrl)).find((cookie) => cookie.name === "virki_recovery_v2");
    expect(firstActive?.value).toBe(first.requestKey);

    await page.goto(candidate.actionUrl);
    await expect(page.getByRole("status")).toContainText("Outro link está aberto nesta sessão.");
    await expect(page.getByLabel("Nova senha", { exact: true })).toHaveCount(0);
    const beforeConfirmation = await context.cookies(hubUrl);
    expect(beforeConfirmation.find((cookie) => cookie.name === "virki_recovery_v2")?.value).toBe(first.requestKey);
    expect(beforeConfirmation.find((cookie) => cookie.name === "virki_recovery_candidate")?.value).toBe(candidate.requestKey);

    await page.locator('input[name="requestId"]').evaluate((input, value) => { (input as HTMLInputElement).value = value; }, first.requestId);
    await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    await expect(page.locator('p[role="alert"]')).toContainText("Não foi possível usar este link.");
    const afterRejectedSwitch = await context.cookies(hubUrl);
    expect(afterRejectedSwitch.find((cookie) => cookie.name === "virki_recovery_v2")?.value).toBe(first.requestKey);
    expect(afterRejectedSwitch.find((cookie) => cookie.name === "virki_recovery_candidate")?.value).toBe(candidate.requestKey);

    await page.locator('input[name="requestId"]').evaluate((input, value) => { (input as HTMLInputElement).value = value; }, candidate.requestId);
    const switchResponses: string[] = [];
    page.on("response", (response) => {
      const request = response.request();
      const url = new URL(response.url());
      if (request.method() !== "POST" || url.origin !== hubUrl) return;
      const redirectHeader = response.headers()["x-action-redirect"]?.split(";")[0];
      let redirectSummary = "none";
      if (redirectHeader) {
        try {
          const redirect = new URL(redirectHeader, hubUrl);
          redirectSummary = `${redirect.pathname}?${[...redirect.searchParams.keys()].join(",")}`;
        } catch { redirectSummary = "unparseable"; }
      }
      switchResponses.push(`${url.pathname}:${response.status()}:redirect=${redirectSummary}`);
    });
    await page.getByRole("button", { name: "Continuar com este link", exact: true }).click();
    try {
      await expect(page.getByRole("status")).toContainText("Defina uma nova senha para concluir o acesso à sua conta.");
    } catch {
      const currentUrl = new URL(page.url());
      const afterFailure = await context.cookies(hubUrl);
      const activeKey = afterFailure.find((cookie) => cookie.name === "virki_recovery_v2")?.value;
      const candidateStillPresent = afterFailure.some((cookie) => cookie.name === "virki_recovery_candidate" && Boolean(cookie.value));
      const [recoveryState, record, alertText] = await Promise.all([
        getAccountRecoveryState(candidate.requestId, candidate.requestKey, new Date(), "ADMIN"),
        prisma.accountRecoveryRequest.findUnique({
          where: { id: candidate.requestId },
          select: { status: true, emailVerifiedAt: true, expiresAt: true, purpose: true, user: { select: { role: true, isActive: true, accountStatus: true } } }
        }),
        page.getByRole("alert").textContent().catch(() => null)
      ]);
      throw new Error(`Recovery link switch did not render the approved request (path=${currentUrl.pathname}; requestIdMatches=${currentUrl.searchParams.get("requestId") === candidate.requestId}; activeMatchesCandidate=${activeKey === candidate.requestKey}; candidateStillPresent=${candidateStillPresent}; lookup=${recoveryState?.status ?? "missing"}; record=${record?.status ?? "missing"}; emailVerified=${Boolean(record?.emailVerifiedAt)}; unexpired=${Boolean(record && record.expiresAt > new Date())}; purpose=${record?.purpose ?? "missing"}; accountEligible=${Boolean(record?.user.isActive && record.user.accountStatus === "ACTIVE" && record.user.role === "ADMIN")}; alert=${alertText ?? "none"}; responses=${switchResponses.join("|") || "none"}).`);
    }
    await expect(page.getByLabel("Nova senha", { exact: true })).toBeVisible();
    const afterConfirmation = await context.cookies(hubUrl);
    expect(afterConfirmation.find((cookie) => cookie.name === "virki_recovery_v2")?.value).toBe(candidate.requestKey);
    expect(afterConfirmation.some((cookie) => cookie.name === "virki_recovery_candidate" && cookie.value.length > 0)).toBe(false);
  } finally {
    await context.close();
    await prisma.$disconnect();
  }
});

function isFixture(value: unknown): value is AuthFixture {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return isAccount(candidate.admin) && isAccount(candidate.recoveryReviewer);
}

function isAccount(value: unknown): value is FixtureAccount {
  if (!value || typeof value !== "object") return false;
  const account = value as Record<string, unknown>;
  return typeof account.id === "string" && typeof account.email === "string";
}
