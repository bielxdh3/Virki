import { createCsrfToken } from "@bielos/auth/csrf";
import { getAccountSecurityState, listTrustedDevices } from "@bielos/auth/security";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { AccountSecurityPanel, TrustedDeviceList } from "../account-security-panel";

export const dynamic = "force-dynamic";

export default async function AccountSecurityPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-account-security"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  const [state, devices] = await Promise.all([getAccountSecurityState(session.user.id), listTrustedDevices(session.user.id)]);
  const csrfToken = createCsrfToken();
  return <main className="hub-shell"><section className="hub-workspace core-security-workspace"><header className="top-statusbar"><a href="/core/security">Back to security</a></header><header className="core-security-intro"><p className="eyebrow">BielOS Core</p><h1>Account security</h1><p>Manage your second factor and trusted devices.</p></header><AccountSecurityPanel csrfToken={csrfToken} totpActive={state?.totpStatus === "ACTIVE"} recoveryCodeCount={state?.recoveryCodeCount ?? 0} /><TrustedDeviceList csrfToken={csrfToken} devices={devices} /></section></main>;
}
