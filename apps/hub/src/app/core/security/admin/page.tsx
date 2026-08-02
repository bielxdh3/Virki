import { createCsrfToken } from "@bielos/auth/csrf";
import { getCurrentSession } from "../../../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../../../lib/cloudflare-access";
import { getAdministrativeCredentialState, listActiveSecurityElevations } from "@bielos/auth/administration";
import { listPendingAccountRecoveries } from "@bielos/auth/security";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { AdminSecurityPanel } from "../admin-panel";
import { approveRecoveryAction } from "../../../recover/actions";
import { CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

export const dynamic = "force-dynamic";

export default async function AdministrativeSecurityPage() {
  if (!isCloudflareAccessAllowed(await validateHubCloudflareAccess(await headers(), "core-administrative-security"))) forbidden();
  const session = await getCurrentSession();
  if (!session) redirect("/login");
  if (session.user.role !== "OWNER") forbidden();
  const [credential, elevations, recoveries] = await Promise.all([getAdministrativeCredentialState(session.user.id), listActiveSecurityElevations(session.user, session.id), listPendingAccountRecoveries(session.user)]);
  const csrfToken = createCsrfToken();
  return <main className="hub-shell"><section className="hub-workspace core-security-workspace"><header className="top-statusbar"><a href="/core/security">Back to security</a></header><header className="core-security-intro"><p className="eyebrow">BielOS Core</p><h1>Administrative security</h1><p>Separate administrative credential and session-bound elevation.</p></header><AdminSecurityPanel csrfToken={csrfToken} credentialConfigured={credential?.status === "ACTIVE"} activeElevations={elevations} /><section className="panel"><h2>Account recovery approvals</h2>{recoveries.length === 0 ? <p>None.</p> : <ul>{recoveries.map((item) => <li key={item.requestKey}><span>{item.user.displayName ?? item.user.emailNormalized}</span><form action={approveRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} /><input type="hidden" name="requestKey" value={item.requestKey} /><button type="submit">Approve recovery</button></form></li>)}</ul>}</section></section></main>;
}
