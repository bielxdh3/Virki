import { formatDateTime } from "@virki/auth/date-time";
import { getAdministrativeCredentialState, listActiveSecurityElevations } from "@virki/auth/administration";
import { listPendingAccountRecoveries } from "@virki/auth/security";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { createSessionCsrfToken } from "../../../lib/session-csrf";
import { prisma } from "@virki/database";
import { headers } from "next/headers";
import { listUserPasskeys, passkeysEnabledForRequest } from "@virki/auth/passkeys";
import { requireAdminPage } from "../../../lib/admin-page";
import { getSurface, requestHost } from "../../../lib/surface";
import { PasskeyManager } from "../../account/security/passkey-manager";
import { approveRecoveryAction } from "../../recover/actions";
import { CredentialSetup, ElevationControls } from "./security-controls";
import { RecoveryReviewDetails, recoveryNeedsAdministrativeReview } from "./recovery-review-details";

export const dynamic = "force-dynamic";

export default async function SecurityPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  const session = await requireAdminPage();
  const params = await searchParams;
  const requestHeaders = await headers();
  const adminPasskeysEnabled = passkeysEnabledForRequest(getSurface(requestHeaders), requestHost(requestHeaders), process.env, "ADMIN");
  const [credential, activeElevations, recoveryRequests, csrf, activeSessions, adminPasskeys, factor] = await Promise.all([
    getAdministrativeCredentialState(session.user.id),
    listActiveSecurityElevations(session.user, session.id),
    listPendingAccountRecoveries(session.user),
    createSessionCsrfToken("admin-security"),
    prisma.session.count({ where: { userId: session.user.id, revokedAt: null, expiresAt: { gt: new Date() } } }),
    adminPasskeysEnabled ? listUserPasskeys(session.user.id, "ADMIN", requestHost(requestHeaders)) : Promise.resolve([]),
    prisma.user.findUnique({ where: { id: session.user.id }, select: { secondFactorMethod: true, totpFactor: { select: { status: true, confirmedAt: true } } } })
  ]);
  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Segurança</h1><p>Credencial separada, elevação por sessão e recuperação administrativa.</p></div></header>
    {params.status === "credential"
      ? credential?.status === "ACTIVE" && <p className="form-success" role="status">Credencial administrativa configurada. Agora você pode solicitar uma elevação.</p>
      : params.status && <p className="form-success" role="status">Alteração concluída.</p>}{params.error && <p className="form-error" role="alert">A ação não foi concluída. Tente novamente.</p>}
    <CredentialSetup
      csrf={csrf}
      totpActive={factor?.secondFactorMethod === "TOTP" && factor.totpFactor?.status === "ACTIVE" && Boolean(factor.totpFactor.confirmedAt)}
      activeCredential={credential?.status === "ACTIVE" ? {
        keyVersion: credential.keyVersion,
        updatedAt: formatDateTime(credential.updatedAt)
      } : undefined}
    />
    <ElevationControls csrf={csrf} credentialReady={credential?.status === "ACTIVE"} active={activeElevations.map((item) => ({ ...item, expiresAt: item.expiresAt.toISOString() }))} />
    {adminPasskeysEnabled ? <PasskeyManager role="ADMIN" csrfToken={csrf} requiresTotp={factor?.secondFactorMethod === "TOTP"} initialPasskeys={adminPasskeys.map(({ createdAt, lastUsedAt, ...item }) => ({ ...item, createdAt: createdAt.toISOString(), lastUsedAt: lastUsedAt?.toISOString() ?? null }))} /> : null}
    <section className="surface"><h2>Recuperação de contas ({recoveryRequests.length})</h2><p className="muted">Pedidos expirados, não verificados ou da sua própria conta não aparecem aqui. Aprovar autoriza a recuperação apenas após a prova exigida; é necessária elevação ativa e a aprovação não pode ser feita pelo titular.</p>
      {recoveryRequests.length === 0 ? <p className="muted">Nenhum pedido pendente.</p> : <div className="row-list">{recoveryRequests.map((request) => <article className="list-row" key={request.id}><div className="row-main"><strong>{request.user.displayName || request.user.emailNormalized}</strong><span>{request.user.role === "ADMIN" ? "Administrador" : "Usuário"} · {request.user.emailNormalized} · expira {formatDateTime(request.expiresAt)}</span><RecoveryReviewDetails request={request} /></div>{recoveryNeedsAdministrativeReview(request) ? <form action={approveRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="requestId" value={request.id} /><button className="button-primary" type="submit">Aprovar recuperação</button></form> : null}</article>)}</div>}
    </section>
    <section className="surface"><h2>Sessões deste admin</h2><p>{activeSessions} sessão(ões) ativa(s), incluindo a sessão atual.</p></section>
  </main>;
}
