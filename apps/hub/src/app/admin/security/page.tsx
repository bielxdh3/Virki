import { formatDateTime } from "@virki/auth/date-time";
import { getAdministrativeCredentialState, listActiveSecurityElevations } from "@virki/auth/administration";
import { listPendingAccountRecoveries } from "@virki/auth/security";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { createSessionCsrfToken } from "../../../lib/session-csrf";
import { prisma } from "@virki/database";
import { requireAdminPage } from "../../../lib/admin-page";
import { approveRecoveryAction } from "../../recover/actions";
import { CredentialSetup, ElevationControls } from "./security-controls";

export const dynamic = "force-dynamic";

export default async function SecurityPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  const session = await requireAdminPage();
  const params = await searchParams;
  const [credential, activeElevations, recoveryRequests, csrf, activeSessions] = await Promise.all([
    getAdministrativeCredentialState(session.user.id),
    listActiveSecurityElevations(session.user, session.id),
    listPendingAccountRecoveries(session.user),
    createSessionCsrfToken("admin-security"),
    prisma.session.count({ where: { userId: session.user.id, revokedAt: null, expiresAt: { gt: new Date() } } })
  ]);
  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Segurança</h1><p>Credencial separada, elevação por sessão e recuperação administrativa.</p></div></header>
    {params.status === "credential"
      ? credential?.status === "ACTIVE" && <p className="form-success" role="status">Credencial administrativa configurada. Agora você pode solicitar uma elevação.</p>
      : params.status && <p className="form-success" role="status">Alteração concluída.</p>}{params.error && <p className="form-error" role="alert">A ação não foi concluída. Tente novamente.</p>}
    <CredentialSetup
      csrf={csrf}
      activeCredential={credential?.status === "ACTIVE" ? {
        keyVersion: credential.keyVersion,
        updatedAt: formatDateTime(credential.updatedAt)
      } : undefined}
    />
    <ElevationControls csrf={csrf} credentialReady={credential?.status === "ACTIVE"} active={activeElevations.map((item) => ({ ...item, expiresAt: item.expiresAt.toISOString() }))} />
    <section className="surface"><h2>Recuperação de contas ({recoveryRequests.length})</h2><p className="muted">Pedidos expirados, não verificados ou da sua própria conta não aparecem aqui. Aprovar envia uma autorização de troca de senha ao titular; a aprovação exige elevação ativa.</p>
      {recoveryRequests.length === 0 ? <p className="muted">Nenhum pedido pendente.</p> : <div className="row-list">{recoveryRequests.map((request) => <article className="list-row" key={request.id}><div className="row-main"><strong>{request.user.displayName || request.user.emailNormalized}</strong><span>{request.user.role === "ADMIN" ? "Administrador" : "Usuário"} · {request.user.emailNormalized} · E-mail confirmado · expira {formatDateTime(request.expiresAt)}</span></div><form action={approveRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="requestId" value={request.id} /><button className="button-primary" type="submit">Aprovar recuperação</button></form></article>)}</div>}
    </section>
    <section className="surface"><h2>Sessões deste admin</h2><p>{activeSessions} sessão(ões) ativa(s), incluindo a sessão atual.</p></section>
  </main>;
}
