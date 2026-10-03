import { getAdministrativeCredentialState, listActiveSecurityElevations } from "@bielos/auth/administration";
import { listPendingAccountRecoveries } from "@bielos/auth/security";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { getCurrentSession } from "../../../lib/auth";
import { approveRecoveryAction } from "../../recover/actions";
import { CredentialSetup, ElevationControls } from "./security-controls";

export const dynamic = "force-dynamic";

export default async function SecurityPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  const [params, session] = await Promise.all([searchParams, getCurrentSession()]);
  if (!session) return null;
  const [credential, activeElevations, recoveryRequests, csrf, activeSessions] = await Promise.all([
    getAdministrativeCredentialState(session.user.id),
    listActiveSecurityElevations(session.user, session.id),
    listPendingAccountRecoveries(session.user),
    Promise.resolve(createCsrfToken()),
    prisma.session.count({ where: { userId: session.user.id, revokedAt: null, expiresAt: { gt: new Date() } } })
  ]);
  return <main className="admin-main">
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Segurança</h1><p>Credencial separada, elevação por sessão e recuperação administrativa.</p></div></header>
    {params.status && <p className="form-success" role="status">Alteração concluída.</p>}{params.error && <p className="form-error" role="alert">A ação não foi concluída. Tente novamente.</p>}
    {credential?.status === "ACTIVE" ? <section className="surface"><h2>Credencial administrativa</h2><p>Ativa · versão {credential.keyVersion} · atualizada em {credential.updatedAt.toLocaleString("pt-BR")}</p><p><a href="/account/security">Gerenciar MFA, códigos de recuperação e sessões da conta</a></p></section> : <CredentialSetup csrf={csrf} />}
    <ElevationControls csrf={csrf} credentialReady={credential?.status === "ACTIVE"} active={activeElevations.map((item) => ({ ...item, expiresAt: item.expiresAt.toISOString() }))} />
    <section className="surface"><h2>Recuperação de contas ({recoveryRequests.length})</h2><p className="muted">Pedidos expirados ou não verificados não aparecem aqui. Aprovar envia uma autorização de troca de senha ao titular.</p>
      {recoveryRequests.length === 0 ? <p className="muted">Nenhum pedido pendente.</p> : <div className="row-list">{recoveryRequests.map((request) => <article className="list-row" key={request.id}><div className="row-main"><strong>{request.user.displayName || request.user.emailNormalized}</strong><span>{request.user.emailNormalized} · E-mail confirmado · expira {request.expiresAt.toLocaleString("pt-BR")}</span></div><form action={approveRecoveryAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="requestId" value={request.id} /><button className="button-primary" type="submit">Aprovar recuperação</button></form></article>)}</div>}
    </section>
    <section className="surface"><h2>Sessões deste admin</h2><p>{activeSessions} sessão(ões) ativa(s), incluindo a sessão atual.</p></section>
  </main>;
}
