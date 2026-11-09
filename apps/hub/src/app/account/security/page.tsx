import { formatDateTime } from "@virki/auth/date-time";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { createSessionCsrfToken } from "../../../lib/session-csrf";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAccountSecurityData, revokeAccountSessionAction, revokeTrustedDeviceAction } from "./actions";
import { RecoveryEmailRebindControl, SessionRevocationControl, TotpControls } from "./security-controls";
import { isRecoveryEmailRebindSession } from "@virki/auth/recovery-email-rebind";
import { getSurface, safeReturnTo, requestHost } from "../../../lib/surface";
import { listUserPasskeys, passkeysEnabledForRequest } from "@virki/auth/passkeys";
import { PasskeyManager } from "./passkey-manager";
import { ProtectedPageLifecycle } from "../../protected-page-lifecycle";

export const dynamic = "force-dynamic";

export default async function AccountSecurityPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string; recovered?: string; returnTo?: string }> }) {
  const [data, params, requestHeaders] = await Promise.all([getAccountSecurityData(), searchParams, headers()]);
  if (!data) redirect("/login");
  const surface = getSurface(requestHeaders);
  if ((surface === "hub" && data.session.user.role !== "ADMIN") || (surface === "portal" && data.session.user.role !== "USER")) redirect("/");
  const recoveryContinueTo = safeReturnTo(params.returnTo, surface, data.session.user.role);
  const csrf = await createSessionCsrfToken("account-security");
  const passkeysEnabled = data.session.user.role === "USER" && passkeysEnabledForRequest(surface, requestHost(requestHeaders));
  const passkeys = passkeysEnabled ? await listUserPasskeys(data.session.user.id) : [];
  const logoutCsrf = await createSessionCsrfToken("logout");
  const totpPending = data.state?.totpStatus === "PENDING";
  return <>
    <ProtectedPageLifecycle />
    <main className="admin-main" data-protected-page-content>
    <a className="text-link" href={data.session.user.role === "ADMIN" ? "/admin/security" : "/"}>← Voltar</a>
    <header className="page-header"><div><p className="eyebrow">Minha conta</p><h1>Segurança</h1><p>{data.session.user.displayName || data.session.user.email}</p></div></header>
    {params.status === "sessions" ? <p className="form-success" role="status">Outras sessões encerradas. Esta sessão continua ativa.</p> : params.status === "no-sessions" ? <p className="form-success" role="status">Nenhuma outra sessão ativa foi encontrada. Esta sessão continua ativa.</p> : params.status ? <p className="form-success" role="status">Alteração concluída.</p> : null}
    {params.error && <p className="form-error" role="alert">{params.error === "sessions" ? "Não foi possível encerrar as outras sessões. Confira a senha e tente novamente." : "A ação não foi concluída. Confira o código e tente novamente."}</p>}
    {params.recovered === "totp" ? <section className="surface" aria-labelledby="totp-recovered-title"><h2 id="totp-recovered-title">Autenticador anterior revogado</h2><p className="form-success" role="status">Configure o TOTP novamente e guarde os novos códigos de recuperação.</p>{recoveryContinueTo ? <a className="button-primary" href={recoveryContinueTo}>Continuar para o acesso solicitado</a> : null}</section> : null}
    {isRecoveryEmailRebindSession(data.session) ? <RecoveryEmailRebindControl csrf={csrf} oldEmail={data.session.user.email} /> : null}
    {data.state && !data.state.emailVerified ? <section className="surface"><h2>Confirme seu e-mail</h2><p>O endereço ainda não foi confirmado. Encerre esta sessão e entre novamente para receber um código de verificação.</p><form action="/api/logout" method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={logoutCsrf} /><button type="submit">Sair e verificar e-mail</button></form></section> : null}
    <TotpControls csrf={csrf} active={data.state?.totpStatus === "ACTIVE"} pending={totpPending} />
    {passkeysEnabled ? <PasskeyManager csrfToken={csrf} requiresTotp={data.state?.totpStatus === "ACTIVE"} initialPasskeys={passkeys.map(({ createdAt, lastUsedAt, ...item }) => ({ ...item, createdAt: createdAt.toISOString(), lastUsedAt: lastUsedAt?.toISOString() ?? null }))} /> : null}
    <section className="surface"><h2>Dispositivos lembrados ({data.devices.length})</h2><p className="muted">Revogar um dispositivo remove sua autorização para pular verificações de login.</p>{data.devices.length === 0 ? <p className="muted">Nenhum dispositivo lembrado.</p> : <div className="row-list">{data.devices.map((device) => <article className="list-row" key={device.deviceKey}><div className="row-main"><strong>{device.label || "Dispositivo sem nome"}</strong><span>Último uso {formatDateTime(device.lastSeenAt)}</span></div><form action={revokeTrustedDeviceAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="deviceKey" value={device.deviceKey} /><button type="submit">Revogar</button></form></article>)}</div>}</section>
    <section className="surface"><h2>Sessões ativas ({data.otherSessionCount + 1})</h2><p className="muted">A lista mostra esta sessão e até 49 outras. Exibimos apenas criação e expiração; dispositivo, navegador e último acesso não são registrados para estas sessões.</p><SessionRevocationControl csrf={csrf} otherSessionCount={data.otherSessionCount} role={data.session.user.role} /><div className="row-list">{data.sessions.map((item) => <article className="list-row" key={item.id}><div className="row-main"><strong>{item.id === data.session.id ? "Esta sessão" : "Outra sessão"}</strong><span>Criada {formatDateTime(item.createdAt)} · expira {formatDateTime(item.expiresAt)}</span></div>{item.id !== data.session.id && <form action={revokeAccountSessionAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="sessionId" value={item.id} /><button className="button-danger" type="submit">Encerrar</button></form>}</article>)}</div></section>
    </main>
  </>;
}
