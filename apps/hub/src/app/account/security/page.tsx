import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getAccountSecurityData, revokeAccountSessionAction, revokeTrustedDeviceAction } from "./actions";
import { TotpControls } from "./security-controls";
import { getSurface } from "../../../lib/surface";

export const dynamic = "force-dynamic";

export default async function AccountSecurityPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string; recovered?: string }> }) {
  const [data, params, requestHeaders] = await Promise.all([getAccountSecurityData(), searchParams, headers()]);
  if (!data) redirect("/login");
  const surface = getSurface(requestHeaders);
  if ((surface === "hub" && data.session.user.role !== "ADMIN") || (surface === "portal" && data.session.user.role !== "USER")) redirect("/");
  const csrf = createCsrfToken({ scope: "account-security" });
  const totpPending = data.state?.totpStatus === "PENDING";
  return <main className="admin-main">
    <a className="text-link" href={data.session.user.role === "ADMIN" ? "/admin/security" : "/"}>← Voltar</a>
    <header className="page-header"><div><p className="eyebrow">Minha conta</p><h1>Segurança</h1><p>{data.session.user.displayName || data.session.user.email}</p></div></header>
    {params.status && <p className="form-success" role="status">Alteração concluída.</p>}{params.error && <p className="form-error" role="alert">A ação não foi concluída. Confira o código e tente novamente.</p>}
    {params.recovered === "totp" ? <p className="form-success" role="status">O autenticador anterior foi revogado. Configure o TOTP novamente e guarde os novos códigos de recuperação.</p> : null}
    {data.state && !data.state.emailVerified ? <section className="surface"><h2>Confirme seu e-mail</h2><p>O endereço ainda não foi confirmado. Encerre esta sessão e entre novamente para receber um código de verificação.</p><form action="/api/logout" method="post"><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><button type="submit">Sair e verificar e-mail</button></form></section> : null}
    <TotpControls csrf={csrf} active={data.state?.totpStatus === "ACTIVE"} pending={totpPending} />
    <section className="surface"><h2>Dispositivos lembrados ({data.devices.length})</h2><p className="muted">Revogar um dispositivo remove sua autorização para pular verificações de login.</p>{data.devices.length === 0 ? <p className="muted">Nenhum dispositivo lembrado.</p> : <div className="row-list">{data.devices.map((device) => <article className="list-row" key={device.deviceKey}><div className="row-main"><strong>{device.label || "Dispositivo sem nome"}</strong><span>Último uso {device.lastSeenAt.toLocaleString("pt-BR")}</span></div><form action={revokeTrustedDeviceAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="deviceKey" value={device.deviceKey} /><button type="submit">Revogar</button></form></article>)}</div>}</section>
    <section className="surface"><h2>Sessões ativas ({data.sessions.length})</h2><div className="row-list">{data.sessions.map((item) => <article className="list-row" key={item.id}><div className="row-main"><strong>{item.id === data.session.id ? "Esta sessão" : "Outra sessão"}</strong><span>Criada {item.createdAt.toLocaleString("pt-BR")} · expira {item.expiresAt.toLocaleString("pt-BR")}</span></div>{item.id !== data.session.id && <form action={revokeAccountSessionAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="sessionId" value={item.id} /><button className="button-danger" type="submit">Encerrar</button></form>}</article>)}</div></section>
  </main>;
}
