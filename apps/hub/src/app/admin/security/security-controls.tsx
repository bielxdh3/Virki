"use client";

import { useActionState } from "react";
import { useRouter } from "next/navigation";
import type { ElevationScope } from "@bielos/auth/administration";
import { changeAdminPasswordAction, completeCredentialSetupAction, regenerateAdminRecoveryCodesAction, startCredentialSetupAction, startElevationAction, verifyElevationAction, revokeElevationAction, revokeOtherSessionsAction, type SecurityFormState } from "./actions";

const initialState: SecurityFormState = { status: "idle" };
const scopes: Array<[ElevationScope, string]> = [
  ["ACCOUNT_STATE_CHANGE", "Alterar contas"],
  ["PROJECT_ACCESS_CHANGE", "Alterar acessos"],
  ["PROJECT_CONNECTION_MANAGE", "Gerenciar conexões"],
  ["ADMIN_CREDENTIAL_CHANGE", "Alterar credencial administrativa"],
  ["ADMIN_RECOVERY_REGENERATE", "Gerar códigos de recuperação"]
];

export function CredentialSetup({ csrf }: { csrf: string }) {
  const router = useRouter();
  const [start, startAction, starting] = useActionState(startCredentialSetupAction, initialState);
  const [complete, completeAction, completing] = useActionState(completeCredentialSetupAction, initialState);
  return (
    <section className="surface">
      <h2>Credencial administrativa</h2>
      <p>Configure uma senha administrativa separada e guarde os códigos de recuperação fora deste dispositivo.</p>
      {complete.recoveryCodes ? (
        <>
          <RecoveryCodes codes={complete.recoveryCodes} />
          <button type="button" onClick={() => router.refresh()}>Continuar para elevação</button>
        </>
      ) : start.requestKey ? (
        <form action={completeAction} className="form-stack">
          <input type="hidden" name="csrfToken" value={csrf} />
          <input type="hidden" name="requestKey" value={start.requestKey} />
          <label>Código enviado por e-mail<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label>
          <label>Nova senha administrativa (16 caracteres ou mais)<input name="newPassword" type="password" autoComplete="new-password" minLength={16} maxLength={256} required /></label>
          <button type="submit" disabled={completing}>{completing ? "Configurando…" : "Configurar credencial"}</button>
          {complete.status === "error" && <p className="form-error" role="alert">Código inválido ou expirado. Inicie novamente.</p>}
        </form>
      ) : (
        <form action={startAction} className="form-stack">
          <input type="hidden" name="csrfToken" value={csrf} />
          <label>Senha normal atual<input name="normalPassword" type="password" autoComplete="current-password" required /></label>
          <button type="submit" disabled={starting}>{starting ? "Enviando…" : "Enviar código de confirmação"}</button>
          {start.status === "error" && <p className="form-error" role="alert">Não foi possível iniciar a configuração. Confira o e-mail validado e tente novamente.</p>}
        </form>
      )}
    </section>
  );
}

export function ElevationControls({ csrf, credentialReady, active }: { csrf: string; credentialReady: boolean; active: Array<{ requestKey: string; scope: string; manualUntilRevoked: boolean; expiresAt: Date | string }> }) {
  const [state, action, pending] = useActionState(startElevationAction, initialState);
  const [passwordState, passwordAction, passwordPending] = useActionState(changeAdminPasswordAction, initialState);
  const [recoveryState, recoveryAction, recoveryPending] = useActionState(regenerateAdminRecoveryCodesAction, initialState);
  return <section className="surface"><h2>Elevação temporária</h2><p>As ações sensíveis exigem senha normal, credencial administrativa e código de e-mail por sessão.</p>
    {!credentialReady ? <p className="muted">Configure a credencial administrativa primeiro.</p> : <form action={action} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Permissão<select name="scope" required>{scopes.map(([scope, label]) => <option value={scope} key={scope}>{label}</option>)}</select></label><label>Validade<select name="duration" defaultValue="60"><option value="15">15 minutos</option><option value="60">1 hora</option><option value="240">4 horas</option><option value="1440">24 horas</option><option value="manual">Até revogar (alto risco)</option></select></label><label>Senha normal atual<input name="normalPassword" type="password" autoComplete="current-password" required /></label><label>Senha administrativa<input name="administrativePassword" type="password" autoComplete="current-password" required /></label><label><span><input type="checkbox" name="manualConfirmed" value="true" /> Confirmo validade até revogação (obrigatório para essa opção)</span></label><button type="submit" disabled={pending}>{pending ? "Enviando…" : "Solicitar elevação"}</button>{state.status === "error" && <p className="form-error" role="alert">Não foi possível solicitar. Confira as credenciais e o tipo de elevação.</p>}</form>}
    {state.requestKey && <form action={verifyElevationAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><input type="hidden" name="requestKey" value={state.requestKey} /><p>Digite o código enviado por e-mail para ativar “{scopes.find(([scope]) => scope === state.scope)?.[1]}”.</p><label>Código<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit">Ativar elevação</button></form>}
    <h3>Elevações ativas nesta sessão</h3>{active.length === 0 ? <p className="muted">Nenhuma elevação ativa.</p> : <div className="row-list">{active.map((item) => <article className="list-row" key={item.requestKey}><div className="row-main"><strong>{scopes.find(([scope]) => scope === item.scope)?.[1] ?? "Permissão"}</strong><span>{item.manualUntilRevoked ? "Até revogação" : `Expira ${new Date(item.expiresAt).toLocaleString("pt-BR")}`}</span></div><form action={revokeElevationAction}><input type="hidden" name="csrfToken" value={csrf} /><input type="hidden" name="requestKey" value={item.requestKey} /><button type="submit">Revogar</button></form></article>)}</div>}
    <form action={revokeOtherSessionsAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><button className="button-danger" type="submit">Revogar outras sessões deste admin</button></form>
    {credentialReady && <><h3>Recuperação da credencial</h3><form action={passwordAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Nova senha administrativa<input name="newPassword" type="password" autoComplete="new-password" minLength={16} maxLength={256} required /></label><button type="submit" disabled={passwordPending}>Alterar senha administrativa</button>{passwordState.status === "error" && <p className="form-error" role="alert">A alteração requer elevação ativa para essa ação.</p>}{passwordState.status === "complete" && <p className="form-success">Senha alterada. Elevações anteriores foram revogadas.</p>}</form><form action={recoveryAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><button type="submit" disabled={recoveryPending}>Gerar novos códigos de recuperação administrativa</button>{recoveryState.status === "error" && <p className="form-error" role="alert">A ação requer elevação ativa para códigos de recuperação.</p>}{recoveryState.recoveryCodes && <RecoveryCodes codes={recoveryState.recoveryCodes} />}</form></>}
  </section>;
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  return <section className="surface form-success" aria-live="polite"><h3>Códigos de recuperação — exibidos uma vez</h3><p>Guarde-os em local seguro. A página não poderá recuperá-los.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></section>;
}
