"use client";

import { formatDateTime } from "@virki/auth/date-time";

import { useActionState, useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import type { ElevationScope } from "@virki/auth/administration";
import { changeAdminPasswordAction, completeCredentialSetupAction, recoverAdminCredentialAction, regenerateAdminRecoveryCodesAction, startCredentialSetupAction, startElevationAction, verifyElevationAction, revokeElevationAction, revokeOtherSessionsAction, type SecurityFormState } from "./actions";

const initialState: SecurityFormState = { status: "idle" };
const passwordReuseMessage = "A senha administrativa precisa ser diferente da senha de login.";
const elevationPasswordReuseMessage = "A senha administrativa precisa ser diferente da senha de login. Altere a senha administrativa para continuar.";
const scopes: Array<[ElevationScope, string]> = [
  ["ACCOUNT_STATE_CHANGE", "Alterar contas"],
  ["PROJECT_ACCESS_CHANGE", "Alterar acessos"],
  ["PROJECT_CONNECTION_MANAGE", "Gerenciar conexões"],
  ["ADMIN_CREDENTIAL_CHANGE", "Alterar credencial administrativa"],
  ["ADMIN_RECOVERY_REGENERATE", "Gerar códigos de recuperação"]
];

export function CredentialSetup({ csrf, activeCredential }: { csrf: string; activeCredential?: { keyVersion: number; updatedAt: string } }) {
  const [start, startAction, starting] = useActionState(startCredentialSetupAction, initialState);
  const [complete, completeAction, completing] = useActionState(completeCredentialSetupAction, initialState);
  const [recovery, recoveryAction, recovering] = useActionState(recoverAdminCredentialAction, initialState);
  const [recoveryCodesAcknowledged, setRecoveryCodesAcknowledged] = useState(false);
  const acknowledgingRecoveryCodes = useRef(false);
  const showRecoveryCodes = Boolean(complete.recoveryCodes && !recoveryCodesAcknowledged);
  return (
    <section className="surface">
      <h2>Credencial administrativa</h2>
      <p>{activeCredential ? "Credencial administrativa separada configurada. Gerencie-a com elevação de segurança." : "Configure uma senha administrativa separada e guarde os códigos de recuperação fora deste dispositivo."}</p>
      {showRecoveryCodes && complete.recoveryCodes ? (
        <>
          <RecoveryCodes codes={complete.recoveryCodes} />
          <a
            className="button-secondary"
            href="/admin/security?status=credential#admin-content"
            onClick={(event) => {
              event.preventDefault();
              if (acknowledgingRecoveryCodes.current) return;
              acknowledgingRecoveryCodes.current = true;
              const destination = event.currentTarget.href;
              // Commit dismissal before the outgoing document can enter the browser's back/forward cache.
              flushSync(() => setRecoveryCodesAcknowledged(true));
              window.location.replace(destination);
            }}
          >
            Continuar para elevação
          </a>
        </>
      ) : activeCredential ? (
        <>
          <p>Ativa · versão {activeCredential.keyVersion} · atualizada em {activeCredential.updatedAt}</p>
          <p><a href="/account/security">Gerenciar MFA, códigos de recuperação e sessões da conta</a></p>
          <h3>Recuperar credencial administrativa</h3>
          <p>Use sua senha normal e um código administrativo de uso único. A recuperação revoga elevações ativas e emite novos códigos.</p>
          {recovery.recoveryCodes ? (
            <OneTimeRecoveryCodes
              codes={recovery.recoveryCodes}
              destination="/admin/security?status=recovered#admin-content"
              label="Já guardei os novos códigos"
            />
          ) : (
            <form action={recoveryAction} className="form-stack">
              <input type="hidden" name="csrfToken" value={csrf} />
              <label>Senha normal atual<input name="normalPassword" type="password" autoComplete="current-password" required /></label>
              <label>Código de recuperação administrativa<input name="recoveryCode" autoComplete="one-time-code" maxLength={32} required /></label>
              <label>Nova senha administrativa (16 caracteres ou mais)<input name="newPassword" type="password" autoComplete="new-password" minLength={16} maxLength={256} required /></label>
              <button type="submit" disabled={recovering}>{recovering ? "Recuperando…" : "Recuperar credencial"}</button>
              {recovery.status === "error" && <p className="form-error" role="alert">Não foi possível recuperar a credencial. Confira a senha e o código de uso único.</p>}
              {recovery.status === "password-reuse" && <p className="form-error" role="alert">{passwordReuseMessage}</p>}
            </form>
          )}
        </>
      ) : start.requestKey ? (
        <form action={completeAction} className="form-stack">
          <input type="hidden" name="csrfToken" value={csrf} />
          <input type="hidden" name="requestKey" value={start.requestKey} />
          <label>Código enviado por e-mail<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label>
          <label>Nova senha administrativa (16 caracteres ou mais)<input name="newPassword" type="password" autoComplete="new-password" minLength={16} maxLength={256} required /></label>
          <button type="submit" disabled={completing}>{completing ? "Configurando…" : "Configurar credencial"}</button>
          {complete.status === "error" && <p className="form-error" role="alert">Código inválido ou expirado. Inicie novamente.</p>}
          {complete.status === "password-reuse" && <p className="form-error" role="alert">{passwordReuseMessage}</p>}
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
  const [verificationState, verificationAction, verifying] = useActionState(verifyElevationAction, initialState);
  const [passwordState, passwordAction, passwordPending] = useActionState(changeAdminPasswordAction, initialState);
  const [recoveryState, recoveryAction, recoveryPending] = useActionState(regenerateAdminRecoveryCodesAction, initialState);
  useEffect(() => {
    if (verificationState.status === "complete") {
      window.location.replace("/admin/security?status=elevation#admin-content");
    }
  }, [verificationState.status]);
  return <section className="surface"><h2>Elevação temporária</h2><p>As ações sensíveis exigem senha normal, credencial administrativa e código de e-mail por sessão.</p>
    {!credentialReady ? <p className="muted">Configure a credencial administrativa primeiro.</p> : <form action={action} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Permissão<select name="scope" required>{scopes.map(([scope, label]) => <option value={scope} key={scope}>{label}</option>)}</select></label><label>Validade<select name="duration" defaultValue="60"><option value="15">15 minutos</option><option value="60">1 hora</option><option value="240">4 horas</option><option value="1440">24 horas</option><option value="manual">Até revogar (alto risco)</option></select></label><label>Senha normal atual<input name="normalPassword" type="password" autoComplete="current-password" required /></label><label>Senha administrativa<input name="administrativePassword" type="password" autoComplete="current-password" required /></label><label><span><input type="checkbox" name="manualConfirmed" value="true" /> Confirmo validade até revogação (obrigatório para essa opção)</span></label><button type="submit" disabled={pending}>{pending ? "Enviando…" : "Solicitar elevação"}</button>{state.status === "error" && <p className="form-error" role="alert">Não foi possível solicitar. Confira as credenciais e o tipo de elevação.</p>}{state.status === "password-reuse" && <p className="form-error" role="alert">{elevationPasswordReuseMessage}</p>}</form>}
    {state.requestKey && <form action={verificationAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><input type="hidden" name="requestKey" value={state.requestKey} /><p>Digite o código enviado por e-mail para ativar “{scopes.find(([scope]) => scope === state.scope)?.[1]}”.</p><label>Código<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit" disabled={verifying}>{verifying ? "Ativando…" : "Ativar elevação"}</button>{verificationState.status === "error" && <p className="form-error" role="alert">Código inválido ou expirado. Solicite uma nova elevação.</p>}</form>}
    <h3>Elevações ativas nesta sessão</h3>{active.length === 0 ? <p className="muted">Nenhuma elevação ativa.</p> : <div className="row-list">{active.map((item) => <article className="list-row" key={item.requestKey}><div className="row-main"><strong>{scopes.find(([scope]) => scope === item.scope)?.[1] ?? "Permissão"}</strong><span>{item.manualUntilRevoked ? "Até revogação" : `Expira ${formatDateTime(item.expiresAt)}`}</span></div><form action={revokeElevationAction}><input type="hidden" name="csrfToken" value={csrf} /><input type="hidden" name="requestKey" value={item.requestKey} /><button type="submit">Revogar</button></form></article>)}</div>}
    <form action={revokeOtherSessionsAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><button className="button-danger" type="submit">Revogar outras sessões deste admin</button></form>
    {credentialReady && <><h3>Recuperação da credencial</h3><form action={passwordAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Nova senha administrativa<input name="newPassword" type="password" autoComplete="new-password" minLength={16} maxLength={256} required /></label><button type="submit" disabled={passwordPending}>Alterar senha administrativa</button>{passwordState.status === "error" && <p className="form-error" role="alert">A alteração requer elevação ativa para essa ação.</p>}{passwordState.status === "password-reuse" && <p className="form-error" role="alert">{passwordReuseMessage}</p>}{passwordState.status === "complete" && <p className="form-success">Senha alterada. Elevações anteriores foram revogadas.</p>}</form><form action={recoveryAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><button type="submit" disabled={recoveryPending}>Gerar novos códigos de recuperação administrativa</button>{recoveryState.status === "error" && <p className="form-error" role="alert">A ação requer elevação ativa para códigos de recuperação.</p>}{recoveryState.recoveryCodes && (
  <OneTimeRecoveryCodes
    codes={recoveryState.recoveryCodes}
    destination="/admin/security?status=recovery-codes#admin-content"
    label="Já guardei os novos códigos"
  />
)}</form></>}
  </section>;
}

function OneTimeRecoveryCodes({ codes, destination, label }: { codes: string[]; destination: string; label: string }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const acknowledging = useRef(false);
  if (acknowledged) return null;
  return (
    <>
      <RecoveryCodes codes={codes} />
      <a
        className="button-secondary"
        href={destination}
        onClick={(event) => {
          event.preventDefault();
          if (acknowledging.current) return;
          acknowledging.current = true;
          const target = event.currentTarget.href;
          flushSync(() => setAcknowledged(true));
          window.location.replace(target);
        }}
      >
        {label}
      </a>
    </>
  );
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  return <section className="surface form-success" aria-live="polite"><h3>Códigos de recuperação — exibidos uma vez</h3><p>Guarde-os em local seguro. A página não poderá recuperá-los.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></section>;
}
