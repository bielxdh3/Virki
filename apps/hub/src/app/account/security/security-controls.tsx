"use client";

import { useSensitiveFormAction } from "../../../lib/use-sensitive-form-action";
import { confirmTotpAction, disableTotpAction, regenerateRecoveryCodesAction, revokeOtherAccountSessionsAction, startTotpAction, type AccountSecurityState } from "./actions";
import { confirmRecoveryEmailRebindAction, startRecoveryEmailRebindAction, type RecoveryEmailRebindState } from "./actions";

const initial: AccountSecurityState = { status: "idle" };

const initialRebind: RecoveryEmailRebindState = { status: "idle" };

export function RecoveryEmailRebindControl({ csrf, oldEmail }: { csrf: string; oldEmail: string }) {
  const [started, startAction, starting] = useSensitiveFormAction(startRecoveryEmailRebindAction, initialRebind);
  const [verified, verifyAction, verifying] = useSensitiveFormAction(confirmRecoveryEmailRebindAction, initialRebind);
  return <section className="surface" aria-labelledby="recovery-email-rebind-title">
    <h2 id="recovery-email-rebind-title">Recuperar acesso ao e-mail da conta</h2>
    <p>Seu acesso foi recuperado. Se perdeu a caixa <strong>{oldEmail}</strong>, confirme um novo endereço agora. Esta opção expira 20 minutos após a recuperação. O código será enviado somente para o e-mail novo.</p>
    <form action={startAction} className="form-stack">
      <input type="hidden" name="csrfToken" value={csrf} />
      <label>Novo endereço de e-mail<input name="newEmail" type="email" autoComplete="email" maxLength={254} required /></label>
      <button type="submit" disabled={starting}>{starting ? "Enviando…" : "Enviar código ao novo endereço"}</button>
      {started.status === "started" && <p className="form-success" role="status">Se o endereço estiver disponível e o envio configurado, o código foi solicitado.</p>}
      {started.status === "error" && <p className="form-error" role="alert">Não foi possível solicitar o código. Confira o e-mail e tente novamente.</p>}
    </form>
    <form action={verifyAction} className="form-stack">
      <input type="hidden" name="csrfToken" value={csrf} />
      <label>Código recebido no novo e-mail<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} pattern="[0-9]{6}" required /></label>
      <button type="submit" disabled={verifying}>{verifying ? "Confirmando…" : "Confirmar novo e-mail"}</button>
      {verified.status === "error" && <p className="form-error" role="alert">Código inválido, expirado ou sessão encerrada.</p>}
    </form>
    <p className="muted">Após confirmar, você será desconectado. Use o novo endereço e a senha recuperada para entrar.</p>
  </section>;
}

export function TotpControls({ csrf, active, pending }: { csrf: string; active: boolean; pending: boolean }) {
  const [enrollment, startAction, starting] = useSensitiveFormAction(startTotpAction, initial);
  const [confirmation, confirmAction, confirming] = useSensitiveFormAction(confirmTotpAction, initial);
  const [regenerated, regenerateAction, regenerating] = useSensitiveFormAction(regenerateRecoveryCodesAction, initial);
  return <section className="surface"><h2>Autenticação multifator</h2><p>{active ? "Aplicativo autenticador (TOTP) ativo." : pending ? "Existe uma configuração TOTP pendente." : "TOTP não está ativo. A verificação por e-mail continua disponível."}</p>
    {pending && !active && !enrollment.secret && <p role="status">A chave pendente não pode ser recuperada após recarregar esta página. Confirme sua senha para gerar uma nova chave; a anterior será invalidada.</p>}
    {!active && !enrollment.secret && <form action={startAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Senha atual<input name="password" type="password" autoComplete="current-password" maxLength={256} required /></label><button type="submit" disabled={starting}>{starting ? "Iniciando…" : pending ? "Reiniciar configuração do autenticador" : "Configurar aplicativo autenticador"}</button>{enrollment.status === "error" && <p className="form-error" role="alert">Não foi possível iniciar. A configuração não substitui um TOTP ativo.</p>}</form>}
    {enrollment.secret && confirmation.status !== "complete" && <form action={confirmAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><p>Adicione esta chave no aplicativo autenticador:</p><p><code data-sensitive-one-time-value="true">{enrollment.secret}</code></p><label>Código atual do aplicativo<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit" disabled={confirming}>{confirming ? "Confirmando…" : "Ativar TOTP"}</button>{confirmation.status === "error" && <p className="form-error" role="alert">Código inválido ou configuração expirada.</p>}</form>}
    {confirmation.status === "complete" && confirmation.recoveryCodes && <RecoveryCodes codes={confirmation.recoveryCodes} />}
    {active && <><form action={regenerateAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Confirme com TOTP para substituir códigos de recuperação<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button type="submit" disabled={regenerating}>{regenerating ? "Gerando…" : "Gerar novos códigos"}</button>{regenerated.status === "error" && <p className="form-error" role="alert">Código inválido ou já usado. Tente com o código atual.</p>}{regenerated.recoveryCodes && <RecoveryCodes codes={regenerated.recoveryCodes} />}</form><form action={disableTotpAction} className="form-stack"><input type="hidden" name="csrfToken" value={csrf} /><label>Confirme com TOTP para desativar e encerrar todas as sessões<input name="code" inputMode="numeric" autoComplete="one-time-code" minLength={6} maxLength={6} required /></label><button className="button-danger" type="submit">Desativar TOTP</button></form></>}
  </section>;
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  return <section className="surface form-success" aria-live="polite" data-sensitive-one-time-value="true"><h3>Códigos de recuperação — exibidos uma vez</h3><p>Guarde-os fora deste dispositivo. Os códigos anteriores foram invalidados.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></section>;
}

export function SessionRevocationControl({ csrf, otherSessionCount, role }: { csrf: string; otherSessionCount: number; role: string }) {
  if (role !== "USER") return null;
  if (otherSessionCount === 0) return <p className="muted">Nenhuma outra sessão ativa.</p>;
  return <details className="form-stack">
    <summary>Encerrar todas as outras sessões</summary>
    <p>Isso encerrará {otherSessionCount === 1 ? "a outra sessão ativa" : `as ${otherSessionCount} outras sessões ativas`} no Virki. Esta sessão continuará ativa.</p>
    <form action={revokeOtherAccountSessionsAction} className="form-stack">
      <input type="hidden" name="csrfToken" value={csrf} />
      <label>Confirme sua senha atual<input name="password" type="password" autoComplete="current-password" maxLength={256} required /></label>
      <label><span><input name="confirmed" type="checkbox" value="yes" required /> Confirmo que desejo encerrar as outras sessões</span></label>
      <button className="button-danger" type="submit">Confirmar encerramento</button>
    </form>
  </details>;
}
