"use client";

import { useActionState, useEffect } from "react";
import {
  startRecoveryNewMailboxAction, verifyRecoveryNewMailboxAction,
  type RecoveryNewMailboxActionState
} from "./actions";

const initial: RecoveryNewMailboxActionState = { status: "idle" };

export function RecoveryNewMailStage({ requestId, csrf, csrfFieldName, challengeSent }: {
  requestId: string; csrf: string; csrfFieldName: string; challengeSent: boolean;
}) {
  const [startState, startAction, starting] = useActionState(startRecoveryNewMailboxAction, initial);
  const [verifyState, verifyAction, verifying] = useActionState(verifyRecoveryNewMailboxAction, initial);
  useEffect(() => {
    if (startState.status === "sent" || verifyState.status === "verified") window.location.reload();
  }, [startState.status, verifyState.status]);
  return <section className="form-stack" aria-label="Verificação do novo e-mail">
    <h2>Confirme um novo e-mail antes de trocar a senha</h2>
    <p>Seus fatores atuais continuam ativos até que o novo endereço receba e confirme um código. Use um e-mail ao qual você tenha acesso. O endereço antigo não receberá o código.</p>
    <form className="form-stack" action={startAction}>
      <input type="hidden" name={csrfFieldName} value={csrf} />
      <input type="hidden" name="requestId" value={requestId} />
      <label>Novo endereço de e-mail<input type="email" name="newEmail" maxLength={254} autoComplete="email" required disabled={starting} /></label>
      {startState.status === "error" ? <p role="alert" className="form-error">Não foi possível enviar o código. Confira o endereço e tente novamente.</p> : null}
      <button className="button-primary" type="submit" disabled={starting}>{starting ? "Enviando…" : challengeSent ? "Trocar endereço ou reenviar código" : "Enviar código ao novo e-mail"}</button>
    </form>
    {challengeSent ? <form className="form-stack" action={verifyAction}>
      <input type="hidden" name={csrfFieldName} value={csrf} />
      <input type="hidden" name="requestId" value={requestId} />
      <label>Código recebido no novo e-mail<input type="text" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required disabled={verifying} /></label>
      {verifyState.status === "error" ? <p role="alert" className="form-error">Código inválido ou expirado. Confirme o código mais recente.</p> : null}
      <button className="button-primary" type="submit" disabled={verifying}>{verifying ? "Verificando…" : "Confirmar novo e-mail"}</button>
    </form> : null}
  </section>;
}
