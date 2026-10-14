"use client";

import { useActionState } from "react";
import { verifyRecoveryAction, type RecoveryVerificationActionState } from "./actions";

const initialState: RecoveryVerificationActionState = { status: "idle" };

export function RecoveryVerificationForm({ csrf, csrfFieldName, requestId }: { csrf: string; csrfFieldName: string; requestId: string }) {
  const [state, action, pending] = useActionState(verifyRecoveryAction, initialState);

  if (state.status === "verified") {
    return <p role="status">E-mail confirmado. Um administrador analisará a solicitação. Após a aprovação, você receberá um novo e-mail com um link para definir a senha; abra esse novo link, pois esta página não será atualizada.</p>;
  }

  return <form className="form-stack" action={action}>
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <input type="hidden" name="requestId" value={requestId} />
    {state.status === "error" && <p className="form-error" role="alert">Não foi possível validar o código. Confira o código enviado ou solicite novas instruções.</p>}
    <label>Código de verificação<input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" maxLength={6} required /></label>
    <button className="button-primary" type="submit" disabled={pending}>{pending ? "Verificando…" : "Verificar e-mail"}</button>
  </form>;
}
