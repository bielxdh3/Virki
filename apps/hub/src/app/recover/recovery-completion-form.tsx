"use client";

import { useActionState, useEffect } from "react";
import { completeRecoveryAction, type RecoveryCompletionActionState } from "./actions";

const initialState: RecoveryCompletionActionState = { status: "idle" };

export function RecoveryCompletionForm({ csrf, csrfFieldName, requestId, expectedRole, purpose }: {
  csrf: string;
  csrfFieldName: string;
  requestId: string;
  expectedRole: "ADMIN" | "USER";
  purpose: "INVITATION" | "RECOVERY";
}) {
  const [state, action, pending] = useActionState(completeRecoveryAction, initialState);
  useEffect(() => {
    if (state.status === "completed") {
      // Full document navigation ensures Access and the newly issued session
      // are checked together instead of reusing a stale Server Action RSC render.
      window.location.replace(expectedRole === "ADMIN" ? "/admin/accounts" : "/account/security?recovered=password");
    }
  }, [expectedRole, state.status]);
  const passwordError = purpose === "INVITATION"
    ? "Escolha uma senha de pelo menos 12 caracteres, sem caracteres de controle."
    : expectedRole === "ADMIN"
      ? "A senha administrativa deve ter pelo menos 16 caracteres, sem caracteres de controle."
      : "A senha deve ter pelo menos 12 caracteres, sem caracteres de controle.";

  return <form className="form-stack" action={action}>
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <input type="hidden" name="requestId" value={requestId} />
    {state.status === "password-error" ? <p className="form-error" role="alert">{passwordError}</p> : null}
    {state.status === "completed" ? <p role="status">Recuperação concluída. Abrindo sua conta…</p> : null}
    <label>{purpose === "INVITATION" ? "Criar senha" : "Nova senha"}<input type="password" name="newPassword" minLength={expectedRole === "ADMIN" ? 16 : 12} maxLength={256} pattern="[^\u0000-\u001f\u007f-\u009f]{12,256}" autoComplete="new-password" required /></label>
    <button className="button-primary" type="submit" disabled={pending || state.status === "completed"}>{pending ? "Salvando…" : purpose === "INVITATION" ? "Ativar conta" : "Concluir recuperação"}</button>
  </form>;
}
