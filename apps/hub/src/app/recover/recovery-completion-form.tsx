"use client";

import { useEffect, useRef, useState } from "react";
import { completeRecoveryAction, type RecoveryCompletionActionState } from "./actions";

const initialState: RecoveryCompletionActionState = { status: "idle" };
type RecoveryCompletionFormState = RecoveryCompletionActionState | { status: "browser-error" };

export function RecoveryCompletionForm({ csrf, csrfFieldName, requestId, expectedRole, purpose }: {
  csrf: string;
  csrfFieldName: string;
  requestId: string;
  expectedRole: "ADMIN" | "USER";
  purpose: "INVITATION" | "RECOVERY";
}) {
  const [state, setState] = useState<RecoveryCompletionFormState>(initialState);
  const [pending, setPending] = useState(false);
  const submitting = useRef(false);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => { setHydrated(true); }, []);
  const action = async (formData: FormData) => {
    if (submitting.current) return;
    submitting.current = true;
    setPending(true);
    try {
      if (!navigator.locks?.request) {
        setState({ status: "browser-error" });
        return;
      }
      await navigator.locks.request("virki-recovery-start-v1", async () => {
        // Completion clears the same cookies that start/switch write. Hold the
        // shared cross-tab lock until this response's Set-Cookie is processed,
        // so a delayed completion cannot erase a newer recovery pair.
        const result = await completeRecoveryAction(initialState, formData);
        if (result.status === "completed") {
          // Navigate from this pending action continuation after the response
          // has installed the session cookie and cleared recovery cookies.
          setState(result);
          window.location.replace(expectedRole === "ADMIN" ? "/admin/accounts" : "/account/security?recovered=password");
          return;
        }
        setState(result);
      });
    } finally {
      submitting.current = false;
      setPending(false);
    }
  };
  const passwordError = purpose === "INVITATION"
    ? "Escolha uma senha de pelo menos 12 caracteres, sem caracteres de controle."
    : expectedRole === "ADMIN"
      ? "A senha administrativa deve ter pelo menos 16 caracteres, sem caracteres de controle."
      : "A senha deve ter pelo menos 12 caracteres, sem caracteres de controle.";

  return <form className="form-stack" action={action}>
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <input type="hidden" name="requestId" value={requestId} />
    {state.status === "password-error" ? <p className="form-error" role="alert">{passwordError}</p> : null}
    {state.status === "browser-error" ? <p className="form-error" role="alert">Não foi possível concluir a recuperação neste navegador. Use uma versão atualizada com acesso seguro (HTTPS).</p> : null}
    {state.status === "completed" ? <p role="status">Recuperação concluída. Abrindo sua conta…</p> : null}
    <label>{purpose === "INVITATION" ? "Criar senha" : "Nova senha"}<input type="password" name="newPassword" minLength={expectedRole === "ADMIN" ? 16 : 12} maxLength={256} pattern="[^\u0000-\u001f\u007f-\u009f]{12,256}" autoComplete="new-password" required /></label>
    <button className="button-primary" type="submit" disabled={!hydrated || pending || state.status === "completed"}>{pending ? "Salvando…" : purpose === "INVITATION" ? "Ativar conta" : "Concluir recuperação"}</button>
  </form>;
}
