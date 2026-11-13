"use client";

import { useActionState, useEffect } from "react";
import { switchRecoveryAction, type RecoverySwitchActionState } from "./actions";

const initialState: RecoverySwitchActionState = { status: "idle" };

export function RecoverySwitchForm({ csrf, csrfFieldName, requestId }: { csrf: string; csrfFieldName: string; requestId: string }) {
  const [state, action, pending] = useActionState(async (previous: RecoverySwitchActionState, formData: FormData): Promise<RecoverySwitchActionState> => {
    // A delayed modern start may still set its bearer cookies after this
    // explicit legacy adoption. Hold the same per-origin browser lock across
    // the entire Server Action response, including its Set-Cookie processing.
    if (!navigator.locks?.request) return { status: "error" };
    try {
      return await navigator.locks.request("virki-recovery-start-v1", () => switchRecoveryAction(previous, formData));
    } catch {
      // If the lock cannot be acquired, leave the existing bearer untouched.
      return { status: "error" };
    }
  }, initialState);

  useEffect(() => {
    if (state.status === "complete" && state.requestId) {
      window.location.replace(`/recover?requestId=${encodeURIComponent(state.requestId)}`);
    }
  }, [state]);

  return <form className="form-stack" action={action}>
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <input type="hidden" name="requestId" value={requestId} />
    {state.status === "error" ? <p className="form-error" role="alert">Não foi possível usar este link. Abra o link mais recente enviado por e-mail ou solicite novas instruções.</p> : null}
    <button className="button-primary" type="submit" disabled={pending}>{pending ? "Trocando link…" : "Continuar com este link"}</button>
  </form>;
}
