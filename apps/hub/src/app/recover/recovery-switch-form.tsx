"use client";

import { useActionState, useEffect, useState } from "react";
import { switchRecoveryAction, type RecoverySwitchActionState } from "./actions";

const initialState: RecoverySwitchActionState = { status: "idle" };

export function RecoverySwitchForm({ csrf, csrfFieldName, requestId }: { csrf: string; csrfFieldName: string; requestId: string }) {
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => { setHydrated(true); }, []);
  const [state, action, pending] = useActionState(async (previous: RecoverySwitchActionState, formData: FormData): Promise<RecoverySwitchActionState> => {
    // A delayed modern start may still set its bearer cookies after this
    // explicit legacy adoption. Hold the same per-origin browser lock across
    // the entire Server Action response, including its Set-Cookie processing.
    if (!navigator.locks?.request) return { status: "error" };
    try {
      return await navigator.locks.request("virki-recovery-start-v1", async () => {
        const result = await switchRecoveryAction(previous, formData);
        if (result.status === "complete" && result.requestId) {
          // The Server Action can refresh the RSC tree and unmount this form
          // before a state-driven effect runs. Navigate from the still-running
          // action callback, after its response has installed Set-Cookie and
          // while the shared recovery lock still serializes browser writers.
          window.location.replace(`/recover?requestId=${encodeURIComponent(result.requestId)}`);
        }
        return result;
      });
    } catch {
      // If the lock cannot be acquired, leave the existing bearer untouched.
      return { status: "error" };
    }
  }, initialState);

  return <form className="form-stack" action={action}>
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <input type="hidden" name="requestId" value={requestId} />
    {state.status === "error" ? <p className="form-error" role="alert">Não foi possível usar este link. Abra o link mais recente enviado por e-mail ou solicite novas instruções.</p> : null}
    <button className="button-primary" type="submit" disabled={!hydrated || pending}>{pending ? "Trocando link…" : "Continuar com este link"}</button>
  </form>;
}
