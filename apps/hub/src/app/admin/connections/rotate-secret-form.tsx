"use client";

import { useEffect, useState } from "react";
import { useSensitiveFormAction } from "../../../lib/use-sensitive-form-action";
import { rotateProjectClientSecretAction, type ConnectionActionState } from "../actions";

const initialState: ConnectionActionState = { status: "idle" };

export function RotateSecretForm({ csrf, connectionId }: { csrf: string; connectionId: string }) {
  const [state, action, pending] = useSensitiveFormAction(rotateProjectClientSecretAction, initialState);
  const [copied, setCopied] = useState(false);
  useEffect(() => { setCopied(false); }, [state.secret]);
  return <div><form action={action}><input type="hidden" name="csrfToken" value={csrf} /><input type="hidden" name="connectionId" value={connectionId} /><button type="submit" disabled={pending}>{pending ? "Rotacionando…" : "Rotacionar secret"}</button></form>
    {state.status === "error" && <p className="form-error" role="alert">Não foi possível rotacionar o secret.</p>}
    {state.secret && <section className="surface form-success" aria-live="polite" data-sensitive-one-time-value="true"><p>Client secret novo — copie agora e atualize o projeto:</p><code>{state.secret}</code><button type="button" onClick={async () => { await navigator.clipboard.writeText(state.secret ?? ""); setCopied(true); }}>{copied ? "Copiado" : "Copiar"}</button></section>}
  </div>;
}
