"use client";

import { useActionState, useEffect, useState } from "react";
import { createProjectConnectionAction, type ConnectionActionState } from "../actions";

const initialState: ConnectionActionState = { status: "idle" };

export function ConnectionForm({ csrf }: { csrf: string }) {
  const [state, action, pending] = useActionState(createProjectConnectionAction, initialState);
  const [copied, setCopied] = useState(false);
  useEffect(() => { setCopied(false); }, [state.secret]);
  return <form action={action} className="form-stack">
    <input type="hidden" name="csrfToken" value={csrf} />
    <label>Nome<input name="name" required maxLength={80} /></label>
    <label>Identificador (slug)<input name="slug" required maxLength={48} pattern="[a-z0-9]+(?:-[a-z0-9]+)*" /></label>
    <label>Origem HTTPS<input name="origin" type="url" required placeholder="https://project.example.invalid" /></label>
    <label>Redirect URIs exatas<textarea name="redirectUris" required placeholder="https://project.example.invalid/oidc/callback" /></label>
    <p className="muted">Uma URI por linha. Apenas HTTPS em domínio público; curingas e origens embutidas são recusados.</p>
    {state.status === "error" && <p className="form-error" role="alert">A conexão não foi criada. Revise os campos e a elevação de segurança.</p>}
    {state.secret && <section className="surface form-success" aria-live="polite"><h2>Credenciais exibidas uma vez</h2><p>Guarde-as no cofre de segredos do projeto agora. Esta tela não as recupera depois.</p><p><strong>Client ID</strong><br /><code>{state.clientId}</code></p><p><strong>Client secret</strong><br /><code>{state.secret}</code></p><button type="button" onClick={async () => { await navigator.clipboard.writeText(`${state.clientId}\n${state.secret}`); setCopied(true); }}>{copied ? "Copiado" : "Copiar credenciais"}</button></section>}
    <button className="button-primary" type="submit" disabled={pending}>{pending ? "Criando…" : "Registrar conexão"}</button>
  </form>;
}
