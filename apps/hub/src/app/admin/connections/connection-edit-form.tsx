"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import { updateProjectConnectionAction, type ConnectionEditActionState } from "../actions";

const initialState: ConnectionEditActionState = { status: "idle" };

type ConnectionEditValues = {
  id: string;
  name: string;
  slug: string;
  origin: string;
  launchUrl: string | null;
  redirectUris: string[];
  configurationRevision: string;
};

export function ConnectionEditForm({ csrf, csrfFieldName, connection }: { csrf: string; csrfFieldName: string; connection: ConnectionEditValues }) {
  const [state, action, pending] = useActionState(updateProjectConnectionAction, initialState);
  const reapplyButtonRef = useRef<HTMLButtonElement | null>(null);
  const saveButtonRef = useRef<HTMLButtonElement | null>(null);
  const [focusSaveAfterReapply, setFocusSaveAfterReapply] = useState(false);
  const [draft, setDraft] = useState(() => ({
    name: connection.name,
    slug: connection.slug,
    origin: connection.origin,
    launchUrl: connection.launchUrl ?? "",
    redirectUris: connection.redirectUris.join("\n"),
    expectedRevision: connection.configurationRevision,
  }));

  const conflictRevision = state.status === "conflict" ? state.latest.configurationRevision : null;
  const canReapplyDraft = state.status === "conflict" && draft.expectedRevision !== state.latest.configurationRevision;

  useEffect(() => {
    if (conflictRevision) reapplyButtonRef.current?.focus();
  }, [conflictRevision]);

  useEffect(() => {
    if (focusSaveAfterReapply && !canReapplyDraft) {
      saveButtonRef.current?.focus();
      setFocusSaveAfterReapply(false);
    }
  }, [canReapplyDraft, focusSaveAfterReapply]);

  return <details open={state.status === "error" || state.status === "invalid" || state.status === "conflict"}>
    <summary>Editar configuração</summary>
    <p className="muted">Alterar origem ou redirect URIs encerra fluxos OIDC pendentes. As concessões dos usuários permanecem.</p>
    <form action={action} className="form-stack">
      <input type="hidden" name={csrfFieldName} value={csrf} />
      <input type="hidden" name="connectionId" value={connection.id} />
      <input type="hidden" name="expectedRevision" value={draft.expectedRevision} />
      <label>Nome<input name="name" required maxLength={80} value={draft.name} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></label>
      <label>Identificador (slug)<input name="slug" required maxLength={48} pattern="[a-z0-9]+(?:-[a-z0-9]+)*" value={draft.slug} onChange={(event) => setDraft((current) => ({ ...current, slug: event.target.value }))} /></label>
      <label>Origem HTTPS<input name="origin" type="url" required value={draft.origin} onChange={(event) => setDraft((current) => ({ ...current, origin: event.target.value }))} /></label>
      <label>URL de entrada (opcional)<input name="launchUrl" type="url" value={draft.launchUrl} onChange={(event) => setDraft((current) => ({ ...current, launchUrl: event.target.value }))} /></label>
      <label>Redirect URIs exatas<textarea name="redirectUris" required value={draft.redirectUris} onChange={(event) => setDraft((current) => ({ ...current, redirectUris: event.target.value }))} /></label>
      {state.status === "invalid" && <p className="form-error" role="alert">Não foi possível salvar. Use uma origem HTTPS canônica, uma URL de entrada na mesma origem e de 1 a 10 redirect URIs HTTPS exatas, únicas e sem fragmentos; confira também o nome e o formato do slug. Seu rascunho foi mantido.</p>}
      {state.status === "error" && <p className="form-error" role="alert">Ocorreu um erro ao salvar a configuração. Confira os dados e tente novamente. Se persistir, consulte outro ADMIN. Seu rascunho foi mantido.</p>}
      {state.status === "conflict" && <>
        <p className="form-error" role="alert">Outro ADMIN alterou esta conexão. Seu rascunho continua aberto. Compare os valores atuais abaixo; confirme se quer reaplicar seu rascunho antes de salvar.</p>
        <section className="conflict-summary" aria-label="Configuração salva atualmente">
          <h3>Valores salvos atualmente</h3>
          <dl>
            <div><dt>Nome</dt><dd>{state.latest.name}</dd></div>
            <div><dt>Slug</dt><dd>{state.latest.slug}</dd></div>
            <div><dt>Origem</dt><dd><code>{state.latest.origin}</code></dd></div>
            <div><dt>URL de entrada</dt><dd><code>{state.latest.launchUrl ?? "Não configurada"}</code></dd></div>
            <div><dt>Redirect URIs</dt><dd><ul>{state.latest.redirectUris.map((uri) => <li key={uri}><code>{uri}</code></li>)}</ul></dd></div>
          </dl>
          {canReapplyDraft && <button ref={reapplyButtonRef} type="button" onClick={() => { setDraft((current) => ({ ...current, expectedRevision: state.latest.configurationRevision })); setFocusSaveAfterReapply(true); }}>Reaplicar meu rascunho sobre esta versão</button>}
        </section>
      </>}
      <button ref={saveButtonRef} type="submit" disabled={pending || state.status === "conflict" && draft.expectedRevision !== state.latest.configurationRevision}>{pending ? "Salvando…" : "Salvar configuração"}</button>
    </form>
  </details>;
}
