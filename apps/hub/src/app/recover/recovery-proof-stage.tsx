"use client";

import type { startAuthentication as startAuthenticationType } from "@simplewebauthn/browser";
import { useActionState, useEffect, useState } from "react";

export type RecoveryProof = "EMAIL" | "TOTP" | "PASSKEY";
export type RecoveryProofActionState = { status: "idle" | "error" | "verified" };
export type RecoveryPasskeyStartState =
  | { status: "ready"; options: Parameters<typeof startAuthenticationType>[0]["optionsJSON"] }
  | { status: "error" };

const initialState: RecoveryProofActionState = { status: "idle" };

export function RecoveryProofStage({ csrf, csrfFieldName, requestId, requiredProofs, verifiedProofs, needsAdminReview, adminReviewed,
  verifyEmailAction, verifyTotpAction, startPasskeyAction, verifyPasskeyAction }: {
  csrf: string;
  csrfFieldName: string;
  requestId: string;
  requiredProofs: readonly RecoveryProof[];
  verifiedProofs: readonly RecoveryProof[];
  needsAdminReview: boolean;
  adminReviewed: boolean;
  verifyEmailAction: (_state: RecoveryProofActionState, formData: FormData) => Promise<RecoveryProofActionState>;
  verifyTotpAction: (_state: RecoveryProofActionState, formData: FormData) => Promise<RecoveryProofActionState>;
  startPasskeyAction: (formData: FormData) => Promise<RecoveryPasskeyStartState>;
  verifyPasskeyAction: (formData: FormData) => Promise<RecoveryProofActionState>;
}) {
  const allVerified = requiredProofs.length > 0 && requiredProofs.every((factor) => verifiedProofs.includes(factor));
  return <section aria-label="Confirmação de identidade">
    <p>Confirme os fatores escolhidos para prosseguir. Cada confirmação vale somente para esta solicitação.</p>
    {requiredProofs.includes("EMAIL") ? <RecoveryCodeProof
      title="E-mail cadastrado" verified={verifiedProofs.includes("EMAIL")}
      description="Informe o código recebido no e-mail cadastrado."
      action={verifyEmailAction} csrf={csrf} csrfFieldName={csrfFieldName} requestId={requestId}
    /> : null}
    {requiredProofs.includes("TOTP") ? <RecoveryCodeProof
      title="Aplicativo autenticador" verified={verifiedProofs.includes("TOTP")}
      description="Informe o código atual do aplicativo autenticador."
      action={verifyTotpAction} csrf={csrf} csrfFieldName={csrfFieldName} requestId={requestId}
    /> : null}
    {requiredProofs.includes("PASSKEY") ? <RecoveryPasskeyProof
      verified={verifiedProofs.includes("PASSKEY")} csrf={csrf} csrfFieldName={csrfFieldName} requestId={requestId}
      supportsLegacyKey={requiredProofs.includes("EMAIL") || requiredProofs.includes("TOTP")}
      startAction={startPasskeyAction} finishAction={verifyPasskeyAction}
    /> : null}
    {needsAdminReview ? <p role="status">
      {adminReviewed ? "Aprovação administrativa confirmada." : allVerified
        ? "Fator confirmado. A solicitação precisa da aprovação de outro administrador ativo."
        : "A aprovação de outro administrador ativo será necessária após a confirmação do fator."}
    </p> : null}
    {allVerified && (!needsAdminReview || adminReviewed) ? <p role="status">Fatores confirmados. Continue com a etapa de definição da nova senha.</p> : null}
  </section>;
}

function RecoveryCodeProof({ title, description, verified, action, csrf, csrfFieldName, requestId }: {
  title: string;
  description: string;
  verified: boolean;
  action: (_state: RecoveryProofActionState, formData: FormData) => Promise<RecoveryProofActionState>;
  csrf: string;
  csrfFieldName: string;
  requestId: string;
}) {
  const [state, submit, pending] = useActionState(action, initialState);
  useEffect(() => {
    if (state.status === "verified") window.location.reload();
  }, [state.status]);

  return <div className="form-stack" aria-label={title}>
    <h2>{title}</h2>
    {verified ? <p role="status">Confirmado.</p> : <form className="form-stack" action={submit}>
      <input type="hidden" name={csrfFieldName} value={csrf} />
      <input type="hidden" name="requestId" value={requestId} />
      <p className="muted">{description}</p>
      {state.status === "error" ? <p className="form-error" role="alert">Não foi possível validar o código. Confira e tente novamente.</p> : null}
      <label>Código de seis dígitos<input type="text" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required disabled={pending} /></label>
      <button className="button-primary" disabled={pending} type="submit">{pending ? "Validando…" : "Confirmar"}</button>
    </form>}
  </div>;
}

function RecoveryPasskeyProof({ verified, csrf, csrfFieldName, requestId, supportsLegacyKey, startAction, finishAction }: {
  verified: boolean;
  supportsLegacyKey: boolean;
  csrf: string;
  csrfFieldName: string;
  requestId: string;
  startAction: (formData: FormData) => Promise<RecoveryPasskeyStartState>;
  finishAction: (formData: FormData) => Promise<RecoveryProofActionState>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);

  async function verify() {
    setError(false);
    setPending(true);
    try {
      const form = new FormData();
      form.set(csrfFieldName, csrf);
      form.set("requestId", requestId);
      const start = await startAction(form);
      if (start.status !== "ready") throw new Error("Passkey verification unavailable");
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const assertion = await startAuthentication({ optionsJSON: start.options });
      const response = new FormData();
      response.set(csrfFieldName, csrf);
      response.set("requestId", requestId);
      response.set("assertion", JSON.stringify(assertion));
      const result = await finishAction(response);
      if (result.status !== "verified") throw new Error("Passkey verification failed");
      window.location.reload();
    } catch {
      setError(true);
    } finally {
      setPending(false);
    }
  }

  return <div className="form-stack" aria-label="Chave de acesso">
    <h2>Passkey</h2>
    {verified ? <p role="status">Confirmada.</p> : <>
      <p className="muted">Use a passkey cadastrada no Virki para confirmar sua identidade.</p>
      {supportsLegacyKey ? <p className="muted">Se uma chave de segurança antiga não aparecer, confirme primeiro o e-mail ou o autenticador e tente a passkey novamente.</p> : null}
      {error ? <p className="form-error" role="alert">Não foi possível confirmar a passkey. Tente novamente.</p> : null}
      <button className="button-primary" type="button" disabled={pending} onClick={verify}>{pending ? "Validando passkey…" : "Confirmar com passkey"}</button>
    </>}
  </div>;
}
