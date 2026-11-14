"use client";

import { useEffect, useState } from "react";
import { RECOVERY_RESTART_METHOD_SUFFIX, recoveryPolicyFromMethod } from "./recovery-method-selection";
import type { RecoveryRequestMethod } from "./recovery-method-selection";
export type { RecoveryRequestMethod } from "./recovery-method-selection";

type RecoveryMethodOption = { value: RecoveryRequestMethod; title: string; description: string };

const independentMethods: readonly RecoveryMethodOption[] = [
  { value: "PASSKEY_EMAIL", title: "Passkey + e-mail", description: "Confirme a sua chave de acesso e o e-mail cadastrado." },
  { value: "TOTP_EMAIL", title: "Autenticador + e-mail", description: "Confirme o código do aplicativo autenticador e o e-mail cadastrado." },
  { value: "PASSKEY_TOTP", title: "Passkey + autenticador", description: "Confirme a sua chave de acesso e o código do aplicativo autenticador." }
];

const assistedMethods: readonly RecoveryMethodOption[] = [
  { value: "PASSKEY_ADMIN", title: "Passkey + outro administrador", description: "Confirme a sua chave de acesso; outro administrador ativo deverá aprovar." },
  { value: "TOTP_ADMIN", title: "Autenticador + outro administrador", description: "Confirme o código do aplicativo; outro administrador ativo deverá aprovar." },
  { value: "EMAIL_ADMIN", title: "E-mail + outro administrador", description: "Confirme o e-mail cadastrado; outro administrador ativo deverá aprovar." }
];

export function truncateRecoveryComment(value: string): string {
  return [...value].slice(0, 300).join("");
}

export function RecoveryRequestForm({ action, resumeAction, csrf, csrfFieldName, availableMethods, hasOtherActiveAdmin, initialMethod, hasExistingBrowserRecovery = false }: {
  action: (formData: FormData) => void | Promise<void>;
  resumeAction: (formData: FormData) => Promise<{ requestId: string | null }>;
  csrf: string;
  csrfFieldName: string;
  availableMethods: readonly RecoveryRequestMethod[];
  hasOtherActiveAdmin: boolean;
  initialMethod?: RecoveryRequestMethod;
  hasExistingBrowserRecovery?: boolean;
}) {
  const independent = independentMethods.filter(({ value }) => availableMethods.includes(value));
  const assisted = hasOtherActiveAdmin
    ? assistedMethods.filter(({ value }) => availableMethods.includes(value))
    : [];
  const [method, setMethod] = useState<RecoveryRequestMethod | "">(() =>
    initialMethod && [...independent, ...assisted].some(({ value }) => value === initialMethod) ? initialMethod : "");
  const [comment, setComment] = useState("");
  const [browserLockUnavailable, setBrowserLockUnavailable] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => { setHydrated(true); }, []);
  const isAssisted = assisted.some(({ value }) => value === method);
  const canSubmit = independent.some(({ value }) => value === method) || isAssisted;

  async function resumeWithBrowserLock(formData: FormData): Promise<void> {
    if (!navigator.locks?.request) {
      setBrowserLockUnavailable(true);
      return;
    }
    const result = await navigator.locks.request("virki-recovery-start-v1", () => resumeAction(formData));
    // A full same-origin document request keeps Hub vs Portal identity and
    // Access provenance intact, unlike an internal action-RSC navigation.
    window.location.replace(result.requestId
      ? "/recover?requestId=" + encodeURIComponent(result.requestId)
      : "/recover?restart=1");
  }

  async function resumeFromButton(): Promise<void> {
    const formData = new FormData();
    formData.set(csrfFieldName, csrf);
    await resumeWithBrowserLock(formData);
  }

  async function submitWithBrowserLock(formData: FormData): Promise<void> {
    // The first two tabs may submit before EITHER has a recovery cookie.
    // Serializing only after server-side cookie inspection is too late: two
    // responses can arrive out of order and the second can erase a newly
    // proven first recovery. The lock must cover the fetch+Set-Cookie itself.
    // Web Locks are per-origin; Hub and Portal remain separately isolated.
    // An insecure/unsupported browser must not silently fall back to an
    // unsafe concurrent submission.
    if (!navigator.locks?.request) {
      setBrowserLockUnavailable(true);
      return;
    }
    // The submitted FormData, not an asynchronously hydrated React state,
    // is the only reliable source for the checkbox value. Preserve the
    // browser's exact acknowledgement while the cross-tab lock is pending;
    // the server validates the field and checks role, origin and CSRF.
    const confirmed = hasExistingBrowserRecovery && formData.get("confirmRecoveryRestart") === "yes";
    if (hasExistingBrowserRecovery && !confirmed) {
      // A missing URL or damaged intent must not strand a previously proven
      // browser. Neither this lookup nor its navigation alters capabilities.
      await resumeWithBrowserLock(formData);
      return;
    }
    const selected = formData.get("method");
    if (confirmed && typeof selected === "string" && recoveryPolicyFromMethod(selected)) {
      // Use the existing host/CSRF-validated Server Action rather than a
      // second RPC with different Access provenance. The backend only admits
      // the literal six-method whitelist plus this exact consent suffix.
      formData.set("method", selected + RECOVERY_RESTART_METHOD_SUFFIX);
    }
    await navigator.locks.request("virki-recovery-start-v1", async () => {
      await action(formData);
    });
  }

  return <form action={submitWithBrowserLock} className="form-stack">
    <input type="hidden" name={csrfFieldName} value={csrf} />
    <label>E-mail da conta<input type="email" name="email" autoComplete="email" maxLength={320} required /></label>
    <p className="muted">Escolha como deseja confirmar sua identidade. As opções disponíveis não indicam quais fatores estão cadastrados em uma conta.</p>
    {independent.length > 0 ? <fieldset>
      <legend>Confirmar com dois fatores</legend>
      {independent.map((option) => <RecoveryMethodChoice key={option.value} option={option} selected={method === option.value} disabled={!hydrated} onSelect={() => { setMethod(option.value); setComment(""); }} />)}
    </fieldset> : null}
    {assisted.length > 0 ? <fieldset>
      <legend>Um fator e aprovação de outro administrador</legend>
      <p className="muted">O administrador que aprovar deverá ser outra pessoa com conta ativa. A aprovação só é válida após a confirmação do fator escolhido.</p>
      {assisted.map((option) => <RecoveryMethodChoice key={option.value} option={option} selected={method === option.value} disabled={!hydrated} onSelect={() => setMethod(option.value)} />)}
    </fieldset> : null}
    {isAssisted ? <label>Comentário para análise (opcional, até 300 caracteres)
      <textarea name="comment" maxLength={600} value={comment} onChange={(event) => setComment(truncateRecoveryComment(event.target.value))} rows={3} />
      <small aria-live="polite">{[...comment].length}/300</small>
    </label> : null}
    {hasExistingBrowserRecovery ? <label>
      <input type="checkbox" name="confirmRecoveryRestart" value="yes" disabled={!hydrated} />
      Confirmo que quero substituir a recuperação anterior neste navegador e posso perder o progresso que ainda não foi concluído em outra aba.
    </label> : null}
    {hasExistingBrowserRecovery ? <button type="button" className="button-secondary"
      disabled={!hydrated} onClick={resumeFromButton}>Retomar recuperação anterior</button> : null}
    <button className="button-primary" type="submit" disabled={!canSubmit || !hydrated}>Solicitar recuperação</button>
    {browserLockUnavailable ? <p role="alert" className="form-error">
      Não foi possível iniciar a recuperação neste navegador. Use uma versão atualizada com acesso seguro (HTTPS).
    </p> : null}
    {independent.length + assisted.length === 0 ? <p className="muted" role="status">Nenhum método de recuperação está disponível neste momento.</p> : null}
  </form>;
}

function RecoveryMethodChoice({ option, selected, disabled, onSelect }: { option: RecoveryMethodOption; selected: boolean; disabled: boolean; onSelect: () => void }) {
  return <label style={{ display: "flex", alignItems: "flex-start", gap: "0.65rem", marginTop: "0.7rem", cursor: "pointer" }}>
    <input type="radio" name="method" value={option.value} checked={selected} disabled={disabled} onChange={onSelect} style={{ width: "1.15rem", minHeight: "1.15rem", height: "1.15rem", padding: 0, marginTop: "0.2rem", flexShrink: 0 }} />
    <span><strong style={{ display: "block", color: "var(--text)" }}>{option.title}</strong><small>{option.description}</small></span>
  </label>;
}
