"use client";

import React, { useActionState, useState } from "react";
import type { BielosLocale } from "@bielos/ui";
import {
  ELEVATION_SCOPE_ACTIONS,
  UI_ELEVATION_SCOPES,
  type ElevationScope
} from "@bielos/auth/elevation-scopes";
import {
  completeAdminSetupAction,
  recoverAdminCredentialAction,
  revokeElevationAction,
  startAdminSetupAction,
  startElevationAction,
  verifyElevationAction,
  type AdminActionState
} from "./admin-actions";

const initialState: AdminActionState = { status: "idle" };
const CSRF_FIELD = "csrfToken";

const copy = {
  "pt-BR": {
    heading: "Segurança administrativa",
    setupDescription: "Defina uma senha administrativa separada. Ela nunca é enviada por e-mail.",
    normalPassword: "Senha normal",
    administrativePassword: "Senha administrativa",
    newAdministrativePassword: "Nova senha administrativa",
    emailCode: "Código enviado por e-mail",
    offlineRecoveryCode: "Código de recuperação offline",
    setup: "Enviar código de configuração",
    create: "Criar credencial administrativa",
    authenticatorCode: "Código do autenticador",
    scope: "Ação",
    duration: "Duração",
    timed: "Temporária",
    manual: "Manual até revogar",
    minutes: "Minutos",
    manualConfirm: "Confirmo explicitamente o modo manual até revogar.",
    startElevation: "Iniciar confirmação",
    verifyElevation: "Verificar confirmação",
    recover: "Recuperar credencial administrativa",
    reset: "Redefinir credencial",
    error: "A ação de segurança administrativa está indisponível.",
    completed: "Concluído",
    saveCodes: "Salve estes códigos de recuperação administrativa uma única vez.",
    activeElevations: "Confirmações ativas",
    none: "Nenhuma.",
    revoke: "Revogar",
    manualUntilRevoked: "Manual até revogar",
    timedUntil: "Temporária até",
    show: "Mostrar",
    hide: "Ocultar"
  },
  en: {
    heading: "Administrative security",
    setupDescription: "Set a separate administrative password. It is never emailed.",
    normalPassword: "Normal password",
    administrativePassword: "Administrative password",
    newAdministrativePassword: "New administrative password",
    emailCode: "Email code",
    offlineRecoveryCode: "Offline recovery code",
    setup: "Send setup code",
    create: "Create administrative credential",
    authenticatorCode: "Authenticator code",
    scope: "Action",
    duration: "Duration",
    timed: "Timed",
    manual: "Manual until revoked",
    minutes: "Minutes",
    manualConfirm: "I explicitly confirm manual-until-revoked mode.",
    startElevation: "Start elevation",
    verifyElevation: "Verify elevation",
    recover: "Recover administrative credential",
    reset: "Reset credential",
    error: "Administrative security action unavailable.",
    completed: "Completed",
    saveCodes: "Save these administrative recovery codes once.",
    activeElevations: "Active elevations",
    none: "None.",
    revoke: "Revoke",
    manualUntilRevoked: "Manual until revoked",
    timedUntil: "Timed until",
    show: "Show",
    hide: "Hide"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const scopeLabels: Record<BielosLocale, Partial<Record<ElevationScope, string>>> = {
  "pt-BR": {
    ACCOUNT_APPLICATION_REVIEW: "Revisão de solicitação de conta",
    ACCOUNT_ACTIVATION_REISSUE: "Reemitir ativação de conta",
    MODULE_ACCESS_CHANGE: "Acesso a módulo",
    FEATURE_PERMISSION_CHANGE: "Permissão de recurso",
    ACCOUNT_STATE_CHANGE: "Aprovação de recuperação de conta",
    PROJECT_OWNER_ACCESS_CHANGE: "Acesso de projeto Core",
    CORE_PROJECT_ARCHIVE: "Arquivamento de projeto Core"
  },
  en: {
    ACCOUNT_APPLICATION_REVIEW: "Account application review",
    ACCOUNT_ACTIVATION_REISSUE: "Reissue account activation",
    MODULE_ACCESS_CHANGE: "Module access",
    FEATURE_PERMISSION_CHANGE: "Feature permission",
    ACCOUNT_STATE_CHANGE: "Account recovery approval",
    PROJECT_OWNER_ACCESS_CHANGE: "Core project access change",
    CORE_PROJECT_ARCHIVE: "Core project archive"
  }
};

function PasswordField({
  id,
  name,
  label,
  autoComplete,
  minLength,
  showLabel,
  hideLabel
}: {
  id: string;
  name: string;
  label: string;
  autoComplete: string;
  minLength?: number;
  showLabel: string;
  hideLabel: string;
}) {
  const [visible, setVisible] = useState(false);

  return (
    <label className="admin-security-field" htmlFor={id}>
      <span>{label}</span>
      <span className="admin-security-password-control">
        <input
          id={id}
          name={name}
          type={visible ? "text" : "password"}
          autoComplete={autoComplete}
          minLength={minLength}
          required
        />
        <button
          className="button-ghost"
          type="button"
          aria-pressed={visible}
          aria-label={`${visible ? hideLabel : showLabel} ${label}`}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? hideLabel : showLabel}
        </button>
      </span>
    </label>
  );
}

export type AdminFeedbackStage = "setup" | "setup-complete" | "recovery" | "elevation" | "elevation-complete";

export function getFeedbackForStage(
  stage: AdminFeedbackStage,
  states: Record<AdminFeedbackStage, AdminActionState>
): { stage: AdminFeedbackStage; state: AdminActionState } | null {
  const state = states[stage];
  return state.status === "idle" ? null : { stage, state };
}

function activeElevationLabel(scope: string, manualUntilRevoked: boolean, expiresAt: Date, locale: BielosLocale): string {
  const t = copy[locale];
  const label = scopeLabels[locale][scope as ElevationScope] ?? ELEVATION_SCOPE_ACTIONS[scope as ElevationScope]?.label ?? t.error;
  return manualUntilRevoked
    ? `${label} — ${t.manualUntilRevoked}`
    : `${label} — ${t.timedUntil} ${expiresAt.toLocaleString(locale)}`;
}

export function AdminSecurityPanel({
  csrfToken,
  credentialConfigured,
  activeElevations,
  initialElevationScope,
  locale = "en"
}: {
  csrfToken: string;
  credentialConfigured: boolean;
  activeElevations: Array<{
    requestKey: string;
    scope: string;
    manualUntilRevoked: boolean;
    expiresAt: Date;
  }>;
  initialElevationScope?: ElevationScope;
  locale?: BielosLocale;
}) {
  const t = copy[locale];
  const [setup, startSetup] = useActionState(startAdminSetupAction, initialState);
  const [setupComplete, completeSetup] = useActionState(completeAdminSetupAction, initialState);
  const [recovery, recoverCredential] = useActionState(recoverAdminCredentialAction, initialState);
  const [elevation, startElevation] = useActionState(startElevationAction, initialState);
  const [elevationComplete, completeElevation] = useActionState(verifyElevationAction, initialState);
  const [duration, setDuration] = useState<"TIMED" | "MANUAL">("TIMED");
  const [feedbackStage, setFeedbackStage] = useState<AdminFeedbackStage>("setup");
  const codes = setupComplete.recoveryCodes ?? recovery.recoveryCodes;
  const submitSetup = (formData: FormData) => { setFeedbackStage("setup"); startSetup(formData); };
  const submitSetupCompletion = (formData: FormData) => { setFeedbackStage("setup-complete"); completeSetup(formData); };
  const submitRecovery = (formData: FormData) => { setFeedbackStage("recovery"); recoverCredential(formData); };
  const submitElevation = (formData: FormData) => { setFeedbackStage("elevation"); startElevation(formData); };
  const submitElevationCompletion = (formData: FormData) => { setFeedbackStage("elevation-complete"); completeElevation(formData); };
  const feedback = getFeedbackForStage(feedbackStage, {
    setup,
    "setup-complete": setupComplete,
    recovery,
    elevation,
    "elevation-complete": elevationComplete
  });

  return (
    <section className="panel admin-security-panel" aria-labelledby="admin-security-heading">
      <h2 id="admin-security-heading">{t.heading}</h2>
      {!credentialConfigured ? (
        <div className="admin-security-stage">
          <p>{t.setupDescription}</p>
          {!setup.requestKey ? (
            <form className="compact-form admin-security-form" action={submitSetup}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <PasswordField id="setup-normal-password" name="normalPassword" label={t.normalPassword} autoComplete="current-password" showLabel={t.show} hideLabel={t.hide} />
              <div className="button-row"><button className="button-primary" type="submit">{t.setup}</button></div>
            </form>
          ) : (
            <form className="compact-form admin-security-form" action={submitSetupCompletion}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <input type="hidden" name="requestKey" value={setup.requestKey} />
              <label className="admin-security-field"><span>{t.emailCode}</span><input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>
              <PasswordField id="setup-new-password" name="newPassword" label={t.newAdministrativePassword} autoComplete="new-password" minLength={16} showLabel={t.show} hideLabel={t.hide} />
              <div className="button-row"><button className="button-primary" type="submit">{t.create}</button></div>
            </form>
          )}
        </div>
      ) : (
        <div className="admin-security-stage">
          <form id="admin-elevation-form" className="compact-form admin-security-form" action={submitElevation}>
            <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
            <PasswordField id="elevation-normal-password" name="normalPassword" label={t.normalPassword} autoComplete="current-password" showLabel={t.show} hideLabel={t.hide} />
            <PasswordField id="elevation-administrative-password" name="administrativePassword" label={t.administrativePassword} autoComplete="current-password" showLabel={t.show} hideLabel={t.hide} />
            <label className="admin-security-field" htmlFor="elevation-scope"><span>{t.scope}</span><select id="elevation-scope" name="scope" defaultValue={initialElevationScope ?? UI_ELEVATION_SCOPES[0]}>{UI_ELEVATION_SCOPES.map((scope) => <option key={scope} value={scope}>{scopeLabels[locale][scope] ?? ELEVATION_SCOPE_ACTIONS[scope].label}</option>)}</select></label>
            <label className="admin-security-field" htmlFor="elevation-duration"><span>{t.duration}</span><select id="elevation-duration" name="duration" value={duration} onChange={(event) => setDuration(event.target.value as "TIMED" | "MANUAL")}><option value="TIMED">{t.timed}</option><option value="MANUAL">{t.manual}</option></select></label>
            {duration === "TIMED" ? (
              <label className="admin-security-field" htmlFor="elevation-minutes"><span>{t.minutes}</span><select id="elevation-minutes" name="minutes" defaultValue="15"><option value="15">15</option><option value="60">60</option><option value="240">240</option><option value="1440">1440</option></select></label>
            ) : (
              <label className="checkbox-line admin-security-manual-confirm" htmlFor="manual-confirm"><input id="manual-confirm" type="checkbox" name="manualConfirm" value="yes" required /><span>{t.manualConfirm}</span></label>
            )}
            <div className="button-row"><button className="button-primary" type="submit">{t.startElevation}</button></div>
          </form>
          {elevation.requestKey ? (
            <form className="compact-form admin-security-form" action={submitElevationCompletion}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <input type="hidden" name="requestKey" value={elevation.requestKey} />
              <label className="admin-security-field"><span>{t.emailCode}</span><input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>
              <div className="button-row"><button className="button-primary" type="submit">{t.verifyElevation}</button></div>
            </form>
          ) : null}
          <details className="admin-drawer admin-recovery-drawer">
            <summary>{t.recover}</summary>
            <form className="compact-form admin-security-form" action={submitRecovery}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <PasswordField id="recovery-normal-password" name="normalPassword" label={t.normalPassword} autoComplete="current-password" showLabel={t.show} hideLabel={t.hide} />
              <label className="admin-security-field" htmlFor="recovery-code"><span>{t.offlineRecoveryCode}</span><input id="recovery-code" name="recoveryCode" autoComplete="one-time-code" required /></label>
              <PasswordField id="recovery-new-password" name="newPassword" label={t.newAdministrativePassword} autoComplete="new-password" minLength={16} showLabel={t.show} hideLabel={t.hide} />
              <div className="button-row"><button className="button-secondary" type="submit">{t.reset}</button></div>
            </form>
          </details>
        </div>
      )}
      {feedback ? <p className={feedback.state.status === "error" ? "admin-security-feedback is-error" : "admin-security-feedback is-ok"} role={feedback.state.status === "error" ? "alert" : "status"}>{feedback.state.status === "error" ? t.error : t.completed}</p> : null}
      {codes ? <div className="admin-security-feedback is-ok" role="status"><p>{t.saveCodes}</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></div> : null}
      <div className="admin-security-active" aria-labelledby="active-elevations-heading">
        <div className="panel-title"><h3 id="active-elevations-heading">{t.activeElevations}</h3><span>{activeElevations.length}</span></div>
        {activeElevations.length === 0 ? <p>{t.none}</p> : <ul className="admin-security-elevation-list">{activeElevations.map((item) => <li key={item.requestKey}><span className="status-pill is-active">{activeElevationLabel(item.scope, item.manualUntilRevoked, item.expiresAt, locale)}</span><form action={revokeElevationAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><input type="hidden" name="requestKey" value={item.requestKey} /><button className="button-danger" type="submit">{t.revoke}</button></form></li>)}</ul>}
      </div>
    </section>
  );
}
