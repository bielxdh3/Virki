"use client";

import React, { useActionState, useState } from "react";
import {
  ELEVATION_SCOPE_ACTIONS,
  UI_ELEVATION_SCOPES,
  type ElevationScope
} from "@bielos/auth/elevation-scopes";
import {
  completeAdminSetupAction,
  revokeElevationAction,
  startAdminSetupAction,
  startElevationAction,
  verifyElevationAction,
  type AdminActionState
} from "./admin-actions";

const initialState: AdminActionState = { status: "idle" };
const CSRF_FIELD = "csrfToken";

function PasswordField({
  id,
  name,
  label,
  autoComplete,
  minLength
}: {
  id: string;
  name: string;
  label: string;
  autoComplete: string;
  minLength?: number;
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
          aria-label={`${visible ? "Hide" : "Show"} ${label}`}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? "Hide" : "Show"}
        </button>
      </span>
    </label>
  );
}

export type AdminFeedbackStage = "setup" | "setup-complete" | "elevation" | "elevation-complete";

export function getFeedbackForStage(
  stage: AdminFeedbackStage,
  states: Record<AdminFeedbackStage, AdminActionState>
): { stage: AdminFeedbackStage; state: AdminActionState } | null {
  const state = states[stage];
  return state.status === "idle" ? null : { stage, state };
}

function activeElevationLabel(scope: string, manualUntilRevoked: boolean, expiresAt: Date): string {
  const label = ELEVATION_SCOPE_ACTIONS[scope as ElevationScope]?.label ?? "Unrecognized scope";
  return manualUntilRevoked
    ? `${label} — Manual until revoked`
    : `${label} — Timed until ${expiresAt.toLocaleString()}`;
}

export function AdminSecurityPanel({
  csrfToken,
  credentialConfigured,
  activeElevations,
  initialElevationScope
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
}) {
  const [setup, startSetup] = useActionState(startAdminSetupAction, initialState);
  const [setupComplete, completeSetup] = useActionState(completeAdminSetupAction, initialState);
  const [elevation, startElevation] = useActionState(startElevationAction, initialState);
  const [elevationComplete, completeElevation] = useActionState(verifyElevationAction, initialState);
  const [duration, setDuration] = useState<"TIMED" | "MANUAL">("TIMED");
  const [feedbackStage, setFeedbackStage] = useState<AdminFeedbackStage>("setup");
  const codes = setupComplete.recoveryCodes;
  const submitSetup = (formData: FormData) => { setFeedbackStage("setup"); startSetup(formData); };
  const submitSetupCompletion = (formData: FormData) => { setFeedbackStage("setup-complete"); completeSetup(formData); };
  const submitElevation = (formData: FormData) => { setFeedbackStage("elevation"); startElevation(formData); };
  const submitElevationCompletion = (formData: FormData) => { setFeedbackStage("elevation-complete"); completeElevation(formData); };
  const feedback = getFeedbackForStage(feedbackStage, {
    setup,
    "setup-complete": setupComplete,
    elevation,
    "elevation-complete": elevationComplete
  });

  return (
    <section className="panel admin-security-panel" aria-labelledby="admin-security-heading">
      <h2 id="admin-security-heading">Administrative security</h2>
      {!credentialConfigured ? (
        <div className="admin-security-stage">
          <p>Set a separate administrative password. It is never emailed.</p>
          {!setup.requestKey ? (
            <form className="compact-form admin-security-form" action={submitSetup}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <PasswordField id="setup-normal-password" name="normalPassword" label="Normal password" autoComplete="current-password" />
              <div className="button-row"><button className="button-primary" type="submit">Send setup code</button></div>
            </form>
          ) : (
            <form className="compact-form admin-security-form" action={submitSetupCompletion}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <input type="hidden" name="requestKey" value={setup.requestKey} />
              <label className="admin-security-field"><span>Email code</span><input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>
              <PasswordField id="setup-new-password" name="newPassword" label="New administrative password" autoComplete="new-password" minLength={16} />
              <div className="button-row"><button className="button-primary" type="submit">Create administrative credential</button></div>
            </form>
          )}
        </div>
      ) : (
        <div className="admin-security-stage">
          <form id="admin-elevation-form" className="compact-form admin-security-form" action={submitElevation}>
            <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
            <PasswordField id="elevation-normal-password" name="normalPassword" label="Normal password" autoComplete="current-password" />
            <PasswordField id="elevation-administrative-password" name="administrativePassword" label="Administrative password" autoComplete="current-password" />
            <label className="admin-security-field" htmlFor="elevation-scope"><span>Scope</span><select id="elevation-scope" name="scope" defaultValue={initialElevationScope ?? UI_ELEVATION_SCOPES[0]}>{UI_ELEVATION_SCOPES.map((scope) => <option key={scope} value={scope}>{ELEVATION_SCOPE_ACTIONS[scope].label}</option>)}</select></label>
            <label className="admin-security-field" htmlFor="elevation-duration"><span>Duration</span><select id="elevation-duration" name="duration" value={duration} onChange={(event) => setDuration(event.target.value as "TIMED" | "MANUAL")}><option value="TIMED">Timed</option><option value="MANUAL">Manual until revoked</option></select></label>
            {duration === "TIMED" ? (
              <label className="admin-security-field" htmlFor="elevation-minutes"><span>Minutes</span><select id="elevation-minutes" name="minutes" defaultValue="15"><option value="15">15</option><option value="60">60</option><option value="240">240</option><option value="1440">1440</option></select></label>
            ) : (
              <label className="checkbox-line admin-security-manual-confirm" htmlFor="manual-confirm"><input id="manual-confirm" type="checkbox" name="manualConfirm" value="yes" required /><span>I explicitly confirm manual-until-revoked mode.</span></label>
            )}
            <div className="button-row"><button className="button-primary" type="submit">Start elevation</button></div>
          </form>
          {elevation.requestKey ? (
            <form className="compact-form admin-security-form" action={submitElevationCompletion}>
              <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
              <input type="hidden" name="requestKey" value={elevation.requestKey} />
              <label className="admin-security-field"><span>Email code</span><input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label>
              <div className="button-row"><button className="button-primary" type="submit">Verify elevation</button></div>
            </form>
          ) : null}
        </div>
      )}
      {feedback ? <p className={feedback.state.status === "error" ? "admin-security-feedback is-error" : "admin-security-feedback is-ok"} role={feedback.state.status === "error" ? "alert" : "status"}>{feedback.state.status === "error" ? "Administrative security action unavailable." : `${feedback.stage} completed.`}</p> : null}
      {codes ? <div className="admin-security-feedback is-ok" role="status"><p>Save these administrative recovery codes once.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></div> : null}
      <div className="admin-security-active" aria-labelledby="active-elevations-heading">
        <div className="panel-title"><h3 id="active-elevations-heading">Active elevations</h3><span>{activeElevations.length}</span></div>
        {activeElevations.length === 0 ? <p>None.</p> : <ul className="admin-security-elevation-list">{activeElevations.map((item) => <li key={item.requestKey}><span className="status-pill is-active">{activeElevationLabel(item.scope, item.manualUntilRevoked, item.expiresAt)}</span><form action={revokeElevationAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><input type="hidden" name="requestKey" value={item.requestKey} /><button className="button-danger" type="submit">Revoke</button></form></li>)}</ul>}
      </div>
    </section>
  );
}
