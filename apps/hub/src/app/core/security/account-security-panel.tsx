"use client";

import { useActionState } from "react";
import { confirmTotpEnrollmentAction, disableTotpAction, regenerateRecoveryCodesAction, revokeTrustedDeviceAction, startTotpEnrollmentAction, type SecurityActionState } from "./account-actions";

const initialState: SecurityActionState = { status: "idle" };
const CSRF_FIELD = "csrfToken";

export function AccountSecurityPanel({ csrfToken, totpActive, recoveryCodeCount }: { csrfToken: string; totpActive: boolean; recoveryCodeCount: number }) {
  const [setup, startSetup] = useActionState(startTotpEnrollmentAction, initialState);
  const [confirmation, confirmSetup] = useActionState(confirmTotpEnrollmentAction, initialState);
  const [regeneration, regenerate] = useActionState(regenerateRecoveryCodesAction, initialState);
  const codes = confirmation.recoveryCodes ?? regeneration.recoveryCodes;
  return <section className="panel" aria-labelledby="account-security-heading"><h2 id="account-security-heading">Second factor</h2><p>{totpActive ? "TOTP is active." : "Email verification is the current second factor."}</p>
    {!totpActive && !setup.secret ? <form action={startSetup}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">Set up TOTP</button></form> : null}
    {setup.secret ? <div><p>Show this setup secret only during enrollment:</p><code>{setup.secret}</code><p><code>{setup.uri}</code></p><form action={confirmSetup}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><label>Authenticator code<input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label><button type="submit">Confirm TOTP</button></form></div> : null}
    {totpActive ? <><form action={regenerate}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">Regenerate recovery codes</button></form><form action={disableTotpAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">Use email factor</button></form></> : null}
    {codes ? <div role="status"><p>Save these recovery codes now. They are shown once.</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></div> : null}
    {setup.status === "error" || confirmation.status === "error" || regeneration.status === "error" ? <p role="alert">Security action unavailable.</p> : null}<p>Stored recovery codes: {recoveryCodeCount}</p>
  </section>;
}

export function TrustedDeviceList({ csrfToken, devices }: { csrfToken: string; devices: Array<{ deviceKey: string; label: string | null; lastSeenAt: Date; createdAt: Date }> }) {
  return <section className="panel" aria-labelledby="trusted-devices-heading"><h2 id="trusted-devices-heading">Trusted devices</h2>{devices.length === 0 ? <p>No trusted devices.</p> : <ul>{devices.map((device) => <li key={device.deviceKey}><span>{device.label ?? "Trusted device"}</span><form action={revokeTrustedDeviceAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><input type="hidden" name="deviceKey" value={device.deviceKey} /><button type="submit">Revoke</button></form></li>)}</ul>}</section>;
}
