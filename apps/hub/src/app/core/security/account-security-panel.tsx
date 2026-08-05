"use client";

import { useActionState } from "react";
import type { BielosLocale } from "@bielos/ui";
import { confirmTotpEnrollmentAction, disableTotpAction, regenerateRecoveryCodesAction, revokeTrustedDeviceAction, startTotpEnrollmentAction, type SecurityActionState } from "./account-actions";
import { getTrustedDeviceCopy, getTrustedDeviceDisplay } from "./trusted-device-view";

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

export function TrustedDeviceList({ csrfToken, devices, locale }: { csrfToken: string; devices: Array<{ deviceKey: string; label: string | null; lastSeenAt: Date; createdAt: Date }>; locale: BielosLocale }) {
  const copy = getTrustedDeviceCopy(locale);
  return <section className="panel trusted-device-panel" aria-labelledby="trusted-devices-heading"><h2 id="trusted-devices-heading">{copy.title}</h2>{devices.length === 0 ? <p className="trusted-device-empty">{copy.empty}</p> : <ul className="trusted-device-list">{devices.map((device) => { const display = getTrustedDeviceDisplay(device, locale); return <li key={device.deviceKey} className="trusted-device-row"><div><strong>{display.label}</strong><dl><div><dt>{copy.lastSeen}</dt><dd><time dateTime={device.lastSeenAt.toISOString()}>{display.lastSeen}</time></dd></div><div><dt>{copy.created}</dt><dd><time dateTime={device.createdAt.toISOString()}>{display.created}</time></dd></div></dl></div><form action={revokeTrustedDeviceAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><input type="hidden" name="deviceKey" value={device.deviceKey} /><button type="submit">{copy.revoke}</button></form></li>; })}</ul>}</section>;
}
