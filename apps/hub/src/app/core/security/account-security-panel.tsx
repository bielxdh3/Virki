"use client";

import { useActionState } from "react";
import type { BielosLocale } from "@bielos/ui";
import { confirmTotpEnrollmentAction, disableTotpAction, regenerateRecoveryCodesAction, revokeTrustedDeviceAction, startTotpEnrollmentAction, type SecurityActionState } from "./account-actions";
import { getTrustedDeviceCopy, getTrustedDeviceDisplay } from "./trusted-device-view";

const initialState: SecurityActionState = { status: "idle" };
const CSRF_FIELD = "csrfToken";

const copy = {
  "pt-BR": {
    secondFactor: "Segundo fator",
    totpActive: "TOTP está ativo.",
    emailFactor: "A verificação por e-mail é o segundo fator atual.",
    setupTotp: "Configurar TOTP",
    setupSecret: "Exiba este segredo apenas durante a configuração:",
    confirmTotp: "Confirmar TOTP",
    authenticatorCode: "Código do autenticador",
    regenerate: "Regenerar códigos de recuperação",
    useEmail: "Usar fator por e-mail",
    saveCodes: "Salve estes códigos de recuperação agora. Eles serão exibidos uma vez.",
    unavailable: "A ação de segurança está indisponível.",
    storedCodes: "Códigos de recuperação armazenados:",
    show: "Mostrar",
    hide: "Ocultar"
  },
  en: {
    secondFactor: "Second factor",
    totpActive: "TOTP is active.",
    emailFactor: "Email verification is the current second factor.",
    setupTotp: "Set up TOTP",
    setupSecret: "Show this setup secret only during enrollment:",
    confirmTotp: "Confirm TOTP",
    authenticatorCode: "Authenticator code",
    regenerate: "Regenerate recovery codes",
    useEmail: "Use email factor",
    saveCodes: "Save these recovery codes now. They are shown once.",
    unavailable: "Security action unavailable.",
    storedCodes: "Stored recovery codes:",
    show: "Show",
    hide: "Hide"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

export function AccountSecurityPanel({ csrfToken, totpActive, recoveryCodeCount, locale }: { csrfToken: string; totpActive: boolean; recoveryCodeCount: number; locale: BielosLocale }) {
  const t = copy[locale];
  const [setup, startSetup] = useActionState(startTotpEnrollmentAction, initialState);
  const [confirmation, confirmSetup] = useActionState(confirmTotpEnrollmentAction, initialState);
  const [regeneration, regenerate] = useActionState(regenerateRecoveryCodesAction, initialState);
  const codes = confirmation.recoveryCodes ?? regeneration.recoveryCodes;
  return <section className="panel" aria-labelledby="account-security-heading"><h2 id="account-security-heading">{t.secondFactor}</h2><p>{totpActive ? t.totpActive : t.emailFactor}</p>
    {!totpActive && !setup.secret ? <form action={startSetup}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">{t.setupTotp}</button></form> : null}
    {setup.secret ? <div><p>{t.setupSecret}</p><code>{setup.secret}</code><p><code>{setup.uri}</code></p><form action={confirmSetup}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><label>{t.authenticatorCode}<input name="code" inputMode="numeric" pattern="[0-9]{6}" autoComplete="one-time-code" required /></label><button type="submit">{t.confirmTotp}</button></form></div> : null}
    {totpActive ? <><form action={regenerate}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">{t.regenerate}</button></form><form action={disableTotpAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><button type="submit">{t.useEmail}</button></form></> : null}
    {codes ? <div role="status"><p>{t.saveCodes}</p><ul>{codes.map((code) => <li key={code}><code>{code}</code></li>)}</ul></div> : null}
    {setup.status === "error" || confirmation.status === "error" || regeneration.status === "error" ? <p role="alert">{t.unavailable}</p> : null}<p>{t.storedCodes} {recoveryCodeCount}</p>
  </section>;
}

export function TrustedDeviceList({ csrfToken, devices, locale }: { csrfToken: string; devices: Array<{ deviceKey: string; label: string | null; lastSeenAt: Date; createdAt: Date }>; locale: BielosLocale }) {
  const copy = getTrustedDeviceCopy(locale);
  return <section className="panel trusted-device-panel" aria-labelledby="trusted-devices-heading"><h2 id="trusted-devices-heading">{copy.title}</h2>{devices.length === 0 ? <p className="trusted-device-empty">{copy.empty}</p> : <ul className="trusted-device-list">{devices.map((device) => { const display = getTrustedDeviceDisplay(device, locale); return <li key={device.deviceKey} className="trusted-device-row"><div><strong>{display.label}</strong><dl><div><dt>{copy.lastSeen}</dt><dd><time dateTime={device.lastSeenAt.toISOString()}>{display.lastSeen}</time></dd></div><div><dt>{copy.created}</dt><dd><time dateTime={device.createdAt.toISOString()}>{display.created}</time></dd></div></dl></div><form action={revokeTrustedDeviceAction}><input type="hidden" name={CSRF_FIELD} value={csrfToken} /><input type="hidden" name="deviceKey" value={device.deviceKey} /><button type="submit">{copy.revoke}</button></form></li>; })}</ul>}</section>;
}
