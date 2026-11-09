# Normal-password recovery: source and release gates

Date: 2026-11-09. Status: **implementation in progress, operational NO-GO**.

This document records independent read-only review findings against the starting Virki `main` (`7c8914ed222f0672ccc87e0331daf6a4c3f0f5a7`). It is not evidence that a successor fix is complete. No production changes or SMTP sends are authorized here.

## Critical integration gates

1. **Lost inbox must not block recovery.** Legacy recovery requires an email OTP, then an ADMIN approval and another emailed bearer link (`packages/auth/src/security.ts`, original 636-681, 705-721, 748-765, 771-800). A new `PASSKEY_TOTP` or `PASSKEY_ADMIN` ceremony needs its own durable browser-bound capability and server-side proof state, with no mailbox dependency. Do not count the same email link and emailed OTP as independent factors.
2. **Lost inbox must not block first login afterward.** Current new-device login sends email verification even for TOTP unless the device is already trusted; recovery revokes trusted-device state and USER recovery revokes passkeys/TOTP. Two-factor proof at reset must provide a carefully reviewed single-use bootstrap session or another equally strong path; then allow re-enrollment. Do not weaken default device login.
3. **ADMIN WebAuthn cannot reuse the USER-only RP implementation.** Current passkey enrollment and login are USER-only on `portal.biel.dev.br`; the ADMIN `hub.biel.dev.br` origin differs. A recovery assertion must not mint a normal login session prematurely. Until proper ADMIN passkey enrollment/cross-origin binding is demonstrated, gate ADMIN passkey combinations as unsupported.
4. **ADMIN lost-email recovery may be blocked before reaching the app.** `/recover` on the hub presently validates Cloudflare Access; the portal treats accounts as USER. Independently verify the external access policy and design a separately reviewed alternative if that gate itself requires the lost mailbox. Never bypass Access by simply accepting ADMIN recovery on an unguarded portal route.
5. **Prove each factor still counts at use-time.** Bind TOTP and WebAuthn assertions to exact account, role, request, browser, factor identity/revision, expiry and purpose. A factor revoked or rotated before password mutation must not authorize based solely on an old `verifiedAt` timestamp. Confirm at the final transaction's account lock, and prove one winner under races.
6. **Keep email verification truthful and invitation/ADMIN purposes separate.** Original password reset always writes `User.emailVerifiedAt=now`; a passkey+TOTP recovery without mailbox access cannot be used as proof that the inbox was verified. Existing recovery requests, invitation links, and the separate administrative elevation credential must remain isolated, with all sessions, remembered devices, OIDC artifacts and older recovery attempts revoked consistently.

## Review before any push, merge, deploy or release

Require tested code for three two-factor pairs (PASSKEY+TOTP, PASSKEY+EMAIL, TOTP+EMAIL), assisted single-factor choices (each factor plus a **different**, active/elevated ADMIN), comment 300-character validation server-side, account-enumeration-resistant initiation and synthetic stage, expiry, replay, cross-role/client/response cookies, stale proofs, lost-inbox first-login bootstrap, identity provider/session revocation, and migrations on a disposable PostgreSQL instance.

Review UI must never show a success or next-step option merely because a client set a form field, selected a radio button, or forged completion flags. Entirely unsupported methods must be hidden or disabled, without implying that an enrolled factor exists. Avoid secret or comment text in audit events.
