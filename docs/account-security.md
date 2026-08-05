# BielOS account security

The normal password is only the first login factor. Login creates no session until the security ceremony completes.

## Factors and devices

- Email is the default second factor and uses short-lived one-time codes.
- TOTP enrollment stores only an AES-256-GCM ciphertext under `BIELOS_TOTP_ENCRYPTION_KEY`. The setup secret is returned only to the enrollment screen.
- TOTP codes accept the adjacent clock window but a matched step cannot be used twice while active.
- Recovery codes are random, hashed, one-use values. Regeneration deletes all previous codes and the plaintext list is returned only once.
- A new opaque device cookie is verified by email before a trusted-device row is created. No fingerprint, IP, or user-agent is used for device identity.
- Trusted devices and sessions are listed and revoked only within the current user scope; UI references are opaque keys. The trusted-device screen has an explicit empty state and shows only a safe label plus available timestamps; raw device keys remain internal form values.

## Remembered-browser login

After a browser completes its required security ceremony, BielOS stores a server-side remembered-browser grant for an absolute seven-day period. The grant is bound to the user and trusted-device hash, stores no bearer value, is revocable, and is rotated only after strong verification completes.

During that period, ordinary BielOS logout revokes only the current session and preserves the device cookie and remembered grant. The next login still requires the password but can skip email and TOTP. An expired grant on a known TOTP browser requires TOTP without email; an expired email-factor grant requires email verification. Unknown, malformed, mismatched, revoked, recovered, blocked, or security-reset browsers fail closed into the applicable strong flow.

Remembered-browser login never remembers administrative elevation. Device revocation, password change/reset, account recovery, TOTP enrollment/replacement/disable, account blocking/deactivation, and confirmed revoke-all security actions invalidate the grant.

## Ordinary recovery

Recovery requests have generic responses. The email challenge must be verified before the OWNER can approve it. Approval is a separate decision from email control; consuming an approved request changes the normal password and revokes existing sessions. Administrative-password recovery is a separate ceremony and is never delegated to another user.

## Production boundary

Email-dependent login and recovery require the provider-neutral outbox to have a real production adapter. Until then, production intake remains disabled and no test transport is treated as readiness.
