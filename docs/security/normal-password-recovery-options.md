# Normal-password recovery: independent factors and assisted fallback

Status: **design and acceptance criteria only**. This is not authorization to deploy or evidence that the flow works in staging.

This specification concerns the **normal login password** for an eligible account, including an administrator's normal login password. The separate administrative elevation password and account invitations remain separate purposes and cannot use these proofs interchangeably.

## Method choices

The user chooses a method before presenting factors. Each method must be bound immutably to its persisted request; changing the method requires starting another request.

| Method | Required proofs |
| --- | --- |
| `PASSKEY_TOTP` | User-verified WebAuthn passkey + current unused TOTP |
| `PASSKEY_EMAIL` | User-verified WebAuthn passkey + verified mailbox OTP |
| `TOTP_EMAIL` | Current unused TOTP + verified mailbox OTP |
| `PASSKEY_ADMIN` | User-verified WebAuthn passkey + separate eligible ADMIN approval |
| `TOTP_ADMIN` | Current unused TOTP + separate eligible ADMIN approval |
| `EMAIL_ADMIN` | Verified mailbox OTP + separate eligible ADMIN approval |

Optional three-factor confirmation may be offered, but must not be required to obtain the selected two-factor recovery. No combination can be reduced to a single factor by treating the request link/cookie as a substitute for an additional proof.

Assisted methods have an optional comment of **at most 300 Unicode characters**, validated server-side, escaped on rendering, and restricted to authorized reviewers. No comment is logged or added to e-mail plaintext by default. An assisted request must be refused unless another eligible ADMIN exists and is distinct from the target, active, with current independent administrative approval privileges. Revalidate this when approving; self-approval and request-owner-approval are forbidden. Do not reveal account existence, factor enrollment, or admin identities on the anonymous public request page.

## Security acceptance criteria

- The first request binds role (`USER` or `ADMIN`), account, exact method, expiry, comment and unique opaque recovery capability. ADMIN and USER host/surface controls are not interchangeable.
- The passkey path must implement a password-independent **recovery** WebAuthn ceremony bound to the request and the exact credential owner, origin and RP ID, with user verification required, anti-replay counter/revision update and a consumed challenge. Existing passkey login requires a password for email-based enumeration, and cannot simply be relabeled as recovery. Existing passkey support for USER does not imply ADMIN support; do not display an unsupported ADMIN passkey choice as working.
- TOTP verification consumes the exact accepted step with transactional CAS under active-factor validation, preventing replay and handling concurrency.
- E-mail verification proves the current inbox **only once** for this request. Do not count the recovery cookie, email link or a remembered device as another factor.
- Assisted recovery with a lost inbox must not require a new emailed link to finish after an administrator approves. Instead use a bound, short-lived, revocable, HttpOnly/Secure/SameSite recovery capability from the browser that completed the first factor. Losing it requires a new request/proof, not a bypass.
- Pairwise proof verification must reach the required complete state before allowing password reset. Assisted verification requires a single valid factor plus a distinct authorized ADMIN approval, before reset.
- Use rate limits at source, account, ceremony and credential levels; uniform public responses and indistinguishable failure surfaces for nonexistent accounts and unavailable methods.
- Password replacement, one-shot request consumption, revocation of pre-existing sessions, remembered devices and appropriate stale authenticators/credentials must be atomic with audit, and fail closed under transaction races.
- Preserve invitation activation semantics, current recovery cookies and role-specific routes, public origin/CSRF checks, security audit redaction and no real SMTP/production operations in source-only tests.

## UI behavior

The request screen presents selectable recovery routes, not just an email box. A two-factor route lets the user identify which factors to prove; an assisted route shows the selected first factor, a clearly optional comment textarea with a `300` character limit, and an explanation that another ADMIN must approve. Do not imply an admin is available unless a privacy-safe, server-checked eligibility condition is met at runtime. Unsupported methods are disabled or omitted, not clickable simulations.

Two-factor completion must not wait for an unrelated administrator; assisted completion must never auto-approve. A request's selected method is displayed again at each step and cannot be changed by mutating client-side form fields.

## Adversarial tests required

Wrong role or origin; old requests/invitations; forged, expired, reused or swapped request keys/cookies; a valid WebAuthn assertion for the wrong user/request/RP; passkey counter=0 concurrent replay; TOTP step replay; wrong or changed email; method downgrade; switching methods after first proof; self-approval; sole ADMIN; approval by inactive/expired/non-elevated ADMIN; 301-character comment; combined proofs from distinct requests; simultaneous password resets; revoked or replaced factor between proof and reset; stale sessions after reset; and tests that show no unrelated queued email is sent.
