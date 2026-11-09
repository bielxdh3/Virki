# Cold-browser ADMIN recovery under Cloudflare Access: required release gate

Date: 2026-11-09. **Operational status: NO-GO.** This is a design and acceptance record only; it does not authorize or implement an Access configuration change, new identity provider, policy edit, public Portal route, deployment, or external email delivery.

## Observed boundary versus application recovery

Read-only Access inventory earlier on 2026-11-09 established: `hub.biel.dev.br` is protected by one `Owner only` **Allow** policy with both **Include: email** and **Require: email**, a 168-hour Access application session, and a single configured **One-Time PIN** identity provider. The public `portal.biel.dev.br` is intentionally not an Access application and must never serve as a back door to the ADMIN recovery flow. These are observations of the configured account, not new queries performed by this document.

The six Virki normal-password methods and three separate ADMIN-credential methods operate **after** Cloudflare authorizes the Hub request. They do not create, extend, reissue or alter Cloudflare Access authorization. A browser without an acceptable Access identity can be stopped at the outer perimeter before seeing `/recover` or POSTing its Server Actions. An active Virki recovery capability, new verified Virki mailbox, valid TOTP, signed WebAuthn assertion or approval by another Virki ADMIN **cannot substitute** for an expired Cloudflare Access session.

Cloudflare's published behavior confirms that Access application JWTs and global SSO JWTs have separate lifetimes; an expired application session can be renewed from a still-valid global session if policy permits, but expiry of the global session requires IdP reauthentication. Therefore the 168-hour configured application duration **does not prove** a cold-browser lost-mailbox recovery path. Its One-Time PIN login depends on delivery to a policy-approved email address and a single-use PIN; an inaccessible original mailbox blocks that identity path. See Cloudflare's [session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/) and [One-Time PIN login](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/) documentation.

## Allowed design direction, not an implemented workaround

For independent continuity of the **same authorized owner**, investigate a separately reviewed, phishing-resistant Access authentication method enrolled **before** mailbox loss, while retaining the owner's precise policy eligibility. Cloudflare's current [Access passkeys guide](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/passkeys/) documents passkey sign-in, prior-method identity verification during enrollment and Access-policy checks after authentication; its [identity-provider guide](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/) documents additional identity providers. Neither guide establishes that a newly configured method automatically satisfies this account's existing `Owner only` email Include **and** Require rules. The actual asserted identity, authentication strength, Access policy evaluation, reauthentication, revocation and fallback must be independently tested **before** any production change. Do not assume a Virki passkey is an Access passkey; their enrollment and trust domains are separate.

Possible future approach to investigate, contingent on the owner's explicit authorization and a separate security review:

1. In an isolated Access **staging** application with an equally restrictive owner identity policy, enroll a hardware-backed Access passkey or independently secured IdP account for the same allowed owner. Ensure the identity claim really matches the owner policy and cannot be self-asserted by an arbitrary email account. Preserve explicit Include **and** Require constraints; never broaden the policy to an email domain, `Everyone`, unauthenticated `Bypass`, service-token-only interactive user, or public Portal entry.
2. Validate truly cold-browser Access reauthentication (no application JWT, no global JWT, no old email inbox), lost-device/passkey revocation, denied unlisted identity and session expiry. If enrollment was not completed before the incident, document the resulting dead end; no account-recovery method inside Virki can solve that external identity bootstrap by itself.
3. Only after valid Access authentication, exercise the full Next Hub recovery UI/POST/CSRF/host-only HttpOnly Secure Lax cookies with a real disposable PostgreSQL database, signed WebAuthn proofs where used, a separately verified replacement mailbox and single-winner reset. Reconfirm a new cold browser still passes the external policy with the approved identity. For any second ADMIN reviewer, independently verify **that reviewer also has a legitimate Access-authorized path to the Hub**; DB eligibility alone does not grant Access eligibility.
4. Keep protected/admin endpoints inaccessible from the public Portal throughout; validate wrong RP, origin, role, user, token, IdP, and email claims are denied **before** account mutation. Require an explicit owner security approval and rollback plan for any Access identity-provider/policy change; this document performs none.

## Required end-to-end acceptance matrix

| Scenario | Expected perimeter result | Required application result |
| --- | --- | --- |
| No Access session, original OTP mailbox lost, current OTP-only IdP | **Denied / cannot authenticate** under current configuration; do not claim operational recovery | No Hub recovery GET/POST or privileged mutation reachable |
| Existing Access session, original mailbox subsequently lost | Access may admit the still-valid session; this is **not** a cold-browser proof | Virki still needs two independent live factors or one + eligible elevated other ADMIN, and verified new mailbox if old email was not proven |
| Expired application JWT, still-valid global SSO JWT | Must measure true Access renewal and policy re-evaluation, not infer from timer | Never treat mere browser cookie presence as Virki recovery proof |
| Cold owner browser with independently pre-enrolled Access authentication | **Unproven until staging and actual matching identity claim/policy evaluation** | Execute real Hub two-factor recovery/CSRF/cookie/session bootstrap tests after Access admits owner |
| Old owner identity removed from policy or new Virki email not allowed | **Denied** until a separately authorized external policy change | New email verified inside Virki does not authorize Access |
| Other Virki ADMIN not in the `Owner only` allowlist | **Denied** under current Access policy | Do not advertise their database role as sufficient proof of practical reviewer availability |
| Wrong identity, replayed Access JWT, wrong aud/iss, public Portal `ADMIN` request | **Denied** | No account enumeration, session bootstrap, recovery approval or factor revocation |

## Evidence still missing and release decision

The direct signed WebAuthn + PostgreSQL tests, TLS SMTP loopback tests and local Next builds are strong **application-level** evidence but are not Cloudflare Access cold-identity evidence. The isolated Playwright Linux Docker runner was unavailable because the Docker Desktop Linux Engine pipe was missing; WSL on the test machine had Node 22 but lacked the private Chromium/NSS `certutil` prerequisites. Do not bypass TLS verification, modify shared Windows certificate trust or point tests to production to fill the gap.

**NO-GO** for lost-original-mailbox ADMIN recovery from a truly cold browser. Release requires actual proof of external owner identity reauthentication, end-to-end protected UI, authorized reviewer reachability, and explicit change control. Existing `Owner only` settings, production traffic and credentials remain untouched.
