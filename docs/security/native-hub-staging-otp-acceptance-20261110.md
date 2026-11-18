# Virki native Hub — segregated staging and authentic OTP acceptance

**Status: NOT EXECUTED / RELEASE NO-GO.** This is a test-only operating and
evidence contract, not permission to provision a host, modify Cloudflare,
send email, mutate a real account, deploy, or release. The production Hub
continues behind Cloudflare Access and ADMIN passkeys remain disabled there.

## 1. External authorization gate — fail closed

Before creating or modifying a single external resource, the operator must
obtain an express approval naming **the exact staging host**, separate
PostgreSQL instance and roles, dedicated ADMIN/USER test identities, designated
test inboxes and authorized recipients, ingress policy, test time window,
image digest, expected application SHA and rollback owner. Do not reuse any
production or deManage database, account, email secret, mailbox or hostname.
The previously observed PR #92 DNS/Compose/mock origin is **not** independent
staging evidence. Do not infer authorization from this document or a successful
GitHub Actions run. The authorized operator must prove the host and database
actually exist and are segregated before an E2E mutation.

The owner may authorize the **direction** of removing Cloudflare Access, but
actual production cutover requires a separate final explicit approval after
all the gates below pass. Do not disable Cloudflare Access, enable ADMIN
passkeys in production or turn `VIRKI_HUB_PERIMETER_MODE=native` on in
production during this staging acceptance.

**Already independently observed in hosted CI (not external staging):** run
`42866864398` at exact source SHA
`43c4708b23f78b8af3a7f407141ece13c0e48d86` finished `SUCCESS` on
2026-11-10. Its mandatory native Hub Chromium HTTPS step actually executed
three tests: **3 PASS, 0 FAIL, 0 SKIP** (54.7 s); the conventional browser,
isolated passkey, production-Hub rehearsal, Validate and exclusive PostgreSQL
HOL/CAS jobs also succeeded. The production image publishing job was skipped
by branch policy. This proves an **isolated CI fixture**, not deployment of
the SHA/digest on an independent staging host, real SMTP provider delivery,
or approval of a production Access cutover.

## 2. Preflight: evidence that must be obtained, never assumed

| Gate | Required operator evidence | Without it |
| --- | --- | --- |
| Provenance | Signed/verified final source SHA, exact-SHA hosted CI/CodeQL and GHCR build-provenance evidence, immutable OCI manifest digest/platform, and runtime image ID/config hash on the independent host | BLOCK |
| Segregation | Approved staging host identity, DB host/database/roles different from production, test accounts and separate owned mailboxes | BLOCK |
| Ingress | HTTPS with valid staging certificate; deny unknown hosts; because native mode skips Access JWT validation inside Hub, a separate edge/firewall policy must default-deny and allow only owner-approved operator/test source IPs or private VPN; independently observe the active rule on the actual edge; retain an opaque receipt; do not change production DNS, Access policies or hostnames, and do not create a broad Access bypass; verify Portal and Hub routing separately | BLOCK |
| Egress | Separate independently evidenced Hub and worker host/firewall policies: worker only to the staging DB, approved SMTP relay and approved DNS resolution path; Hub only to the staging DB, signed identity/application endpoints and approved DNS resolution path. Both must deny all Docker Engine TCP API listeners (including 2375/2376 and any custom port), SSH/RDP, host-gateway management services and every unapproved destination, even on an internal Docker network. Require distinct policy IDs and distinct receipts; independently observe that each policy is active on the actual host/firewall because an ID or receipt string alone proves nothing | BLOCK |
| Application flags | Staging-only `VIRKI_HUB_PERIMETER_MODE=native`, both passkey flags explicitly `false` until staging RP IDs exist, `CLOUDFLARE_ACCESS_JWT_REQUIRED=false` and no Access audience/team/JWKS inputs; unchanged production `access` behavior and `VIRKI_ADMIN_PASSKEYS_ENABLED=false` | BLOCK |
| Persistence | Committed migrations deployed to **staging only**; restored `_prisma_migrations` names and SHA-256 checksums exactly match every committed migration directory, with no missing/extra/duplicate/unfinished/rolled-back row; least-privilege runtime/worker/migrator accounts, snapshot and restored rollback rehearsal | BLOCK |
| Database authentication | Distinct Hub/worker/migrator/bootstrap principals; **operator/migrator libpq** remote probes require `sslmode=verify-full` and an approved `sslrootcert`. **Hub/worker Prisma 6** URLs instead require `sslmode=require&sslaccept=strict&sslcert=<approved image CA path>`; their Linux engine's actual CA-chain and hostname/SAN verification remain **BLOCK** pending observed positive/negative TLS tests. Exact database/user `hostssl` `scram-sha-256` HBA rules prohibit trust/cert/MD5 and broad/group fallback. Rollback bootstrap uses the staging-only superuser and two exact local `peer` rules (one for `postgres`, one for the fresh restore DB), with no options/includes and a verified canonical HBA reload after file modification | BLOCK |
| Worker and SMTP | Separate staging relay credentials, approved recipient allowlist, TLS authentication and connectivity checked **before enabling the mail-draining worker** | BLOCK |
| Recovery safety | Old-email loss path tested without using third-party inbox access; independent ADMIN elevation and no self-review | BLOCK |
| Monitoring | Redacted application security audit, queue status, SMTP attempts and externally observed events; no OTP/secret in logs | BLOCK |

**Mail-worker-disabled staging:** the source's `stage` action starts only
`public-site`, `hub`, `oidc-issuer`, and `session-cleanup`; it explicitly
refuses an already-running `email-worker` before and after health checks.
It does **not** start, stop, or provision the worker, nor authorize SMTP.
There is no implicit transition from staging health to mail delivery.
The normal production `deploy`/`start`/`restart` paths still start the
mail worker before final HTTP checks; those paths are **not** substitute
staging procedures. HTTP/port health does not prove SMTP delivery, and
rollback cannot retract an OTP already accepted by the relay. The operator
must independently prove the worker-specific database role, relay TLS/AUTH,
test-recipient allowlist, account and provider rate budget **before** any
separately authorized mail drain. Do **not** execute the generic production
deployment script as an unreviewed staging provisioner. Do not send a
diagnostic to an unapproved address. A local preflight is not permission to
send the first real OTP.

**Passkey staging blocker:** the source candidate adds a strictly
opt-in staging RP resolver in `packages/auth/src/passkeys.ts`, shared with
recovery liveness checks. Production defaults remain USER
`portal.biel.dev.br` and ADMIN `hub.biel.dev.br` without opt-in. A staging
opt-in requires exactly `VIRKI_STAGING_PASSKEY_RP_ENABLED=true`,
`NODE_ENV=production`, `VIRKI_HUB_PERIMETER_MODE=native`, and separate,
canonical, explicitly configured `VIRKI_PORTAL_HOSTNAME` and
`VIRKI_HUB_HOSTNAME` values that are not either production RP. An invalid
opt-in rejects both roles; `VIRKI_PASSKEYS_LOCAL_TESTING` is **never** a
production substitute. No approved staging RP host pair, external TLS/DNS
validation, real WebAuthn ceremony or independent accepted final source SHA
exists yet. **Keep `VIRKI_STAGING_PASSKEY_RP_ENABLED` unset, both passkey
flags false, and Portal/Hub RP separation BLOCK** until the actual signed
staging inventory and user-agent/browser/role/recovery acceptance are proven.
Source-only unit/route tests do not satisfy this release gate. TOTP-based
recovery may be checked separately but cannot replace passkey acceptance.

The worker uses `VIRKI_EMAIL_MIN_SEND_INTERVAL_MS`, forwarded only to the
email-worker Compose service with its unchanged 250 ms default (valid range:
0–60000 ms). The operator must explicitly review the staging effective value
and provider quota; a syntactically valid value is not evidence of a safe
provider rate budget. No SMTP retry,
`Message-ID`, or queue `SENT` flag alone proves inbox receipt.

### Optional offline attestation-consistency preflight (does not unlock staging)

`scripts/staging-otp-preflight.mjs` is **local-only**. It reads only two
operator-provided JSON documents and two **public** Ed25519 PEM files; it
never reads `.env`, contacts Docker/SSH, SMTP, Cloudflare or any database,
starts a worker, performs an inbox probe or authorizes external operations.
The operator passes the effective SMTP tenant/endpoint/account IDs, host, port,
TLS mode and SHA-256 of the configured SMTP username as explicit non-secret
arguments; the CLI compares these to both signed declarations. The password
is never read, hashed or emitted by this tool.
Stage these four input files in a private directory on a **verified local
filesystem** (0700 directory on POSIX). The CLI rejects UNC paths, symlink
parents, hardlinked files, unsafe POSIX directory permissions and duplicate
JSON member names, including escaped and nested duplicates; it reads via a
bounded, metadata-checked file descriptor instead of re-opening by filename.
This is an input-integrity check, **not proof of a trusted filesystem**:
Node.js on Windows does not expose `O_NOFOLLOW`, and mounted or mapped
network filesystems and races by a process running under the same OS account
cannot be categorically excluded. An operator must rule out those cases
outside this tool. On unverified storage, treat the preflight as **NO-GO**,
even if its signatures and declarations are consistent.
Obtain authorization and independently inspect the target **outside this tool**
first. Do not put real recipient addresses, passwords, tokens, connection
strings, OTPs or transport headers in these documents. Recipient IDs must be
opaque, pre-approved aliases, with mappings held by the authorized operator.

```sh
node scripts/staging-otp-preflight.mjs \
  --approval /approved/offline-approval.json \
  --observation /approved/independent-observation.json \
  --approver-public-key /approved/owner.pub.pem \
  --observer-public-key /approved/independent-observer.pub.pem \
  --expected-source-sha <exact-40-hex-approved-sha> \
  --smtp-tenant-id <opaque-staging-tenant-id> \
  --smtp-endpoint-id <opaque-staging-endpoint-id> \
  --smtp-account-id <opaque-staging-account-id> \
  --smtp-host <approved-lowercase-relay-host> \
  --smtp-port <approved-port> \
  --smtp-secure <true-or-false> \
  --smtp-username-sha256 <sha256-of-configured-smtp-username>
```

The approver and independent observer must sign their JSON payloads **out of
band**, with distinct, separately vetted/pinned Ed25519 public keys. The JSON
envelopes have exactly `version: 1`, `approval` or `observation`, and a base64
`signature`; the Ed25519 signature covers UTF-8
`Virki staging OTP approval v1\n` or
`Virki staging OTP observation v1\n`, followed by the payload's recursively
key-sorted compact JSON. The export `canonicalStagingJson` implements this
encoding; the synthetic, entirely local specimen is in
`scripts/staging-otp-preflight.test.mjs`. Never pass a private signing key to
this verifier or treat an arbitrary operator-supplied public key as a
pre-established trusted anchor.

The schema is exact-key and fail-closed: older approvals/observations that do
not contain the current worker-resource and SMTP tenant/endpoint/account,
runtime fingerprint and relay-authentication evidence fields are invalid.
Reissue and independently sign both complete canonical payloads; never append
fields to an already signed document or reuse an earlier signature.

The signed **approval** binds distinct owner, operator and observer IDs,
observer public-key SHA-256 fingerprint, UTC approval window and exact source
SHA. It separately binds the immutable worker and Hub OCI digests, distinct
worker and Hub Compose project identities, and the SHA-256 of the exact
Hub-only Compose file. The staging host, database host/name, three disjoint DB
role IDs, SMTP tenant/endpoint/account IDs, exact SMTP host/port/TLS mode,
SHA-256 of the SMTP account username, and Docker network ID are bound
separately from their production comparison identities. The SMTP password is
never included in the signed documents. The Hub and worker must share the
approved staging network, while that network must differ from production. The
approval also binds the opaque recipient allowlist/policy ID, worker interval,
provider per-minute quota and an absolute per-run handoff budget. It binds a
worker resource-policy ID and exact positive memory-byte, CPU-nanocore and PID
limits; these values must match the standalone Compose inputs and the physical
container's effective `HostConfig`. Production comparison values are
attestable non-secret identifiers only, never production credentials.

The independently signed **observation**, no older than five minutes, must
match that authorization's source, both OCI digests, both Compose project
identities, Hub Compose file hash and staging host/database/network target,
then independently attest:

- Worker `stopped`, zero running replicas, restart and autostart disabled,
  **no outbox drain begun** and a separately documented worker observation;
  the virgin pre-drain outbox has zero queued, processing, retryable, sent,
  terminal messages **and zero delivery attempts**.
- Exact worker resource-policy ID, independent resource-policy evidence
  reference, and memory/CPU/PID limits equal to the signed owner approval.
  Missing, zero, changed or unbounded limits fail closed. The offline verifier
  proves only that the two signed declarations agree; the operator must still
  compare the actual Docker `HostConfig` values on the staging host.
- Effective interval `1..60000` ms in the worker **alone**, together with the
  entire expected Compose service-name inventory, without rendering secrets.
- Provider/relay **hard-enforced** recipient allowlist and rate/attempt caps,
  a separately evidenced rejection of an unlisted recipient, remaining quota
  and exact agreement with the approved opaque recipient IDs. The relay
  observation must independently verify SMTP authentication against the
  approved tenant and bind its tenant, endpoint, account, host, port, TLS mode
  and username fingerprint to the owner approval, with a separate opaque
  `smtpAuthenticationEvidenceRef`. The CLI also compares the
  actual worker SMTP host/port/TLS mode and SHA-256 of its configured username
  to those signed values; it never accepts or hashes the SMTP password. No
  email is sent by this command; provider observations belong to a separately
  approved collection window.

Failures return `STAGING_OTP_PREFLIGHT=BLOCK:<reason>` and exit nonzero,
without echoing document contents. A consistent pair returns only
`SIGNED_OFFLINE_DECLARATIONS_CONSISTENT`, plus explicit
`LIVE_WORKER_STATE=NOT_OBSERVED_BY_THIS_TOOL`,
`STAGING_AUTHORIZATION=NOT_GRANTED_BY_THIS_TOOL` and
`PRODUCTION_RELEASE=NO_GO`. **Signatures prove provenance of the supplied
declarations, not that their contents were honestly observed, that the worker
is still stopped, that the actual OCI digest was loaded, or that external
provider controls operate.** The real target, trust anchors, effective
runtime policy and all external acceptance gates still require separately
authorized, current human/independent verification; a stale observation
cannot be reused to permit mail draining.

Run the side-effect-free negative/mutation contract locally with
`node --test scripts/staging-otp-preflight.test.mjs`. This does not run E2E,
contact a provider or waive **RELEASE NO-GO**.

## 3. E2E acceptance: separate normal vs administrative passwords

On the **authorized** staging digest only, collect HTTP/browser, PostgreSQL,
audit and sanitized outbox evidence for independent test users. Use a fresh
browser profile and no Cloudflare Access JWT/JWKS synthetic server in native
mode. Every case needs an explicit PASS/FAIL (never a silent SKIP):

1. **Normal USER/ADMIN login-password recovery:** prove both roles, without
   exclusive dependence on the original mailbox; correctly configured TOTP;
   separately mark Portal/Hub passkey relying-party separation BLOCK until
   dedicated staging RP IDs/origins are available; and,
   where required, authorization by a **different**, active, independently
   elevated ADMIN. Prove verified replacement-mailbox OTP before commit,
   new normal password in a fresh browser, old password/session/trusted
   device denied, replay/expiration/unknown identity denial and self-review
   rejection. Test USER `TOTP_ADMIN` and `PASSKEY_ADMIN` separately; an ADMIN
   RP passkey test is not evidence of a USER Portal RP passkey test.
2. **ADMIN separate credential — verified original-mailbox OTP + current
   normal password:** demand existing ADMIN login session+MFA, fresh session
   CSRF and the current normal password both to request and to complete;
   verify actual worker SMTP attempt and independent recipient confirmation;
   reject wrong/expired/revoked/replayed OTP or changed mailbox/session;
   persist the replacement administrative hash, rotate exactly ten stored
   recovery-code hashes and deny every old code and old password.
3. **ADMIN separate credential — unused administrative recovery code +
   current normal password:** reject absent/used/revoked code, wrong normal
   password, stale session, wrong USER role, self-authorization and replay;
   prove concurrent same-code submissions cannot both rotate. Persist ten
   new codes, reject all old codes and prevent a second successful audit.
4. **ADMIN separate credential — ACTIVE TOTP + current normal password:**
   verify current counter and authenticator state, reject old/expired/used
   counter, revoked/missing credential or factor, wrong normal password,
   concurrent replays and privilege mismatch. Preserve the legitimate active
   TOTP for future login; persist ten new administrative codes.

For each administrative method, prove the normal login password remains
unchanged; prior active or pending privileged elevations and affected sibling
sessions/devices are revoked; an administrative mutation **fails without** a
fresh matching elevation; the old administrative password cannot elevate;
the new password + real MFA can obtain a new scoped elevation and subsequently
authorize the matching protected mutation. A database hash assertion alone
does not prove any of these interactive effects.

## 4. Authentic OTP chain, with no code or link disclosure

Under the approved external test, correlate these **distinct** observations:

1. Virki action returns a **non-secret** event status, with identity, session,
   role, and request isolation verified server-side. The raw recovery
   `requestKey`, action/CSRF tokens, raw idempotency keys and signed URLs are
   capabilities; never put them in operator logs or evidence exports.
2. Staging database has the matching outbox row, correct OTP category,
   recipient binding and bounded age, and at most the intended active
   ceremony. Record aggregate row counts and a separately salted HMAC of
   internal row IDs; never export encrypted payload or decrypted OTP. A
   generic outbox ID is not by itself a durable request-to-provider join.
3. The dedicated worker records one legitimate claim/CAS winner and the
   attempt state. Verify SMTP TLS/authenticated relay and report a sanitized
   RFC `Message-ID` only if provider diagnostics can match that header.
   A reserved `Message-ID` on a FAILED/interrupted attempt is **not** proof
   of SMTP acceptance. Treat uncertain-at-least-once outcomes explicitly.
4. The relay/provider supplies a distinct sanitized acceptance/event record.
   Its provider-specific message ID is **not** automatically the SMTP header
   `Message-ID`, and an SMTP `250` is **not** final mailbox delivery.
5. The recipient of the **authorized test inbox** independently confirms
   the actual Virki-generated OTP email. Sender, subject and approximate
   receipt time alone are **insufficient** to distinguish retries or
   concurrent messages. Require a distinct non-secret, end-to-end matched
   RFC `Message-ID` or an equivalent provider-to-inbox trace identifier
   confirmed through the authorized recipient's safe mail-client metadata;
   if unavailable, mark `OTP_CORRELATION_UNPROVEN` and **BLOCK** the acceptance,
   rather than inferring a join from time or subject. Never share full raw
   headers or request an OTP, recovery link, capability, mailbox credential
   or any sensitive transport metadata.

The previously confirmed Brevo diagnostic marker `672c634dc954` proves only
receipt of that earlier diagnostic, **not** a genuine Virki OTP. Do not
resend it or relabel its evidence. Do not access third-party inboxes.

## 5. Rollback and final release gate

Keep an owner-approved snapshot and tested restore procedure; compare
test-only user/session/recovery/elevation, outbox, sent-attempt and audit
counts before and after staging rollback. The local production migration
snapshot now hashes **every** outbox message kind and corresponding delivery
attempt, including lease expiry and SMTP Message-ID; the disposable dump/restore
fixture exercises recovery, ADMIN verification, mailbox rebind, notices and
an interrupted in-flight worker lease. These are local integrity checks, **not**
evidence of an independently provisioned staging host, actual provider
delivery or an owner-approved staging rollback. The staging operator must
independently inventory every test-only email kind, attempt and processing
lease before and after its own restore, keep the mail worker disabled until
pending/uncertain sends are reconciled, and preserve redacted audit evidence.
Never restore production from a staging snapshot, nor let an old worker resume
sending uncertain pending messages after a rollback.

Evidence must be labeled with exact SHA, OCI digest, UTC timestamps, host
ownership, test DB identity, PASS/FAIL/SKIP counts, scoped redacted audit
events, worker/SMTP status, provider receipt distinction, recipient's actual
inbox confirmation, independent security review, rollback result and explicit
operator/owner approvals. Restrict access to the evidence repository; mask
recipients and avoid plaintext secrets, OTPs, cookies or bearer keys.

**Release decision: NO-GO** until (a) exact-SHA hosted native Chromium 3
PASS/0 FAIL/0 SKIP, (b) every required original-mailbox-independent and
ADMIN-credential method passes physical staging E2E, (c) real OTP traverses
outbox→worker→SMTP/provider→authorized inbox with independent confirmation,
(d) independent security review and rollback rehearsal pass, and (e) the
owner expressly approves the final production switch. A static checklist,
code review, unit test or DNS observation cannot waive any of these gates.
