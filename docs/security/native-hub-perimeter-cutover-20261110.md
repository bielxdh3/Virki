# Native Hub authentication perimeter — isolated candidate, not production approval

Date: 2026-11-10. Based on the approved PR #117 code SHA
`b43abfa514a97c494984b9d3b871732a5e6d2364`, in a separate child worktree.

## Scope and activation

`VIRKI_HUB_PERIMETER_MODE=native` explicitly selects the Virki-authenticated
Hub perimeter. An absent, misspelled or different value retains the prior
Cloudflare Access JWT requirement. No Cloudflare policy or production config
was changed by this candidate.

In native mode, the application's Hub ingress no longer requires a Cloudflare
Access JWT for `/login`, `/login/verify`, `/recover`, or their public server
actions. The normal Virki ADMIN password, fresh second factor, session and
role checks remain in place. Protected Hub pages still require a valid ADMIN
session, and sensitive mutations still enforce same-origin/session CSRF and
any required independent privilege elevation. Unknown host and production
loopback denials, Portal/Hub RP separation and security headers are unchanged.
Caller-supplied Access JWT assertions are removed at the native Hub ingress.

**Important:** This only changes the **application**. Existing Cloudflare
Access protection at `hub.biel.dev.br` still intercepts browsers at the edge.
Removing or migrating that edge application is a separate high-risk operator
change requiring explicit owner authorization and rollback; this commit does
not call the Cloudflare API or reconfigure any production traffic.

## External acceptance before cutover

1. Review the native Hub entry points, account enumeration, credential-reset
   ceremonies, privilege elevation and reviewer role checks with an independent
   security reviewer. Do not assume passing proxy unit tests proves end-to-end
   security or delivery.
2. Prove a genuinely isolated staging deployment (dedicated host/PG, mailbox,
   identities and Cloudflare edge route), exact code SHA and configured mode.
3. In an isolated external browser exercise lost-original-inbox ADMIN recovery
   with two independent factors or a different actually elevated ADMIN;
   separately verify all three ADMIN-credential recovery modalities (each with
   the *current normal password*), new privilege elevation and protected action.
4. Prove USER/ADMIN recovery races, replay, CSRF, session and remembered-browser
   revocation, expiry, rate limiting, missing/revoked factors, passkeys and
   strict Portal/Hub origin/RP separation. Require a clean browser without any
   Cloudflare Access cookie to complete the intended native flow.
5. Before cutover, review operator ownership and rollback, ingress restrictions,
   audit integrity, deployment provenance and security monitoring. Keep
   `VIRKI_ADMIN_PASSKEYS_ENABLED=false` in production until separately approved.

## SMTP correlation limit

New delivery-attempt metadata may store a strictly validated RFC `Message-ID`
header returned from Nodemailer. It contains no OTP or email body. This is
**not** the Brevo provider `mid`, an SMTP delivery receipt, or proof of inbox
receipt. The Brevo event and the recipient's inbox confirmation still require
separate authorized evidence. The nullable database column requires a reviewed
forward migration before deployment.

The SMTP client now derives the header identifier deterministically from the
persisted opaque outbox ID and claimed attempt number, using the verified
sender domain. If SMTP accepts a message but the process crashes before the
delivery-attempt row commits, the first header identifier can be recalculated
from the durable outbox attempt history, while a reclaimed send uses a new
identifier. The recovery outbox's migration sentinel projects this optional
metadata through `to_jsonb(attempt)` so it remains compatible both before and
after the nullable column is added. This improves correlation only: it cannot
establish that a recipient received an OTP.

**Decision: draft implementation only. No release, deploy, Cloudflare policy
change or externally hosted E2E authorized by this document.**

## Owner and recipient evidence received on 2026-11-10

- In the conversation, the owner answered **"Sim"** to the pending authorization
  to replace production Cloudflare Access with the native Virki perimeter **only
  after isolated staging and the required security validations pass**. Treat
  this as conditional owner approval of the intended direction, **not** as
  permission to cut over now, use real credentials, deploy to production or
  bypass the external release gates. Exact resources, rollout and rollback must
  still be approved and documented at execution time.
- The recipient supplied a Gmail screenshot showing an **Inbox** message from
  `no-reply@biel.dev.br`, subject
  `Virki - teste diagnostico de entrega SMTP (672c634dc954)`, body mentioning
  the same diagnostic marker and an interface timestamp of **1:34 AM**, with a
  relative label of **8 hours ago**. This supports actual recipient-inbox
  presence of the **previously sent diagnostic**, not merely SMTP acceptance.
  Screenshot evidence is user-supplied, not an independently authenticated
  mailbox API record; absolute timezone and RFC Message-ID are not available.
- This screenshot is **not** proof that a Virki-generated recovery OTP from
  the approved PR SHA was received. That separate end-to-end correlation
  (application/outbox, worker, Brevo and recipient) remains pending, as do
  isolated staging and external ADMIN/USER recovery acceptance tests.
