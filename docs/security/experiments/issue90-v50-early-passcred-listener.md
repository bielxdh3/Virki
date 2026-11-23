# Issue #90 V50 — prepare AF_UNIX credentials before accept (DEV-only)

V49 prevents an inherited AF_UNIX connection from impersonating the original
sender via `SCM_RIGHTS` and consuming a durable test permit. However, the
receiver enabled `SO_PASSCRED` **inside** its FD-read function. This was
too late for messages already queued by a legitimate sender on native Ubuntu.

## New native CI RED and minimal reproducible RED

The original V49 GitHub-hosted Validate job on commit
`b02e79789f6d7d315b7d327d27566415c392b49d` actually failed its
existing positive `TestC1V37AuthenticatedUnixRightsHandoff/authenticated-one-fd`
and `TestC1V39DurableTestPermitAndAuthenticatedPublication/authentic_peer_is_admitted_only_after_durable_claim`,
with `C1 V49 refused malformed or sender-mismatched FD handoff`.
Adversarial inherited-socket refusals passed. This is a real false refusal of
valid peer credentials, not permission to bypass authentication.

A V50 test-side invariant, `v50AssertPasscredPrearmed`, independently
reproduced RED on WSL2: a newly accepted Unix socket had `SO_PASSCRED=0`
before the receiver touched it; the V37 and V39 positive fixtures failed the
new check. The previous success on WSL2 depended on a kernel behavior not
guaranteed for already-queued control messages on Ubuntu CI.

## V50 correction and GREEN

The new production helper `v50ArmPasscredBeforeAccept` sets
`SO_PASSCRED` on the *protected listening socket* before any external
sender may connect. The accepted socket is verified to inherit this policy;
the receiver refuses if the option was not already armed, **rather than**
enabling the policy after untrusted messages may have entered the queue.
Legitimate test peers now receive one kernel `SCM_CREDENTIALS` and one
`SCM_RIGHTS`; unrelated or inherited-process senders still fail closed.

The V37, V39 and V49 tests now deliberately arm the listener before exposing
its path, then assert the option on every accepted connection before invoking
the receiver. The original deny cases remain unchanged and run normally;
V49 still requires matching actual sender PID/UID/GID and validates the FD
before claiming its durable DEV permit.

V50 is an independent, additive patch applied after V49. The original
V23–V49 patch files remain byte-for-byte unchanged. The patch-index replay
attests the pinned V49 tree
`c02dad283db232bba7f02128e88697feeea6dffa` and the new V50 tree
`6d2225efbfd67865e08a726678b1a13361441eb5`.

These fixtures are **not** production-authority signoff. The real deployment
still requires protected listener ownership, a trustworthy supervisor,
independent process lifetime evidence (rather than numeric PID alone), owner
key custody and monotonic anti-rollback proof. This work authorizes no merge,
deployment, C1/C4 activation or issue closure.
