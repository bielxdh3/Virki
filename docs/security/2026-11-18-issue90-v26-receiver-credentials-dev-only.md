# C1 V26 — DEV-only receiver credential hardening (2026-11-18)

## Disposition

V26 hardens the V25 independently supervised receiver. Protected FileSync remains disabled. Issue #90 and PR #133 remain NO-GO for merge or production.

## Changes

- Real, effective and saved Linux UID/GID must agree.
- Independent receiver requires zero effective, permitted and inheritable capabilities (ambient capabilities cannot exist without permitted and inheritable capability membership).
- The launcher requires a configured private temporary directory and rejects a conflicting TMPDIR override. The independent receiver checks the configured directory's ownership and private permissions.
- Positive synthetic cross-UID fixture exercises the new identity/capability checks and private temporary directories for both child processes.
- V24 private-parent-only behavior is a prerequisite, not a claim of same-UID isolation. V25 provides the explicit independently supervised DEV entry point; its historical function name is retained for compatibility.

## Reproduction chain

Apply in order over BuildKit upstream commit `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`:

| Version | SHA-256 of patch | Tree |
| --- | --- | --- |
| V23 | `6B18C0817D315512AF4143A97BF36925A0CF31591B9F67C69654F02C2E524AE1` | Local baseline |
| V24 | `9CF15BCA430A121C1FD8722499BF8D587179B96855E6BBE6AE299A1C74DE3587` | `d4b9e014f42deaa152bc7e3be3175080f1ddb271` |
| V25 | `32BE63C7D2265F3E477241AF44F78E20E5B5E37F20D3B89A743BCC222294A18D` | `b0bcf49bf41ece17080aeba5a4f218f0cb165fb1` |
| V26 | `ED463CD7A1C0F45189A7FA17849DA199E64641A59CCD44F42B5D1906999AE3DB` | `1b0ad7d10b0ef7413a2a72b6bdff5c8b90f51d2f` |

V23 is an unpublished prerequisite; the GitHub PR is not standalone. Local chain reconstruction was verified against the pinned upstream; the incremental V26 patch passed clean-index apply, tree equality, reverse check and scratch reverse check. No hosted Go reproduction claim.

## Evidence

- Ordinary V24 regression tests: 4 PASS, root-supervised fixture skipped by default.
- Targeted race suite: PASS; explicit positive cross-UID integration with race-enabled binary: PASS.
- Linux and Windows-target vet: PASS with `copylocks` disabled. This is an exception for the previously identified V15 finding, not an unrestricted vet pass.
- The ordinary NoNewPrivs test requires the parent thread to start at zero and return unchanged, and checks the child inherits one; it passed in the current WSL environment.

Remaining: supervisor identity provisioning/exclusivity, independent review, complete peer authentication and descriptor/namespace assurance, and the unfulfilled issue #90 adversarial acceptance criterion. The inherited fixture socketpair is supervisor provisioned; its peer credentials must not be mistaken for proof of child identity. No adversarial reproduction, production activation, merge or deployment performed.
