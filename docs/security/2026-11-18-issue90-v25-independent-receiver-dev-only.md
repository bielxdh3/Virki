# C1 V25 — independently supervised DEV receiver integration (2026-11-18)

## Disposition

DEV-only. A positive integrated Linux transfer now succeeds between two distinct, unprivileged process identities. This is not a closure of issue #90, a proof of resistance to adversarial filesystem races, or permission to enable protected FileSync. All production gates remain NO-GO.

## Provenance

- Virki parent: `756659a25c3b6b19d7fe6e77c83edde773626792`.
- Pinned BuildKit upstream: `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`.
- Apply the existing V23 patch, corrected incremental V24 patch, then `docs/security/experiments/buildkit-v0.34.1-c1-v25-independent-receiver-dev-only.patch`.
- V24 SHA-256: `9CF15BCA430A121C1FD8722499BF8D587179B96855E6BBE6AE299A1C74DE3587`.
- V25 SHA-256: `32BE63C7D2265F3E477241AF44F78E20E5B5E37F20D3B89A743BCC222294A18D`.
- Corrected V24 tree: `d4b9e014f42deaa152bc7e3be3175080f1ddb271`; V25 tree: `b0bcf49bf41ece17080aeba5a4f218f0cb165fb1`.

## Implementation

The explicit DEV entry point FSSyncSealedV24 invokes the existing sealed FileSync receiver under a trusted supervisor-provisioned identity. It requires separate configured sender and receiver ownership, a non-root receiver, no supplementary groups, inherited NoNewPrivs, a private receiver directory, and a root-controlled enclosing directory. The strict path validates configured wire ownership before mapping metadata to receiver ownership; manifest, packet, byte, replay and publication checks remain in place. The earlier V15 DEV fixture path remains separate and is not an independent-custody authorization.

The opt-in synthetic integration fixture runs two unprivileged processes on Linux under a temporary privileged test supervisor and uses a private inherited socketpair with the existing gRPC session. The fixture verifies both identities, absence of supplementary groups, NoNewPrivs, actual transfer, resulting bytes and receiver ownership. It creates no persistent accounts, exposed listener, or external network connection.

## Verification

- Targeted ordinary V24 suite: 4 PASS, privileged fixture SKIP by default.
- Opt-in root-supervised positive multi-UID fixture: PASS, separately PASS with the race-enabled binary.
- Targeted V24 race suite: PASS, with privileged fixture explicitly skipped and separately exercised.
- Linux and Windows-target go vet with copylocks disabled: PASS. Existing copylocks finding is excluded, not fixed.
- V25 patch: clean-index apply check, application, tree equality and reverse check PASS; reverse check against the scratch PASS.
- No independent external review was performed in this single-agent round.

## Remaining boundaries

This is positive ordinary integration evidence from WSL/Linux with a trusted synthetic supervisor and an explicit DEV entry point. It does not attest production provisioning or the full lifetime of receiver custody under hostile concurrent filesystem mutation, and does not replace the unresolved adversarial/mount acceptance criteria. No vulnerability reproduction or offensive test was performed. No protected feature activation, publication of the experimental branch, merge, issue closure, or deployment is authorized or performed.
