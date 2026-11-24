# Issue #90 — V54 saved UID/GID guard (DEV/TEST only)

## Finding

The V53 receiver policy checked only real/effective UID and GID. It did not
inspect the saved IDs. A receiver launched with real/effective UID/GID set to
the expected nonroot identity but saved UID/GID still equal to zero could pass
those checks. A Linux reproduction with zero permitted/effective capabilities,
empty supplementary groups, `NoNewPrivs=1`, and dumpability disabled still
restored effective UID 0 with `setuid(0)` and opened a root-only file.

This is a conditional receiver-isolation gap: the existing V53 fixture uses
`SysProcAttr.Credential`, which drops the saved IDs too, so the prior physical
V52/V53 tests did not exercise this launcher edge case. It is not evidence of
production exposure; the V53/V54 patch chain remains exclusively DEV/TEST.

## Correction

V54 is additive and leaves the published V53 patch unchanged. The receiver
now obtains `getresuid()` and `getresgid()` and requires real, effective, and
saved IDs to all match the supervisor-assigned nonroot identity. The policy
rejects saved UID/GID 0 and any other real/effective/saved mismatch before the
receiver opens the FileSync stream.

## RED → GREEN evidence

- RED: the extracted real/effective-only predicate accepted both
  `saved-uid-root` and `saved-gid-root` cases; the new regression failed in
  those two subtests while the fully-dropped control passed.
- GREEN: after checking all six IDs, the regression passed 3/3 subtests under
  `go test -race`.
- Tagged `go vet` passed for `session/filesync`, `util/localcontext`,
  `cmd/buildkitd/config`, and `cmd/buildkitd`.
- The Linux credential PoC independently confirmed that saved UID 0 can be
  restored even with `CapPrm=0`, `CapEff=0`, `NoNewPrivs=1`, and
  `PR_SET_DUMPABLE=0`.

The hosted workflow applies V54 only after verifying the immutable V53 tree,
then verifies the V54 tree and requires the saved-ID regression together with
the existing V52/V53 physical root fixtures. SKIPs are rejected.

## Patch receipt

- Patch: `infra/offline/patches/buildkit-v0.34.1-c1-v53-to-v54-saved-uid-guard-dev.patch`
- SHA-256: `273e94f1a3f18118377fd8d709f6f3088809a2358190300aedbfc91411f70a48`
- V53 source tree: `c399a293604e2a55d695c5f73b89a2bbc7906e35`
- V54 result tree: `5d5ae2375e43bd1eed89e462ed184ae7466d9448`

The zero-context patch is applied with `git apply --cached --unidiff-zero`
to the exact V53 tree, without conflicts; the resulting Git tree matched the receipt.

## Limits

V54 is a local DEV/TEST candidate only. It does not establish owner-approved
C4, production process-launch integration, production FileSync authority,
solver/OCI end-to-end authority, deployment identity, or public-edge security.
No merge, deploy, cutover, Cloudflare, DNS, or tunnel change was made.
Production remains **NO-GO** and issues #90/#119 remain open.
