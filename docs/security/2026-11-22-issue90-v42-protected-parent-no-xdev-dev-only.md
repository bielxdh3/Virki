# Issue #90 — V42 DEV-only: refuse cross-mount protected publication destinations

V42 is an incremental hardening patch against the immutable V41 cumulative BuildKit tree `bd76aa00d4a62fa04523f4be26692de11dfb229d`. V23–V41 patch bytes, hashes and Git trees are unchanged. Its cumulative tree is `b6231f822efcd8f0be7956c93e189a30418c51b4`; the patch SHA-256 is `abe97dbc03449866e1349cc6280aecc0b9aef45ca80f28eeebb6c7af60e20f00`.

## Security boundary

The V36/V38 root-owned publication routine already checked the source using bounded `openat2` resolution, but resolved the protected destination's parent without `RESOLVE_NO_XDEV`. V42 adds that constraint alongside `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS` so publication refuses bind/FUSE/tmpfs crossings relative to the supervisor's root directory descriptor. It does not bypass the refusal on error or attempt alternate publication paths.

Positive synthetic privileged fixtures V36–V38 use `/var/tmp`, which shares the supervisor filesystem on the tested WSL environment, instead of the separately mounted `/tmp`. A new V36 root fixture creates an otherwise root-owned private destination under the `/tmp` cross-mount and verifies `EXDEV`, absence of publication, and refusal before the protected parent is pinned. Where `/tmp` shares the same filesystem, that negative fixture skips rather than claiming a cross-mount proof. This is an environmental test, not proof of every bind mount or malicious mount namespace.

## Verification and limits

Privileged WSL root `go test -mod=vendor -race` V36–V40 fixtures passed, including the cross-mount subtest, V39 peer authentication and V40 integrity/recovery regressions. The full `session/filesync` race suite and `go vet -copylocks=false` also passed. The issue #119 HTML `<select>` parser false-PASS regression is a separate worktree change, validated in the offline Node suite.

V42 remains **DEV-only and unwired**. Neither path protection nor V40's root-local checkpoint demonstrates root-independent monotonic rollback protection. C4 V3 signed candidate verification explicitly does not grant actual release authorization; it must never be converted into a V15 test-domain publication permission. Real owner-signed release, deployment custody, and operational proof are still missing. Protected production C1/C4: **NO-GO**. No merge, deploy, or administrative issue closure is authorized by this patch.
