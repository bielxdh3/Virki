# C1 V28 — DEV-only supervisor resource and identity hardening (2026-11-19)

## Disposition

V28 hardens launcher resource handling and supervisor policy checks on top of V27. Protected FileSync remains disabled. Issue #90 and PR #133 remain NO-GO for merge or production.

## Changes

- `runV24IsolatedSubprocessWithFiles` (`session/filesync/sealed_custody_v24_linux.go`):
  - Verifies the helper executable via `os.Lstat` as a non-symlink regular file without group/world write bits (`0022`).
  - Rejects `nil` entries in inherited `files` before process creation.
  - Rejects identical `ExpectedReceiverUID` and `ExpectedSenderUID`.
  - Verifies `PrivateTempDir` via `os.Lstat` as a real `0700` directory (not a symlink or permissive directory).
- `validateV24IndependentCustody`: requires `PrivateTempDir` to be distinct from `filepath.Dir(dest)` during policy validation (before runtime kernel/group checks).
- Ordinary synthetic regression tests (`session/filesync/sealed_custody_v24_linux_test.go`): `TestC1V28LauncherResourceAndIdentityRefusals` and `TestC1V28IndependentCustodyPolicyRefusals`.

## Evidence and remaining limits

- Incremental V28 patch SHA-256: `0333a3045969f532c1cfb052b9dbaa1bcaec610853ebd97880ea9c8d86291461`, V28 tree `2d3ddadc785dc2738c6b2175b7c9bd317d590961`.
- Ordinary V24/V28 Go tests, `-race` across 3 packages, and Windows `go vet -copylocks=false` passed locally in WSL.
- Remaining: independent supervisor provisioning/exclusivity, complete peer authentication and descriptor/namespace assurance, privileged multi-UID CI execution, and the unfulfilled issue #90 adversarial acceptance criterion.
