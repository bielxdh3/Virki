# C1 V28 — DEV-only supervisor resource and identity hardening (2026-11-19)

## Disposition

V28 hardens launcher resource handling and supervisor policy checks on top of V27. Protected FileSync remains disabled. Issue #90 and PR #133 remain NO-GO for merge or production.

## Changes

- `runV24IsolatedSubprocessWithFiles` (`session/filesync/sealed_custody_v24_linux.go`):
  - Verifies the helper executable via `os.Lstat` as a non-symlink regular file without group/world write bits (`0022`).
  - Rejects `nil` entries in inherited `files` before process creation.
  - Rejects identical `ExpectedReceiverUID` and `ExpectedSenderUID`.
  - Verifies `PrivateTempDir` via `os.Lstat` as a real `0700` directory owned by the receiver identity (not a symlink, permissive directory, or foreign-owned directory).
  - Refuses `RequireUnprivileged` launches as root (`euid == 0`) without an explicit `ExpectedReceiverUID`, and refuses mismatched `ExpectedReceiverGID` when `ExpectedReceiverUID == os.Geteuid()`.
  - Rejects `extraEnv` overrides of `TMPDIR`, `PATH`, `HOME`, `LC_ALL`, `LD_*`, empty keys, or NUL/malformed entries.
- `validateV24IndependentCustody`: requires `PrivateTempDir` to be distinct from `filepath.Dir(dest)` (including nested paths under `PrivateTempDir` or `dest`) during policy validation (before runtime kernel/group checks).
- Ordinary synthetic regression tests (`session/filesync/sealed_custody_v24_linux_test.go`): `TestC1V28LauncherResourceAndIdentityRefusals` and `TestC1V28IndependentCustodyPolicyRefusals`.

## Evidence and remaining limits

- Incremental V28 patch SHA-256: `0056a98a83cd97060e96efdd004423894f10b388aa951a78687aa6eba9535661`, V28 tree `15ccfac7cc82f7350463465ea9f7e63b6e4a9dd2`.
- Ordinary V24/V28 Go tests, `-race` across 3 packages, and Windows `go vet -copylocks=false` passed locally in WSL.
- Remaining: independent supervisor provisioning/exclusivity, complete peer authentication and descriptor/namespace assurance, privileged multi-UID CI execution, and the unfulfilled issue #90 adversarial acceptance criterion.
