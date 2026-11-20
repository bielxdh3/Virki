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
- Ordinary synthetic regression tests (`session/filesync/sealed_custody_v24_linux_test.go`): `TestC1V28LauncherResourceAndIdentityRefusals`, `TestC1V28IndependentCustodyPolicyRefusals`, and `TestC1V28AdversarialCustodyBoundaryRefusals`.
- Multi-process cross-UID concurrent swap race test (`session/filesync/sealed_custody_v24_independent_linux_test.go`): `TestC1V28AdversarialMultiProcessCustodyAndSwapRace` (3 distinct unprivileged UIDs: receiver `60001`, sender `60002`, concurrent peer `60003` racing symlink/mkdir/write/rename swaps around publication).

## Evidence and remaining limits

- Incremental V28 patch SHA-256: `0cdf12e672acf0c2b405aec34737476c7b567f44487f63ebd0903eed7087b244`, V28 tree `c7234b862c991a940c3047f05a6f2752d7fd1e6f`.
- Ordinary V24/V28 Go tests, `-race` across 3 packages, and Windows `go vet -copylocks=false` passed locally in WSL; `TestC1V24IndependentReceiverProcess` and `TestC1V28AdversarialMultiProcessCustodyAndSwapRace` passed inside an isolated `--network none` Linux container.
- Protected FileSync remains disabled in production; merge, issue closure, and production activation require explicit owner authorization.
