# Issue #90 — V43 DEV-only: portable cross-mount regression fixture

The hosted `Validate` job for SHA `e07a8d2fbfdde89f34b45c054a34fa62ffcc4220` failed because its root filesystem and `/tmp` share a device number. V42's cross-mount negative test therefore **skipped**, which correctly violated the mandatory CI `! grep '--- SKIP:'` invariant. This was a fixture-environment mismatch, not a failed V42 permission or authorization check.

V43 changes only `session/filesync/sealed_publication_broker_v36_linux_test.go`. The privileged negative fixture checks `/dev/shm` first, and `/tmp` second, accepting a candidate only if `st_dev` differs from the trusted root's. It then creates a root-owned private destination and requires the V42 protected `openat2` to reject it with `EXDEV`, with no publication. If no separate writable mount exists, the test still skips (and hosted CI still fails): it never fabricates cross-device proof.

V42's immutable patch checksum and Git tree are unchanged. V43 incremental patch SHA-256 is `f180f1af520eed9ba34fd52987b7ea58cc4799f51905856eac9a6a9e2ec9f71c`, cumulative Git tree is `5c732ac1f0873141eacfc88cc2f222f543fd4d6d`. Local WSL root `-race` test V36 including the negative fixture and `go vet` passed. This change is **DEV-only** and does not imply C4 production release or root-independent monotonic rollback safety.
