# Issue #90 — V46 DEV-only: cross-process replay and durable pre-append crash fence

V46 adds regression coverage to the experimental, disabled C1 BuildKit receiver. It is an incremental **test-only** patch on immutable V45 tree `7952e6dc2599b447fa97b86dda77e27416de8c7e`, not a production mechanism. Patch SHA-256: `d3b8743900bac1de7a1f28fecd5927d0d4df6117b134d987613abc8d7003baed`; cumulative tree: `4e8440c77a86e009685717e86194bb4e6a83ff81`. V23–V45 bytes and hashes remain untouched.

## What the root-only Linux tests prove

1. Six independent OS processes attempt to consume the **same** cryptographically valid synthetic V15 test permit against a shared V40 root-owned ledger. The processes use real `flock`/file durability and protected checkpoint paths. Exactly one succeeds, five refuse; the authenticated log and checkpoint agree on exactly one entry and epoch 7, and the transaction intent file is absent after a clean commit.
2. A separate disposable ledger starts with a valid empty checkpoint but a **durably fsynced** `.virki-v40-inflight` marker, simulating an interruption after recording intent and before appending a claim. Two independent restarted processes refuse the unchanged valid test permit. Neither the log nor genesis checkpoint mutates, and the marker cannot be silently repaired. An operator-controlled recovery protocol would be required to proceed.

The suite uses opt-in `VIRKI_V46_RUN_ROOT_FIXTURE=1`, isolated disposable `/var/tmp` roots, no public endpoint, no network peer and no signed production owner approval. It exercises only negative admission properties. Local WSL Linux Go1.26.10 tests ran with `-race`, as did unrestricted Go vet on `session/filesync`. The CI privileged fixture now selects V46 alongside existing V24/V28–V40/V44 tests and rejects **all** skips. The replay index now includes **24 immutable patches, V23–V46**.

**NO production release is authorized.** These tests do not provide independent monotonic owner authority against a compromised root, real C4 release signatures, production UID/mount/listener custody or recovery sign-off; protected FileSync remains disabled/NO-GO until independently satisfied.
