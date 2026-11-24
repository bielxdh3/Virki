# Issue #90 — V45 DEV-only: retain full Go vet coverage in packet-receiver fixtures

V45 is a **test-only** incremental BuildKit hardening after the immutable V44 cumulative tree `a3e5add39cd2ac188314ba4b79294a391cc7fc4c`. Its SHA-256 patch checksum is `63a4f9f0b3f68ae58a44ec529b48e2d216e4816a93b5e2dbd765cb48d00c5200`; cumulative tree `7952e6dc2599b447fa97b86dda77e27416de8c7e`. None of the V23–V44 patch bytes, hashes or trees are modified.

In `sealed_guard_v15_test.go`, the fake gRPC packet stream previously copied a generated protobuf `types.Packet` by struct assignment. Generated protobuf messages embed synchronization/message-state fields, so Go vet correctly reported a `copylocks` violation. The test fixture now uses `proto.Reset` followed by `proto.Merge` into the receiving packet, preserving the wire-receive behavior without copying message-state locks or aliasing the original packet. This changes no production FileSync behavior and no cryptographic verification rules.

Previously, selected runs disabled the `copylocks` vet analyzer; after this patch, the mandatory hosted CI step runs **unrestricted `go vet -mod=vendor ./session/filesync`**. Local WSL Linux Go1.26.10 default vet and full `session/filesync` `-race` test suite passed. The V44 privileged root proof continues to be selected without skips. The replay index now validates **23 immutable incremental patches, V23–V45**.

This fixture-quality improvement is not a C4 release implementation or proof of independent monotonic rollback. Owner-signed release binding, live C1/C4 operational custody and deployment remain separate, explicit owner gates; protected production publication is **NO-GO**.
