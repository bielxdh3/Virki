# Issue #90 — V44 DEV-only: C4 candidate signatures cannot authorize V15 publication

This incremental V44 patch adds **negative compatibility tests only** to the pinned BuildKit experimental tree. V23–V43 patches and their SHA-256 checksums/trees are unchanged. The V44 patch checksum is `cb02a52d42bcba6d31c5c4e3520c787ebe9c752151fee6dc3e806c146dfcff22` and its cumulative Git tree is `a3e5add39cd2ac188314ba4b79294a391cc7fc4c`.

## Boundary exercised

Native C4 V3 uses Ed25519 signed-message domains `VIRKI_OFFLINE_OWNER_APPROVAL_V3` and `VIRKI_C4_CANDIDATE_RECEIPT_V3`; a candidate-verification receipt explicitly denies release (`deployAuthorized=false`, `releaseSignature=false`). The BuildKit V15 synthetic owner permit has a **different test domain**, manifest scope and replay ledger. A cryptographically valid signature in a C4 approval/receipt domain is not a valid V15 permit, even when signed by the same Ed25519 key.

The nonroot V44 test verifies that real V15 test permits are accepted only in their exact domain and frozen-manifest scope while C4-domain signed messages are refused. The opt-in privileged root test provisions a disposable root-only V40 key/checkpoint and empty claim ledger, attempts both foreign-domain signatures, and asserts **no claim, checkpoint mutation or permit burn**. It then admits one genuine V15 test permit and rejects its replay. This is a negative proof against accidental signature-domain substitution, not a complete bridge to native C4 approval semantics.

## Validation and limits

Linux/WSL Go 1.26.10 offline `-race` targeted V44 tests passed (including privileged V40 ledger checks), and Go vet for `session/filesync` passed. CI now selects both V44 tests inside the mandatory root fixture and refuses skips, plus validates the cumulative patch tree.

**This does not authorize production C1/C4.** V44 adds no release gate, trusted cross-application approval translation, signed destination/OCI/worker binding, independent monotonic rollback witness, networking, deployment or owner-controlled signing. Root-local HMAC checkpoint V40 and candidate-only C4 V3 receipt are not interchangeable with an actual production owner release. Protected publication remains **NO-GO**, and neither issue #90 nor #119 is ready for administrative closure on these tests alone.
