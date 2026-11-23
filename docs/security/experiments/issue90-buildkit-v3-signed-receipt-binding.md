# Issue #90: real BuildKit VROA_V3 signed candidate receipt/request binding (DEV-only)

## Scope and provenance

The immutable original patch
`infra/offline/patches/buildkit-v0.34.1-c1-c4-native.patch`
pins Git tree `a8620ea2ddadbe7125168d8edef8c58cc1b4ddb1` atop BuildKit
`f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`.

The **additive** `infra/offline/patches/buildkit-v0.34.1-c1-c4-receipt-binding-dev.patch`
has SHA-256
`63c3823a50156a4902ff1e5bc12485a221c242f2c4f6da99d95f4954fc7e4ad5`
and yields Git tree `056ddc9815176e137117281e2d360a9c10048296`.
The original native patch, independent historical V23–V50 BuildKit series,
their manifest and replay index remain unchanged. CI verifies both patches
and each tree **before** running the native daemon and Go tests.

## Reproduced defect (RED)

`util/localcontext/service_vroa_v3_linux.go` in the *real* BuildKit consumer
previously accepted any valid Ed25519-signed candidate ack with matching
`approvalEnvelopeSha256` and `evidenceSha256`. The recipient did not bind the
signed ack to the specific request's job, worker, role, nonce, scope, image,
four context digests/lengths, or signed frame epoch/sequence. A valid receipt
for candidate A could therefore satisfy the local verifier for candidate B
where those two SHA-256 values were unchanged. The signed receipt remained
non-authorizing; this is a DEV provenance failure, **not proof that production
publication was enabled**.

An isolated pinned baseline checkout (`a8620ea2…`) was tested with a Go
regression adapted only to the old three-argument API. The positive signed
ack succeeded, but 18 of 20 malicious swaps were **incorrectly accepted**:
job, worker, scope, image, role, nonce, source commit, FileSync manifest,
approval ID/serial, context tree/stream/length, epoch, wrong command, and
unsigned response epoch/sequence/scope. The approval/evidence SHA swaps were
already refused. This is a behavioral RED against the actual old consumer,
not a compilation-failure proxy.

## Correction (GREEN) and integration

`VROAV3Service.Complete` now passes its exact native `vroaV3RequestFrame` to
`verifyReceipt`. The verifier checks Ed25519 signature, candidate-only
non-release flags, signed approval/evidence bytes, the expected scope, job,
worker, role, nonce, approval identifiers, source/plan/policy, image and
FileSync claims, four context tree/stream digests and lengths, and epoch plus
sequence. The C4 native V3_VERIFY response intentionally leaves its
**unsigned** response-frame `ScopeToken` empty; the verifier requires that
wire shape and validates scope against the **signed AckJSON** instead. No
unsigned response field is promoted to trusted provenance.

The new Go test `TestVROAV3SignedCandidateReceiptIsBoundToExactBuildKitRequest`
contains one legitimate signed positive control, 17 request-swap cases and
three response-frame swaps. On the corrected pinned BuildKit tree, the unit
test is GREEN. `TestVROAV3ServiceWithRealManagerAndNativeDaemon` also passes
against native C4 using ephemeral DEV signer keys; its production-build
variant still requires `SIGNING_DISABLED` (22). Applicable Go race and vet
tests are mandatory and should never be skipped to obtain a green run.

This does **not** generate actual C4 owner keys, secure production custody,
a monotonic external authority, trusted release approval, or deployment.
These remain independent protected operational gates. Do not merge, deploy,
cut over, enable C1 FileSync publication, enable C4 production signing, or
close issues #90/#119 without their separate approvals and evidence.
