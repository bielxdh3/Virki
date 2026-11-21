# VROA V3 exporter-intent binding

Date: 2026-11-20

## Scope and provenance

This is a separate hardening change for the VROA V3 / BuildKit exporter flow introduced through PR #136. It is not a change to issue #90 or PR #133. The original worker-13 Medium review was performed against PR #136 HEAD `2e48f2febfc0d356f3d5a834aadce027e88493f6` and reported a P2 / NO-GO finding in `VROAV3Service.Begin`. The verbatim review package was not recoverable; the original worker-13 supplied the factual summary and source locations again on 2026-11-20.

The finding was not classified as exclusively belonging to issue #90. It concerns binding the signed VROA_AP3 exporter intent to the exporter selected for the current solve. No issue #90 state, comments, PRs, or PR #133 code were changed.

## Finding

The signed approval envelope carries `ExporterIntentSHA256`. Before this change, `decodeAndVerifyApproval` checked the envelope signature and the job, role, nonce, and approval identifiers, but did not compare the signed exporter digest with `binding.Exporter.AttributesDigest`.

When `VROAV3Options.ExporterPolicy` was unset, `Begin` fell back to `binding.Exporter`. The manager's later equality check therefore compared the binding with a value derived from the same binding, after the V3_BEGIN request had already been sent. A signed approval for exporter A could consequently reach the native Begin request with a solve binding for exporter B.

The original review assessed that later evidence validation prevents a valid candidate receipt for the divergent intent. The reproduced defect is earlier: Begin does not reject the mismatch before attempting native transfer. This note does not claim a valid candidate receipt was obtained with mismatched intent.

## Change

`VROAV3Service.decodeAndVerifyApproval` now:

1. Validates the solve binding's exporter intent.
2. Compares the signed `ExporterIntentSHA256` with the validated `binding.Exporter.AttributesDigest` (removing the `sha256:` prefix from the latter).
3. If a non-empty `VROAV3Options.ExporterPolicy` is configured, validates it and requires exact equality with the solve binding before Begin can send the native request.

The BuildKit patch carries a Linux regression test that signs an approval for exporter A and supplies a binding for exporter B. It asserts that Begin returns the exporter-intent error instead of reaching the deliberately missing C4 socket. The same test also covers a configured exporter policy that differs from the solve binding.

## Reproduction and validation

The reproduction used a disposable BuildKit worktree at upstream base `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`, with the BuildKit integration patch from the current Virki main (`669e897d0adf3d0457d18ff680b7cf2123a2885d`) applied. The updated Virki patch SHA-256 is `77dbbc1e575608fcc7a7c89f644f87c66349a44569f480b3472c2ea7f1f05277`.

- RED/GREEN reproduction: a Go `-overlay` outside the worktree removed only the signed approval-to-binding exporter-digest comparison. The mismatch regression then reached the deliberately missing owner socket and failed with `dial unix .../missing-owner.sock: connect: no such file or directory`; the normal source passed the same targeted test. The overlay and map are preserved at `E:\Temp\virki-vroa-p2-red-overlay-20261121.go` and `E:\Temp\virki-vroa-p2-red-overlay-20261121.json` (SHA-256: `154b6a7bd7075b77f341ce62a4bd57b967a6f0ad5bf0b98bba97a4184ef5f219` and `4c0ef34ba7c0eb9ff71c17b0aa7b2d21c4148cef6a0ff5daefdac8462116e26f`, respectively).
- `go test ./util/localcontext -count=1`: PASS.
- `go test -race ./util/localcontext -count=1`: PASS.
- `go test ./control ./solver/llbsolver -count=1`: PASS.
- `go test ./util/localcontext -run '^TestVROAV3ServiceWithRealManagerAndNativeDaemon$' -count=1 -v`: PASS, including both `dev-test-build-candidate-receipt` and `production-signing-disabled` subtests.
- `go vet ./util/localcontext ./control ./exporter/containerimage`: PASS.
- A broader `go vet` including `solver/llbsolver` reports three existing warnings in untouched upstream files (`solver/llbsolver/export.go:34`, `solver/llbsolver/export.go:87`, and `solver/llbsolver/history.go:110`); those warnings are outside this patch.
- `git apply --reverse --check` passed from the Windows BuildKit scratch worktree, confirming the updated patch matches the applied source tree. `git diff --check` passed in both the Virki patch worktree and the BuildKit scratch worktree.

Validation ran with Go 1.26.10 from `E:\Tools\Go1.26.10-linux` under WSL, GCC/CC 15.2.0, `GOPROXY=off`, and the Go build cache at `E:\Tools\go-cache`. The native C4 daemon integration test was therefore executed locally rather than skipped. An independent read-only review confirmed the signed approval-A vs binding-B comparison occurs before `V3_BEGIN`, and confirmed RED/GREEN plus patch/scratch parity. That review is limited to this narrow P2; it does not attest overall C1-C4 readiness or full end-to-end integration. Publication is limited to this downstream patch artifact in Virki: the BuildKit scratch tree contains the broader 73-change C1-C4 integration and remains a local verification tree, not a publishable source branch. The upstream `moby/buildkit` remote is not writable by this account, and publishing the full scratch tree would exceed this P2 scope. C1-C4 therefore remain NO-GO. Hosted CI/CodeQL on the exact Virki PR commit remain pending.

## Safety boundary

This is DEV/code validation only. No production credentials, Cloudflare, TLS, infrastructure, deploy, cutover, or activation were touched. The following invariants remain unchanged:

```text
SIGN_ACK = 22
DeployAuthorized = false
WorkerReceiptPairAdmitted = false
ReleaseSignature = false
```
