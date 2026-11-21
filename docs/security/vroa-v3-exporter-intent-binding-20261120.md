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

The reproduction used a disposable BuildKit worktree at upstream base `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`, with the BuildKit integration patch from the current Virki main (`669e897d0adf3d0457d18ff680b7cf2123a2885d`) applied. The canonical Git-blob SHA-256 of the updated patch is `bd1c476af409290ef18769a5f18ea1a1704d584435dd88bd1b91ac68c8f99ccf`. On the Windows worktree, `core.autocrlf=true` converts the text patch to CRLF, so hashing the working-tree bytes yields `77dbbc1e575608fcc7a7c89f644f87c66349a44569f480b3472c2ea7f1f05277`; that is not the blob digest consumed by the Linux hosted workflow.

- RED/GREEN reproduction: a Go `-overlay` outside the worktree removed only the signed approval-to-binding exporter-digest comparison. The mismatch regression then reached the deliberately missing owner socket and failed with `dial unix .../missing-owner.sock: connect: no such file or directory`; the normal source passed the same targeted test. The overlay and map are preserved at `E:\Temp\virki-vroa-p2-red-overlay-20261121.go` and `E:\Temp\virki-vroa-p2-red-overlay-20261121.json` (SHA-256: `154b6a7bd7075b77f341ce62a4bd57b967a6f0ad5bf0b98bba97a4184ef5f219` and `4c0ef34ba7c0eb9ff71c17b0aa7b2d21c4148cef6a0ff5daefdac8462116e26f`, respectively).
- `go test ./util/localcontext -count=1`: PASS.
- `go test -race ./util/localcontext -count=1`: PASS.
- `go test ./control ./solver/llbsolver -count=1`: PASS.
- `go test ./util/localcontext -run '^TestVROAV3ServiceWithRealManagerAndNativeDaemon$' -count=1 -v`: PASS, including both `dev-test-build-candidate-receipt` and `production-signing-disabled` subtests.
- `go vet ./util/localcontext ./control ./exporter/containerimage`: PASS.
- A broader `go vet` including `solver/llbsolver` reports three existing warnings in untouched upstream files (`solver/llbsolver/export.go:34`, `solver/llbsolver/export.go:87`, and `solver/llbsolver/history.go:110`); those warnings are outside this patch.
- `git apply --reverse --check` passed from the Windows BuildKit scratch worktree, confirming the updated patch matches the applied source tree. `git diff --check` passed in both the Virki patch worktree and the BuildKit scratch worktree.

Validation ran with Go 1.26.10 from `E:\Tools\Go1.26.10-linux` under WSL, GCC/CC 15.2.0, `GOPROXY=off`, and the Go build cache at `E:\Tools\go-cache`. The native C4 daemon integration test was therefore executed locally rather than skipped. An independent read-only review confirmed the signed approval-A vs binding-B comparison occurs before `V3_BEGIN`, and confirmed RED/GREEN plus patch/scratch parity. That review is limited to this narrow P2; it does not attest overall C1-C4 readiness or full end-to-end integration. Publication is limited to this downstream patch artifact in Virki: the separate BuildKit scratch tree contains the broader C1-C4 integration and remains a local verification tree, not a publishable source branch. The upstream `moby/buildkit` remote is not writable by this account, and publishing the full scratch tree would exceed this P2 scope. C1-C4 therefore remain NO-GO.

Hosted validation on the current PR #139 head `b6f6eed7808be9d7e562644c9777b562b0c62c93` completed successfully:

- CI run `44879018147`: Validate, authenticated browser E2E, mandatory ADMIN recovery PG18 proofs, exclusive email-worker HOL/CAS PostgreSQL tests, Prisma tooling policy, production dependency audit, and Virki identity all PASS.
- The Validate job rechecked the exact patch blob SHA-256 `bd1c476af409290ef18769a5f18ea1a1704d584435dd88bd1b91ac68c8f99ccf`, applied it to upstream BuildKit base `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`, and reproduced tree `f88abcec589b1fa111124d7c94053d1a7830a3c7`. `go vet ./...` passed; the native Go-to-C4 bridge regression passed 1/1; `TestVROAV3ServiceWithRealManagerAndNativeDaemon` passed both `dev-test-build-candidate-receipt` and `production-signing-disabled` subtests; the solver local-context regression suite passed.
- CodeQL run `44879018078`: SUCCESS. Its downloaded SARIF contains 48 results, zero `js/shell-command-injection-from-environment`, zero `js/bad-tag-filter`, and the reviewed-SARIF policy accepts 48/48 with zero violations.
- GitHub Codex review of the exact `b6f6eed780` head completed without major findings.
- Build tested production images is **SKIPPED**, not PASS; it is not a required PR gate and no multiarch image build is claimed.

The same Validate job also replays the pre-existing issue #90 V23-V28 experimental patches already present on `main`; those artifacts and tests are unchanged by PR #139. Their presence in the shared CI workflow is inherited coverage, not a PR #139 dependency or a claim that issue #90 is resolved. The `setpriv` no-new-privileges subtest is skipped when the CI parent is already hardened. No issue #90, PR #133, or broader C1-C4 source was changed by this PR.

## Hosted pin and tree reconciliation — 2026-11-21

The historical and updated Git objects were checked directly, not inferred from the Windows working copy:

- Before the VROA patch change (`7d3a8e1685abbb1fd5be5b93e2d735cdddb5f331^`), the patch blob SHA-256 was `660462d999e2d3c1a143a7b78577ecd95545cc4f82837f76fd7f8a9c392e696a`, and the historical workflow expected tree was `3cabbc82887e87a900eeb7b838196bef00374055`.
- After the VROA exporter-intent patch change (`7d3a8e1685abbb1fd5be5b93e2d735cdddb5f331`), the patch blob SHA-256 became `bd1c476af409290ef18769a5f18ea1a1704d584435dd88bd1b91ac68c8f99ccf`. The first commit intentionally exposed the old workflow pin; the subsequent pin-refresh commit `af9c9012f2ae56926c177ed394db3cbd53b9949c` changed the workflow digest to this exact blob SHA and the expected patched tree to `f88abcec589b1fa111124d7c94053d1a7830a3c7`.
- Hosted Validate run `44865501539` on `af9c9012f2ae56926c177ed394db3cbd53b9949c` executed the patch `sha256sum --check` (`...patch: OK`), applied it to upstream base `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`, asserted the exact `write-tree` value `f88abcec...`, and passed the native Go-to-C4 bridge test.
- A fresh local temporary Git index, independent of the preserved historical index, also applied the exact Git-blob bytes to the pinned base and produced `f88abcec589b1fa111124d7c94053d1a7830a3c7`. The pre-existing expected-tree index independently continued to report the same tree. Neither operation changed the BuildKit scratch working tree.

This reconciles the apparent `77db...` versus `bd1c...` difference as Windows CRLF conversion, not a remote pin mismatch. The old `660462...` / `3cabbc...` pair is preserved as historical provenance. PR #139 remains OPEN/Draft; this evidence does not authorize C1-C4 integration or production activation.

## Safety boundary

This is DEV/code validation only. No production credentials, Cloudflare, TLS, infrastructure, deploy, cutover, or activation were touched. The following invariants remain unchanged:

```text
SIGN_ACK = 22
DeployAuthorized = false
WorkerReceiptPairAdmitted = false
ReleaseSignature = false
```

## Begin-path negative coverage completion — 2026-11-21

An independent review of the published PR found that the exporter-intent negative regression existed in the downstream BuildKit patch but was not selected by the hosted Validate command. It also identified that malformed caller-supplied `Binding.Exporter` values did not have service-path coverage. Both gaps are corrected in the current working revision:

- `TestVROAV3BeginRejectsMismatchedExporterIntentBeforeNativeTransfer` now also exercises six malformed binding shapes: unsupported schema version, nonzero exporter ID, non-image exporter type, empty destination, wildcard destination, and malformed attributes digest. Each case calls `VROAV3Service.Begin` with a valid signed approval and asserts the invalid exporter-intent error occurs before the deliberately missing native socket can be reached.
- The hosted CI Go test selector now executes both `TestVROAV3BeginRejectsMismatchedExporterIntentBeforeNativeTransfer` and `TestVROAV3ServiceWithRealManagerAndNativeDaemon`; the latter still runs both DEV candidate-receipt and production-signing-disabled subtests.
- The updated patch Git-blob SHA-256 is `986b8d974e064840959e04fa746798072f9f795327d088d936524b363c235dc9`. Applying its LF bytes to BuildKit base `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e` reproduces tree `a8620ea2ddadbe7125168d8edef8c58cc1b4ddb1`. The CI pins were updated together.
- Local isolated BuildKit validation: patch `git apply --check` PASS; expected tree reproduced; Go 1.26.10 `go test -mod=vendor -count=1 -v ./util/localcontext -run '^(TestVROAV3ServiceWithRealManagerAndNativeDaemon|TestVROAV3BeginRejectsMismatchedExporterIntentBeforeNativeTransfer)$'` PASS. The negative test passed all six malformed-binding subtests; the native-daemon test passed both existing subtests.
- The full corresponding local workflow segment also passed: `go vet ./...` for `infra/offline/c1-c4-native-bridge`, `npm run test:offline:c1-c4-native-bridge` (1/1), and `go test -mod=vendor -count=1 -v ./solver/llbsolver -run '^TestLocalContext'`.

These are local results only. The updated patch digest/tree and newly selected test must pass on the next exact PR head in hosted CI and CodeQL before this change is considered Build Ready. The PR remains Draft; no merge, release, image publication, or production action is authorized.
