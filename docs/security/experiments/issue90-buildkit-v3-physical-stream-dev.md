# Issue #90: physical BuildKit C1 context streams to native C4 (DEV only)

This integration exercises BuildKit's **real** `session/filesync.BuildLocalContextStream`
against disposable Linux filesystem trees, then passes its four resulting
context streams to the **existing** `util/localcontext.Manager`, `VROAV3Service`
and native C4 daemon. Each physical tree contains a directory, a regular file
and a symbolic link. The stream's digest, tree digest, length, file bytes and
entry count are observed by the BuildKit producer, rather than assembled by
the previous manual test encoder.

The existing native C4 test runs two modes: an ephemeral DEV test signer emits
a signed `CANDIDATE_VERIFIED` receipt whose non-release flags stay false; the
ordinary C4 build verifies the same physical stream bytes and returns
`SIGNING_DISABLED` (status 22). C4 runs on an isolated Unix socket and ledger
under `t.TempDir()`. The source directory is never a deployment or shared
published path.

## Immutable base and additive patch

On PR #141 SHA `452edebf343cced9f871a42b34e91a35f2e92586`:

- BuildKit `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`;
- original C1/C4 patch produces `a8620ea2ddadbe7125168d8edef8c58cc1b4ddb1`;
- prior signed-receipt-binding patch produces `056ddc9815176e137117281e2d360a9c10048296`;
- this physical C1 producer patch, `infra/offline/patches/buildkit-v0.34.1-c1-c4-physical-stream-dev.patch`, has SHA-256 `9f16059ae03bac7d7345602c2a34e04ec151740433b3fe0f90cd86af50c001a6` and produces `8fa0196e163da1c0f40a2034a3d968ec5e1c469b`.

The original two patches and their SHA/tree pins remain unchanged. CI checks
the third patch byte digest and resulting Git tree before executing Go tests.

## Test evidence

In an independent disposable checkout, adding the test before the new
`cmd/virki-c1-dev-stream` producer resulted in RED: the `go run` command
failed because the physical C1 producer executable source did not exist.
After implementation, `TestVROAV3ServiceWithRealManagerAndNativeDaemon`
passed both native C4 modes using the physical BuildKit producer. This is a
missing integration-harness capability, not a newly demonstrated authorization
bypass or a pre-existing broken FileSync implementation.

The pinned CI integration invokes:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  VIRKI_C4_TEST_SOURCE_DIR="$GITHUB_WORKSPACE/infra/offline/native-owner-authority" \
  go test -mod=vendor -count=1 -v ./util/localcontext \
    -run '^TestVROAV3ServiceWithRealManagerAndNativeDaemon$'
```

The test uses `go run -mod=vendor ./cmd/virki-c1-dev-stream`
for each of the four contexts. No network package retrieval is required.

## Remaining boundary

This proves physical C1 **stream production and consumption** by C4, not a
complete authenticated BuildKit solve or production publication. The test still
uses an ephemeral synthetic owner approval, constructed causal solver paths
and OCI blobs. It does not connect a protected C1 V15/V24 FileSync receiver,
the V36 root publisher, a live OCI exporter or an operational C4 owner key.
It cannot provide native production host attestation, independent key custody,
release signing, rollback immunity or deployment authority. Keep the protected
FileSync, any publisher-to-release transition and production signing disabled.
