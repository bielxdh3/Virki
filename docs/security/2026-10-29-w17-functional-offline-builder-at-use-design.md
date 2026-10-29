# W17 — functional offline image builder: at-use custody and safe test seam

**Scope:** PR #88; historical pre-hold builder base
`ede8beefd05bb8666aa4581c0e709dc47ed1ef83`, with the mandatory public
fail-closed hold published in `73324fb3731e8f8c1dfd2ca13d46d29d6ac6fcbc`.
**Status:** DEV-only adversarial reproduction and design, **NOT** a functioning secure builder.
**Production authority:** NEVER GRANTED. No Docker daemon, WSL, root, network, owner install,
release, image push, GHCR or production system was accessed for this work.

## 1. Historical pre-hold execution path and its trust break (now unreachable)

The **current** public `buildOfflineManualImages` unconditionally rejects an
opted-in build before staging filesystem operations and Docker contact. Its
internal build-launch seam separately refuses. The steps and approximate line
references below describe the **old, now unreachable** execution path at
`ede8bee`, solely to explain why re-enabling it would be unsafe. They do not
describe commands that can generate images on the current PR branch.

The old public `buildOfflineManualImages` export in
`scripts/offline-manual-image-build.mjs` had Windows local opt-in, a canonical
repository root, an owner-protected Windows staging ACL and local Docker Desktop
executable/signature checks (historical lines 322–360). It then:

1. Uses real `git rev-parse`, `git status`, `git ls-tree` and `git archive` to create
   an extracted checkout (`377–392`), checking its Git blob graph and the exact
   canonical Dockerfile hash.
2. Parses the committed lock and authenticates **339** pinned npm SHA-512 tarball
   records in the separately prepared `_cacache` (`393–411`), checks exactly two
   pinned Prisma engine binaries (`412–416`), and writes a derived Dockerfile.
3. Constructs **both** `runtime` and `migrator` build argument vectors via
   `createOfflineManualBuildWithCachePlan` (`418–420`). Each passes FOUR external
   pathname inputs: (a) the Git `source/` directory as the last argument;
   (b) `-f <session>/Dockerfile.manual-offline`; (c)
   `--build-context offline-npm-cacache=<cache>/_cacache`; (d)
   `--build-context offline-prisma-engines=<engines>` (`89–107`).
4. Rechecks source, cache, and Prisma (`426–432`), then launches the **real**
   Docker CLI consuming these names **later** (`434`). It rechecks the source,
   cache and engines after consumption (`435–440`, `459–460`). It then inspects,
   exports and verifies TAR receipts through a WSL Linux parser (`441–469`).

The pre/post validation describes *two observations* of mutable files. It does
**not** establish what bytes the Docker Desktop CLI or BuildKit daemon read in
the interval. A same-user process with write access can substitute, have the
consumer read, and restore the exact originals before the second observation.
The derived Dockerfile is especially important: it is created once from a
pinned file but **not** verified against the original derived bytes at use.
Even if it were, a double hash cannot prevent this swap-and-restore attack.

`mode:0700`, a Windows protected owner DACL, `chmod`, snapshots in a directory
still controlled by the **same SID**, and post-build hashes **do not** solve the
at-use problem. A locally returned Docker image label saying `sourceSha` is not
an independent statement that BuildKit actually ingested only the pinned bytes.

## 2. Concrete local evidence (negative, not authorization)

`scripts/offline-manual-image-build-four-context-threat.test.mjs` imports the
**actual production argument planner** and the **actual Git-blob source verifier**.
For both roles, a disposable fake Docker process parses those real argument
vectors, obtains each of the four paths, and dispatches a distinct same-user
attacker subprocess to mutate the targeted pathname. It reads the poisoned bytes
and dispatches a second attacker subprocess to restore the original bytes.
Source Git-blob and all other SHA-256 pre/post checks still pass.

Eight cases are proved (two roles × source, derived Dockerfile, npm cache,
Prisma). The test uses synthetic content, fake Docker, and throwaway temp files,
and does **not** contact Docker/Desktop, call `buildOfflineManualImages`, execute
the signed Docker CLI, authenticate the real 339 cache blobs or two Prisma
artifacts, invoke Linux TAR verification, or produce a real image.

**Interpretation:** a passing test proves the pathname-use hazard is reproducible
without timing assumptions. It is **not** an exploit of the full public function,
an integrated RED→GREEN for a new production fix, an authenticated builder or a
safe/functional image. Neither the synthetic test nor a signed manifest of bytes
from the same-user staging directory may be upgraded to release evidence.

## 3. What blocks a safe full-public fake-Docker test today

The existing `buildOfflineManualImages` API is not dependency-injected. It
requires an actually present signed Docker Desktop CLI at a fixed system path,
PowerShell Authenticode, Git archive of a clean exact revision, a pinned
protected Windows staging DACL, all **339** verified npm archive/index entries,
the two authentic (~17.6 MiB and ~19.6 MiB) Prisma ELF binaries, Docker image
metadata and a WSL Linux/root TAR broker.

The source also hard-wires `spawnSync` to the signed CLI and imports the npm and
Prisma verifiers dynamically; a fake external binary path or a public
`skipSignature` / `skipCacheSRI` / `skipPrisma` / `skipWSL` / `fakeAuth` flag in
the release-facing API would bypass the very safety boundary being tested.
There is no separately installed broker/daemon authority, no protected at-use
four-context transport, and no evidence an independent recipient consumed the
bytes. **Therefore a legitimate full-public-path injectable fake-Docker
adversarial test is NOT IMPLEMENTED in this wave.**

Never present a copied orchestration loop, a mock of `assertSourceMatchesCommittedBlobs`,
or an isolated launcher function as equivalent to running the public builder.
Likewise, a test intentionally returning a valid unsigned receipt from a fake
image is **not** evidence that the four inputs reached a real daemon safely.

## 4. Proposed trustworthy architecture (not installed)

1. **Independent owner custody:** provision an operator-owned, independently
   reviewed service with a *different* Windows SID / Linux UID and storage that
   the source staging user **cannot write or ask to rewrite**. On Windows,
   Docker Desktop's pipe accessible by the same user is NOT enough. Running
   WSL as root within that same user's own distro is also NOT an independent
   custody boundary. The privilege/namespace and daemon endpoint must be
   independently controlled and authenticated before they become trusted.
2. **Receive all inputs:** authenticate a bounded source TAR against separately
   trusted owner-pinned Git objects/commit and canonical modes; receive a
   separately hash-pinned derived Dockerfile; individually verify all 339 npm
   SRI blobs and all required `_cacache` graph/index entries; verify both
   Prisma engines by length, ELF target, pinned SHA. Inputs enter the broker
   over a bounded stream or through broker-only FDs. Never trust a caller-supplied
   `verified=true` or a receipt made on the mutable Windows staging path.
3. **Protect the handoff:** materialize input trees and Dockerfile in private
   broker-owned storage unreachable to the source user, with no mutable
   hardlink, bind mount, DrvFS bridge or alias writable by the submitter. The
   independently controlled daemon must read *these exact broker-owned trees*.
   The broker must also protect builder CLI/runtime, build frontend, cache and
   service identities; otherwise the same user can replace the consumer.
4. **Verify at use and after build:** remeasure the pinned metadata+content in
   broker custody before handing over to the daemon, retain per-role input
   digests, and bind the received build result to the authenticated immutable
   daemon image ID and the actual consumed contexts. Prevent eviction/tag swap,
   unpinned base images, external network, attacker-controlled BuildKit mount
   points and cross-role cache substitution.
5. **Separate evidence from permission:** return only
   `ownerSignatureVerified:false`, `transferAuthorized:false`,
   `deployAuthorized:false`, `hostedCi:NOT_RUN`, `codeql:NOT_RUN` for a
   purely local DEV run. Owner identity, durable receipts, hosted scanner/CI,
   native operator install and production approval remain different gates.

No single API flag or digest computed by the mutable Windows process can
replace this trust separation. Before implementing any functionally open DEV
build path, have an independent security peer review the exact broker contract,
identity chain, byte custody, four input contexts and negative at-use races.

## 5. TDD acceptance for a future actual public path

For each of `runtime` and `migrator`, construct an authenticated DEV fixture
through the same public `buildOfflineManualImages` path and inject a *fake
consumer at the trusted broker boundary*, **not** a fake trust verifier.

The RED must make the consumer observe a mutated source file, Dockerfile,
npm cache blob or Prisma engine, restore pre/post bytes and show a wrongly
accepted build receipt in the old path. The GREEN must prove the independent
broker consumed only authenticated immutable bytes or denied the build before
consumer invocation. Include race-by-rename, in-place edits, same-SID writes,
cache index poisoning, hardlinks/reparse points, two roles and two attempts.

Additionally, use real callback/log evidence of the executable consumer,
not merely source `includes('launchSecureBuild')` text tests. A fake daemon can
prove orchestration but cannot certify a real independently installed daemon;
those separate native-host acceptance tests must remain NOT_RUN until permitted.

**Current outcome:** test-only negative evidence plus reviewed design candidate.
Do not remove or bypass any previously frozen fail-closed hold and do not merge
this work as a secure functional builder. No stage, commit, push, merge or deploy.
