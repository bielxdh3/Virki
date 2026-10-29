# Offline npm cache for DEV-only local Docker image builds

**Status: investigational developer fixture. This is not an owner-signed release, a GHCR substitute, or a production installation path.**

**Security hold: `images:offline:manual` is deliberately disabled.**

The local image builder now fails closed at its public API entry, **before
staging filesystem writes or contacting Docker**, because the committed Git
source, derived Dockerfile, npm cache and Prisma engine BuildKit contexts are
not independently immutable at Docker read-time. Same-user substitution and
restoration can pass pre/post verification. A private Windows DACL for that
same user is not sufficient. The earlier command lines and successful local
build observations below are **historical DEV evidence**, not steps that
currently generate images. Cache prewarm and independent inspection remain
separate, nonauthorizing operations. Production remains NOT AUTHORIZED.

The canonical `infra/Dockerfile.prod` is pinned by SHA-256 and intentionally
unchanged. Its `build` and `production-dependencies` stages each run `npm ci`;
`--network=none` alone cannot satisfy a missing registry tarball. The exact
current lockfile contains **339** `https://registry.npmjs.org/...tgz` tarball
URLs with `sha512-` Subresource Integrity values, plus exactly seven local
workspace records (including the root) and six exact workspace link pairs.
Any extra unresolved `node_modules` entry or changed local link fails closed.
The optional OS/CPU packages are included in all 339; prefetching only
Windows-compatible dependencies does not prepare Linux Alpine image builds.

## Separate online prewarm, explicit opt-in

`scripts/offline-npm-cache.mjs` plans every lockfile tarball, refuses URLs
outside the official HTTPS registry, rejects missing/malformed SHA-512
integrities, and refuses conflicting resolutions. With the explicit environment
opt-in and an **already provisioned owner-only Windows DACL-protected** staging
parent *outside the Git checkout*, it uses Node's **direct HTTPS client** to
fetch exactly the 339 `registry.npmjs.org` URLs without npm CLI redirects,
credential configuration, proxies or redirects. HTTP 3xx is rejected on the
first response, before another host is contacted. Network errors, incomplete
responses, Content-Length conflicts, oversized tarballs, and SHA-512 mismatches
fail without caching the response. Only verified buffers are inserted with the
bundled, pinned npm `cacache@20.0.3` `put()` API, keyed by the original URL and
lockfile SRI. Every cache index entry and independent cached blob SHA-512 are
checked after insertion and again against the complete lock inventory; a
poisoned or incomplete cache cannot produce a ready receipt. Any failed
prewarm leaves its incomplete private attempt for diagnosis.

```powershell
$env:VIRKI_OFFLINE_NPM_CACHE_WARM = '1'
node scripts/offline-npm-cache.mjs --repository E:\Virki --staging-parent E:\VirkiOfflineBuilds
```

This is the **only step that may contact the official npm registry**. It is
not automatically invoked by the Docker builder. Its successful receipt names
the cache's `_cacache` directory, the package-lock SHA-256, 339 verified blobs,
and the unsigned development status. Before any build, verify the cache again
and match the receipt's lock SHA-256 against the exact committed source.
`npm cache verify` alone is insufficient because it only verifies npm's cache
metadata against its own digests, not the lockfile expected integrity. The
trusted Node installation must bundle exactly `cacache@20.0.3`; other versions
and platforms fail closed.

## Docker BuildKit named context, offline build

`derivePinnedOfflineDockerfile(canonicalText)` first checks the original
Dockerfile against the separately reviewed literal SHA-256 and rewrites **only**
the two exact `RUN npm ci` lines. The derived file belongs in the separate
private temporary staging directory. It uses one read-only BuildKit named
context `offline-npm-cacache` and copies `_cacache` into an ephemeral in-image
directory. Both install commands add `--offline`, retaining the original
`--omit`/`--ignore-scripts` flags. They delete the temporary cache within the
same `RUN` layer. The canonical source and its Git blob inventory remain
unchanged; no host `node_modules`, build-time credentials or npmrc files enter
the container. The host architecture is irrelevant to dependency selection:
`npm ci` resolves optional platform packages **inside the Linux build**.

Before this fail-closed hold, the local image builder required
`--npm-cache-receipt` and refused to run Docker without an exact, independently
rechecked cache inventory. Its
cache receipt must name the same canonical committed source SHA and raw Git
`package-lock.json` digest, and live under the same protected owner staging
parent as the build. **An unsigned cache receipt alone never suffices**: all
339 SHA-512 tarball bytes and corresponding npm cacache indices are rechecked
before the first build and before/after each image build.

The previously supported invocation below is **now blocked**, even if the
explicit online prewarm has finished and the receipt exists. It formerly
built the two targets using the *same clean Git checkout*:

```powershell
$env:VIRKI_MANUAL_IMAGES_LOCAL_BUILD = '1'
npm run images:offline:manual -- --repository E:\Virki `
  --staging-parent E:\VirkiOfflineBuilds `
  --npm-cache-receipt E:\VirkiOfflineBuilds\npm-offline-XXXXXX\npm-offline-cache-receipt.json `
  --prisma-engine-dir E:\VirkiOfflineBuilds\prisma-engines-XXXXXXXXXXXXXXXXXXXXXXXX\context
```

The historical builder's Docker invocation was equivalent to the following (with
the existing exact source SHA, base digest, private staging and image
verification checks still mandatory):

```powershell
docker build --pull=false --network=none --platform linux/amd64 `
  --no-cache --build-context "offline-npm-cacache=<private-cache-path>\_cacache" `
  --build-context "offline-prisma-engines=<private-engine-context>" `
  -f <private-derived-Dockerfile> --target production `
  --build-arg "VIRKI_BUILD_REVISION=<40-char-commit-sha>" `
  --tag <unique-local-runtime-tag> <verified-Git-source-context>
```

Use `--target migrator` for the other role. The context argument must refer
to the `_cacache` directory, not an npm cache containing logs or credentials.
`--pull=false` is insufficient to forbid registry access when the base is
absent: separately inspect the *exact* `node:22-alpine@sha256:0a7108...`
RepoDigest before build. This image became locally cached later on 2026-10-28;
the full private 339-tarball cache has since been prewarmed and SHA-512
verified. Both local runtime and migrator targets previously built successfully with
an explicit pinned Prisma engine sidecar and `--network=none`; final TAR
validation and independent peer review remain separate gates. The integrated
builder previously refused incomplete cache or native engines BEFORE Docker
rather than attempting a network-enabled fallback. The current security hold
refuses all local image creation even when these caches are valid.

## Isolated local BuildKit fixture

The opt-in command below creates a synthetic package tarball, uses a **local
loopback mock registry only while prewarming**, closes it, and tests `npm ci
--offline` in a disposable Docker build using the named context and
`--network=none --no-cache` on both negative and positive builds. It first
checks a locally cached, immutable Docker Hub fixture base
`node@sha256:69a5713e7f4997e96d579aafd78734810e0dac0dd5ee4621d72c27a2891a4088`
for exact `linux/amd64`, image ID and RepoDigest; missing image fails before
build. This fixture is deliberately distinct from the production Alpine digest.
The fixture and preparation entry points refuse WSL/Linux before any Docker use.

```powershell
$env:VIRKI_NPM_BUILDKIT_DEV_FIXTURE = '1'
node scripts/offline-npm-buildkit-fixture.mjs
node --test scripts/offline-npm-cache.test.mjs
```

This proof can validate the transport and npm offline resolution without
network, but it does not validate Prisma's Linux postinstall, full Next.js
build, 339 real tarballs, the production base, independent owner signing,
GHCR CI, or native production Docker authority. Those must be demonstrated
independently before any release readiness claim.
