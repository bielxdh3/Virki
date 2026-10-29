# Prisma 6.19.3 native engines for network-isolated builds

**Development-only image build inputs. Not an owner-signed release, independent trust root, or production installation.**

In a real `--network=none` build, all 339 npm tarballs installed offline, but
the `prisma:generate` postinstall then attempted to fetch the Prisma library
engine from `binaries.prisma.sh`. It failed without network. Do **not** use
`PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING`: that does not supply the binary and
would weaken integrity verification.

Two official Prisma 6.19.3 binaries, from the exact engine commit
`c2990dca591cba766e3b7ef5d9e8a84796e47ab7`, target
`linux-musl-openssl-3.0.x`, are independently pinned in
`scripts/offline-prisma-engine-cache.mjs`:

| Official gzip asset | Pinned gzip SHA-256 | Pinned native ELF SHA-256 |
| --- | --- | --- |
| `libquery_engine.so.node.gz` | `00b82195745fa317411a0a7793769b3a53e631a30d82e27772ca13622b0b7a8e` | `28abc36457335e1a45fe2fe79a4c781b55347e696d6f4410c83bf232d92a726c` |
| `schema-engine.gz` | `cf5f99b0e589976a814655f4ed9c2f11f8e124a3ac2dabb8be8142c7784695d4` | `955e3bff1be23248a0922a219f7c4e200acc8fdd1fc72479557c0a9d782bd64a` |

The explicitly opt-in prewarm performs direct authenticated HTTPS GETs to
the exact official CDN paths; redirections, other hosts, incomplete downloads,
size overrun, malformed gzip, and either SHA mismatch fail closed. It writes
two verified Linux/AMD64 ELF bytes to an owner-private `context`, with a
non-authorizing receipt outside the context:

```powershell
$env:VIRKI_OFFLINE_PRISMA_ENGINES_WARM = '1'
npm run cache:offline:prisma-engines -- --staging-parent E:\VirkiOfflineBuilds
```

Pass that returned `context` directory to `images:offline:manual` alongside
the npm cache receipt. The image builder rechecks exactly two file names,
byte lengths, ELF64/x86_64 headers and both pinned uncompressed SHA-256 hashes
before and after each Docker build. The temporary Dockerfile injects only
BuildKit `COPY --from=offline-prisma-engines` and the exact supported Prisma 6
`PRISMA_QUERY_ENGINE_LIBRARY` and `PRISMA_SCHEMA_ENGINE_BINARY` paths into the
original pinned Node Alpine build stage. It changes the two npm install RUNs
to `npm ci --offline`, without changing canonical Git source or production
Dockerfile. Neither Docker build can access the network.

An actual disposable test completed `npm ci --offline`, `prisma generate` and
then a full local Virki `runtime` build with `--pull=false --no-cache
--network=none`. These local tests prove the preparation technique, not the
independent operator custody, source signatures, witness or safe production
deployment. Revalidation of full archived image provenance is a separate gate.
