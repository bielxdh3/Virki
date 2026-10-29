# Manual local images without GitHub Actions or GHCR

**Status: local development/export only. Production release NOT AUTHORIZED.**

The `images:offline:manual` command provides the *local image-build* portion
of the future independent manual path. It builds the `runtime` and `migrator`
targets from the **committed Git tree** using `infra/Dockerfile.prod`. It never
downloads a Virki image or SARIF from GHCR, queries Actions, publishes images,
connects over SSH, or alters a production host.

On a Windows operator workstation with the reviewed Authenticode-signed Docker
Desktop CLI, an existing private staging directory on a non-repository volume,
and all required base images/npm dependencies **already cached**:

```powershell
$env:VIRKI_MANUAL_IMAGES_LOCAL_BUILD = '1'
npm run images:offline:manual -- --repository E:\Virki `
  --staging-parent E:\VirkiOfflineBuilds `
  --npm-cache-receipt E:\VirkiOfflineBuilds\npm-offline-XXXXXX\npm-offline-cache-receipt.json `
  --prisma-engine-dir E:\VirkiOfflineBuilds\prisma-engines-XXXXXXXXXXXXXXXXXXXXXXXX\context
```

The command requires a clean committed source checkout and locally runs `git
-c core.autocrlf=false archive`; the extracted temporary Docker build context contains only tracked,
regular Git blobs, after rejection of links/submodules and restricted secret,
backup or archived data paths. It rechecks every extracted file against its
Git blob before and after each build, and rejects foreign files. The staging
Dockerfile must also match the exact SHA-256 of the separately reviewed,
canonical Git Dockerfile bytes; unexpected `FROM`/`COPY --from`/frontend
changes require a fresh security review and pin update, never a registry pull.
The staging parent must be created in advance with an owner-only **protected Windows DACL**
(only the current operator, SYSTEM and Administrators may have allow rules;
inheritance disabled). A group-writable or inherited ACL fails before Docker.
The Docker Desktop Linux engine endpoint is
pinned to its local named pipe, not an ambient Docker context, network or remote
daemon. Both targets use `--pull=false`, `--network=none`, `linux/amd64`, and
the exact source revision build arg. The offline npm cache must first be
prepared separately with `cache:offline:npm`, using exact SHA-512-integrity
tarballs from the official registry. Its owner-private receipt, source commit,
package-lock digest and all 339 blobs are checked before a named BuildKit
cache context is admitted. Only two reviewed `npm ci` steps are changed to
`npm ci --offline` in a temporary derived Dockerfile, and the canonical Git
Dockerfile remains unchanged. The separate native Prisma engine sidecar is
prepared with `cache:offline:prisma-engines` and checked against exact pinned
gzip and ELF64 hashes; see `docs/offline-manual-prisma-engines.md`. Missing or
altered npm packages or native engines are a **failure**, never permission to
reenable networking or ignore Prisma engine checksums.

Successful builds must pass fresh `docker image inspect` for exact full source
SHA, canonical OCI source, Linux/amd64 and `node:node`; runtime and migrator
image IDs must differ. `docker image save` exports each image by its immutable
ID, not a mutable name, to a distinct `.tar`. The full archive is hashed and
checked with the existing strict `verifyOfflineDockerSaveTar` parser, including
archive member graph, image labels and layer digests. Only after every check
does the tool write `local-image-receipt.json` with source and image hashes.

Output always declares `hostedCi=NOT_RUN`, `codeql=NOT_RUN`, `ghcr=NOT_USED`,
`ownerSignatureVerified=false`, `transferAuthorized=false`, and
`deployAuthorized=false`. The receipt is an **unsigned, local build inventory**;
it may supply source/image IDs to `offline-release-build.mjs`, but independent
raw scanner/CI/smoke/restore reports and distinct owner/builder signatures
are still required. The `offline-release-build.mjs` command will independently
create its own three-file candidate bundle; do not substitute this receipt for
the owner-signed candidate.

The tool preserves failed attempts and generated image tags for manual
reconciliation rather than guessing which daemon resources can be deleted.
Do not point the staging parent inside the Git checkout. No command here
installs independent owner trust, proves an off-host monotonic ledger witness,
attests a native isolated Docker daemon or moves a release into production.
