# Manual native two-image import: exact host contract and disposable evidence

**State: integration fixture tested; real owner installation and release are BLOCKED.**
The manual lane is self-hosted and does not depend on Actions, GHCR or any
external image registry. An independently accepted owner/builder Ed25519
candidate and native host custody are mandatory. This file does not establish
either custody or signing authority.

## Operator-to-host contract (not yet wired to remote transfer)

1. An independent owner first reviews and pins the Linux/amd64 root bootstrap,
   signed installation approval, owner key, interpreter, Git binary, and **all
   eleven installed ESM verifier modules**. `installOwnerApprovedVerifier()`
   publishes only after verifying the host-bound owner authorization, approved
   digest inventory, immutable trust policy and initial replay ledger. Its
   root-protected outputs are `/usr/local/lib/virki/offline-release`,
   `/etc/virki/offline-release` and `/var/lib/virki/offline-release`. Installation
   attempts are one-shot: failed or interrupted publication remains latched.
2. The independent owner provisions the isolated Docker daemon supervisor,
   root-owned daemon executable and CLI pins under
   `/etc/virki/offline-import-daemon/daemon-policy.json` and
   `/etc/virki/offline-import-cli.sha256`. The dedicated endpoint is
   `/run/virki-offline-import/docker.sock` (root-owned `0600`, protected `0700`
   parent), with separate private data and exec roots. The policy must bind
   daemon binary hash, daemon PID/start ticks, socket inode, exact cgroup and
   mount/network/PID namespaces. A real supervisor must continuously retain
   ownership and prevent connection forwarding to a production Docker daemon.
3. The builder creates committed-tree runtime/migrator image TARs with
   `npm run images:offline:manual`, then independently obtains the approved
   eleven-file candidate. Its canonical manifest must bind both SHA-256 TARs,
   distinct immutable image IDs, exact Git commit, owner/builder signatures,
   source TAR and evidence inventory, and measured host identity. Source
   verification **requires clean named `main` at the signed SHA, matching
   `origin/main`**. The unmerged stage17 feature branch cannot bypass this
   check and no temporary test key counts as owner authority.
   **Source and builder tooling are different identities:** the already built,
   privately receipted image pair has source revision
   `c3ea768956bc3522363b725c138086a3c3e1c399` (stage16 / PR #86), while
   the stage17 builder implementation is
   `ce9d6a2b102747da0f353ee7098aafbde787a402` (PR #87). An
   owner must independently pin and review BOTH where applicable, check their
   relationship and sign the real source revision; substituting the builder
   SHA into the image source label is invalid. Do not rebuild existing images
   merely to make those SHAs match.
4. `npm run deploy:manual -- --candidate ... --trust ... --stage-parent ...`
   currently creates a private *local* eleven-file copy, fully reinspects its
   signatures and source, then returns exit code 2 and transfer blocked. A
   future independently authenticated remote transport must bind the original
   manifest SHA, signed envelope SHA, host identity and all eleven file hashes
   into a receipt before the host owns the immutable staging directory.
5. Host receiver must publish a private root-owned `0700` stage beneath
   `/var/lib/virki/offline-staging` with exactly eleven root-owned single-link
   `0600` files, `O_NOFOLLOW` opens, full digest readback and directory fsync.
   The existing `coordinateTrustedOfflineRelease({candidateDirectory})` then
   verifies the installed owner/builder trust, source Git, host identity and
   one-shot attempted ledger *before* any image POST. An uncertain admission
   must remain pending for external owner reconciliation.
6. A future owner-installed import entrypoint must independently revalidate
   the isolated daemon's kernel identity and use **one already connected
   AF_UNIX FD** held across `/_ping`, `/info`, both image loads, and both
   image-inspects. The reviewed `native-docker-fd-transport.c` uses
   `SO_PEERCRED`, per-message `SCM_CREDENTIALS`, pidfd/start ticks, and
   mount/net/pid namespace and cgroup continuity. Both signed archive FDs
   must be verified and detached under the private
   `/var/lib/virki/offline-import-quarantine` before the first POST. The
   native code must verify each archive SHA on the exact inherited FD; both
   inspect responses must match the pinned immutable IDs and the signed Git
   revision/source, `linux/amd64`, `node:node` and no mutable tags. Record the
   two NDJSON load receipt digests and bounded inspect responses durably in an
   independently protected attempted journal, with fsync and a new signed
   off-host monotonic CAS head before allowing any later activation step.
7. Only a separately owner-approved, witness-bound activation coordinator may
   fence traffic, verify backup, run clone/live migrations, inspect private
   health and eventually activate the pinned images. Image import is never
   equivalent to container start, release completion or rollback authority.

The production command connecting steps 4 through 7 does **not exist**. In
particular, `trusted-image-import.mjs` still uses a separately pinned Docker
CLI, and `isolated-docker-daemon-identity.mjs` is a read-only diagnostic. Neither
currently passes the verified connected kernel FD into an installed importer.
The original native sealed-memory transport limits uploads to **64 MiB**.
The separately exposed `vdt_exchange_detached` accepts a large private,
unlinked, read-only **input**, but sends ONLY a separate immutable `memfd`
snapshot. Before the first POST, it verifies `MemAvailable` and all readable
cgroup-v2 ancestor limits have at least size + 50% + 512MiB operating reserve,
fully copies and hashes the input, applies `F_SEAL_WRITE | F_SEAL_GROW |
F_SEAL_SHRINK | F_SEAL_SEAL`, and independently rehashes the SEALED content
against the pinned SHA-256. If any resource guard, seal, or digest check
fails, there is no POST. Only one image's snapshot is allocated at a time.
Memory checks are **not a reservation** or guarantee against concurrent OOM:
a real independent supervisor must enforce killable staging and accounting.

**Critical lease-break P1 (2026-10-29):** a same-UID process can open
`/proc/<uploader PID>/fd/<anonymous stage FD>` with `O_WRONLY|O_NONBLOCK`,
trigger `SIGIO`, force-break a Linux `F_WRLCK` lease and ultimately mutate
the same unsealed bytes while POST is ongoing. The previous lease-only
disk-FD streaming path is unsafe and has been REMOVED from the candidate.
It must never be used as a production transport. The corrected candidate
still requires a NEW independent peer review of its exact source hashes.

The owner must still privately stage/unlink both images, close staging
writers, budget temporary disk and snapshot memory, and durably latch the
import before this call. The actual 959,170,560-byte runtime and
1,330,946,048-byte migrator TARs have **not** been end-to-end imported using
the revised path. Mock daemon compatibility cannot certify production import.

## Runnable nonprivileged owner-review handoff

The independently executable `scripts/offline-manual-native-host-package.mjs`
prepares a private `0700` directory of exactly eleven verifier ESM source
modules and a **separate** four-file native review supplement (C transport,
header, isolated daemon diagnostic, image receipt comparison). It binds exact
SHA-256 hashes of every staged file to an unsigned JSON inventory, records
the two distinct original image IDs and TAR digests from the existing developer
receipt, and separately records the builder source revision. It never creates
owner signatures, daemon policy or a privileged installation authority.

In WSL Ubuntu Node 22 with an existing separate private Linux staging parent:

```sh
mkdir -m 700 -p "$HOME/virki-owner-review-stages"
node scripts/offline-manual-native-host-package.mjs \
  --repository /mnt/e/Virki/.worktrees/virki-manual-host-image-w27-20261028 \
  --image-receipt /mnt/e/VirkiManualPrivate20261028/manual-images-IRh9ul/local-image-receipt.json \
  --stage-parent "$HOME/virki-owner-review-stages" \
  --builder-revision ce9d6a2b102747da0f353ee7098aafbde787a402
```

The command prints the exact published inventory directory with an intentional
exit status `2`, signifying **owner installation remains blocked**. The private
receipt is only read, never rewritten. The CLI accepts canonical Windows E:
paths from the real stage17 receipt using the existing strict WSL path mapper.
For independent installation, an owner must review the inventory hashes,
reconcile Git source and builder identities, and provision `verifier-pins.json`,
separately signed `installation-approval.json`, host-bound root bootstrap,
protected daemon policy and the off-host witness. The already available
`installOwnerApprovedVerifier()` must receive the eleven files from the
`verifier/` tree **only**. The `native/` supplement is a distinct audit target;
the current eleven-module installer does not approve or publish native C code.

## What the new tests actually establish

`infra/offline/native-supervisor/manual-native-image-batch-fixture.c` is
intentionally buildable only with `-DVIRKI_DISPOSABLE_MANUAL_BATCH=1`; it accepts
solely a generated `/tmp/virki-native-manual-XXXXXX` directory and connects to
that directory's disposable AF_UNIX mock daemon. It reuses the existing native
FD transport, first verifies **both archive hashes before any HTTP**, then
copies each into an unlinked private `O_TMPFILE` FD and closes the writers;
their original names no longer control the uploaded bytes. It copies each into
an independently SHA-256-pinned sealed memfd, transmits those sealed bytes, and
receives two bounded Docker inspect responses
over the same peer-checked connection. On a partial second
load it reports `BLOCKED_DISPOSABLE_BATCH_UNCERTAIN` and never claims rollback.

`infra/offline/manual-native-image-receipt.mjs` independently compares the
returned runtime/migrator image identities, archive hashes and Docker JSON
against the expected *already authenticated* manifest values. It calls the
existing `compareUntrustedLoadedImageForPreview` and always returns
`dockerLoadAuthorized:false` / `deployAuthorized:false`. The fixture's caller
can forge expected inputs: neither module verifies real owner keys or a remote
host, and its successful receipt cannot authorize Docker import in production.

Linux Node 22 + GCC, disposable only, no Docker socket or production services:

```sh
VIRKI_DISPOSABLE_MANUAL_BATCH=1 node --test \
  infra/offline/manual-native-image-receipt.test.mjs \
  infra/offline/native-supervisor/manual-native-image-batch-fixture.test.mjs \
  scripts/offline-manual-native-host-package.test.mjs
```

External owner provision still missing: independently approved root bootstrap
and verifier pins, real protected receiver/transport, supervised daemon and
immutable daemon lifetime proof, monotonic out-of-host witness CAS, compatible
large-image FD snapshot, and native PostgreSQL/activation/rollback review.
