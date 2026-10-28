# Offline candidate transfer: disposable staging protocol

**Development fixture only. Production transfer and deployment: NO-GO.**

`infra/offline/disposable-candidate-transfer-fixture.mjs` demonstrates a
protected offline candidate copy protocol without contacting GitHub, an SSH
host, a Docker daemon or production data. It takes only the five fixed fields
`fixtureRoot`, `candidateDirectory`, `operatorDirectory`, `stagingDirectory`,
and `measuredHostIdentitySha256`, and the three directories must be distinct
siblings under `/tmp/virki-offline-transfer-fixture-XXXXXX`. The Linux/amd64
root environment must explicitly set `VIRKI_OFFLINE_TRANSFER_FIXTURE=1`, use
private tmpfs for `/tmp`, and be an isolated disposable container. No other
filesystem destination can be selected. The host identity argument is a
**synthetic test challenge**, not a production identity attestation.

An operator provisions exactly three root-owned 0600 files in an independent
root-owned 0700 directory: `trust-policy.json`, `ledger.json`, and
`transfer-pins.json`. The transfer pin file is canonical JSON with exact keys
`version` (1), `mode` (`disposable-candidate-transfer-v1`),
`hostIdentitySha256`, and `files`. The `files` array has exactly the following
lexicographically ordered eleven entries, each containing exact keys `name`,
`sizeBytes`, and `sha256`: `backup-restore.json`, `ci-report.json`,
`finding-review.json`, `manifest.json`, `migrator-smoke.json`, `migrator.tar`,
`runtime-smoke.json`, `runtime.tar`, `scanner-report.json`, `signatures.json`,
`source.tar`. Size limits are bounded (8 GiB per archive and 16 MiB per other
file), and every digest is a lowercase 64-character SHA-256 hex string.
**For these tests only**, the root fixture locally generates the owner and
builder signing keys, protective policy, ledger and host challenge. These are
ephemeral synthetic authorities; their existence cannot establish that a real
owner independently approved production transfer or that a real host identity
was measured. The signed source SHA is checked for consistency with the
manifest, but the fixture does **not** compare TAR contents with trusted
Git objects on an independent native host. No hosted CI, scanner provenance,
Git blob authenticity or externally monotonic ledger witness is attested.

Before staging, the fixture verifies the owner and builder signatures against
the **independently protected** policy and ledger, checks manifest identity,
sequence, expiry and all archive/evidence hashes, and opens the approved eleven
regular files through an anchored source directory descriptor. Source and
operator inputs must be root-owned, mode 0600, single-link regular files; an
unexpected file, symlink, hardlink, tamper or inode swap fails closed. The
input inventory must match the separately provisioned transfer pins **before
the first byte is written**. File bytes are then copied through the same
opened, pinned source descriptors to exclusive destination descriptors using
bounded 64 KiB reads and writes. Both source and destination are verified
against the locked digests and inode metadata. In the final phase the fixture
re-reads operator trust material and checks every staged byte again.

The target `staging/.incoming` is created exclusively and fsynced before
transfer. On success, after revalidation, it is atomically renamed to
`staging/published` within the same pinned staging directory. Any failure,
interruption, forged replacement or pre-existing orphan prevents publication;
the orphan intentionally blocks retries. No cleanup is attempted until the
entire **disposable** fixture is destroyed. Error messages are deliberately
generic and never print supplied paths or content. The returned status is
`DISPOSABLE_CANDIDATE_TRANSFER_STAGED_ONLY` and both
`transferAuthorized` and `deployAuthorized` remain `false`.

Test the real Linux FD and rename behavior using Node 22 in a private tmpfs:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m,mode=1777 \
  --mount type=bind,source="$PWD",target=/work,readonly \
  -w /work -e VIRKI_OFFLINE_TRANSFER_FIXTURE=1 \
  node:22.23.3 node --test infra/offline/disposable-candidate-transfer-fixture.test.mjs
```

The production protocol still needs a separately audited, owner-installed
native receiver and launcher; an independently attested host/machine identity;
protected destination allocation and storage quotas; a pinned sender/receiver
authenticated channel without ambient SSH options or arbitrary shell/rsync;
independent replay/CAS witness; final FD-to-release-verifier handoff; and
atomic rollback and deployment authorization. A valid GitHub-free local copy
proves none of those external properties, and the hosted production deployment
path remains unchanged.
