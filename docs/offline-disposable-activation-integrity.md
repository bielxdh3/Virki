# Disposable activation journal and health-evidence integrity

The standalone `infra/offline/disposable-activation-integrity.mjs` is a **DEV-ONLY,
NON-AUTHORIZING native filesystem experiment**. It does not connect to Docker,
PostgreSQL, production SSH, the independent witness, the release coordinator,
CI, or the existing `scripts/production-server.sh` activation flow.
It does not attest that a release is approved or safe to deploy. Every returned
state explicitly has `deployAuthorized:false`, `witnessCasAuthorized:false`,
`transferAuthorized:false`, and `dockerLoadAuthorized:false`.

The only accepted API argument is an OS temporary-directory fixture root
with the exact `virki-activation-integrity-XXXXXX` naming convention.
`VIRKI_DISPOSABLE_ACTIVATION_INTEGRITY=1` and Linux are required. The
entire fixture is independently prepared with private owner-only directories
(0700), regular owner-only files (0600), an exact predecessor and candidate
revision, and a protected `operator/activation.json` plan. There are no
injected runtime handles, operator commands, report flags or callbacks.
An assessor verification key is pinned by SPKI SHA-256 in this **fixture**
plan; this does not establish a production owner trust root.
The plan also independently pins `expectedPreviousRuntimeSha256` for the
predecessor release bytes, alongside the candidate runtime and unchanged
data digests. Every operation, including read-only inspection and rollback,
rechecks all three native file digests against the protected plan. A
regular 0600 predecessor whose contents have changed blocks rollback before
the `current` symlink can be switched back.

`activateDisposableRevision` appends an exclusive `intent` journal record,
fsyncs the file and directory, then atomically renames a temporary symlink
to switch `current` from the predecessor to the candidate. The containing
directory is fsynced before `switched` is journaled. Event files are immutable
by protocol, `O_EXCL | O_NOFOLLOW` opens refuse overwrite/symlink redirection,
and a strict canonical hash chain binds sequence, phase, a fresh random
event nonce, and the protected plan digest. The switch event hash is therefore
unknown before the switch is recorded, preventing advance-signing of a health
receipt for a predictable journal. A second invocation cannot silently replay
the transition.

`confirmDisposableRevisionHealth` accepts no health claims through its
request. It reads an independently supplied **fixture Ed25519-signed** file
from the fixed path `evidence/health.json`. The signed message is bound to
the exact transaction ID, fixture host identity, previous/current revision,
second durable journal event SHA-256, route, native candidate runtime bytes
and unchanged live data bytes. A mismatched signature, current symlink,
symlink/hardlink file, tampered journal or altered native bytes refuses health
confirmation. Successful confirmation appends an exclusive fsynced
`health-confirmed` event binding the SHA-256 of the **exact signed evidence
bytes**. Subsequent inspection verifies this journal-to-proof hash link,
including after restart; no release authorization follows.

`rollbackDisposableRevision` can run only from the pending candidate state
before any health evidence has appeared. It writes and fsyncs
`rollback-intent` **before** atomically restoring the predecessor symlink,
fsyncs the directory, and then journals `rolled-back`. No data, old runtime
or candidate runtime file is changed. This exercises **routing rollback only**;
it is deliberately not a production PostgreSQL restore or migration rollback.

An OS crash or SIGKILL after an intent or symlink rename leaves an
irreconcilable journal phase and the API returns `blocked-ambiguous-dev-only`.
It never automatically retries, deletes a latch, rewinds the ledger or
pretends that an interrupted switch is a verified success. A test-only
`VIRKI_DISPOSABLE_ACTIVATION_FAULT` supports `after-intent`,
`after-rename`, `after-rollback-intent`, and `after-rollback-rename`
process termination.

Run focused tests on a disposable Linux filesystem:

```sh
node --test infra/offline/disposable-activation-integrity.test.mjs
```

These tests use native file creation, O_EXCL, fsync and actual killed processes
inside private OS temporary fixtures. Tests in WSL exercise the Linux
filesystem APIs but are **not native production host proof**. A signed
synthetic runtime report is not a real service health check: it proves that
the selected signer approved the measured fixture route and file digests,
not that Virki's public/ADMIN endpoints, PostgreSQL, migrations, security
boundaries or runtime processes are healthy. A same-UID/root adversary able
to rewrite all protected fixture files, plan and journal is outside the
integrity model, as is power-loss durability of untrusted storage hardware.

Production remains **NO-GO** until independently provisioned host and owner
trust, a separate authenticated remote witness and durable monotonic
checkpoint, owner-signed CAS and native ledger reservation, independently
verified exact daemon/image identity at use time, backup restore plus
migrations against an isolated PostgreSQL clone, real health measurements
after activation, and a separately reviewed, installed native reconciliation
policy are all available. The production activation path is unchanged.
