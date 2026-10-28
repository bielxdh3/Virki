# Manual GitHub-free release — local operator staging

`npm run deploy:manual` is a **real local staging and readback command** for the independently owner-signed offline candidate. It is currently **not a production deploy command**: the independently installed native bootstrap, off-host monotonic witness CAS, and native supervised release/rollback authorization must be established and reviewed before any remote mutation. Its current exit status is always `2`, including a successful local staging. No GitHub Actions API, GHCR, Docker load, production database, or production service modification occurs.

## Operator invocation

Use a Linux operator environment with Node 22, private candidate and root-owned separate trust files. The verified source must be a clean named `main` at the exact SHA of the owner-signed manifest, equal to cached `origin/main`. A Windows-native process cannot satisfy the Linux protected-file requirements. WSL can run local Linux tests or perform read-only operator checks with appropriate root-owned trust, but **WSL itself is never the production host**, and WSL files do not establish the independently provisioned trust root of the native release host.

Create the **local** staging parent separately as a private, existing `0700` directory owned by the invoking account. It must be disjoint from the checkout, trust directory, and input candidate. Files in the source candidate must have mode `0600` and the source directory `0700`. The stage receives exactly the eleven signed candidate files, preserving an immutable copy for subsequent independent owner review:

```bash
node --version
mkdir -m 700 /private/operator/manual-stages
npm run deploy:manual -- \
  --candidate /private/operator/owner-signed-candidate \
  --trust /private/operator/independently-provisioned-trust \
  --stage-parent /private/operator/manual-stages
```

The protected trust directory must contain only `ledger.json`, `trust-policy.json`, `transport-policy.json`, and `ssh-known-hosts`, each root-owned and mode `0600`. The directory itself must be root-owned `0700`. The transport policy now also requires an independently pinned `sshUser` (`[A-Za-z_][A-Za-z0-9_.-]{0,63}`): ambient SSH user aliases are ignored. SSH runs with `-F none`, explicit host, port and user to prevent `Match exec` from user/system SSH configuration. Existing transport policies without `sshUser` are refused and must be **independently reapproved**, not silently upgraded. The pinned known-hosts Ed25519 public key, owner/builder Ed25519 identities, exact accepted Git SHA, host identity, ledger anchor, and capacity budget must be provisioned and approved independently of the uploaded candidate. The CLI does not create these pins or make signing decisions. For initial native verifier installation and the independently signed bootstrap policy, follow [the owner verifier installation procedure](offline-owner-verifier-installation.md).

**Read-only verification stages:** existing `prepareVerifiedOfflineTransportPlan` checks the signed envelope, owner/builder key pins, evidence structure (including 19 local CI stage claims), clean source identity, SSH configuration, native host preflight, and SSH host machine identity. A passing preflight is a signed candidate and SSH pretransfer inspection, not externally attested CI execution or a release approval.

**Local copy stage:** after that inspection succeeds, `stageLocalOfflineCandidate` copies the exact eleven regular files in bounded chunks through no-follow file descriptors into a new `0700` local directory, creates `0600` files with exclusive opens, hashes and fsyncs the copied data, independently hashes every output again, reinspects both candidate directories, and atomically publishes the stage under the private parent. It rejects symlinks, hardlinks, extra files, altered digests and overlapping roots. A failed staging operation cleans up its own unpublished temporary directory. After publication the operator repeats the **full signed owner/builder, CI, source and pinned-host preflight on the staged copy** and binds the canonical signature-envelope SHA-256 as well as the manifest SHA-256 to the original approved check. A post-check swap of `signatures.json` is not accepted merely because the manifest did not change. The published local copy is still treated as untrusted for any host use.

**Crash uncertainty:** if `rename` succeeded but the final staging-parent `fsync` fails, the code never reports success and does **not** silently discard the published path. It returns the exact protected random staging path for owner reconciliation with `deployAuthorized:false`. This is not proof of durability across a reboot; the operator must inspect the parent filesystem and should not retry automatically.

The command returns machine-readable JSON. Relevant statuses:

| Status | Meaning | Next action |
| --- | --- | --- |
| `MANUAL_OPERATOR_INPUT_REJECTED` | Unsafe paths, overlapping trust, invalid options or caller-supplied overrides | Correct input paths and invoke exactly three flags |
| `MANUAL_PRETRANSFER_NOT_READY` | The private owner-signed candidate, protected local trust, Git source or read-only pinned host check failed | Reconcile operator pins and evidence outside the candidate |
| `MANUAL_LOCAL_STAGING_FAILED` | Verified inputs were inspected but local copy/readback failed | Review private staging filesystem and candidate bytes |
| `MANUAL_POST_STAGE_SIGNATURE_RECHECK_FAILED` | Copy exists but complete staged signed-envelope preflight or exact signature identity failed | Quarantine the retained stage; no remote transfer |
| `MANUAL_STAGING_SYNC_UNCERTAIN_RETAINED` | Published private copy exists but final parent fsync failed | Inspect the reported owner-scoped path and independently reconcile before retry |
| `MANUAL_LOCAL_STAGE_VERIFIED_REMOTE_BLOCKED` | Local eleven-file copy and readback succeeded; host release authority is still missing | Obtain independently reviewed native provisioning and monotonic witness evidence |

All statuses return `transferAuthorized:false` and `deployAuthorized:false`. The JSON `phases` fields state which stage ran, which was blocked and why; the successful local-copy result includes the private local path, exact source revision, and signed manifest SHA-256 for operator review.

## What an owner must independently provision before release

1. Audit and approve the **exact native executable bytes, their loader/Node dependencies, verifier's eleven pinned ESM modules, and bootstrap identity**. Provision the already-reviewed bootstrap under `/usr/local/lib/virki/offline-bootstrap` and protected policy under `/etc/virki/offline-bootstrap` using the [owner-approved installation procedure](offline-owner-verifier-installation.md). Only the independently approved native installer may publish the installed verifier to `/usr/local/lib/virki/offline-release`; candidate-provided code is never executed as a bootstrap.
2. Independently maintain the protected trust policy, revocations, Git source store and durable replay ledger for the authenticated host, and obtain a real off-host **monotonic compare-and-swap witness**. A signed read-only witness challenge or a `staged` local coordinator response cannot serve as CAS approval.
3. Review and install a real native supervisor with verified immutable runtime/migrator image identities at the Docker use point, protected PostgreSQL backup and disposable restore, migrations, health checks and rollback. The existing scripts include disposable/native fixture work, but those fixtures do not prove this production control path.
4. Extend this operator workflow only after independently auditing the host transfer protocol, authenticated remote staging receipt, exclusive witness reservation and native finalization, with a real native test on a disposable approved host. Keep the standard GitHub-based production path unchanged.

The command deliberately exposes no SSH write operation or remote staging endpoint today. The root-owned verifier installer has a separately gated preview/install path, and its existence alone must never be interpreted as authority to transfer release artifacts. This is the precise open integration boundary, not a bypass flag.
