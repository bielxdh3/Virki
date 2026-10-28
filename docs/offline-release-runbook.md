# Virki offline release — operator preparation (NOT AUTHORIZED)

**Status: implementation foundation only, NOT an enabled production deployment workflow.**
The ordinary GitHub/CodeQL/GHCR deployment path remains unchanged. A successful
local test run or a GitHub PR marked *mergeable* must never be represented as
hosted CodeQL approval or as permission to deploy.

## Explicit contingency preflight (read-only)

The GitHub-backed release remains the primary path. When GitHub Actions/GHCR
is unavailable, the operator may **explicitly** inspect an independently signed
offline release candidate without substituting local tests for hosted results:

```bash
npm run preflight:offline -- --candidate /absolute/path/to/private/signed-candidate --trust /absolute/path/to/independent/operator-trust
```

This command uses `prepareVerifiedOfflineTransportPlan` with the checked-out
canonical repository root. It validates the owner/builder signatures, private
trust files, exact local `main` SHA, claimed evidence, protected SSH identity,
and read-only native-host capacity checks. The signed source SHA must match
the clean local `main` and the cached `refs/remotes/origin/main`. This
offline-only source check performs **no `git ls-remote` or GitHub API call**;
the cached ref alone is not an authority and cannot replace the owner-signed
source identity. The ordinary hosted path still requires the live remote and
exact-SHA hosted evidence. The preflight does **not** run the hosted
`deploy:prod` command, copy artifacts, load Docker images, alter the ledger,
run migrations, or activate services. The output intentionally excludes host
configuration, credentials, full verifier diagnostics and file contents.

`OFFLINE_NOT_READY` with exit code 1 means that prerequisites were absent,
unsafe or could not be verified. `OFFLINE_PRETRANSFER_INSPECTED_ONLY` with
exit code 0 means *only* that this preliminary inspection passed; both
`transferAuthorized` and `deployAuthorized` remain `false`. A real offline
release remains **NO-GO** until a separately owner-approved native trust root,
independent ledger CAS, authenticated Docker daemon lifecycle, protected
transfer, live backup/restore/migration and activation/rollback path have
independent evidence. Never interpret the preflight as an emergency bypass of
a failed security test.

## Boundaries and exact release identity

- Use a clean named `main` checkout with `HEAD == refs/remotes/origin/main`
  and record its full 40-character SHA. Worktrees stay below
  `E:\Virki\.worktrees` on the development computer.
- Run the exact-SHA isolated 19-stage CI with Node 22. A 22/22 E2E result in
  one run does not erase another run's failure; preserve all failures and the
  original run manifest. `validateOfflineCiEvidence` checks report shape, **not
  independently authenticated execution**.
- Run Semgrep OSS separately, preserve its raw report and explicit per-finding
  dispositions. CodeQL is **NOT_RUN**; Semgrep is **not equivalent to CodeQL**.
  A replacement of assurance requires separate, explicit owner acceptance.
- Build runtime and migrator locally from the **same accepted `main` SHA**
  using the pinned Dockerfile, with `linux/amd64`, read-only non-root runtime,
  OCI source/revision labels and no GHCR pull or publication. Test both images,
  keep real raw smoke logs and their exact hash-bound JSON receipts.
- Prepare the **unsigned** candidate using
  `node scripts/offline-release-build.mjs --request <private-absolute-request.json>`.
  The request must refer only to existing real evidence: source SHA, independent
  host identity, predecessor, sequence, scanner rules, CI, smoke and disposable
  backup-restore. The builder does not run those checks for the operator and
  does not attest they occurred. It leaves a 10-file candidate, not an approved
  release.
- A separately protected builder key and distinct owner key must each sign the
  exact canonical manifest. The owner must independently inspect and affirm its
  SHA-256 digest and explicitly accept the reduced offline assurance. Do not
  generate owner signatures from the candidate, commit private keys or install
  keys on the server using code supplied in an unverified TAR. The owner-signed
  candidate contains **exactly 11 files**: `manifest.json`, `signatures.json`,
  `source.tar`, `runtime.tar`, `migrator.tar`, `ci-report.json`,
  `scanner-report.json`, `finding-review.json`, `runtime-smoke.json`,
  `migrator-smoke.json`, `backup-restore.json`.

## Host trust and stop conditions

1. Independent, root-owned, already-installed native Linux/amd64 verifier;
   **v2 trust policy** and revocations in `/etc/virki/offline-release`, durable replay
   ledger in `/var/lib/virki/offline-release`. Both `revokedKeyIds` and
   `revokedPinsSha256` must be independently synchronized with the owner's
   revocation decisions; merely revoking a signer ID on a development PC does
   not revoke its host-pinned key. The old pin-only v1 policy fails closed.
   **No installer or trust root may
   originate from a candidate archive.** WSL is not an acceptable target.
   The replay-ledger root is exclusive to its protected ledger file and its
   transient atomic lock. The candidate staging directory must instead be the
   independent sibling `/var/lib/virki/offline-staging` (owner-only 0700), never
   `/var/lib/virki/offline-release/staging` or a child of the trusted source-Git
   store `/var/lib/virki/offline-source`.
   The repository's `trusted-verifier-dependency-closure` check audits static
   ESM imports and selected runtime launch surfaces (including the single
   approved native Git command). It is a regression guard, **not** a sandbox
   or a complete proof against arbitrary JavaScript evaluation. In particular,
   passing this check cannot replace independently reviewed verifier bytes,
   separately approved root-owned SHA-256 pins, safe native installation or
   executable-bytes-at-use-point verification. It grants no release authority.
   The audited dependency inventory now requires **11 pinned modules**, including
   `trusted-release-coordinator.mjs`, the durable `offline-release-ledger.mjs`
   and the separately gated `trusted-image-import.mjs`. Former eight- and
   ten-module operator pinsets fail closed. An operator must independently
   audit and approve all 11 current SHA-256 digests; no automatic pin migration
   or implied installation is permitted.
2. Verify host identity, independent builder/owner Ed25519 key pins, explicit
   owner assurance flag, revocations, predecessor, sequence, validity window,
   source/archive/report digests, OCI layer/config identities, full source Git
   blob correspondence and trusted provenance of scanner/CI reports.
3. Authenticate the **same immutable bytes at their use point**. Do not feed a
   path back to `docker load` after verification if the path could be replaced.
   Verify loaded image ID, revision/source labels, architecture and nonroot user
   before tagging expected private image aliases.
4. Reserve the accepted nonce/sequence in a crash-durable *attempted* state.
   Hold the operation boundary until protected backup+disposable restore,
   migration, application health, Cloudflare and rollback checks finish.
   After a crash, manual reconciliation is required; never delete a lock to
   silently retry or mark an interrupted release completed.
5. The production host requires a separately measured disk budget. The
   conservative estimator retains **4 GiB after** full staged archives, two
   copies of expanded Docker images, and 3x database footprint plus 512 MiB.
   Image/DB sizes must be measured on the target host, not asserted by the
   uploaded bundle. Preserve old release, database, volumes, Cloudflare Tunnel
   and **every deManage service and data resource**.
6. Existing `scripts/deploy-production.mjs` and
   `scripts/production-server.sh` **do not implement this offline protocol**:
   they require hosted CodeQL/GHCR and the latter assumes `ci=success`.
   Piping their unverified source script to `bash` is expressly forbidden for
   offline release. No deployed marker may claim hosted CI success.

## Disposable coordinator regression (explicit opt-in)

Run `npm run test:offline:coordinator:container` only where the pinned
Node 22.23.3 Docker image is already cached. The dedicated launcher uses
`docker run --rm --network none --read-only`, an immutable image digest,
a read-only checkout mount, `--cap-drop=ALL`, and isolated `tmpfs` mounts
for `/etc`, `/var/lib`, `/usr/local/lib/virki`, and `/tmp`.
The test refuses to start unless the protected directories are empty
real tmpfs mounts inside a disposable root container. Its fixtures never
use the host's trust roots, machine ID, Git pin or production ledger.
This destructive-path fixture is deliberately excluded from ordinary
`test:production-revision` and must be run separately. A successful
`staged` result from it is never release authorization.

## Isolated, untagged native image import (development boundary)

`infra/offline/trusted-image-import.mjs` is an independent, installed-host-only
import boundary. `importApprovedOfflineImages({candidateDirectory})` accepts
only a root-owned private candidate directory, and always processes both the
`runtime` and `migrator` images under one signed admission. Legacy single-role
calls are rejected; uploaded code cannot
inject an image digest, signer, trust token, subprocess or Docker host.
It invokes the independently installed coordinator, which validates the signed
owner/builder manifest, Git source, host identity and exclusive ledger attempt
before image inspection or loading. A read-only dedicated daemon health check
occurs before reserving admission; all failures after admission retain the
durable attempted lock.

After admission, it validates both signed digests of private, root-owned copies
and parses each complete Docker TAR through the same respective file descriptor.
Both copies are unlinked and their parent fsynced **before the first load**;
each inherited read-only descriptor becomes Docker stdin in order. Replacing
or modifying either uploaded TAR while Docker reads cannot mutate its detached
inode. It calls only the separately owner-pinned
`/run/virki-offline-import/docker` CLI with the dedicated
`unix:///run/virki-offline-import/docker.sock` endpoint; its binary SHA-256
must match the independently provisioned root:root 0600
`/etc/virki/offline-import-cli.sha256` file. The dedicated executable and
daemon socket directory must be root-owned and inaccessible to non-root users.
The caller never chooses the Docker executable or socket.

The importer refuses both preexisting image IDs and validates each newly loaded
image's exact content ID, revision/source labels, Linux/amd64 architecture,
non-root user and empty tag/digest aliases. Its only successful result is
`IMPORTED_BOTH_UNTAGGED_ATTEMPT_LOCKED`. It **never tags or starts containers,
deploys, finalizes the ledger, or modifies production services**. A failed
post-load comparison is a fail-closed refusal, not an atomic rollback of bytes
already imported into the isolated daemon; a second-image failure deliberately
retains the first image and the admission latch for manual reconciliation.
This is not an atomic two-image Docker transaction.

The explicit coordinator fixture exercises a simulated Docker executable
inside an ephemeral pinned-Node container with root-only temporary mounts
for `/etc`, `/var/lib`, `/usr/local/lib/virki` and `/run`. It uses no
actual Docker daemon, no host Docker socket and no production resources.
Passing these tests does not prove a real isolated Docker-in-Docker import,
an independently installed operator binary, production-ready runtime, or
authorization to deploy. This module must not be installed or invoked on the
production host until its 11-file byte inventory, separate executable pin,
trusted isolated daemon lifecycle and broader release policy are independently
reviewed and approved.

## Dedicated Docker daemon identity: read-only evidence, NOT admission

`infra/offline/isolated-docker-daemon-identity.mjs` is a separate, **read-only**
identity inspector, not an image-loader dependency, daemon launcher or deploy
entrypoint. Run `npm run test:offline:daemon-identity` for portable, in-memory
adversarial /proc and Docker-info simulations. No test opens, mounts or contacts
the host Docker socket. The native inspector refuses Windows, WSL, non-root,
unavailable /procfs, caller-supplied pins, arbitrary process paths or extra
input. It makes no Docker API request and does not start a daemon.

The independent operator must provision canonical, root:root 0600 JSON at
`/etc/virki/offline-import-daemon/daemon-policy.json` inside a root:root 0700
directory. Version 1 / `virki-isolated-daemon-owner-pin-v1` records exactly:
`version`, `mode`, `cliSha256`, `daemonSha256`, `daemonPid`,
`daemonStartTicks`, `socketKernelInode`, `daemonCgroup`,
`mountNamespace`, `netNamespace`, `pidNamespace`. It must be approved
from **separately trusted native-host observations**, not generated, signed or
overwritten by uploaded release bytes. The independently maintained
`/etc/virki/offline-import-cli.sha256` digest must agree with the new owner
policy. Pin updates require manual review after every intentional daemon
restart; stale PID/start ticks or listener inodes fail closed.

The inspector checks the root-owned private Unix socket at
`/run/virki-offline-import/docker.sock`; obtains the **listening** Unix
stream kernel socket inode from the pinned PID's `/proc/PID/net/unix`;
verifies that the same process holds an FD to that inode; validates the
running `/proc/PID/exe` content against the independently pinned dockerd
SHA-256; and checks the CLI SHA, exact dockerd command line, root IDs, cgroup
v2 path, namespaces, start ticks and procfs PID stability before and after
observation. Both the daemon's `--data-root`
(`/var/lib/virki/offline-import-daemon-data`) and `--exec-root`
(`/run/virki-offline-import/exec`) are required to be independent, root-only
directories. The process's mount, network and PID namespaces must differ from
the inspector's. The strict, ordered daemon command line also disables
iptables, ip6tables, bridge and userland proxy and uses `/dev/null` for
the daemon configuration file. A Docker `info` response can be compared
separately, but its `DockerRootDir` is **self-reported** and cannot establish
socket peer identity, root separation or lifecycle provenance.

**Fundamental P1 boundary:** a process holding a listening Unix socket does
not prove which peer accepted this importer's particular connection. Node's
built-in APIs do not expose a kernel-verified `SO_PEERCRED` binding across
the current Docker CLI calls, and process polling does not provide an
independent supervisor's continuous lifecycle/fencing proof. A proxy could
forward a private-looking socket to the real host daemon. Therefore **even
matching root-owned pins and kernel observations return
`dockerLoadAuthorized:false` and `deployAuthorized:false`**. This module
is deliberately not wired to `trusted-image-import.mjs` and is not added
to the installed 11-module executable verifier pin set. A later integration
must first independently audit and pin its new source bytes and prove a
kernel-bound peer credential + daemon lifecycle/namespace/cgroup isolation
at the **use point of every Docker command**, preferably via an independently
installed, separately owner-pinned native supervisor and disposable
Docker-in-Docker tests. Merely creating a `docker.sock` path, trusting
`docker info`, overriding the WSL kernel check or presenting a synthetic
fixture result must never enable a production Docker import or deploy.

### Kernel-backed Unix peer FD experiment (non-authorizing)

The separately reviewed experimental sources in
`infra/offline/native-peer/native-peer-probe.c` and
`infra/offline/native-peer/native-peer-probe.test.mjs` demonstrate the
**actual Linux socket-credential primitive**, not a Docker image-import
implementation. Run `npm run test:offline:peer:container` to compile the
small C program inside a disposable pinned Node 22 Linux root container and
run real Unix-stream kernel tests. This fixture uses `--network=none`,
`--read-only`, `--cap-drop=ALL`, `no-new-privileges`, a read-only
repository bind and an executable throwaway `/tmp` tmpfs. It does **not**
mount `/var/run/docker.sock`, contact Docker Engine through the test
program, or access production resources. The test runner's use of Docker is
limited to creating and removing its isolated disposable test container.

The C test client restricts endpoints to `/tmp/virki-peer-fixture-<16 hex
digits>/docker.sock` under a root-owned 0700 test directory. It opens a
separately stored root-owned 0600 `peer.pin` file using `O_NOFOLLOW`,
requires a canonical fixed version, exact PID and Linux start ticks, opens
**one** Unix connection with `SOCK_CLOEXEC`, gets `SO_PEERCRED` from
that same connected socket FD, and obtains a `pidfd_open` for the peer.
It verifies the live PID start ticks and pidfd liveness twice while keeping
the socket FD open. The experiment transmits **zero bytes** and closes
the FD before returning a non-authorizing diagnostic. Tests exercise true
kernel-backed credentials, stale PID/start ticks, a replacement root-owned
server using the same socket name, bad policy modes/aliases/hardlinks,
invalid endpoints, and non-private sockets. Neither environment flags nor
fixture policy content can opt in to Docker mutation.

The `peer.pin` is generated by the *disposable test harness* and is not an
independent owner approval for a real daemon. `SO_PEERCRED` identifies
the accepted Unix peer, **including a forwarding proxy if one owns that
connection**; it does not attest its upstream targets, executable,
`DockerRootDir`, mount namespace, cgroup or independently controlled
service lifecycle. A pidfd pins a process while held, not future connections
after it is closed. The measured socket FD is also **not** the FD that the
current `trusted-image-import.mjs` passes to the Docker CLI. Therefore the
success diagnostic always carries `dockerLoadAuthorized:false` and
`deployAuthorized:false`. This experiment is not part of the installed
11-module verifier inventory, is never automatically built or installed,
and cannot modify the release admission decision.

**Minimum native supervisor design required before any integration:**
An independently audited owner-pinned native binary and unit must start and
supervise the dedicated daemon within reviewed mount/net/pid namespaces
and a dedicated cgroup, with a protected, separate Docker data root and
no bind-mounted production socket or volumes. Its owner-controlled policy
must be provisioned outside release input and bind the exact supervisor
executable digest, daemon executable digest, service unit, unit/cgroup,
namespace identities, data-root filesystem/mount ID, listener FD and
daemon PID/starttime. The supervisor must keep the daemon pidfd and each
connected socket FD live across admission and all Docker API operations.
It must check kernel `SO_PEERCRED`, listener ownership, daemon lifecycle
and namespaces **on the very same FD carrying the authenticated import
request**; a separate CLI invocation that reconnects is insufficient.
Only signed, verified TAR bytes from the detached immutable FD may be
streamed as an exact bounded HTTP request. Each subsequent read/inspect
connection must be independently pinned to the same supervised daemon.
The supervisor must durably fence the attempt and refuse on exit, restart,
proxy mismatch, network/cgroup replacement, unexpected response or a
partial image import. Independent owner installation and real disposable
isolated daemon tests, plus fresh code inventory/digest approvals, are
prerequisites. This design is **not implemented** by the read-only probe.

### Supervised same-FD protocol experiment (no Docker authorization)

`infra/offline/native-supervisor/fd-lifecycle-fixture.c` implements a
separate, explicitly disposable Linux-native supervisor/protocol experiment.
`npm run test:offline:supervisor:container` is **not an automatic Docker
invocation**. It requires an explicit `VIRKI_DISPOSABLE_SUPERVISOR_RUN_DOCKER=1`
on Windows, an installed Docker Desktop CLI at the reviewed absolute path, and
the fixed local Linux named pipe
`npipe:////./pipe/dockerDesktopLinuxEngine`. An empty temporary Docker
configuration and scrubbed environment ignore ambient Docker contexts,
remote sockets and credential settings. The test image is digest-pinned,
never pulled, and runs with networking disabled, all capabilities dropped,
read-only filesystem/repository, `no-new-privileges`, and one executable
tmpfs at `/tmp`. The container receives a randomized ownership label and
immutable container-ID file; any cleanup is limited to a full 64-hex ID whose
inspected label matches this run. Failure to verify ownership must never lead
to wildcard/name cleanup. A missing CID file does **not** prove cleanup: a
failed or timed-out run might have started the container before writing its ID.
If an unsuccessful invocation cannot confirm cleanup, the local fixture
directory is preserved for separate operator review even when the CID is
missing, instead of silently forgetting a potentially live container. Local
test-fixture deletion is restricted to the temporary directory created in the
same Node process, checked against its original device/inode and an exact
known-file inventory. No general recursive-delete path is accepted: foreign
directories, replaced roots, hardlinked CID records, symlinks, and unexpected
children preserve the evidence and fail the test. A valid CID's full container
ID and exact owner label must be verified before Docker cleanup. These
path/metadata checks do not create a kernel-atomic same-handle guarantee
against a privileged or same-user concurrent file replacement, nor do they
prove Windows ACL ownership. Such environments are **not** production trust
boundaries. The launcher does not mount a host Docker socket.
No real Docker-in-Docker daemon is started or authorized.
Startup errors before Docker CLI invocation are reported distinctly from errors
after the CLI was invoked; once invoked, daemon contact **cannot be ruled out**
even if the CLI reports failure or times out. Diagnostics never claim otherwise.

For local development **without contacting Docker at all**, native C fixtures
also run with root inside a separately opted-in Ubuntu WSL2 test VM:
`VIRKI_DISPOSABLE_SUPERVISOR_TEST=1
VIRKI_DISPOSABLE_SUPERVISOR_WSL_TEST=1 node --test
infra/offline/native-supervisor/fd-lifecycle-fixture.test.mjs`.
The fixture verifies the WSL2 kernel identifier and compiles the C binary
into a transient protected `/tmp` directory. WSL2 is **not** a production
supervisor isolation proof and is not a substitute for native service tests.

The test-only supervisor forks and owns its own fake Unix-stream service
under a randomly generated root-owned private
`/tmp/virki-supervisor-*/engine.sock` directory, retains a `pidfd_open`
descriptor to the exact child, and connects once using `SOCK_CLOEXEC`.
Before and after each synthetic framed exchange it reads `SO_PEERCRED`
from that **same connected socket FD**, checks the child's Linux start
ticks and pidfd liveness, and compares its mount, network and PID namespace
identifiers and cgroup-v2 path against the initial `/proc` snapshot.
The client also enables Linux `SO_PASSCRED` and uses `recvmsg` to verify
`SCM_CREDENTIALS` on **every received synthetic response chunk**. It refuses
absent, truncated, unexpected or differently attributed credentials. This
adds a sender check to the existing connect-time peer check; it is not a
capability-restricted daemon attestation.
Only fixed synthetic `LOAD`, `INSPECT` and `INFO` phase requests with fresh
kernel-generated 128-bit transaction challenges are allowed. Every fake
`ACK` must echo the same phase and nonce; replayed or prequeued acknowledgments
for a previous request cannot satisfy a subsequent phase. These are **not
valid Docker HTTP requests**: no archive is loaded, and no fake service can
interpret or forward Docker API operations. One absolute `CLOCK_MONOTONIC`
deadline covers the complete three-phase exchange, including individual
reads, writes and delays. The parser checks for surplus bytes after each
response, then half-closes the client socket after `INFO` and requires clean
peer EOF to reject even a late trailing payload. Cleanup first attempts
`SIGTERM`, then bounded `SIGKILL` and nonblocking `waitpid` reaping. EINTR is
retried within the deadline, and a positive lifecycle result is forbidden
unless `waitpid` positively confirms the exact child was reaped. Disposable
fault injection tests cover interrupted waits and lost reap confirmation.
The socket directory is removed only after successful child cleanup and
verification that it is the originally created root-owned directory inode,
not a renamed/replaced path. If those proofs fail, the test refuses positive
status and preserves the private socket path for manual reconciliation.
The child must also exit successfully; nonzero exits or signal termination
preserve the original root/socket evidence rather than deleting it, even if
`waitpid` confirmed the child was reaped. A swapped fixture root is reported
alongside its separately renamed original path only when that former location
still has the exact root-owned original device/inode. No arbitrary symlink
target is resolved or disclosed by this diagnostic.
These C pathname/inode checks are not a kernel-atomic same-directory-handle
cleanup primitive against an independently privileged concurrent attacker;
they demonstrate fail-closed swaps in the disposable fixture only.

The adversarial tests demonstrate continuity of the kernel peer identity
across the entire *synthetic* operation; they also cover daemon death before
or during the exchange, response tampering, three prequeued syntactically
valid responses, late trailing bytes, slow-trickle deadlines, TERM-ignoring
children, inherited-FD and real `SCM_RIGHTS` transfers to a second process
that sends otherwise valid replies while the pinned daemon remains alive,
changed private socket-root inodes, fake negative root-directory
responses and mode/path escape. The
`fake-rootdir` case remains a **synthetic negative acknowledgment**, not
proof against a syntactically valid malicious real Docker `/info` response.
Even
the positive fixture reports `isolatedNamespacesApproved:false`,
`dockerLoadAuthorized:false` and `deployAuthorized:false`. Its child
shares the test container's cgroup and namespaces; an independently
reviewed owner-provisioned service unit, immutable pinset, dedicated
daemon binary/RootDir, mount-ID binding and durable restart fencing remain
absent. The native code explicitly has **no production entrypoint**, is
not installed, and is not added to the existing 11-module verifier graph.
In a WSL2 test, the child likewise shares the WSL test VM's namespaces;
there is no dedicated independently owner-approved isolation boundary.
`SO_PEERCRED` identifies the socket's connect-time peer, not necessarily the
writer of every subsequent response. The new per-chunk `SCM_CREDENTIALS`
check rejects the demonstrated inherited-FD and `SCM_RIGHTS` handoffs when
the sender has no capability to impersonate another PID. Linux permits
privileged senders (notably those with `CAP_SYS_ADMIN`) to supply alternate
PID credentials, and this disposable fixture does not prove those privileges
are absent throughout a real daemon lifecycle. It also cannot establish
the provenance of upstream traffic forwarded by a proxy. A pidfd and
per-message credentials alone do not prove independent control or isolation.
**Production NO-GO.**

To move beyond the experiment, commission an independent security review
of an owner-signed native service installer and constrained supervisor:
verify executable content by pinned inode before launch, create a dedicated
process and cgroup with locked mount/net/pid namespaces, prove that no
real Docker socket, production volume or data root is reachable, pin the
daemon executable and data-root mount ID, supervise PID/FD lifecycle through
every real Docker API request on the same connection, verify real daemon
responses and reconcile partial imports without authorizing deploy. Test
this on a dedicated ephemeral native Linux VM (not a privileged container
sharing a production daemon), including root-owned socket proxies, daemon
restarts, disconnects, cgroup movement, mount swaps and kernel audit logs.
Until that external proof is reviewed, **a socket, pidfd, owner pin, or
successful fake-service test cannot grant Docker import authorization**.

## Evidence and disposition

### Independent ledger witness read (non-authorizing prototype)

`npm run test:offline:witness-read` runs a local Ed25519 verification contract
in `scripts/lib/offline-ledger-witness-proof.mjs`. The fixture-only probe
generates a fresh unpredictable 256-bit challenge and validates an exact,
canonical signed response bound to the independently pinned witness public
key, host identity, whole local ledger SHA-256, sequence, accepted revision and
a maximum 30-second validity window. It rejects response replay, foreign keys,
rewound snapshots, unknown/duplicate fields and forged signatures. No private
witness signing key belongs on the release host or in the repository.

This is **only a signed remote-read protocol contract**: its transport callback
is enabled solely with `VIRKI_DISPOSABLE_WITNESS_PROBE=1` for tests. There is
no deployed independent witness, owner-provisioned public-key pin, mutually
authenticated transport, atomic distributed compare-and-swap, durable external
state, host-controlled timing, or native release integration. No response grants
`witnessCasAuthorized`, `dockerLoadAuthorized` or `deployAuthorized`. In
particular, a signed fresh read does **not** guarantee that a later local
append was accepted by an independently durable monotonic authority. Real
release admission and completion must remain blocked until independent CAS
and reconciliation are implemented and reviewed.

Before approval, retain the exact final SHA, `run-manifest.json` with all
19/19 stages, complete scanner/finding-review report, runtime and migrator
image IDs and hashes, real disposable restoration report, host-preflight and
free disk measurements, owner-approved manifest SHA-256, key IDs, policy
revision and rollback procedure. Private credentials, raw database content,
recovery factors or email payloads must not appear in logs or PR comments.

**Current release gate: BLOCKED.** The native installed trust policy, owner
approval/signature, trusted image-loading/application path and source/host
verification must be completed before any production mutation. Until that is
true, operators may inspect and test offline artifacts locally only.
