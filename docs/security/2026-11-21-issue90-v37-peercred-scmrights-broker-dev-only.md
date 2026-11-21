# Issue #90 — V37 DEV Unix-domain authenticated descriptor handoff

V37 is an incremental, **unwired DEV-only** reference composition after V36. None of the immutable V23–V36 patch bytes or Git trees change; the original #141 reviewed SHA `1123f0f` remains traceable against `main@6802c432`. There is no production endpoint, deployment, C1/C4 signing or owner permission conferred by this experiment.

## Security mechanism

The trusted broker receives a previously accepted local `net.UnixConn` from a protected supervisor, with a separately specified, expected **PID, UID and GID** of its spawned nonroot sender. The Linux kernel `SO_PEERCRED` values must match before accepting the source and must remain unchanged after handoff. Read time is bounded, the message has exactly one fixed marker byte, and a single `SCM_RIGHTS` directory descriptor must be received without truncation or any additional control messages/descriptors. All rejected descriptors are closed; an accepted descriptor receives `CLOEXEC`. Its owner UID/GID, directory type and private mode are rechecked via `fstat` before passing it to the V36 broker, which copies into new protected root-owned inodes and atomically publishes under a root 0700 parent.

The sender never selects the target path, the expected owner IDs, the manifest, the trusted key or any C4 release decision: those are independently supplied broker inputs. This prototype **does not** itself validate a C4 signature, authenticate an end-user, protect a socket that was passed to an unintended process, guarantee a deployed listener's lifetime, or provide durable replay/crash fencing. Peer credentials alone must never be treated as owner approval. It also cannot prove that no hostile process shares the receiver UID or that a production mount namespace is isolated. Before any real activation, a trusted supervisor must ensure the socket and receiver lifetime, the origin of approved manifests, a durable owner permit, and correct failure recovery with independent evidence.

## Deterministic adversarial fixture

`TestC1V37AuthenticatedUnixRightsHandoff` requires `VIRKI_V37_RUN_ROOT_FIXTURE=1` and real root in an expendable isolated Linux DEV environment. The supervisor creates a disposable socket under a root-owned non-writable parent, grants socket group access only to synthetic receiver UID/GID `60012`, and launches a separate unprivileged **actual child process**. The child sends the same-UID-owned source directory descriptor with one fixed marker, not an arbitrary path string. Positive test: exact peer PID/UID/GID and one FD produce a manifest-exact root-protected copy. Negative tests: two SCM_RIGHTS FDs and mismatched expected peer PID must fail with no published destination. The tests have bounded socket deadlines, use synthetic content and do not attach to any production listener.

- V36 input tree: `ba02b937798adb90eed08d17196f9aca91b13721`.
- V37 LF patch SHA-256: `84a016940fcc04c6a72de153c5d8168c74df9a012fb845764cf9a87aec89681f`.
- V37 cumulative tree: `fcaf997a3f72c64904a04fd5c240db44773f0b13`.
- `bash scripts/security/issue90-replay-index.sh <pinned BuildKit source>` must reproduce all **15/15** manifest hashes and Git trees without touching the working tree.
- Linux Go 1.26.10 with vendored dependencies: unprivileged FileSync suite and `-race`, vet, and synthetic root V24/V28–V31/V36/V37 fixtures with `-race` must pass at the **exact** PR SHA.

**Disposition:** V37 narrows the missing broker handoff mechanism but does **not** meet the complete #90 admission/release criterion. C1/C4 protected FileSync and production release remain **NO-GO** until signed-owner authorization, crash/replay discipline, full supervisor/namespace isolation and independently approved integration are proven. The Close Issue button remains exclusively the owner's.
