# Issue #90 — V36 DEV reference broker: independent root-owned publication authority

V36 is a **new, unwired, opt-in DEV experiment**. It does NOT modify a production BuildKit call site, daemon, endpoint, service, container or tunnel. The existing V23–V35 patch chain and Git trees are unchanged. The original PR #141 SHA `1123f0fde7ca54b6553091f956c4ebd77b91852e` remains immutable against `main@6802c432163ef7270cdcedc6d9fb55120698a1f3`.

## Why this changes the security boundary

V35 still stages and publishes under a **receiver-owned** parent directory. If a malicious process shares the receiver UID, a check followed by `renameat2` cannot prevent it from replacing the source name or mutating published files. Rehashing detects some tampering but never guarantees that unverified bytes were not briefly exposed.

V36 prototypes the alternative **separate trusted publication principal**. The unexported `publishV36RootOwnedSnapshot` method may execute only as real/effective UID 0 in a controlled DEV fixture, with an explicit distinct unprivileged source UID/GID. It requires a pinned private source directory FD, an internally consistent bounded V15 manifest, a destination whose *entire ancestor chain* is protected root ownership, and a final root-owned 0700 parent. Within this parent it creates fresh root-owned inodes, copies only manifest-approved regular source files using Linux `openat2` (`RESOLVE_BENEATH`, `NO_SYMLINKS`, `NO_MAGICLINKS`, `NO_XDEV`), checks per-file size/hash against the frozen manifest, independently rechecks the trusted copied tree and its filesystem metadata, fsyncs, and publishes with `RENAME_NOREPLACE`. **The input source FD can remain same-UID mutable: it is never itself renamed into the trusted destination.** The published copy is inaccessible for write/rename by that unprivileged UID throughout verification and release.

## Adversarial controls and remaining assumptions

`TestC1V36RootBrokerCopiesIntoIndependentPublicationAuthority` requires `VIRKI_V36_RUN_ROOT_FIXTURE=1` and actual root in an expendable Linux DEV environment. It provisions a disposable root 0711 supervisor directory, 0700 root-owned broker parent, and 0700 synthetic UID 60011 receiver-owned source. The fixture checks a real nonroot same-UID subprocess **can write its own source** (positive control) but **cannot write the published root-owned copy** (negative control), and that an already-mutated source is rejected with no published destination. It races 12 separate broker publications against 300 same-UID source rewrites, allowing only an exact `SAFE` copy or no published path. Symlink source escapes, pre-existing destinations and sender-owned destination parents must be refused. Synthetic source and payloads only; no real credentials, user files, or network publication.

The fixture does **not** establish trusted origin identity, C4 owner signature, authenticated process-to-process source-FD passing, exclusive mount/UID custody over the complete lifetime, durable replay prevention, crash recovery or an actual deployed broker. Those require a **separately authenticated SCM_RIGHTS/peer-credentials handoff and independent authority contract**, wiring and further adversarial testing, plus explicit authorization before any operational change. A caller-supplied manifest digest is internally consistent, but **is not itself owner authentication**. Never expose this unexported DEV function as a public RPC or bypass the existing C1 deny-by-default path. C1/C4 production **NO-GO** remains.

## Immutable incremental evidence

- V35 input cumulative Git tree: `4da0f43bfcdad770f4a1bf5786ec6df79f6f4a97`.
- V36 incremental LF patch SHA-256: `fac7bd7a03845a24f8f22de89b862bce1662b4c19b932cb57bb4fc430edfc7a0`.
- V36 cumulative Git tree: `ba02b937798adb90eed08d17196f9aca91b13721`.
- Replay: `bash scripts/security/issue90-replay-index.sh <pinned BuildKit tree>`; verifies all **14** checksums and expected trees using an isolated index.
- Go 1.26.10 Linux: root-supervised synthetic fixture with `-race`; unprivileged FileSync tests, V32 same-UID ptrace/procfd positive and negative controls, V33/V35 adversarial races, and `go vet -copylocks=false` must remain green. Hosted CI and review must be checked **at the exact latest PR SHA**.
