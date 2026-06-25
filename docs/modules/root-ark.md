# root.ark Zero-Knowledge Planning Document

root.ark is not implemented yet. This document is a planning gate only and does not enable file storage, upload, import/export, indexing/search, UI, routes, APIs, database schema, Prisma migrations, encryption code, or private data ingestion.

root.ark is now intended as a higher-risk public-facing file transfer/storage module with compartment-based access and a zero-knowledge or end-to-end encrypted file model. Implementation remains blocked until a dedicated root.ark architecture phase is completed.

## Module Identity

- Module name: root.ark.
- Module owner: BielOS owner.
- Module purpose: Future public-facing encrypted compartment system for file transfer or storage.
- Current status: Planning only. Implementation is blocked.

## Data Classification

- Classification: highly sensitive.
- Private data types: Future encrypted file contents and minimal encrypted or non-sensitive compartment metadata, pending architecture.
- Data explicitly not collected in this phase: files, plaintext filenames, plaintext metadata, passwords, passphrases, keys, secrets, raw links, raw tokens, raw logs, raw headers, raw IPs, JWTs, cookies, private keys, database dumps, backups, uploads, archive files, and any real private records.
- Public or non-private data, if any: Module name, locked/planned status, and this planning document.

## Public Surface And Compartments

- root.ark is intended to have a public-facing surface, unlike the private hub modules.
- Access must be compartment-based.
- A user or recipient must only access their own compartment.
- There should be no normal public sign-in flow.
- Recipient access may use capability links, one-time keys, passphrases, or another future approved mechanism.
- Link leakage is a critical security risk and must be treated as equivalent to possible compartment compromise unless the future design proves otherwise.
- Admin-only credentials may manage compartments but must not grant access to decrypted file contents.

## Zero-Knowledge File Model

- The server must not be able to decrypt user files.
- The admin must not be able to decrypt user files through admin credentials alone.
- File contents must be encrypted client-side or through an equivalent end-to-end encrypted design before reaching server storage.
- Server-side storage may hold only encrypted blobs and minimal metadata.
- Metadata minimization is required. Future design must avoid plaintext filenames, sensitive MIME details, recipient identity details, or stable correlation identifiers unless explicitly justified.
- Key generation, derivation, wrapping, sharing, rotation, recovery, and loss behavior require a dedicated architecture phase before implementation.

## Storage Model

- Storage location: Not defined.
- Database tables or files: None in this phase.
- Encryption or key-management needs: Dedicated root.ark architecture phase required before any code exists.
- Search/indexing behavior: Not enabled. Plaintext indexing is incompatible with the zero-knowledge goal.
- Derived data or caches: Not enabled.

## Migration Plan

- Prisma schema changes: None in this phase.
- Migration files: None in this phase.
- Backfill requirements: None.
- Rollback approach: Documentation-only rollback.
- Disposable validation plan: Required before any future schema, storage, encryption, or public access work.

## Backup And Restore

- Backup impact: None in this phase.
- Restore validation impact: None in this phase.
- Data that must never be exported: Plaintext file contents, raw keys, passphrases, raw capability links, raw tokens, sensitive filenames, and decrypted metadata.
- Disaster recovery notes: Future design must define whether encrypted blobs are recoverable when client-side keys are lost. Server-side recovery must not bypass zero-knowledge constraints.

## Access Control

- Required user roles: Admin-only management for compartments, pending architecture.
- Public recipient access: No normal public sign-in. Future access must use approved compartment capabilities.
- Cloudflare Access assumptions: The admin management surface may remain behind Cloudflare Access. The public recipient surface needs a separate architecture decision.
- BielOS internal auth requirements: Admin management remains behind BielOS internal auth when reachable from the hub.
- Module-specific unlocks: Required for admin compartment management if sensitive.
- Cross-module access boundaries: root.ark must not share file contents, keys, links, or compartment data with other modules without explicit design.

## Audit Events

- Events to record: Future design must define compartment creation, compartment revocation, encrypted upload, encrypted download, failed access, deletion, admin management, and key/capability lifecycle events if those actions are added.
- Event result values: Use existing sanitized success, failure, or info patterns.
- Sanitized metadata only: Yes.
- Data explicitly excluded from audit logs: File contents, encryption keys, passphrases, raw capability links, raw tokens, plaintext filenames, sensitive metadata, raw headers, raw IPs, cookies, JWTs, raw user agents, private paths, and backup contents.

## Retention, Revocation, And Deletion

- Retention period: Not defined.
- Deletion behavior: Not defined.
- Cleanup command or worker: Not defined.
- Revocation rules: Must be designed before implementation. Future design must define what revocation means after a recipient has already downloaded encrypted content or copied keys.
- User-visible deletion expectations: Future design must define permanent deletion, delayed deletion, backup deletion limits, capability invalidation, and recovery expectations.

## Threat Model

- Primary assets: Future encrypted file blobs, decryption keys, compartment capabilities, recipient access paths, and minimal metadata.
- Abuse cases: Link leakage, token replay, unauthorized compartment access, admin overreach, metadata correlation, unsafe export, unsafe logging, malicious upload, and backup leakage.
- Accidental exposure risks: Raw links in logs, browser history, referrers, screenshots, debug output, plaintext filenames, notifications, previews, and copied URLs.
- Local machine risks: Local filesystem exposure, Docker volume handling, browser cache, and untracked generated files.
- Remote access risks: Public surface abuse, Cloudflare misconfiguration, direct origin exposure, brute force of capabilities, and denial of service.

## Failure Modes

- Database unavailable: Future implementation must fail closed for writes and sensitive reads.
- Storage unavailable: Future implementation must fail closed for upload/download and avoid partial plaintext exposure.
- Backup unavailable: Future implementation must block non-discardable ingestion until backup and restore are validated.
- Cloudflare Access unavailable: Admin management should remain blocked remotely.
- Internal auth unavailable: Admin management must not proceed.
- Key loss: Future design must explicitly state whether server-side recovery is impossible.
- Partial upload or download failure: Future implementation must define atomicity, cleanup, and encrypted blob consistency.

## UI Safety Constraints

- No private data fields until approved: Required.
- No upload inputs until approved: Required.
- No secret, key, passphrase, or raw link display unless specifically designed.
- No raw logs or audit metadata display.
- Safe empty states: Must state that root.ark is locked and not storing files.
- Public UI requires a dedicated safety design before implementation.

## API Safety Constraints

- Allowed methods: None in this phase.
- CSRF requirements: Required for admin mutable routes. Public capability flows need a dedicated design.
- Auth checks: Required for admin routes. Recipient routes must be compartment-scoped by approved capabilities.
- Rate limits: Required for public access, upload, download, and admin mutation paths.
- Request and response redaction: Required.
- Error message behavior: Generic for auth, capability, and access failures.
- Referrer and cache behavior: Future public routes must prevent leaking raw links or tokens through browser and intermediary behavior.

## Secrets Handling

- Required env names: None in this phase.
- Placeholder-only docs: Required for any future env.
- Rotation behavior: Future design required if server-side secrets are introduced.
- Logging restrictions: Never log secrets, tokens, private keys, raw headers, raw IPs, cookies, JWTs, file contents, keys, passphrases, raw links, plaintext filenames, encrypted blob contents, or sensitive metadata.

## Import And Export Rules

- Import sources: Not enabled.
- Export formats: Not enabled.
- Manual confirmation requirements: Required before any future export or admin destructive action.
- Redaction requirements: Required before any future export.
- Files that must stay out of Git: Any dumps, exports, backups, uploads, encrypted blobs, plaintext files, keys, passphrases, raw links, private records, search indexes, or generated archives.

## Required Architecture Phase

Before implementation, root.ark needs a dedicated architecture phase covering:

- public routing and Cloudflare boundary
- compartment identity model
- capability format and lifecycle
- key generation, derivation, wrapping, and recovery
- zero-knowledge proof points and limits
- encrypted blob storage
- metadata minimization
- link leakage mitigations
- revocation and deletion semantics
- admin management boundaries
- audit and rate-limit strategy
- backup and restore behavior
- abuse and denial-of-service controls

## Validation Checklist

- Secret scan: Required for this planning document.
- Lint: Required when runtime code is added.
- Typecheck: Required when runtime code is added.
- Build: Required when UI or runtime code is added.
- Prisma validation: Required when schema changes are added.
- Migration validation: Required when migrations are added.
- Backup and restore validation: Required before ingestion.
- Local admin auth check: Required before admin routes are added.
- Public capability negative tests: Required before public routes are added.
- Cloudflare Access check: Required for admin management exposure.
- Negative tests for unauthorized compartment access: Required before implementation.
