# Security audit

Virki persists security audit events in PostgreSQL `AuditLog`. Runtime accounts can append and read events; UPDATE and DELETE remain denied. Retention runs through the separate maintenance role. The ADMIN investigation page checks the current Cloudflare Access assertion, central session, active account and ADMIN role before every server query, including partial renders. Expanding a native details element reveals only the already authorized, redacted page snapshot; it does not fetch another dataset.

## Version 1 envelope

| Field | Meaning and minimization |
| --- | --- |
| `id`, `createdAt` | Immutable database event identifier and UTC instant. |
| `schemaVersion` | Envelope and metadata contract version; new writers use 1. |
| `eventType`, `category`, `action` | Static event identifier, event family and normalized dotted action. |
| `severity`, `result`, `reason` | INFO or WARNING severity; SUCCESS, FAILURE, DENIED or INFO outcome; bounded machine reason. Reasons are completed, rejected, observed, rate-limited, unavailable, csrf, role and cloudflare. Severity describes the recorded outcome, not an incident assessment. |
| `actorUserId`, `actorEmailHash`, `actorRef` | Existing internal attribution is preserved. UI/search uses a SHA-256 reference to the internal account ID or to an already pseudonymized attempted email reference. A login failure's attempted account is not proof of who performed it. Raw emails and display names are never joined into the investigation view. |
| `actorRole` | ADMIN or USER only when a caller has verified that role. Unknown is null. |
| `targetRef`, `sessionRef`, `deviceRef` | Optional digest references. No cookie, token, session key, browser storage value or hardware identifier is persisted. Availability depends on the call site. |
| `requestId`, `service`, `route`, `method` | Optional actual request context. Next ingress replaces caller-supplied internal audit headers with a generated UUID and a static allowed route/method. Issuer uses its own generated UUID in AsyncLocalStorage; it never adopts public forwarding/correlation headers. Dynamic ceremony selectors, query strings and token-bearing URLs are excluded from routes. |
| `networkProvenance` | `unavailable`: the writer has no independently verified client/proxy network provenance. Forwarded IPs, cf-connecting-ip, request IDs and trace headers from clients do not become network evidence. Existing source-based rate-limit policy remains a separate ingress concern. |
| `beforeState`, `afterState` | Optional allowlist: boolean enabled and ACTIVE/INACTIVE/BLOCKED/PENDING_ACTIVATION accountStatus. The account-state action records the resulting state. Unknown prior state stays absent. |
| `metadata` | Scalar allowlist after recursive secret redaction. No private body, arbitrary object or raw exception is stored. |

The additive migration leaves old rows byte-for-byte intact, tagged `schemaVersion=0`, `category=LEGACY`, `severity=UNKNOWN` with new optional fields null. It does not infer historical roles, request IDs or device identity. Old rows remain searchable by event/resource/ID/time; legacy actor references are displayed safely but cannot be searched by the new actorRef column until a separately reviewed historical migration exists. No backfill is performed by this change.

An absent request/session/device/service/build-version value means unavailable, not an invented value. Issuer context propagates across its asynchronous request work. Hub route-level calls carry sanitized ingress context and Server Actions run their awaited work in that request context, including transactional service writers. Standalone service functions called without a request do not fabricate correlation. A request ID is a local correlation identifier, not a W3C trace or a cross-service trace guarantee.

## Metadata limits and redaction

Persistence allows static source, verification factor, safe scope/error/status labels, remembered-browser/configuration-change booleans, bounded counts and digest references (request, ceremony, device, target, user, connection, client and invitation). Request method/route/ID come only from the internal ingress context. Sensitive keys may retain the constant `[REDACTED]` marker for compatibility; their values are discarded. Other unknown keys are dropped. Raw emails, URL-shaped strings, credential assignments, authorization schemes, opaque credential-shaped material, private keys and JWTs are redacted recursively before allowlisting. The generic sanitizer inspects at most 12 keys per object, 12 array items, depth 4 and 64 nodes; strings are bounded to 80 characters and inspection to 800 characters. Persisted metadata contains scalar fields only.

The browser view applies the same allowlist again to historical metadata and shows static action/event labels, never free-form historical messages. Before/after state receives its own allowlist on both write and read. There is no SQL or unrestricted JSON search UI.

## Event coverage and failure policy

| Boundary | Events and policy |
| --- | --- |
| Login/logout | Existing successes/failures and revocations; login CSRF/origin denials, verification failures and rate-limit denials. Login success audit remains required before a session cookie is returned. Logout and denial audit are best effort, so audit unavailability does not prevent revocation or turn an already refused request into a general outage. |
| Email/TOTP/recovery/devices | Existing transactional ceremony verification, TOTP enrollment/removal/recovery, recovery-code rotation, trusted-device revocation and recovery request/verification/approval/consumption events. Account security and recovery action boundaries record rejected proofs with generic reasons. Plaintext codes, secrets, user input and exception messages are excluded. |
| ADMIN controls | Existing transactional credential/elevation/account/grant/connection mutation events remain required within the mutation transaction. Guard denials record CSRF/role; rejected administrative proof and mutation boundaries record generic failures. A failed audit append in these transactions rolls back the critical state change. |
| OIDC | Existing required authorization/token success/rejection gates; added interaction start/completion/denial and source-limit denials. Interaction completion uses the required response audit gate. Rejected/observed requests use best effort. Provider token/authorization gates retain their previous failure policy. |
| Cloudflare Access | Ingress records missing/invalid/misconfigured denials. Successful Access JWT checks do not produce ACCESS_JWT_VALID on every request. No assertion or raw forwarding value is stored. |
| Maintenance | Existing session/audit cleanup summaries remain bounded. Empty cleanup does not fabricate an event on a virgin database. Maintenance inserts use the same normalized envelope without reading back audit rows. |

The audit is not an SMTP-delivery ledger, a hardware inventory or a recording of every internal function call. Transport delivery diagnostics remain in the existing minimized outbox/worker mechanism. Anonymous denied attempts can lack actor references; service calls without a request context can lack correlation. These absences must not be interpreted as evidence that an action did not occur. Best-effort failures emit only a generic diagnostic, without raw database or security errors. Required writers propagate failure to their existing transaction/response gate.

## Investigation and time policy

The pt-BR ADMIN view uses server-side prefix search over whitelisted event/action, actor reference, resource and event ID fields. Exact filters combine type/category/result/actor class or reference/resource/event ID and a date interval. Search excludes email, message, JSON payload and credentials. Inputs reject repeated/ambiguous values, unsupported enums, unsafe characters, invalid dates and excessive pages. SQL LIKE underscore characters are escaped. Prisma parameterized filters are used throughout.

Each page selects at most 51 rows and renders 50; the extra row determines whether another page exists. Pages are bounded to 1–1000, with deterministic createdAt/id ordering in either direction and filter-preserving URLs. Counts describe the current page, not an invented total. Offset paging can shift under concurrent inserts or retention; narrower filters and exact event IDs support investigation. No P2025 claim follows from pagination: the tested Prisma version returns an empty result for a missing cursor.

Date intervals require both dates, cover at most 366 inclusive calendar days and interpret the final date inclusively in America/Porto_Velho. The shared server-safe formatter explicitly uses that zone, pt-BR, 24-hour output and a visible UTC−4 suffix. The view also names the IANA zone. Audit, credential/recovery dates, active elevations, remembered devices and active sessions use the shared formatter. Persisted instants, expiration calculations and comparisons stay UTC. No browser-local time zone is inferred.

## Retention, privacy and operations

Pseudonymous references are still personal data when linkable to an account. Access is restricted to authorized ADMIN investigation and the existing operational roles. Use the data only for identity/security investigation and proportionate incident handling. Do not export or share audit data merely because the UI is available. The configurable retention remains 180 days by default, bounded to 1–3650 days; the operator must choose a period supported by the actual purpose and obligations. No legal compliance certification is implied. Expiry deletion uses the maintenance credential and must remain separate from normal application privileges.

Indexes cover timestamp/id ordering and category/result/actor/resource with timestamp/id, plus request ID and action. Query plans and throughput on a production-sized history have not been load-tested. The additive columns and index creation require the normal reviewed migration/deployment window. Production still requires exact accepted source, backup/restore validation and the configured remote-host gates. Local disposable migration/query tests do not authorize a production change.
