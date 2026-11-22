# Issues #119 / #90 — manual closure criteria after the three merges

This is a **technical acceptance ledger**, not a release authorization. PRs #137, #138 and #139 were merged into `main` (latest merge `6802c432163ef7270cdcedc6d9fb55120698a1f3`). The user alone decides whether and when to click **Close issue**. No automated issue closure, Cloudflare write, production deploy or C1/C4 activation is allowed by this document.

## Issue #119 — security follow-up and edge/OIDC acceptance

| Original requirement | Implementation / evidence | Closure assessment |
| --- | --- | --- |
| Public-site CSP, normal 200 and 404 HTML hydration | #137 merged; nonce CSP and browser regressions pass in DEV/CI | **Code implemented; live edge not deployed/accepted** |
| `X-Powered-By` removal and exact host-bound headers | Suppression versioned in #132/#137; host-specific recovery/issuer controls | **Code implemented; live public-site header still exposed** |
| Anti-CSRF, recovery cookies, sessions, logout, host-specific role selection | #137 tests for action-scoped CSRF, exact origins/hosts; existing PostgreSQL/browser E2E | **DEV evidence; live authenticated validation pending** |
| OIDC discovery, Authorization Code + PKCE S256, state, nonce, grants, CORS/revocation | #137 unit, integration, registered test-client and E2E coverage; legacy discovery grants removed | **DEV evidence; live registered client and identity pending** |
| Cloudflare TLS 1.0/1.1 disabled; 1.2/1.3 accepted on three hosts | **Owner-authorized** API PATCH changed `min_tls_version` from 1.0 to **1.2** on 2026-11-21; independent GET readback confirmed 1.2 and 12/12 read-only OpenSSL handshakes: TLS 1.0/1.1 rejected by peer, TLS 1.2/1.3 accepted at `biel.dev.br`, `hub.biel.dev.br`, `portal.biel.dev.br`. Issue #119 receipt: `#issuecomment-7069964883`. | **PASS — edge TLS requirement satisfied; no need to repeat absent new evidence** |
| Cloudflare SSL mode, Access perimeter, HSTS, DNS/hygiene | `ssl=flexible` remains unchanged. Live Tunnel routes use internal HTTP service URLs while visitor↔Cloudflare↔Tunnel traffic is encrypted; internal network/mount segmentation and origin policy remain unverified. Hub Access 302; DNS owner decisions required | **Operational owner review; do not conflate Flexible with plaintext over the Tunnel nor certify the HTTP private hop without network evidence** |
| Independent review and actual post-change release provenance | PR branch CodeQL/CI passed and latest main CodeQL/CI passed; no proven post-deploy SHA or live authenticated scan | **Production acceptance not demonstrated** |

### Reproducible issue #119 evidence

- Offline unit tests: `node --test scripts/security/issue119-{edge-evidence,headers-evidence,cloudflare-settings}.test.mjs` (alternatively run each file explicitly). All CI calls are offline and require no Cloudflare token.
- Cloudflare settings **offline**: securely retrieve the current zone settings using an owner-authorized read-only API, keep the input untracked, then pipe its JSON to `node scripts/security/issue119-cloudflare-settings.mjs --stdin`. The output contains only whitelisted configuration values. `visitorReady` checks zone TLS minimum >=1.2 plus modern TLS/HTTPS, never asserts a hostname negotiation or actual origin security. `closureReady` remains false without the other receipts.
- TLS **read-only opt-in**: `node scripts/security/issue119-edge-evidence.mjs --live` performs 12 fixed, bounded handshakes. Local OpenSSL errors are *inconclusive*, never a proof of edge rejection.
- Public HTTP **read-only opt-in**: `node scripts/security/issue119-headers-evidence.mjs --live` makes exactly four requests with no redirects/cookies; 200/404 nonce+CSP and powered-by/HSTS are checked. Hub Access redirect and Portal redirect are explicitly **not origin-proof**.
- For module-capable browsers, classic `<script nomodule>` tags are explicitly excluded from the executable-script nonce receipt, even if the boolean HTML attribute has a value. The parser only treats the **exact** `nomodule` attribute as decisive: `data-nomodule` and other names are not equivalent. Data-only, classic nomodule-only and module-positive fixtures were added to the offline suite. An HTTP classifier PASS is still **not a browser hydration proof**.
- HTML `<script type>` values are classified only when they match executable JavaScript MIME **essences without parameters**, since `type="text/javascript; charset=utf-8"` describes a non-executable data block in an HTML attribute. An enforced CSP `sandbox` without a singular, explicit `allow-scripts` token blocks the nonce execution receipt; duplicate/ambiguous sandbox directives fail closed. Neither positive control proves full origin isolation, cookies, login state or successful browser hydration.
- HTML attribute character references in an executable script's `type` (such as `text&#47;javascript`) are conservatively rejected rather than misclassified as inoperative data: browsers decode them, whereas this minimal security tokenizer does not implement the full HTML5 entity table. The browser-recognized comment-end-bang sequence `--!>` is also rejected when it appears before an ordinary `-->` boundary, preventing a wrong-nonce script from disappearing into a fake comment. Both scenarios have explicit negative and ordinary positive tests. No static receipt claims browser-level hydration.
- A document-level `<meta http-equiv="Content-Security-Policy">` can introduce an additional enforced policy not visible in response headers; the static tokenizer conservatively rejects actual `http-equiv` metadata rather than falsely approving a script nonce despite a blocking meta CSP. Ordinary `<meta charset>`/viewport and fake `data-http-equiv` continue to pass, with explicit regression fixtures. A passing header-only receipt never replaces a real-browser hydration test.
- Additional independent review of `cb7e93a` found three P2 false positives: HTML `<meta/http-equiv>` and `<meta /http-equiv>` are real `http-equiv` attributes after HTML5 slash reprocessing; invalid `< style>` is not a raw-text style opener and must never conceal a wrong-nonce `<script>`; nonempty legacy `<script language="python">` can designate inert content despite omitted `type`. The #141 classifier now refuses these ambiguous cases with negative regressions, while ordinary metadata, empty language fallback and normal nonce-bound scripts remain positive controls. No static HTML classifier can establish actual browser hydration.
- Reviewer P2s on `3ca506d` found that `<style.foo>`/`<script.foo>` must not be recognized by a mere word-boundary tag prefix, and `<script nonce="SAFE"/nomodule>` or `/type="application/json"` must not falsely count as executable (HTML5 slash attribute reprocessing). The follow-up requires true tag-name delimiters and rejects unsupported slash syntax in executable script tags, with mixed SAFE/EVIL and inert-language regressions. This is still offline classification, not a full HTML5 parser or browser-hydration proof.
- The executable-type whitelist now covers all WHATWG JavaScript MIME essences, **including legacy `text/jscript` and `text/javascript1.5`**; mixed scripts with any wrong nonce fail closed. Abrupt comment end tags (`<!-->`, `<!--->`) are refused rather than hiding subsequent live scripts. SVG/MathML foreign-content namespaces are conservatively refused until a browser parser can resolve their integration points, avoiding the SVG `<title>` false-positive. These are **offline receipt checks**, not an assertion of browser execution.
- On 2026-11-21, the live public HTML probe returned **FAIL for both 200 and 404**: `unsafe-inline` scripts, no matching nonce CSP, and `X-Powered-By` exposed. Hub 302 was Access-blocked; Portal 307 supplied redirect-only headers. The checks are read-only; no release occurred. The acceptance classifier requires an actual HTML5 document with at least one executable nonce-bound script and rejects multiple CSP policies, invalid/duplicate HSTS ages, spoofed `data-nonce` attributes, and script-like text inside HTML comments, quoted attributes, inert `<template>`/`<noscript>` subtrees, fallback raw text (`<iframe>`, `<noembed>`, `<noframes>`), or non-executable script types (JSON, importmap, speculationrules). The tokenizer consumes raw-text elements *inside* inert subtrees before testing closers, so strings such as `</template>` inside a `<style>` or `<script>` cannot falsely expose an inert script. With scripting enabled, `<noscript>` is handled as a raw-text region up to its first actual closing-tag candidate; any attributed or ambiguous raw-text end-tag syntax is rejected rather than skipped, so a browser-consumed `</noscript data-note="end">` cannot conceal a live script with a bad nonce. These fragments never count as hydration; legitimate non-executable JSON data scripts do not falsely require a nonce. It does **not** replace actual browser hydration tests.
- A later independent CSP3 review reproduced a nonceable-attribute false PASS for a script with `nonce="SAFE"` and an attribute value containing `<script` (likewise `<style`, `<link`, and encoded references): browsers refuse CSP nonce authorization in this context. The classifier now rejects these attribute markers and conservatively refuses any script attribute `&` reference it cannot fully decode. New focused negative and ordinary positive tests pass; isolated Playwright/Edge browser trials executed the normal control and blocked three suspicious variants. Details: `docs/security/2026-11-22-issue119-csp-nonceable-adversarial.md`. This is still **not** a live authenticated-origin acceptance proof.
- Another independent browser reproduction found that `src=""`, whitespace-only `src` or `src="/missing.js"` with correct nonce could generate a static false PASS although the inline script body does not execute and external loading is not proven. The #141 classifier now rejects empty/ambiguous `src`, checks external nonces but **does not count external tags alone as positive executable receipt**, requiring at least one actual nonce-bearing inline script. The three offline #119 suites pass 33/33; actual Next build 200/404 still pass and the browser reviewer confirmed the negative behavior. See `docs/security/2026-11-22-issue119-external-script-evidence.md`. Live hydration and production approval remain separate.
- DNS owner decisions for security contact/security.txt, CAA, DMARC, DNSSEC DS delegation and extended HSTS must be documented separately; these are **not automatically confirmed vulnerabilities** and require valid deployment contacts/policy.
- Follow-up hardening on PR #141 commit `6f0ea77381d218e1d7aa77bc47826eddb7dc1759` removes a suffix-based public-resource exception from the Hub/Portal proxy. Previously, any path ending `.txt`, `.js`, `.svg` and similar extensions bypassed the proxy's session check even inside `/admin` or `/account`; now only the shipped `/hub-mark.svg` has that exception, alongside already-explicit route and Next asset policies. New proxy regressions assert authentication redirects for extension-shaped private paths. No currently exposed private route with such an extension was demonstrated; this closes a preventive route-classification gap, not a claimed live data disclosure. Hosted unit/build and authenticated browser CI must pass on the new SHA before treating the change as verified.
- A further independent check identified a public-metadata false denial: Next serves `apps/hub/src/app/icon.svg` as `/icon.svg`, which the tightened exact whitelist had omitted. The subsequent focused correction explicitly admits `/icon.svg` on public/native surfaces while keeping `/admin/icon.svg`, `/account/icon.svg` and all other extension-shaped private routes authenticated. The same patch replaces an empty native-only offline image test with a real Linux rejection proof for malformed Docker archives despite internally matching untrusted envelope hashes. Details and no-production limitations: `docs/security/2026-11-22-issues90-119-icon-and-native-fixture.md`.
- Additional PR #141 CSP-evidence adversarial probes reproduced three independent false-PASS cases in the bounded HTML classifier: HTML5 `frameset` insertion mode ignores an apparent script; nonempty whitespace-only legacy `<script language>` does not imply an executable JavaScript type; and HTML5 script-data double-escaped `<!--<script>` sequences make the first apparent `</script>` nonterminal, leaving an apparent subsequent nonced script inert. The classifier now rejects these unsupported constructions conservatively. Offline Node regression coverage rose to **30 cases**, passing under both Windows and Linux; this is **not** a substitute for live browser hydration or a production origin security receipt.
- New reviewer P2 on `c1d60b0`: HTML5 script preparation distinguishes an actually empty `type` from nonempty whitespace-only `type=" "`, and the `module` keyword is ASCII case-insensitive **without trimming** (`type=" module "` is not a module script). The previous tokenizer trimmed both before classification and could report a false executable nonce receipt. The fix tests raw exact empty/module attributes separately, trimming only JavaScript MIME essences. A red-to-green regression includes both inert cases plus positive genuine empty, exact module and MIME-essence scripts; the three offline issue #119 suites now pass **31/31**. Static policy classification is still not browser hydration proof.
- **PR #141 HSTS directive validation follow-up (DEV-only):** The HTTP acceptance classifier previously extracted a valid `max-age` substring while ignoring a second valueless `max-age`, repeated `includeSubDomains`, a valued `includeSubDomains`, duplicate unknown directives or malformed unknown tokens. This produced static `pass` results for policies that violate RFC 6797's unique-directive grammar; Chromium explicitly rejects repeated `max-age`/`includeSubDomains` and valued `includeSubDomains`. A new RED test reproduced the false `pass` on `max-age=2592000; max-age`. The classifier now validates case-insensitive uniqueness and narrow token/value syntax across the complete directive list, checks `includeSubDomains` is valueless and requires exactly one valid positive decimal `max-age`. Good quoted-age and optional-policy controls remain accepted. Four targeted offline suites pass **60/60** after the charset follow-up below. No live HSTS setting, Cloudflare policy, or production deployment was changed; this does not attest active edge behavior.
- **PR #141 HTML charset mismatch follow-up (independent browser P2, DEV-only):** The public 200/404 receipt formerly accepted any `text/html` charset (or none) but its HTTP collector always decoded the downloaded bytes with UTF-8. A reviewer reproduced `pass` for an ISO-2022-JP document whose shifted bytes looked like an executable `<script nonce="SAFE">` in the UTF-8 string while the actual ISO-2022-JP browser DOM contained **no script element**. The initial RED regression reproduced the false `pass`, using raw bytes with the ISO-2022-JP escape sequence and the two competing decoders. The collector now decodes with **fatal UTF-8** and the HTML receipt requires an **explicit UTF-8 Content-Type charset**, refusing ambiguous encoding/HTML-sniffing cases. Positive UTF-8 controls and the stylesheet-path acceptance fixture still pass; four offline suites are **60/60 PASS, 0 SKIP**. The browser check used a disposable offline document, not the production public site. This does not prove live hydration, OIDC, Access or origin custody.

**Current closure recommendation #119: NO.** TLS 1.2 minimum and all 12 handshakes are **complete**, not a pending authorization. Remaining: verify the private Tunnel/origin transport boundary, separately authorize deployment of already merged application hardening, then prove 200/404 CSP/headers on the active SHA and controlled authenticated Access/OIDC/recovery evidence. Do not change `ssl=flexible`, Tunnel, DNS or Access without fresh explicit authorization.

## Issue #90 — same-UID BuildKit stage publication TOCTOU

| Original requirement | Implementation / evidence | Closure assessment |
| --- | --- | --- |
| No publication of maliciously substituted stage between inode validation and rename | V23–V35 hardens same-UID reception/post-commit checks; **V36 DEV broker copies into new root-owned inodes under a protected parent; V37 authenticates a synthetic child's PID/UID/GID and single SCM_RIGHTS source FD before protected publication** | **V35 alone remains vulnerable to transient same-UID mutation; V36/V37 validate a distinct principal on synthetic Linux only, not a signed-owner/wired production solution** |
| Private staging and trusted ancestors | V24/V29 root supervisor chain, private 0700 parent, rejected path/symlink and writable ancestor configurations | **DEV tests pass; real UID/directory ownership not attested** |
| Separate process/identity, protected helper | V24/V28 cross-UID fixtures, V30 FD-pinned executable, V31 unconditional root cross-UID trusted helper | **Linux DEV fixtures pass; production supervisor/peer contract not attested** |
| Same-UID process memory/FD access | V32 `PR_SET_DUMPABLE=0` after exec, readback fail-closed; **V33 mandatory positive unprotected same-UID ptrace/procfd baseline followed by protected denials**. V34 pins ptrace attach/wait/detach to a single OS thread. If a host-wide restriction prevents baseline success, CI fails INCONCLUSIVE | **Verified incremental process boundary on tested Linux host only; no same-UID filesystem-name isolation** |
| Directory/symlink/mount and concurrent attacks | V23–V35 multiprocess and same-UID ptrace/procfd tests; **V36 receiver-UID source-write positive + protected-copy negative and 12 source rewrite races; V37 exact kernel peer credentials with one-FD positive / two-FD and wrong-PID negatives** | **Only synthetic UID/authority and peer credentials proven; no real deployed listener, trusted mount propagation or lifetime supervision** |
| Fixed manifest, no-follow verification, RENAME_NOREPLACE, fsync ambiguity and replay fences | V33 post-fsync rehash + V35 pinned stage/parent checks; **V38 post-rename fsync failure remains published-but-unadmitted**; V39 plain claim-key rows had a reviewer-confirmed valid-hex tampering replay P2; **V40 DEV supersedes that weakness with HMAC-linked rows, separate root-only checkpoint and crash-intent fencing before receiving a peer FD**. V41 additionally refuses wrong SO_PEERCRED before permanently consuming a signed permit; V37 rechecks after FD reception. | **V40/V41 still use TEST-DOMAIN V15 permits, not actual signed C4 authority/monotonic rollback store, release admission or operational recovery; production NO-GO** |
| Independent assurance | Prior review on V31 found no P1/P2; new V32 and operational environment require own review and CI receipts | **Not yet independently signed off for production** |

### Issue #90 operational acceptance procedure (separate authorization)

An operator must provision an exclusive receiver identity and document an unbroken supervision/witness interval, not only a one-off `id` output. Evidence must establish: UID/GID dedicated to the receiver for the *whole transfer*, no hostile same-UID process or inherited FD, root-owned launcher and full protected ancestor chain, private 0700 custody, trusted mount namespace/mount propagation and no attacker-controlled bind/FUSE overlay, actual peer/descriptor authentication, successful and denied real transfers, restart/cleanup, replay and ambiguous `fsync` outcomes, and independent reviewer sign-off. Any failed prerequisite must refuse protected publication; never fall back to the insecure V15 direct path. Capture sanitized operator/host/kernel/container revision and tests, not credentials, tokens, unredacted process environment or private file payloads.

Offline reconstruction: `bash scripts/security/issue90-replay-index.sh <pinned-buildkit-checkout>`. It uses a temporary index and checks 19 patch SHA-256 values and intermediate trees without resetting or writing to the checkout. The immutable V38 tree is `86064bbbfdd3c6ebd9dfc6afc3bcd61938bfa10d`, V39 `0acbf322c771b6c00a2803438fda77ac82c81a40`, V40 `50d92e619251b1b4a889f9c6f6d7489ce2a56f6f`, and V41 `bd76aa00d4a62fa04523f4be26692de11dfb229d`. Mandatory synthetic root-supervised fixtures include `VIRKI_V24_RUN_ROOT_FIXTURE=1`, `VIRKI_V36_RUN_ROOT_FIXTURE=1`, `VIRKI_V37_RUN_ROOT_FIXTURE=1`, `VIRKI_V38_RUN_ROOT_FIXTURE=1`, `VIRKI_V39_RUN_ROOT_FIXTURE=1` and `VIRKI_V40_RUN_ROOT_FIXTURE=1`; V41 PID preflight is covered inside the existing V39 real Unix peer fixture. Same-UID positive/negative ptrace/procfd controls run unprivileged. See V33–V41 supplemental documents for guarantees and non-claims.

**Current closure recommendation #90: NO.** V36 demonstrates separate protected publication in DEV, V37 bounded synthetic Unix/SCM_RIGHTS FD handoff, V38 read-only post-fsync recovery observation, V40 an authenticated, non-autorecovering append-only ledger for **synthetic signed V15 permits**, and V41 early SO_PEERCRED refusal before irreversible permit consumption. V39's unauthenticated history is explicitly superseded. V40/V41 do not protect against a compromised root rolling back key+ledger+anchor together and do **not** establish the real C4 monotonic signed-owner authority, verified deployed listener/mount/UID custody, full restart/release recovery or production wiring. The V35 direct rename remains vulnerable; no fallback may activate protected FileSync. Production C1/C4 **NO-GO**. Disabled C1/C4 mitigates exposure but does not satisfy acceptance.

**V44 incremental boundary:** the replay index now covers **22 immutable patches (V23–V44)**. New privileged and ordinary Go regressions explicitly prove that Ed25519 signatures made for C4 V3 owner-approval or candidate-receipt domains cannot be substituted for synthetic V15 owner permits, cannot alter/burn the V40 trusted claim history, and do not prevent a later genuine V15 test permit from being accepted exactly once. This is a DEV-only *negative separation test*, not real C4 release wiring or monotonic independent authority. See the V44 experiment document.

**V45 test-infrastructure refinement:** a pre-existing fake V15 protobuf stream copied generated message state by value, leading Go vet to report `copylocks` and prior invocations to disable that analyzer. V45 uses protobuf-aware reset/merge semantics in the synthetic receiver fixture, preserving packet behavior. The WSL full filesync `-race` suite and **unrestricted Go vet** passed, and hosted CI now enforces unrestricted vet. Immutable patch replay is **23/23 (V23–V45)**. No production functionality or release authority was activated.

**V46 cross-process and crash-state proof:** an incremental test-only root fixture launches six separate Go test processes against the same synthetic V40 permit and ledger and requires exactly one durable acceptance, five refusals and a verified one-record HMAC checkpoint. A separate durably persisted in-flight marker before any log append refuses valid claims across restarts without modifying the empty ledger or trusted genesis checkpoint. WSL `-race` and unrestricted vet passed. The hosted no-skip privileged matrix now selects V46. This is **24/24 immutable patches (V23–V46)**, with no new production release authority or auto-recovery.

**V47 recovery-path mount parity:** the read-only V38 recovery inspector now explicitly uses `RESOLVE_NO_XDEV` for both its protected parent and the final snapshot name, like the root publication broker and independently protected V40 ledger. Root-only tests include a genuine cross-filesystem mount and a **same-device bind mount inside a disposable mount namespace**. An independent Go-overlay experiment confirmed earlier V24 ancestor validation already rejected `/dev/shm` and `/tmp`, but the original V38 final-name open did accept an identical bind-mounted snapshot as `present-requires-owner-reauthorization` (still **not** a release admission). V47 makes the observation's provenance fail closed under the same trust boundary. The patch does not change V23–V46 hashes; replay covers **25/25 (V23–V47)**. No automatic owner reauthorization, signed release or production activation was added. See the V47 experiment document.

**V48 final-fsync recovery fence:** independently reproduced recoverable EIO on V40's final intent-unlink parent fsync previously returned failure yet left no pending marker, permitting a different legitimate synthetic permit on restart despite missing manual reconciliation. V48 introduces a distinct last-fsync fault seam and, after a recoverable error, restores and durably fsyncs the manual-recovery marker before unlocking, preserving the previously committed HMAC log/checkpoint. Focused Linux root `-race` tests now exercise this precise fault with both same and distinct permits refused across subprocess restarts. Persistent storage EIO can prevent any software marker from being durable; this is explicitly not a claim of hardware failure immunity or external monotonic C4 release authority. V23–V47 patches remain unchanged; replay now covers **26/26 (V23–V48)**. See the V48 experiment document.

**C1→C4 Node contract stream/tree parity (PR #141 follow-up):** The non-authorizing
integration candidate previously checked an input stream's SHA-256 against a
caller-provided stream digest without independently recomputing the claimed
BuildKit v2 tree digest. A re-hashed arbitrary or modified stream could pass
that synthetic provenance step with an inconsistent tree claim. The contract
now parses the bounded BuildKit canonical v1 stream, re-hashes its v2 tree
representation, checks entry count, mode, paths and stream exhaustion, and
refuses independently changed tree claims. Regression RED→GREEN and valid
structured synthetic controls run under Linux; the native C4 V3 verifier's
existing independent FD/tree verification remains untouched. This improves
the synthetic C1→C4 evidence agreement only: it **does not** establish a
trusted C1 producer, signed-owner operational authorization, monotonic
root-of-trust, or deployment custody, and cannot close issue #90.

**C1→C4 canonical stream traversal follow-up (post-`fb3f58f`, not deployed):**
An independently self-consistent pair of stream SHA-256 and tree digest was
accepted despite a file whose parent directory never appeared, reordered
sibling basenames, duplicate file paths, or a traversal segment. None can be
emitted by Go's canonical `filepath.WalkDir`, so they must not attest the
BuildKit provenance contract. RED→GREEN regressions now exercise both the
non-authorizing Node contract and the **actual native C4 V3 FD/tree parser**
compiled directly into a disposable test executable. Both reject invalid
paths and order while accepting the legitimate depth-first directory,
regular-file and symlink sequence; the native verifier checks bounded raw
bytes without a second trusted source or a supplied hash shortcut. This is a
real defensive parser correction, **not** a signed-owner approval, independent
anti-root rollback guarantee or operationally provisioned C1→C4 publication.

**Native C4 path-parity follow-up (after `4a7dff6`, DEV only):** The native
stream parser was still more permissive than the Node C1 provenance verifier:
it accepted a self-consistent sealed stream containing filenames with glob
metacharacters, ASCII control characters, malformed UTF-8 sequences (including
surrogate encodings), or paths beyond the 512 UTF-16-unit canonical admission
limit. Independent native C regressions reproduced these extra admissions
before the correction and passed afterward; a valid non-ASCII UTF-8 filename
remains accepted. The C4 validator now enforces the same fail-closed path
grammar with a bounded UTF-8 decoder. This improves native/Node consistency;
it does **not** create signing authority, key custody, protected publication,
or trusted monotonic host state, and no live C1/C4 release was activated.

**Leading UTF-8 BOM path-alias follow-up (post-`c9f14db`, DEV only):** A new
RED→GREEN adversarial case exposed another discrepancy between Node C1 and the
real native C4 stream verifier. `TextDecoder('utf-8', { fatal: true })` drops a
leading UTF-8 BOM (`EF BB BF`) from each independently decoded pathname. In
particular, `EF BB BF 2E` and `EF BB BF 2E 2E` decode to forbidden `.` and
`..` paths in Node, while native C4 had accepted the original byte strings
with internally valid stream/tree digests. Conversely, Node had accepted the
raw bytes for BOM-prefixed regular names after silently deleting that prefix.
Both verifiers now reject an initial pathname BOM *before* any decoding, so
neither can attest an alias between raw bytes and decoded filesystem path.
The non-ASCII UTF-8 filename positive control remains valid. Focused tests
failed on the pre-fix implementation and passed after the fix; native C4
AddressSanitizer/UBSan tests and the Go/C4 bridge also passed. This is a parser
parity fix, not a signed owner release, independently anchored anti-rollback
witness, production host custody, or authorization to activate publication.

**Deep UTF-8 WalkDir path compatibility follow-up (post-`713d2d9`, DEV only):**
Independent audit reproduced a self-consistent Go-style canonical stream that
Node C1 accepts but the native C4 verifier rejected. Six nested components of
70 CJK codepoints each are legal on Linux (210 octets per basename), totaling
425 UTF-16 units but **1265 UTF-8 bytes** in the final relative path. The
native parser had hard-coded `1024`-byte buffers and rejected the stream even
though its Unicode/WalkDir contract allows 512 UTF-16 units. A real C4 test
binary compiled from production C reproduced the denial (**RED exit 15**),
while the Node provenance test accepted the same path/tree layout. C4 now
allocates bounded path buffers of `3 * 512 + 1` bytes (the safe UTF-8 upper
bound for 512 UTF-16 units), retaining bytewise traversal checks and all
UTF-8/security grammar rules. Positive native/Node fixtures also cover a
near-maximum **512-unit / 1526-byte** pathname with individual basenames
under Linux `NAME_MAX`. Both the original 1024-octet denial and new upper
boundary are tested, without relaxing any test or gate. This addresses a
legitimate build-context **availability** defect, not a signature bypass or
permission to sign, publish, merge, deploy, or provision owner authority.

**PR #141 additional C4 JSON semantic-identity correction (DEV-only, post-`f10c7b1`):**
Independent native review reproduced a conflicting JSON interpretation with a
complete V3 candidate evidence/OCI fixture: a `binding` containing both
`"role":"runtime"` and `"Role":"migrator"` passed the C4 parser with
`runtime`, although Go `encoding/json` accepts case-insensitive struct keys
and can decode the latter occurrence as `migrator`. A separate native RED
showed an escaped `\u0072ole` alias diverging from JSON consumers. The C4
evidence tokenizer now fails closed for escaped/non-ASCII object-key names and
case-insensitive duplicate keys **at every object nesting level**, before
interpreting any signed evidence. It limits each object to 128 distinct keys
to bound adversarial comparison work; ordinary string **values** retain JSON
escape support. The new test compiles the actual production C verifier and
confirms valid canonical fields, rejected duplicate/escaped/case-aliased keys,
and nested aliases. RED was reproduced before the relevant patches; GREEN,
Linux native integration and ASan/UBSan passed. These are provenance-contract
fixes, **not** live signed-owner authority or deployment proof.

**PR #141 PostgreSQL/OIDC regrant deadlock correction (DEV-only):**
`grantProjectAccess` previously locked `User` before `ProjectConnection`,
opposite the OIDC adapter's `ProjectConnection`-first token issuance. On a
disposable PostgreSQL instance, a repeat administrative grant and overlapping
connection-first OIDC lock sequence produced SQLSTATE `40P01` (RED), which can
fail the visible ADMIN grant action/token issuance. The admin transaction now
locks `ProjectConnection` before `User`, preserving active-account checks,
late elevation fencing, audit and grant upsert. The bounded concurrent
PostgreSQL regression requires both physical transactions to complete and
the grant to remain active; it passed (GREEN) alongside the adjacent
revocation, connection-deletion and adapter tests. No owner identity,
Cloudflare configuration or production database was modified.

## Fourth PR after merges

### Incremental DEV-only V42 evidence (PR #141)

**V43 follow-up CI portability:** GitHub's Linux runner has `/tmp` on the root filesystem, so the V42 negative cross-mount fixture skipped and triggered the CI's mandatory no-skip policy. V43 preserves all V42 behavior and selects `/dev/shm` (then `/tmp`) only if the candidate's `st_dev` differs from `/`. The WSL root fixture positively rejected the `/dev/shm` destination with `EXDEV`; V43 remains an incremental test-only patch, with 21 SHA/tree replay entries. A host without any separate writable mount still marks the negative as inconclusive and fails the mandatory hosted no-skip gate; this deliberately does not turn absent evidence into a pass.

V42 adds `RESOLVE_NO_XDEV` when pinning the V36/V38 root-owned publication destination parent. The Linux root fixture now verifies that a private destination beneath a separately mounted `/tmp` is rejected with `EXDEV` before publication; positive V36–V38 fixtures run under `/var/tmp` on the tested root filesystem. Privileged WSL V36–V40 root tests, ordinary filesync `-race`, and Go vet passed. The cumulative V42 BuildKit Git tree is `b6231f822efcd8f0be7956c93e189a30418c51b4`; the replay index now checks **20 immutable patches, V23–V42**. This is synthetic DEV evidence only, not real owner authorization, an anti-root-rollback witness or production release.

The issue #119 static HTML evidence classifier now conservatively refuses `<select>` because its simplified tokenizer does not implement HTML5's special insertion mode; previously an ignored raw-text tag in a select could conceal an executable script with a wrong nonce and yield false PASS. The expanded offline Node suite passed **27/27**. This is still not evidence of live browser hydration or deployed CSP.

PR #140 is a separate V29-only review branch, originally for the same ancestor-custody correction in #90. Its V29 patch content is already present verbatim in merged PR #139, which additionally includes V30/V31. #140 is therefore **duplicate work**, not an unmerged security dependency; its conflict with current `main` is expected. Preserve it until a separately authorized administrative decision on closing the redundant PR. Do **not** merge its stale files over the newer V31/V32 chain.

**Decision rule:** both issues remain OPEN until every originally mandatory acceptance criterion is either proved in the correct deployed context or explicitly judged out of scope by the owner with a documented reason. A green PR or `main` CI is not a substitute for the missing edge/operational assurance.
