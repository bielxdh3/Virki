# Issue #119 — external acceptance evidence to collect after separate owner approval

**Status update — 2026-11-22:** The visitor TLS remediation described in historical
step 1 has **already been performed under separate owner authorization**.
The Cloudflare minimum was raised to TLS 1.2 on 2026-11-21 and an independent
read-only setting GET plus 12 version-specific OpenSSL handshakes confirmed
TLS 1.0/1.1 refusal and TLS 1.2/1.3 acceptance on all three hosts (issue #119,
receipt `#issuecomment-7069964883`). Do **not** repeat the configuration write.
The unchanged `ssl=flexible` setting does not establish the private
Tunnel-to-origin trust boundary. The 2026-11-22 read-only HTTP probe still
returns FAIL for **both public 200 and 404**: legacy `unsafe-inline` script
CSP, missing matching nonce, and exposed `X-Powered-By`. No production
deployment, authenticated Access/OIDC check or origin transport attestation
has occurred in PR #141; items 2–5 remain acceptance gates.

**Status: NOT performed and NOT authorized by this PR.** The repository-owned application code has local/hosted CSP, OIDC, CSRF, session, logout, HTTP header and E2E coverage in `issue119-defensive-maintenance-20261120.md`. No Terraform/Cloudflare write, DNS write, account creation, production deployment or authenticated scan is part of this change. Never commit raw ZAP reports, Access tokens, passwords, cookies, client secrets, or issuer responses containing personal data.

1. **Cloudflare visitor TLS — COMPLETED 2026-11-21.** An owner-authorized change set `min_tls_version=1.2`. Independent read-only API verification and 12 host/version-specific OpenSSL handshakes confirmed remote TLS 1.0/1.1 rejection and TLS 1.2/1.3 acceptance across `biel.dev.br`, `hub.biel.dev.br`, and `portal.biel.dev.br`. Do not make another setting change merely to repeat this completed acceptance. `ssl=flexible` remains unchanged: verifying the independent private Cloudflare Tunnel/origin transport and identity boundary is still necessary, and `flexible` alone proves neither origin encryption nor origin plaintext. Any later TLS check must remain read-only, sanitized, and separate from the immutable historical receipt; do not store account IDs, zone IDs or secrets in this repo.
2. **Post-deploy application vs edge.** Only after a separately authorized rollout of #137/#138 and verified commit-to-artifact provenance, run `node scripts/security/issue119-headers-evidence.mjs --live`. This opt-in, read-only probe issues exactly four bounded unauthenticated requests without following redirects: `GET /` and `GET /__virki_issue119_not_found_20261121__` on `biel.dev.br`; `HEAD /` on each of `hub.biel.dev.br` and `portal.biel.dev.br`. It emits only sanitized pass/fail evidence, never HTML, cookies, tokens, redirect targets or error details. It requires 200 **and** 404 public HTML with a matching script CSP nonce, no `unsafe-inline` script policy, no `X-Powered-By`, and positive HSTS. Hub Access 302 is explicitly `blocked-by-access`, **not** proof of the origin; Portal redirect headers likewise cannot prove a logged-in response. Save the result with observed deployment SHA and timestamp; compare to the merged code. The 2026-11-21 pre-deploy edge still served legacy CSP and `X-Powered-By`; a Git merge alone does not update production.
3. **Authenticated controlled OIDC/recovery.** With separately authorized, disposable registered client and test identity, an isolated mailbox/OTP and an authorized Cloudflare Access test principal (if Hub is in scope), use the existing PostgreSQL/browser integration cases as a replay blueprint. Prove code+PKCE S256, state/nonce binding, exact redirect URI, code expiry/replay, revoked token/session after logout, session rotation on login, CSRF token invalid/missing/wrong action/foreign Origin on recovery, and ADMIN/USER host isolation. Save **redacted** pass/fail summary and revision IDs, not issued tokens or raw logs. Without these identities, mark the live test BLOCKED, not PASS.
4. **DNS/edge governance decisions.** Obtain a *verified* security contact before publishing `security.txt`; document authorized policy owners for CAA issuer restrictions, DMARC enforcement, DNSSEC DS delegation, and longer HSTS or `includeSubDomains`/preload. Review all subdomains and recovery strategy first; do not blindly enable preload or strict DMARC. Record safe DNS/TLS result summaries after owner approval, not guessed addresses or invented contact information.
5. **Acceptance and owner review.** Independent security reviewer must reconcile authorized post-change edge responses with the actual production release, false-positive attribution for Cloudflare Challenge/Access, and any remaining actionable findings. Only then decide closure of issue #119. The historical ZAP counts do not establish confirmed vulnerabilities; absence of scanner findings does not establish security.

**2026-11-22 local #141 follow-up, not deployed:** The public 404 is now a
dedicated, accessible Next page using the external stylesheet. The production
CSP drops `style-src 'unsafe-inline'` without changing script nonces. Real
locally built HTTP 200/404 responses were both 200/404 respectively, with a
matched script nonce, no inline style tags/attributes, an external stylesheet
and `style-src 'self'`; the offline classifier also refuses style unsafe-inline
fallbacks. The disposable production-image smoke now checks both real routes
and these invariants on the published PR SHA when hosted CI runs. A green local
receipt is not a public/deployed receipt; the production edge still needs a
separately authorized rollout, provenance and independently verified results.

**2026-11-22 CSS subdirective adversarial correction (PR #141, not deployed):**
An isolated Edge/Playwright response with valid nonce-bound inline JavaScript,
`style-src 'self'` and overriding `style-src-elem 'none'` demonstrated an actual
CSS blocking violation: the script executed, the external stylesheet did not
apply, yet the old static HTTP classifier returned PASS. The classifier now
refuses a `style-src-elem` override unless it grants exactly the same-origin
external stylesheet, and conservatively allows `style-src-attr` only when it
explicitly denies inline attributes. Negative and positive 200/404 fixtures
passed RED→GREEN. This corrects a false *CSS acceptance receipt*, not an
application XSS or privilege escalation; real deployed styling and transport
still require separately authorized production/browser verification.

**2026-11-22 CSP stylesheet fallback correction (PR #141, not deployed):**
A second independent reproduction showed that checking `style-src-elem` only
when explicitly present was insufficient. With an external same-origin
`/_next/static/css/site.css` link, the prior receipt falsely returned PASS
for `style-src 'none'`, a foreign-only `style-src`, and `default-src 'none'`
when no stylesheet override existed. The fixed evaluator resolves the
effective stylesheet sources in CSP3 order: `style-src-elem`, otherwise
`style-src`, otherwise `default-src`; it requires a single `'self'` source
and refuses missing, blocked or foreign-only policies. It preserves the
separate restrictions on inline styles and style attributes. RED→GREEN
fixtures exercise both public 200 and 404 plus legitimate same-origin
controls. Neither a static green receipt nor a local browser demonstration
proves the deployed public site has been upgraded.

**Independent follow-up: stylesheet markup evidence (same DEV-only PR):**
The CSS source policy alone cannot show that the response actually references
an applicable stylesheet. A second RED→GREEN case now requires at least one
live `<link rel="stylesheet">` in `<head>` with a bounded same-origin
`/_next/static/css/<name>.css` path. It refuses alternate/disabled/print-only,
foreign and non-Next links, ambiguous duplicate or entity-bearing attributes,
unexpected stylesheet SRI, and document `<base>` changes. Active inline
`<style>` elements and `style=` attributes also fail: production `style-src
'self'` would block them. Comments, inert templates and ordinary quoted
attribute contents are not misclassified as active CSS. The fixture helper
models the real Next stylesheet in all positive control documents, and both
production Next 200 and 404 still passed independently in headless Edge with
their external CSS applied and zero CSP console violations. This static
receipt **does not fetch or hash the stylesheet** and cannot prove the asset
exists: actual resource delivery/hydration still requires the separate real
browser/HTTP/OCI runtime gates. No live deployment is attested.

**Disposable OCI CSS fetch gate (follow-up):** The production-image runtime
smoke now derives the verified stylesheet paths from the *same* bounded
HTML/CSP parser, then issues loopback-only GETs to the exact disposable image
for every CSS asset in both its 200 and 404 documents. Any missing/redirected
asset, non-200 response, non-`text/css` content type, or empty content fails
the gate; the parser never supplies an external URL to this HTTP client. A
RED→GREEN production-smoke contract test makes this mandatory. The local
Docker daemon is not available in this environment. The hosted `Validate`
job **passed the actual OCI runtime smoke at `4a033ba`** on 2026-11-22;
that receipt applies only to that SHA, not to subsequent changes or the
public deployed edge.

**2026-11-22 CSP3 script-source override correction (subsequent PR #141
development, not deployed):** The public 200/404 classifier accepted a
`script-src-elem 'nonce-SAFE' https://attacker.invalid` policy as PASS even
though it admitted a foreign script source alongside the legitimate nonce.
It likewise overlooked `script-src-attr 'unsafe-hashes' 'sha256-...'`, which
can admit inline event handlers without the `unsafe-inline` keyword. A new
RED→GREEN test verifies rejection of foreign schemes, hashes and attribute
allowances, as well as additional or duplicate `script-src-elem` nonces,
while preserving narrow nonceable `script-src-elem` and explicit
`script-src-attr 'none'` controls. This is a corrected *static security policy
receipt*, not evidence of a successful application XSS or live deployment.

**2026-11-22 duplicate-directive and sandbox-origin regressions (PR #141,
not deployed):** A reviewer reproduced a policy-acceptance P2: the offline
classifier inspected only the first CSP directive of a name, returning PASS
when it was followed by conflicting or identical `script-src-elem` or
`script-src-attr` declarations. The complete policy is now parsed for
case-insensitive duplicates of **any** directive, including unknown future
directives, and the static receipt refuses all such ambiguity. This does
not misstate browser semantics: later duplicate directives are normally
ignored, not intersected or automatically permission-expanding. Separate
RED→GREEN and actual disposable Microsoft Edge trials proved an enforced
`sandbox allow-scripts` executes nonce scripts in an **opaque** origin (`null`)
and denies cookie access, whereas adding `allow-same-origin` restores the
ordinary origin. The same-origin public CSS/hydration receipt now requires
both sandbox flags when sandbox is present. Neither result proves any live
edge, Access, or OIDC acceptance.

**Explicit boundary:** These documents and offline CI classifiers have no credentials and never modify Cloudflare, DNS, Tunnel, services or production state. Neither opt-in `--live` probe runs from CI or by default. A successful public-header probe does not certify TLS, Access, authenticated OIDC, session security or a live origin release.
