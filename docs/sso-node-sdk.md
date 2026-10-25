# Virki confidential Node.js / TypeScript OIDC SDK

This is an **RP-side** library. Virki remains the identity provider. The relying project creates and revokes its **own** sessions and authorizes its own business actions. This SDK cannot grant project access, bypass Virki, or instantly revoke independently issued RP sessions.

## Runtime and protocol contract

- Package: `@virki/oidc-node`, ESM JavaScript and `.d.ts`, Node **22.13+** (`<23`), npm 10. `npm run build -w @virki/oidc-node` emits `dist/`; the published export does **not** require `tsx`, browser bundlers or a TypeScript runtime.
- Dependency: pinned `openid-client@6.8.8`; no custom OIDC cryptography. The client enables `enableNonRepudiationChecks` so **ES256 ID Token signatures are verified against JWKS**, including key rotation, rather than relying only on the TLS token exchange.
- Trusted issuer `https://portal.biel.dev.br`, pinned exact discovery `issuer`, HTTPS same-origin token/authorization/JWKS URLs. Do not accept arbitrary users' issuer URLs or discovery endpoints. Client authentication is **`client_secret_basic`**, never `client_secret_post`.
- Authorization Code + **PKCE S256**, high-entropy `state`/`nonce`, `openid profile email`, exactly registered HTTPS callback. Existing Virki provider authorization codes last 90 seconds, access tokens 300 seconds. The RP transaction can remain pending up to 10 minutes to accommodate MFA; the provider still enforces the shorter code lifetime.
- OIDC ID Token `iss`, `aud` (with `azp` for multiple audiences), `exp`, `iat`, `nonce`, `auth_time` and claims types are checked in addition to the library's ES256/JWKS validation. `amr` and `acr` are carried through, **not inferred or upgraded**. A USER passkey alone is `amr: ["webauthn"]`, `acr: urn:virki:loa:1`; it does not authorize ADMIN or silently grant `loa:2`.
- The SDK does not implement refresh tokens, introspection, SPA/public clients, dynamic registration, an OIDC provider, global logout or instantaneous grant revocation.

## Registration and entry

An administrator uses **Hub → Conexões** to register the RP's exact HTTPS origin and the full callback URI, enabling the confidential client and keeping the issued secret in the RP's server-side secret manager. **Hub → Acessos** then grants individual active USER accounts. Disabled clients, absent or revoked grants and inactive users are rejected by the Virki issuer at authorization; the SDK validates what the issuer returns and does not assume possession of a browser link is authorization. Never inspect or modify live client records from test code.

```ts
import { createVirkiOidcClient, randomRpSessionId } from "@virki/oidc-node";
import { EncryptedPostgresTransactionStore } from "@virki/oidc-node/postgres-store";
import { Pool } from "pg"; // install pg in YOUR RP, not required by the SDK

const pool = new Pool({ connectionString: process.env.RP_DATABASE_URL });
const key = Buffer.from(process.env.RP_FLOW_ENCRYPTION_KEY_HEX!, "hex"); // exactly 32 bytes
const store = new EncryptedPostgresTransactionStore(pool, key);
const client = await createVirkiOidcClient({
  issuer: "https://portal.biel.dev.br",
  clientId: process.env.RP_CLIENT_ID!,
  clientSecret: process.env["RP_CLIENT_SECRET"]!,
  redirectUri: "https://project.example.invalid/callback", // registered EXACTLY
  store
});

// GET /login: reuse one random browser-binding __Host- RP cookie across tabs
const binding = randomRpSessionId();
const { url } = await client.beginLogin(binding);
// Save ONLY binding in an HttpOnly Secure SameSite=Lax Path=/ host-only cookie.
// HTTP 303 Location: url.href; no tokens or verifier in this URL.

// GET /callback: read the exact browser-binding cookie from this RP host
const { identity, serverOnly } = await client.completeCallback(callbackUrl, binding);
// Write a *new* RP-local server-side session for identity.sub.
// Set another random __Host- RP session cookie, never Virki's session cookie.
// Keep serverOnly.accessToken server-side ONLY if you need userinfo/revocation.
// The example intentionally does not persist serverOnly.
```

The code above is an integration sketch; use the runnable `examples/oidc-node-rp/server.mjs` for a small HTTPS server. It demonstrates `/login`, `/callback`, `/account`, `/logout`, session-ID rotation and `__Host-` cookies without sending access or ID tokens to browsers. Configure `VIRKI_RP_CLIENT_ID`, `VIRKI_RP_CLIENT_SECRET`, `VIRKI_RP_REDIRECT_URI`, `VIRKI_RP_TLS_KEY`, `VIRKI_RP_TLS_CERT`, optionally `VIRKI_RP_ISSUER` and `VIRKI_RP_PORT`, and run `node examples/oidc-node-rp/server.mjs` **after building** the workspace package. Example state is **single-process in memory and is not production-ready**. Real deployments must provide distributed atomically consumed flow storage, a separately backed RP session store, TLS-terminated canonical Host validation, CSRF controls and operational key rotation. Do not disable TLS for convenience.

## PostgreSQL transaction storage (RP-owned database)

Run the following DDL against the relying project's **own** PostgreSQL database, **not** Virki's, not production without the RP operator's approval. `TIMESTAMPTZ` is mandatory: different DB/server time zones must not change expiry semantics.

```sql
CREATE TABLE IF NOT EXISTS "VirkiOidcLoginFlow" (
  "stateHash" CHAR(64) PRIMARY KEY,
  "ciphertext" TEXT NOT NULL,
  "expiresAt" TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS "VirkiOidcLoginFlow_expiresAt_idx"
  ON "VirkiOidcLoginFlow" ("expiresAt");
```

`EncryptedPostgresTransactionStore` stores only SHA-256 of `state` plus an AES-256-GCM authenticated, randomized ciphertext containing nonce, PKCE verifier, exact issuer, client ID, redirect and hashed browser binding. A **single** parameterized `DELETE WHERE stateHash=$1 RETURNING ...` is the only consumption primitive, so two processes cannot both redeem a callback. The encryption key must come from a separate RP secret store (32 random bytes), never from a browser, source code, log or the database. If the key changes before pending flows expire, in-flight flows fail closed. Clean expired rows periodically using RP-controlled `DELETE FROM "VirkiOidcLoginFlow" WHERE "expiresAt" <= now()`; do not treat this cleanup as the consume primitive. Keep database roles restricted to the RP's table.

`MemoryTransactionStore` is strictly a test/development option. Its atomicity is **per Node process only**; using it in replicated or clustered production can break callbacks and invalidate multi-host replay guarantees. The RP caller must never implement `take()` with a non-atomic `SELECT` followed by `DELETE`.

## Threat model and acceptance gates

| Threat | Required property / evidence |
| --- | --- |
| Login CSRF, stolen state, swapped browser, concurrent tabs | Random RP browser cookie bound to hashed state; independent state per tab; one atomic consume, including OAuth errors and token exchange failures |
| Code interception / injection | S256 verifier and correct callback URI/client binding; code redeemable once for 90 seconds at issuer |
| Redirect phishing, SSRF, issuer mix-up | Pinned trusted HTTPS issuer and discovery authority, exact registered callback, no wildcards or arbitrary metadata authority |
| Forged ID Token, malicious algorithm, stale keys | `enableNonRepudiationChecks`, ES256 pinned, JWKS signature verification, valid `kid`, rotation test with old/new keys, unexpected `iss/aud/nonce/exp/iat` rejected |
| Admin or unrelated user entering project | Virki independently rechecks USER role/account/connection and active explicit `UserProjectGrant`; RP checks `sub` in its OWN authorization context |
| Secret and token leaks | No browser `client_secret`, PKCE verifier, nonce or access/ID tokens; no secrets in query URL, logs, cookies, exception text, traces or response body; `serverOnly` result must never be serialized |
| RP session theft / fixation | Separate RP local session, random 32-byte session ID, hashed server-side storage, `__Host-` + HttpOnly + Secure + SameSite=Lax + Path=/, rotate on login and remove on logout |
| Stale privileges/revocation | Grant/client checks happen on *new* Virki authorization, not ongoing RP requests; RP must revoke its own sessions when its policies change; already-issued tokens last until expiry or supported token revocation |

Test strategy: Node 22 ESM compile+import smoke; atomic memory and encrypted store tests (plus physical disposable PostgreSQL across connections); real openid-client protocol with ephemeral ES256 signatures/JWKS and rotated keys, OAuth wrong-state/nonce/issuer/audience/alg/expiry; runnable RP HTTP fixture tests and isolated HTTPS browser against disposable real Virki issuer when available. Synthetic protocol fixtures do **not** attest real hosted CI, Cloudflare, GHCR, external production clients or actual email delivery. Production remains NO-GO without separate human release gates.
