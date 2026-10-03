# External OIDC integration

## Client registration

An ADMIN registers an external project under **Hub → Conexões** with a display name, canonical HTTPS origin, exact callback URI list, and enabled state. BielOS creates a confidential OIDC client. Its client secret is shown only at creation/rotation and must be stored by the relying project in its own secret store.

The optional portal entry URL belongs to that external project. It must start the project's Authorization Code + PKCE flow against the BielOS issuer using the registered client ID and secret. It is a direct project entry point, not a BielOS-hosted project page. Do not configure it until the project can complete the OIDC flow. Changing a connection's origin or callback allowlist clears outstanding OIDC artifacts while preserving the user's access grants.

An ADMIN grants each USER entry under **Hub → Acessos**. The portal displays only enabled projects with a live grant. The issuer denies ungranted, disabled, or inactive accounts even when a client already has an authorization interaction in progress.

## Supported protocol

- Issuer: `https://portal.biel.dev.br`
- Discovery: `/.well-known/openid-configuration`
- Authorization Code flow only
- PKCE method: S256, required
- Client authentication: `client_secret_basic`
- OpenID scopes: `openid`, `profile`, `email`
- Claims: subject, verified email state, display name when present, and the session's authentication methods (`amr`) and assurance level (`acr`)
- State: required for every authorization request
- Nonce: required for OpenID authorization requests
- Authorization code lifetime: 90 seconds, one-time use, bound to its client
- Access token lifetime: 300 seconds
- Refresh tokens, client credentials, dynamic client registration, request objects, device flow, and introspection are disabled
- Token revocation is supported

Use an exact registered HTTPS redirect URI. Wildcards, HTTP, userinfo, fragments, and noncanonical callback forms are rejected. The project must validate the token signature, issuer, audience/client, expiry, state, nonce, and PKCE verifier, then create its own local session. Do not forward or share BielOS cookies.

## Consent and session behavior

BielOS authenticates the user on the portal host. A valid portal session is required at interaction completion. The project access grant is checked server-side at authorization, not inferred from a browser link or client claim. BielOS does not receive or enforce project-internal roles.

Sessions authenticated with a password alone report `amr: ["pwd"]` and `acr: "urn:bielos:loa:1"`. Sessions completed with an email or TOTP one-time code report `amr: ["pwd", "otp", "mfa"]` and `acr: "urn:bielos:loa:2"`. Existing sessions retain the conservative password-only values until the user authenticates again.

The ID token `auth_time` uses the central session's successful authentication time. BielOS requires fresh central proof for `prompt=login` and when `max_age` is exceeded; a stale browser session cannot be re-stamped with the current interaction time. Requests for `urn:bielos:loa:2` also trigger fresh login when the active session does not record MFA.

Essential `claims.id_token.acr` requests are honored only when BielOS can satisfy one of its supported values (`urn:bielos:loa:1` or `urn:bielos:loa:2`). Unsupported essential ACR values are denied instead of repeating an interaction without a satisfiable result.

Logout from a project ends that project's local session. OIDC token revocation is available to clients. Central session logout invalidates the BielOS session and prevents later authorization interactions from completing; already-issued access tokens expire within their documented lifetime.

## Secret and signing-key handling

Client secrets are encrypted at rest and cleared with outstanding transient OIDC artifacts when a connection is disabled, removed, or rotated. The issuer's asymmetric signing key and cookie key are kept in private runtime configuration. The issuer exposes public verification keys through its standard JWKS endpoint.

For signing-key rotation, add a new key with a distinct `kid`, publish both public keys during an overlap period, confirm consumers accept the new key, then remove the previous key after all tokens signed by it have expired. Test the complete procedure before applying it in production. Never log or commit private JWK material.
