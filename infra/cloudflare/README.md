# Cloudflare

Cloudflare Tunnel transports HTTPS to the Virki origin. The owner-approved target ADMIN perimeter (`VIRKI_HUB_PERIMETER_MODE=native`) uses only Virki login, mandatory MFA and its own authorization; an external Cloudflare Access application must not intercept this mode. The legacy `access` perimeter still verifies Access JWTs until separately authorized cutover. Tracked files here are templates and isolated staging harnesses, **not** the live production Tunnel or Access policies. See [native cutover and rollback](../../docs/native-admin-cutover.md).

No tunnel IDs, tokens, account IDs, or access policies should be committed here.
