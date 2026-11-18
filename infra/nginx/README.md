# Nginx

Reserved folder for optional reverse-proxy configuration.

Cloudflare Tunnel is the production ingress transport layer. Production Compose requires an explicit `VIRKI_HUB_PERIMETER_MODE`: `access` preserves the existing Cloudflare Access/JWT requirement until an authorized cutover; `native` uses only Virki ADMIN authentication, with no Nginx login, mTLS, or edge-proof gate. The external Cloudflare Access application must be transitioned separately under the cutover runbook.
