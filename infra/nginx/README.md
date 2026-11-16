# Nginx

Reserved folder for optional reverse-proxy configuration.

Cloudflare Tunnel + Cloudflare Access is the default production ingress layer. For an explicit Cloudflare-Access-free native ADMIN perimeter, `hub-native-edge.conf` and `../docker-compose.native-edge.yml` provide a fail-closed TLS 1.3 + mTLS + CIDR-allowlist edge proxy.
