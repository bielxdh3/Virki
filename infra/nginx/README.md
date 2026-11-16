# Nginx

Reserved folder for optional reverse-proxy configuration.

Cloudflare Tunnel is the production ingress transport layer. Default production Compose keeps Cloudflare Access enabled (`access` mode) until an authorized cutover to `native` mode, where Virki alone authenticates ADMIN requests.
