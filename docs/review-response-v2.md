# BielOS - Response to Review Report v2

## Status

Accepted.

The review correctly identified that the production compose file published hub and public-site ports without binding them to loopback. That could expose the origin directly on hosts with public network interfaces and would weaken the Cloudflare Access security model.

## Answers

### 1. Does the target Linux machine have a direct public IP, or is it behind NAT/router without port-forwarding to 3000/3001?

Current deployment is not intended to expose 3000/3001 directly. The expected BielOS deployment model is:

- services run locally through Docker
- Cloudflare Tunnel is the only intended remote ingress path
- `hub.biel.dev.br` is protected by Cloudflare Access
- BielOS internal authentication remains the second layer

The current/home deployment is treated as NAT/CGNAT-style and should not rely on public host ports.

However, the repository must be safe even if the project later moves to a Linux machine with a public IP or a different network environment. Therefore, binding production debug ports to `127.0.0.1` is mandatory.

### 2. Does the Linux host firewall already explicitly block these ports, or is the plan to rely only on Cloudflare Tunnel?

The project should not rely only on Cloudflare Tunnel or on an assumed external firewall rule.

The corrected baseline is:

1. Docker production ports bind only to `127.0.0.1`.
2. Cloudflare Tunnel reaches services through Docker service names, not public host ports.
3. Any future Linux host with a public interface should also have firewall rules blocking inbound access to `3000/3001` from the internet.
4. `hub.biel.dev.br` must remain protected by Cloudflare Access.
5. BielOS internal auth remains required after Access.

This means the repo-level fix closes the direct Docker bind exposure, while host firewall rules remain defense in depth.

## Actions Taken

- Bound public-site and hub host ports to `127.0.0.1` only.
- Added `npm run status:ports` to inspect published port bindings.
- Updated production, security, operations, and deployment verification documentation.
- Preserved local health checks on `127.0.0.1`.
- Preserved Cloudflare Tunnel routing through Docker service names.
- Removed dead `Session.ipHash` and `Session.userAgent` fields.
- Documented the database migration plan before private data ingestion.
- Documented that the shared production Dockerfile command is overridden by compose services.

## Remaining Accepted Limitations

- Cloudflare Access JWT validation at the origin is still not implemented.
- CSRF protection is still basic.
- Rate limiting is still in-memory.
- Prisma migration workflow must be finalized before non-discardable/private data ingestion.
- Secret scanning and linting are documented follow-up items and are not completed in this phase.
