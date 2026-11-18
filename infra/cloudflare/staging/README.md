# Virki #92: disposable Cloudflared integration proof

The runner owns a new random Docker Compose project on an isolated bridge network with three tiny origins. They serve only `GET /__virki_pr92_probe/<random-nonce>` and refuse requests with an unexpected `Host` or path. Docker never publishes their ports. The runner cleans up only containers/networks labeled with its newly generated Compose project name, including on normal failure.

All modes use the exact production-pinned Cloudflared image **2026.9.3**, UID/GID `65532`, `read_only: true`, `cap_drop: [ALL]`, and `security_opt: [no-new-privileges:true]`. A disposable Node container exercises actual kernel write denial under the same restrictions. Before any Docker mutation, the runner reuses the repository's pinned local Docker Desktop Linux socket admission (or its restricted trusted CI runner case), clears ambient Docker context configuration and rejects remote host overrides. Cleanup errors cause the command to fail. These tests do **not** modify `infra/docker-compose.cloudflare.yml`.

## Run locally without credentials

```sh
node --test scripts/cloudflared-staging.test.mjs
node scripts/cloudflared-staging.mjs --local-only
```

The local mode proves three origin listeners, DNS on the isolated Docker bridge, per-host routing rejection, per-run random nonce matching, the pinned Cloudflared binary starting with hardening, and refusal to write to a read-only container root. It cannot prove Cloudflare edge routing.

## Optional Cloudflare Quick Tunnel proof

```sh
node scripts/cloudflared-staging.mjs --quick-edge
```

The runner creates only temporary `trycloudflare.com` URLs for its fake data, with **no credentials, account/zone DNS changes, production services, volumes, or host ports**. For each mock origin it verifies real HTTPS/TLS and public DNS through the hardened image, then checks route loss after stopping the connector and a new public URL after restarting it. Quick Tunnel ingress differs from a remotely managed named Tunnel; success **never** authorizes editing the functional production Compose file.

## Named Tunnel proof (requires dedicated staging infrastructure)

Only an operator authorized to configure **new isolated staging** Cloudflare resources should prepare a fresh remote-managed Tunnel, with a unique name beginning `virki-pr92-`, and three new proxied CNAMEs belonging to a zone they control. The exact remote-managed ingress rules must be, in order:

| Staging host example | Origin within the disposable Docker network |
| --- | --- |
| `pr92-public.<unique>.staging.<controlled-zone>` | `http://public-site:8080` |
| `pr92-hub.<unique>.staging.<controlled-zone>` | `http://hub:8080` |
| `pr92-issuer.<unique>.staging.<controlled-zone>` | `http://oidc-issuer:8080` |
| *(no host)* | `http_status:404` |

Use a unique `<unique>` label of 6–40 lowercase alphanumeric/dash characters for this run. Each host's **proxied CNAME** must point to `<isolated-tunnel-UUID>.cfargotunnel.com`. Existing `biel.dev.br`, `hub.biel.dev.br`, `portal.biel.dev.br`, PR88-owned infrastructure, production Tunnel and DNS are out of scope. Do not route real apps or authenticating services to these hosts. Do not create the new Tunnel or records from this harness.

Load the following values into the runner process environment through an approved local secret-handling method; **do not put real values in tracked files, command arguments, PR comments or logs**:

| Variable | Purpose |
| --- | --- |
| `VIRKI_PR92_STAGING_TUNNEL_TOKEN` | Fresh dedicated **disposable** remote-managed Tunnel token (never an existing production or PR88 token) |
| `VIRKI_PR92_STAGING_TUNNEL_ID` | UUID of that Tunnel; must equal the ID encoded in the token |
| `VIRKI_PR92_STAGING_ACCOUNT_ID` | Exact 32-hex Cloudflare account tag encoded in the Tunnel token |
| `VIRKI_PR92_STAGING_ZONE_ID` | Cloudflare zone ID containing the three staging DNS records |
| `VIRKI_PR92_STAGING_READ_TOKEN` | Separate short-lived Cloudflare API credential with **Tunnel read** and **DNS read** only; may be revoked after testing |
| `VIRKI_PR92_STAGING_PURPOSE` | Literal `isolated-disposable-issue-92` |
| `VIRKI_PR92_PUBLIC_HOST` | `pr92-public.<unique>.staging.<controlled-zone>` |
| `VIRKI_PR92_HUB_HOST` | `pr92-hub.<unique>.staging.<controlled-zone>` |
| `VIRKI_PR92_ISSUER_HOST` | `pr92-issuer.<unique>.staging.<controlled-zone>` |

Then run:

```sh
node scripts/cloudflared-staging.mjs --named-edge
```

**Fail-closed checks before creating any container:** presence and parseability of the dedicated Tunnel token, matching tunnel/account IDs, explicit disposable purpose, valid per-service hosts sharing the same unique staging suffix, separate read-only API credential, Cloudflare Tunnel metadata (`virki-pr92-` name, remote-managed config), exactly the above ingress rules, and each correctly proxied DNS CNAME. The runner calls only Cloudflare `GET` endpoints and has no mutation API. An inaccessible API, wrong host, extra ingress, missing record, mismatched account or old token stops the test.

On success it verifies all three hosts through real HTTPS and valid public DNS, Cloudflared's running container hardening, loss of the disposable route after connector stop, then recovery after connector restart. Only a **named** Tunnel run with these checks can support a separate decision on future production Compose hardening; this harness itself never changes/deploys production.

Tunnel tokens remain accessible to administrators of the Docker host via container inspection while the disposable connector exists. Never reuse a production Tunnel token. Revoke/delete only the newly created staging resources after verification through the authorized Cloudflare process; the runner deliberately does not alter external state.
