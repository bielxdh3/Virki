import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

test("native ADMIN edge compose and nginx enforce fail-closed mTLS, CIDR allowlist, SNI rejection, and edge proof", () => {
  const composePath = path.join(repositoryRoot, "infra", "docker-compose.native-edge.yml");
  const nginxPath = path.join(repositoryRoot, "infra", "nginx", "hub-native-edge.conf");
  const allowlistPath = path.join(repositoryRoot, "infra", "nginx", "allowlist.conf.example");

  assert.equal(existsSync(composePath), true, "Missing infra/docker-compose.native-edge.yml");
  assert.equal(existsSync(nginxPath), true, "Missing infra/nginx/hub-native-edge.conf");
  assert.equal(existsSync(allowlistPath), true, "Missing infra/nginx/allowlist.conf.example");

  const compose = readFileSync(composePath, "utf8");
  const nginx = readFileSync(nginxPath, "utf8");
  const allowlist = readFileSync(allowlistPath, "utf8");

  // Compose override must explicitly opt out of Access JWT, require edge secret, and run hardened nginx
  assert.match(compose, /CLOUDFLARE_ACCESS_JWT_REQUIRED:\s*"false"/u);
  assert.match(compose, /VIRKI_HUB_PERIMETER_MODE:\s*"native"/u);
  assert.match(compose, /VIRKI_NATIVE_EDGE_PROOF_SECRET:\s*\$\{VIRKI_NATIVE_EDGE_PROOF_SECRET:\?/u);
  assert.match(compose, /hub-edge:/u);
  assert.match(compose, /image:\s*nginx:1\.27-alpine@/u);
  assert.match(compose, /read_only:\s*true/u);
  assert.match(compose, /cap_drop:\s*\[ALL\]/u);
  assert.match(compose, /security_opt:\s*\[no-new-privileges:true\]/u);

  // Nginx edge must enforce TLS 1.3, reject unknown SNI, require client cert (mTLS), deny by default, and sanitize headers
  assert.match(nginx, /ssl_protocols\s+TLSv1\.3;/u);
  assert.match(nginx, /ssl_reject_handshake\s+on;/u);
  assert.match(nginx, /ssl_verify_client\s+on;/u);
  assert.match(nginx, /ssl_client_certificate\s+/u);
  assert.match(nginx, /include\s+\/etc\/nginx\/conf\.d\/allowlist\.conf;/u);
  assert.match(nginx, /proxy_set_header\s+X-Forwarded-Proto\s+https;/u);
  assert.match(nginx, /proxy_set_header\s+X-Forwarded-Host\s+\$host;/u);
  assert.match(nginx, /proxy_set_header\s+Cf-Access-Jwt-Assertion\s+"";/u);
  assert.match(nginx, /proxy_set_header\s+X-Virki-Native-Edge-Proof\s+/u);

  // Default allowlist example must fail closed
  assert.match(allowlist, /^\s*deny\s+all;/mu);
});
