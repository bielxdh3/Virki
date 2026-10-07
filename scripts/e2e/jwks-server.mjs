import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";

const publicKeys = new Map();
const MAX_BODY_BYTES = 16 * 1024;
const registrationToken = process.env.VIRKI_E2E_JWKS_REGISTRATION_TOKEN;
let diagnosticSequence = 0;

if (!registrationToken) throw new Error("E2E JWKS registration token is required.");

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/cdn-cgi/access/certs") {
    const keys = [...publicKeys.values()];
    const userAgent = request.headers["user-agent"];
    report(`GET source=${safeUserAgent(userAgent)} keys=${describeKeys(keys)}`);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": "application/json"
    }).end(JSON.stringify({ keys }));
    return;
  }

  if (request.method === "POST" && request.url === "/__test__/keys") {
    if (!isAuthorizedRegistration(request)) {
      response.writeHead(403).end();
      return;
    }

    try {
      const jwk = await readJwk(request);
      if (!isTestRsaJwk(jwk)) {
        response.writeHead(400).end();
        return;
      }
      publicKeys.set(jwk.kid, jwk);
      report(`REGISTER kid=${safeKid(jwk.kid)} alg=${jwk.alg} kty=${jwk.kty} use=${jwk.use} count=${publicKeys.size}`);
      response.writeHead(204).end();
    } catch {
      response.writeHead(400).end();
    }
    return;
  }

  response.writeHead(404).end();
});

server.listen(3010, "127.0.0.1");

function report(event) {
  diagnosticSequence += 1;
  process.stdout.write(`[E2E JWKS seq=${diagnosticSequence} time=${process.hrtime.bigint()}] ${event}\n`);
}

function safeKid(value) {
  return typeof value === "string" ? value.replace(/[^A-Za-z0-9._-]/gu, "_").slice(0, 64) : "invalid";
}

function safeUserAgent(value) {
  return typeof value === "string" && /^[A-Za-z0-9._/-]{1,80}$/u.test(value) ? value : "unknown";
}

function describeKeys(keys) {
  if (keys.length === 0) return "none";
  return keys.map((key) => `${safeKid(key.kid)}/${key.alg}/${key.kty}/${key.use}`).join(",");
}

async function readJwk(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
      request.destroy();
      throw new Error("JWK request is too large.");
    }
  }
  return JSON.parse(body);
}

function isTestRsaJwk(value) {
  return value && typeof value === "object" &&
    Object.keys(value).every((key) => ["kty", "kid", "alg", "use", "n", "e"].includes(key)) &&
    value.kty === "RSA" && typeof value.kid === "string" && value.kid.length > 0 && value.kid.length <= 64 &&
    value.alg === "RS256" && value.use === "sig" &&
    typeof value.n === "string" && typeof value.e === "string";
}

function isAuthorizedRegistration(request) {
  const authorization = request.headers.authorization;
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) return false;
  const provided = Buffer.from(authorization.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(registrationToken, "utf8");
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
