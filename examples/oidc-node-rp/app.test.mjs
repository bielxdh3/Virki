import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { test } from "node:test";
import { once } from "node:events";
import { createRpHandler } from "./app.mjs";

async function disposableServer(handler, action) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No loopback address");
  try { await action(`http://127.0.0.1:${address.port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

// Node fetch normalizes the Host header to the physical loopback address;
// native http.request lets the fixture exercise a separately routed HTTPS Host.
async function request(base, path, { headers = {}, method = "GET" } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(new URL(path, base), { method, headers }, (res) => {
      const bytes = [];
      res.on("data", (part) => bytes.push(part));
      res.on("end", () => {
        const body = Buffer.concat(bytes).toString("utf8");
        resolve({
          status: res.statusCode,
          headers: {
            get(name) { return res.headers[name.toLowerCase()] ?? null; },
            getSetCookie() { return res.headers["set-cookie"] ?? []; }
          },
          async json() { return JSON.parse(body); }
        });
      });
    });
    req.once("error", reject);
    req.end();
  });
}

test("RP callback creates an independent host-only session, never exposes tokens or clientSecret", async () => {
  const secret = "server-only-auth-secret";
  const token = ["server", "only", "sensitive", "access", "token"].join("-");
  let bound = "";
  const handler = createRpHandler({
    redirectUri: "https://project.example.invalid/callback",
    client: {
      async beginLogin(browserBinding) {
        bound = browserBinding;
        return { url: new URL("https://portal.biel.dev.br/auth?state=safe-state"), expiresAt: new Date(Date.now() + 60_000) };
      },
      async completeCallback(_url, binding) {
        assert.equal(binding, bound);
        return { identity: { sub: "user-fixture", amr: ["webauthn"], acr: "urn:virki:loa:1", email: "test@example.invalid" }, serverOnly: { accessToken: token } };
      }
    }
  });
  await disposableServer(handler, async (base) => {
    const start = await request(base, "/login", { headers: { host: "project.example.invalid" } });
    assert.equal(start.status, 303);
    const cookies = start.headers.getSetCookie();
    const bindingCookie = cookies.find((entry) => entry.startsWith("__Host-virki_rp_login="));
    assert.ok(bindingCookie);
    assert.match(bindingCookie, /HttpOnly/u);
    assert.match(bindingCookie, /Secure/u);
    assert.match(bindingCookie, /SameSite=Lax/u);
    assert.doesNotMatch(JSON.stringify(cookies), new RegExp(`${secret}|${token}`, "u"));
    const browserCookie = bindingCookie.split(";")[0];
    const callback = await request(base, "/callback?state=safe-state&code=fake-code", { headers: { host: "project.example.invalid", cookie: browserCookie } });
    assert.equal(callback.status, 303);
    assert.equal(callback.headers.get("location"), "/account");
    const sessionCookie = callback.headers.getSetCookie().find((entry) => entry.startsWith("__Host-virki_rp_session="));
    assert.ok(sessionCookie);
    assert.match(sessionCookie, /HttpOnly/u);
    assert.match(sessionCookie, /Secure/u);
    assert.doesNotMatch(`${JSON.stringify(callback.headers)} ${sessionCookie}`, new RegExp(`${secret}|${token}`, "u"));
    const account = await request(base, "/account", { headers: { host: "project.example.invalid", cookie: sessionCookie.split(";")[0] } });
    assert.equal(account.status, 200);
    assert.deepEqual(await account.json(), { sub: "user-fixture", amr: ["webauthn"], acr: "urn:virki:loa:1" });
    const badLogout = await request(base, "/logout", { method: "POST", headers: { host: "project.example.invalid", origin: "https://evil.invalid", cookie: sessionCookie.split(";")[0] } });
    assert.equal(badLogout.status, 403);
    const logout = await request(base, "/logout", { method: "POST", headers: { host: "project.example.invalid", origin: "https://project.example.invalid", cookie: sessionCookie.split(";")[0] } });
    assert.equal(logout.status, 303);
    const noLongerAuthenticated = await request(base, "/account", { headers: { host: "project.example.invalid", cookie: sessionCookie.split(";")[0] } });
    assert.equal(noLongerAuthenticated.status, 401);
  });
});

test("RP rejects wrong Host, callback without binding, and duplicate security cookies", async () => {
  const handler = createRpHandler({ redirectUri: "https://project.example.invalid/callback", client: { async beginLogin() { throw new Error("must not reach"); }, async completeCallback() { throw new Error("must not reach"); } } });
  await disposableServer(handler, async (base) => {
    assert.equal((await request(base, "/login", { headers: { host: "attacker.invalid" } })).status, 421);
    assert.equal((await request(base, "/callback?code=x&state=y", { headers: { host: "project.example.invalid" } })).status, 400);
    assert.equal((await request(base, "/callback?code=x&state=y", { headers: { host: "project.example.invalid", cookie: "__Host-virki_rp_login=a; __Host-virki_rp_login=b" } })).status, 400);
  });
});
