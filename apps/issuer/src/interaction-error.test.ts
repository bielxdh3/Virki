import assert from "node:assert/strict";
import Koa from "koa";
import test from "node:test";
import { setIssuerSecurityHeaders, setIssuerSensitiveResponseCachePolicy } from "./http-security";
import { readInteractionDetailsOrRespond } from "./interaction-error";

test("interaction lookup failures return a generic HTTP error with issuer security headers", async () => {
  const app = new Koa();
  app.use(async (context) => {
    setIssuerSecurityHeaders(context.res);
    setIssuerSensitiveResponseCachePolicy(context.res, context.path);
    const result = await readInteractionDetailsOrRespond(context, async () => {
      throw new Error("internal provider session details");
    });
    if (result.ok) context.body = { uid: result.value };
  });

  const server = app.listen(0, "127.0.0.1");
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      if (server.listening) resolve();
      else server.once("listening", resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const response = await fetch(`http://127.0.0.1:${address.port}/interaction/abcdefgh`);
    assert.equal(response.status, 400);
    assert.equal(response.headers.get("content-security-policy")?.includes("default-src 'none'"), true);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.doesNotMatch(await response.text(), /internal provider session details/u);
  } finally {
    if (server.listening) {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  }
});
