import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { after, test } from "node:test";
import React from "react";
import { prisma } from "@virki/database";
import { createTestUser, integrationOptions, queuedEmails } from "./integration-fixtures";
import { hashSessionToken, SESSION_COOKIE_NAME } from "./index";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "./csrf";

Object.assign(globalThis, { AsyncLocalStorage, React });
after(() => prisma.$disconnect());

async function requestContext<T>(host: string, token: string, operation: () => Promise<T>, deviceToken?: string): Promise<T> {
  const { workAsyncStorage } = await import("next/dist/server/app-render/work-async-storage.external");
  const { workUnitAsyncStorage } = await import("next/dist/server/app-render/work-unit-async-storage.external");
  const { createRequestStoreForAPI } = await import("next/dist/server/async-storage/request-store");
  const { NextRequest } = await import("next/server");
  const cookie = `${SESSION_COOKIE_NAME}=${token}${deviceToken ? `; virki_device=${deviceToken}` : ""}`;
  const request = new NextRequest(`https://${host}/account/security`, { headers: { host, cookie } });
  const store = createRequestStoreForAPI(request, { pathname: "/account/security" }, { tags: [], expirationsByCacheKind: new Map() } as never, undefined, undefined, undefined);
  return workAsyncStorage.run({ route: "/account/security" } as never, () => workUnitAsyncStorage.run(store, operation));
}
async function session(role: "ADMIN" | "USER") {
  const user = await createTestUser({ role, label: "security-action" });
  const token = randomBytes(32).toString("base64url");
  await prisma.session.create({ data: { userId: user.id, tokenHash: hashSessionToken(token), expiresAt: new Date(Date.now() + 86400000) } });
  return { user, token };
}

test("security data action rejects a surface-role mismatch and missing Hub Access", integrationOptions, async () => {
  process.env.VIRKI_HUB_HOSTNAME = "hub.example.invalid";
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.invalid";
  process.env.CLOUDFLARE_ACCESS_JWT_REQUIRED = "true";
  const { getAccountSecurityData } = await import("../../../apps/hub/src/app/account/security/actions");
  const admin = await session("ADMIN");
  assert.equal(await requestContext("portal.example.invalid", admin.token, getAccountSecurityData), null);
  assert.equal(await requestContext("hub.example.invalid", admin.token, getAccountSecurityData), null);
  assert.equal(await requestContext("unknown.example.invalid", admin.token, getAccountSecurityData), null);
  const user = await session("USER");
  const own = await requestContext("portal.example.invalid", user.token, getAccountSecurityData);
  assert.equal(own?.session.user.id, user.user.id);
});

test("reauth intent survives password redirect, verification navigation and errors", integrationOptions, async () => {
  process.env.VIRKI_PORTAL_HOSTNAME = "portal.example.invalid";
  process.env.VIRKI_PORTAL_URL = "https://portal.example.invalid";
  const user = await session("USER");
  const { POST: login } = await import("../../../apps/hub/src/app/api/login/route");
  const form = new FormData();
  form.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "login" }));
  form.set("email", user.user.email); form.set("password", user.user.password);
  form.set("reauth", "1"); form.set("returnTo", "/auth/abcdefghijklmnop");
  const response = await login(new Request("https://portal.example.invalid/api/login", { method: "POST", headers: { host: "portal.example.invalid", origin: "https://portal.example.invalid", "cf-connecting-ip": "192.0.2.233" }, body: form }));
  assert.equal(response.status, 303);
  const location = new URL(response.headers.get("location")!);
  assert.equal(location.searchParams.get("reauth"), "1");
  const cookie = response.cookies.get("virki_device")?.value;
  assert.ok(cookie, "Login must issue the bound browser capability for the verification page.");
  const { default: page } = await import("../../../apps/hub/src/app/login/verify/page");
  const params = Object.fromEntries(location.searchParams);
  const tree = await requestContext("portal.example.invalid", user.token, () => page({ searchParams: Promise.resolve({ ...params, factor: "totp" }) }), cookie);
  function elements(node: unknown): Array<{ type?: string; props: Record<string, unknown> }> {
    if (!node || typeof node !== "object") return [];
    if (Array.isArray(node)) return node.flatMap(elements);
    if (!("props" in node)) return [];
    const element = node as { type?: string; props: Record<string, unknown> };
    return [element, ...elements(element.props.children)];
  }
  const nodes = elements(tree);
  assert.ok(nodes.some((node) => node.type === "input" && node.props.name === "reauth" && node.props.value === "1"));
  assert.ok(nodes.some((node) => node.type === "input" && node.props.name === "factor" && node.props.value === "email"),
    "Untrusted factor=totp in a URL cannot upgrade the registered EMAIL ceremony.");
  const links = nodes.filter((node) => node.type === "a").map((node) => new URL(String(node.props.href), "https://portal.example.invalid"));
  assert.ok(links.length >= 1);
  for (const link of links) assert.equal(link.searchParams.get("reauth"), "1");
  const { POST: verify } = await import("../../../apps/hub/src/app/api/login/verify/route");
  const bad = new FormData();
  bad.set(CSRF_FORM_FIELD_NAME, createCsrfToken({ scope: "login-verification" }));
  for (const [key, value] of location.searchParams) bad.set(key, value);
  bad.set("code", "wrong-code");
  const failure = await verify(new Request("https://portal.example.invalid/api/login/verify", { method: "POST", headers: { host: "portal.example.invalid", origin: "https://portal.example.invalid", cookie: `virki_device=${cookie}` }, body: bad }));
  assert.equal(new URL(failure.headers.get("location")!).searchParams.get("reauth"), "1");
  assert.ok((await queuedEmails(user.user.email)).length);
});
