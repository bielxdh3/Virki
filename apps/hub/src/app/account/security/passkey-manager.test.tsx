import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { PasskeyManager } from "./passkey-manager";

const base = { csrfToken: "test-csrf", initialPasskeys: [], requiresTotp: true };

function renderPasskeys(role: "USER" | "ADMIN", nativePerimeter: boolean): string {
  // The repository's tsx test runner uses classic JSX, unlike Next's app build.
  // Match the existing security-controls.test.tsx harness without changing UI code.
  const globals = globalThis as typeof globalThis & { React?: typeof React };
  const previous = Object.getOwnPropertyDescriptor(globalThis, "React");
  globals.React = React;
  try {
    return renderToStaticMarkup(React.createElement(PasskeyManager, { ...base, role, nativePerimeter }));
  } finally {
    if (previous) Object.defineProperty(globalThis, "React", previous);
    else Reflect.deleteProperty(globalThis, "React");
  }
}

test("ADMIN passkey copy distinguishes Access and native trust boundaries", () => {
  const access = renderPasskeys("ADMIN", false);
  const native = renderPasskeys("ADMIN", true);

  for (const html of [access, native]) {
    assert.match(html, /ADMIN_CREDENTIAL_CHANGE/u);
    assert.match(html, /senha normal e do TOTP/u);
    assert.match(html, /credencial administrativa/u);
  }
  assert.match(access, /Cloudflare Access continua obrigatório/u);
  assert.doesNotMatch(native, /Cloudflare Access continua obrigatório/u);
  assert.match(native, /não exige JWT do Cloudflare Access/u);
  assert.match(native, /perímetro externo de rede/u);
});

test("USER passkey copy is independent of the ADMIN perimeter", () => {
  const user = renderPasskeys("USER", true);
  assert.match(user, /Use passkeys no portal/u);
  assert.doesNotMatch(user, /Cloudflare Access|perímetro externo de rede/u);
});

test("ADMIN page sends the server-side perimeter decision to passkey copy", () => {
  const page = readFileSync(new URL("../../admin/security/page.tsx", import.meta.url), "utf8");
  assert.match(page, /nativePerimeter=\{isNativeHubPerimeterEnabled\(\)\}/u);
});
