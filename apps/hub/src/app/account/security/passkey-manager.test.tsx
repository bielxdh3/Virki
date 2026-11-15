import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { PasskeyManager } from "./passkey-manager";

const base = { csrfToken: "test-csrf", initialPasskeys: [], requiresTotp: true };

test("ADMIN passkey copy distinguishes Access and native trust boundaries", () => {
  const access = renderToStaticMarkup(<PasskeyManager {...base} role="ADMIN" nativePerimeter={false} />);
  const native = renderToStaticMarkup(<PasskeyManager {...base} role="ADMIN" nativePerimeter={true} />);

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
  const user = renderToStaticMarkup(<PasskeyManager {...base} role="USER" nativePerimeter={true} />);
  assert.match(user, /Use passkeys no portal/u);
  assert.doesNotMatch(user, /Cloudflare Access|perímetro externo de rede/u);
});

test("ADMIN page sends the server-side perimeter decision to passkey copy", () => {
  const page = readFileSync(new URL("../../admin/security/page.tsx", import.meta.url), "utf8");
  assert.match(page, /nativePerimeter=\{isNativeHubPerimeterEnabled\(\)\}/u);
});
