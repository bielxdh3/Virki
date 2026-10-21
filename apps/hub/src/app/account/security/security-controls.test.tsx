import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { TotpControls } from "./security-controls";

test("a reloaded pending TOTP setup offers an explicit password-checked restart", () => {
  const testGlobals = globalThis as typeof globalThis & { React?: typeof React };
  const reactDescriptor = Object.getOwnPropertyDescriptor(globalThis, "React");
  testGlobals.React = React;
  try {
    const html = renderToStaticMarkup(React.createElement(TotpControls, { csrf: "test-csrf", active: false, pending: true }));
    assert.match(html, /A chave pendente não pode ser recuperada após recarregar esta página/u);
    assert.match(html, /name="password"/u);
    assert.match(html, /Reiniciar configuração do autenticador/u);
    assert.doesNotMatch(html, /name="code"/u, "the page does not imply that it can confirm a key it no longer has");
  } finally {
    if (reactDescriptor) Object.defineProperty(globalThis, "React", reactDescriptor);
    else Reflect.deleteProperty(globalThis, "React");
  }
});
