import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import * as controls from "./security-controls";

const { TotpControls } = controls;

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

test("bulk session revocation asks for deliberate confirmation and current password", () => {
  const component = (controls as Record<string, unknown>).SessionRevocationControl as React.ComponentType<{ csrf: string; otherSessionCount: number; role: string }>;
  assert.equal(typeof component, "function");
  const testGlobals = globalThis as typeof globalThis & { React?: typeof React };
  const reactDescriptor = Object.getOwnPropertyDescriptor(globalThis, "React");
  testGlobals.React = React;
  try {
    const html = renderToStaticMarkup(React.createElement(component, { csrf: "csrf-example", otherSessionCount: 55, role: "USER" }));
    assert.match(html, /<details[\s>]/u);
    assert.match(html, /<summary[^>]*>Encerrar todas as outras sessões<\/summary>/u);
    assert.match(html, /name="csrfToken" value="csrf-example"/u);
    assert.match(html, /<input[^>]*type="password"[^>]*required=""[^>]*name="password"/u);
    assert.match(html, /<input[^>]*type="checkbox"[^>]*required=""[^>]*name="confirmed"/u);
    assert.match(html, /Esta sessão continuará ativa/u);
    assert.doesNotMatch(html, /tokenHash|userAgent|192\.0\.2\./u);
  } finally {
    if (reactDescriptor) Object.defineProperty(globalThis, "React", reactDescriptor);
    else Reflect.deleteProperty(globalThis, "React");
  }
});

test("ADMIN account security does not render the USER bulk revocation control", () => {
  const component = (controls as Record<string, unknown>).SessionRevocationControl as React.ComponentType<{ csrf: string; otherSessionCount: number; role: string }>;
  const testGlobals = globalThis as typeof globalThis & { React?: typeof React };
  const reactDescriptor = Object.getOwnPropertyDescriptor(globalThis, "React");
  testGlobals.React = React;
  try {
    const html = renderToStaticMarkup(React.createElement(component, { csrf: "csrf-example", otherSessionCount: 1, role: "ADMIN" }));
    assert.equal(html, "");
  } finally {
    if (reactDescriptor) Object.defineProperty(globalThis, "React", reactDescriptor);
    else Reflect.deleteProperty(globalThis, "React");
  }
});
