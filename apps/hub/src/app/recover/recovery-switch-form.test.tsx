import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { RecoverySwitchForm } from "./recovery-switch-form";

test("legacy link switch remains disabled in SSR until the shared Web Lock callback hydrates", () => {
  const prior = Object.getOwnPropertyDescriptor(globalThis, "React");
  Object.defineProperty(globalThis, "React", { configurable: true, value: React });
  try {
    const markup = renderToStaticMarkup(<RecoverySwitchForm
      csrf="csrf-test"
      csrfFieldName="csrfToken"
      requestId="legacy-request"
    />);
    assert.match(markup, /name="csrfToken" value="csrf-test"/u);
    assert.match(markup, /name="requestId" value="legacy-request"/u);
    const submit = markup.match(/<button\b[^>]*type="submit"[^>]*>/u)?.[0];
    assert.ok(submit, "legacy switch submit control must exist");
    assert.match(submit, /\bdisabled=""/u,
      "SSR must not permit native submit before navigator.locks client handler exists");
  } finally {
    if (prior) Object.defineProperty(globalThis, "React", prior);
    else Reflect.deleteProperty(globalThis, "React");
  }
});
