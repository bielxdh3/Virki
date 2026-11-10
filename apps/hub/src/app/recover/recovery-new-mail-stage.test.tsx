import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { RecoveryNewMailStage } from "./recovery-new-mail-stage";

function render(challengeSent: boolean): string {
  const original = Object.getOwnPropertyDescriptor(globalThis, "React");
  Object.defineProperty(globalThis, "React", { configurable: true, value: React });
  try {
    return renderToStaticMarkup(<RecoveryNewMailStage
      requestId="opaque-request" csrf="bound-csrf" csrfFieldName="csrfToken"
      challengeSent={challengeSent} />);
  } finally {
    if (original) Object.defineProperty(globalThis, "React", original);
    else Reflect.deleteProperty(globalThis, "React");
  }
}

test("approved recovery without old-mail proof first requires a new mailbox", () => {
  const html = render(false);
  assert.match(html, /Confirme um novo e-mail antes de trocar a senha/u);
  assert.match(html, /Seus fatores atuais continuam ativos/u);
  assert.match(html, /name="newEmail"/u);
  assert.match(html, /name="csrfToken" value="bound-csrf"/u);
  assert.match(html, /name="requestId" value="opaque-request"/u);
  assert.doesNotMatch(html, /name="newPassword"/u);
  assert.doesNotMatch(html, /name="code"/u, "the new email verification form is shown only after sending a code");
});

test("new mailbox challenge stage supports code confirmation and changing address", () => {
  const html = render(true);
  assert.match(html, /name="newEmail"/u);
  assert.match(html, /name="code"/u);
  assert.match(html, /name="csrfToken" value="bound-csrf"/u);
  assert.match(html, /Trocar endereço ou reenviar código/u);
  assert.match(html, /Confirmar novo e-mail/u);
  assert.doesNotMatch(html, /name="newPassword"/u);
});
