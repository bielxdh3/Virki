import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { recoveryPolicyFromMethod } from "./recovery-method-selection";
import { RecoveryRequestForm, type RecoveryRequestMethod } from "./recovery-request-form";

function renderForm(availableMethods: RecoveryRequestMethod[], hasOtherActiveAdmin: boolean, initialMethod?: RecoveryRequestMethod): string {
  const original = Object.getOwnPropertyDescriptor(globalThis, "React");
  Object.defineProperty(globalThis, "React", { configurable: true, value: React });
  try {
    return renderToStaticMarkup(<RecoveryRequestForm
      action={async () => {}}
      csrf="csrf-test"
      csrfFieldName="csrfToken"
      availableMethods={availableMethods}
      hasOtherActiveAdmin={hasOtherActiveAdmin}
      initialMethod={initialMethod}
    />);
  } finally {
    if (original) Object.defineProperty(globalThis, "React", original);
    else Reflect.deleteProperty(globalThis, "React");
  }
}

test("normal password recovery offers all supported independent factor pairs without asking for admin", () => {
  const html = renderForm(["PASSKEY_EMAIL", "TOTP_EMAIL", "PASSKEY_TOTP"], false);
  for (const method of ["PASSKEY_EMAIL", "TOTP_EMAIL", "PASSKEY_TOTP"]) {
    assert.match(html, new RegExp(`value="${method}"`, "u"));
  }
  assert.match(html, /name="csrfToken" value="csrf-test"/u);
  assert.match(html, /name="email"/u);
  assert.doesNotMatch(html, /_ADMIN|name="comment"/u);
  assert.match(html, /disabled=""/u, "the submit button requires an explicit method choice");
});

test("an available different ADMIN allows a single-factor request and optional bounded comment", () => {
  const html = renderForm(["EMAIL_ADMIN", "PASSKEY_ADMIN", "TOTP_ADMIN"], true, "EMAIL_ADMIN");
  for (const method of ["EMAIL_ADMIN", "PASSKEY_ADMIN", "TOTP_ADMIN"]) {
    assert.match(html, new RegExp(`value="${method}"`, "u"));
  }
  assert.match(html, /name="comment" maxLength="300"/u);
  assert.match(html, /outro administrador ativo/u);
  assert.doesNotMatch(html, /value="PASSKEY_TOTP"/u);
});

test("no other active admin never exposes assisted request or comment even if backend lists assisted methods", () => {
  const html = renderForm(["EMAIL_ADMIN", "TOTP_ADMIN"], false);
  assert.doesNotMatch(html, /value="EMAIL_ADMIN"|value="TOTP_ADMIN"|name="comment"/u);
  assert.match(html, /disabled=""/u);
  assert.match(html, /Nenhum método de recuperação está disponível/u);
});

test("server capability list hides unsupported proof combinations", () => {
  const html = renderForm(["TOTP_EMAIL"], true);
  assert.match(html, /value="TOTP_EMAIL"/u);
  assert.doesNotMatch(html, /PASSKEY_|_ADMIN|name="comment"/u);
});

test("server-facing policies bind each selected method to exactly its required independent proofs", () => {
  assert.deepEqual(recoveryPolicyFromMethod("PASSKEY_EMAIL"), { proofs: ["PASSKEY", "EMAIL"], adminReview: false });
  assert.deepEqual(recoveryPolicyFromMethod("TOTP_EMAIL"), { proofs: ["TOTP", "EMAIL"], adminReview: false });
  assert.deepEqual(recoveryPolicyFromMethod("PASSKEY_TOTP"), { proofs: ["PASSKEY", "TOTP"], adminReview: false });
  assert.deepEqual(recoveryPolicyFromMethod("PASSKEY_ADMIN"), { proofs: ["PASSKEY"], adminReview: true });
  assert.deepEqual(recoveryPolicyFromMethod("TOTP_ADMIN"), { proofs: ["TOTP"], adminReview: true });
  assert.deepEqual(recoveryPolicyFromMethod("EMAIL_ADMIN"), { proofs: ["EMAIL"], adminReview: true });
  assert.equal(recoveryPolicyFromMethod("EMAIL_ONLY"), null);
  assert.equal(recoveryPolicyFromMethod("__proto__"), null);
  assert.equal(recoveryPolicyFromMethod({ proofs: ["EMAIL"] }), null);
});
