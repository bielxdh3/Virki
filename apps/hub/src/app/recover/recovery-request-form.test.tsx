import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { parseRecoveryStartMethod, recoveryMethodFromPolicy, recoveryPolicyFromMethod, RECOVERY_RESTART_METHOD_SUFFIX } from "./recovery-method-selection";
import { RecoveryRequestForm, truncateRecoveryComment, type RecoveryRequestMethod } from "./recovery-request-form";

function renderForm(availableMethods: RecoveryRequestMethod[], hasOtherActiveAdmin: boolean, initialMethod?: RecoveryRequestMethod, hasExistingBrowserRecovery = false): string {
  const original = Object.getOwnPropertyDescriptor(globalThis, "React");
  Object.defineProperty(globalThis, "React", { configurable: true, value: React });
  try {
    return renderToStaticMarkup(<RecoveryRequestForm
      action={async () => {}}
      resumeAction={async () => ({ requestId: null })}
      csrf="csrf-test"
      csrfFieldName="csrfToken"
      availableMethods={availableMethods}
      hasOtherActiveAdmin={hasOtherActiveAdmin}
      initialMethod={initialMethod}
      hasExistingBrowserRecovery={hasExistingBrowserRecovery}
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
  assert.match(html, /name="comment" maxLength="600"/u);
  assert.match(html, /outro administrador ativo/u);
  assert.doesNotMatch(html, /value="PASSKEY_TOTP"/u);
});

test("the same explicit replacement acknowledgement appears for synthetic and real browser pairs only", () => {
  const fresh = renderForm(["TOTP_EMAIL"], false, "TOTP_EMAIL", false);
  const active = renderForm(["TOTP_EMAIL"], false, "TOTP_EMAIL", true);
  assert.doesNotMatch(fresh, /confirmRecoveryRestart/u);
  assert.match(active, /name="confirmRecoveryRestart" value="yes"/u);
  assert.match(active, /substituir a recuperação anterior/u);
  assert.match(active, /outra aba/u);
  assert.match(active, /name="csrfToken" value="csrf-test"/u);
  assert.match(active, /Retomar recuperação anterior/u);
  assert.doesNotMatch(fresh, /Retomar recuperação anterior/u);
  assert.match(active, /type="submit"/u);
});

test("recovery method radios stay disabled until hydration can register their state change handlers", () => {
  const html = renderForm(["TOTP_EMAIL", "EMAIL_ADMIN"], true, undefined, true);
  const radios = [...html.matchAll(/<input type="radio"[^>]*>/gu)].map(match => match[0]);
  for (const method of ["TOTP_EMAIL", "EMAIL_ADMIN"]) {
    const radio = radios.find(tag => tag.includes(`value="${method}"`));
    assert.ok(radio, `the ${method} radio must exist`);
    assert.match(radio, /disabled=""/u, `the ${method} radio must await hydration`);
  }
  // Without this gate a pre-hydration click can check a visible radio without
  // setting React's `method` state, leaving a valid ADMIN restart button disabled.
});

test("only fixed recovery methods accept the explicit restart suffix; malformed variants never authorize replacing a pair", () => {
  for (const method of ["TOTP_EMAIL", "PASSKEY_EMAIL", "PASSKEY_TOTP", "EMAIL_ADMIN", "TOTP_ADMIN", "PASSKEY_ADMIN"] as const) {
    assert.deepEqual(parseRecoveryStartMethod(method), { method, confirmedRestart: false });
    assert.deepEqual(parseRecoveryStartMethod(method + RECOVERY_RESTART_METHOD_SUFFIX),
      { method, confirmedRestart: true });
  }
  for (const candidate of [null, "", "EMAIL_ONLY:confirm-restart", "TOTP_EMAIL:confirm-restart:confirm-restart",
    "TOTP_EMAIL:confirm-restart-extra", "TOTP_EMAIL:confirm-restart ", "__proto__:confirm-restart",
    "TOTP_EMAIL+ADMIN:confirm-restart", " TOTP_EMAIL:confirm-restart"]) {
    assert.equal(parseRecoveryStartMethod(candidate), null);
  }
});

test("review comment counts 300 Unicode characters including emoji, while truncating pasted excess", () => {
  const accepted = truncateRecoveryComment("🙂".repeat(301));
  assert.equal([...accepted].length, 300);
  assert.equal(accepted, "🙂".repeat(300));
  assert.equal(truncateRecoveryComment("x".repeat(301)), "x".repeat(300));
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
  for (const method of ["PASSKEY_EMAIL", "TOTP_EMAIL", "PASSKEY_TOTP", "PASSKEY_ADMIN", "TOTP_ADMIN", "EMAIL_ADMIN"] as const) {
    assert.equal(recoveryMethodFromPolicy(recoveryPolicyFromMethod(method)!), method,
      "restoring a UI hint must map only a fixed independent proof policy");
  }
  assert.equal(recoveryMethodFromPolicy({ proofs: ["EMAIL"], adminReview: false }), null);
});
