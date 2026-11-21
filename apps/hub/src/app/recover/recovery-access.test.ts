import assert from "node:assert/strict";
import test from "node:test";
import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { hasValidRecoveryActionCsrf, resolveRecoveryExpectedRole } from "./recovery-access";

const env = {
  NODE_ENV: "production",
  VIRKI_CSRF_SIGNING_KEY: "11".repeat(32),
  VIRKI_HUB_HOSTNAME: "hub.example.test",
  VIRKI_PORTAL_HOSTNAME: "portal.example.test"
} as NodeJS.ProcessEnv;

function formWithToken(token?: string): FormData {
  const form = new FormData();
  if (token !== undefined) form.set(CSRF_FORM_FIELD_NAME, token);
  return form;
}

test("recovery actions bind the expected role to the exact surface host", () => {
  assert.equal(resolveRecoveryExpectedRole(new Headers({ host: "portal.example.test" }), "portal", env), "USER");
  assert.equal(resolveRecoveryExpectedRole(new Headers({ host: "hub.example.test" }), "hub", env), "ADMIN");
  assert.equal(resolveRecoveryExpectedRole(new Headers({ host: "portal.example.test" }), "hub", env), null);
  assert.equal(resolveRecoveryExpectedRole(new Headers({ host: "portal.example.test.attacker.invalid" }), undefined, env), null);
  assert.equal(resolveRecoveryExpectedRole(new Headers({ host: "localhost:3000" }), undefined, env), null);
});

test("recovery actions require same-origin and a valid scope-specific CSRF token", () => {
  const token = createCsrfToken({ env, scope: "recovery-request" });
  const sameOrigin = new Headers({ host: "portal.example.test", origin: "https://portal.example.test" });
  assert.equal(hasValidRecoveryActionCsrf(sameOrigin, formWithToken(token), "recovery-request", env), true);
  assert.equal(hasValidRecoveryActionCsrf(sameOrigin, formWithToken(), "recovery-request", env), false);
  assert.equal(hasValidRecoveryActionCsrf(sameOrigin, formWithToken("invalid"), "recovery-request", env), false);
  assert.equal(hasValidRecoveryActionCsrf(sameOrigin, formWithToken(createCsrfToken({ env, scope: "recovery-verify" })), "recovery-request", env), false);
  assert.equal(hasValidRecoveryActionCsrf(new Headers({ host: "portal.example.test", origin: "https://attacker.invalid" }), formWithToken(token), "recovery-request", env), false);
  assert.equal(hasValidRecoveryActionCsrf(new Headers({ host: "portal.example.test", origin: "null" }), formWithToken(token), "recovery-request", env), false);
  assert.equal(hasValidRecoveryActionCsrf(new Headers({ host: "portal.example.test:8443", origin: "https://portal.example.test" }), formWithToken(token), "recovery-request", env), false);
});

test("an external Origin is rejected even when the recovery request has no email or CSRF field", () => {
  const emptyForm = new FormData();
  const external = new Headers({ host: "portal.example.test", origin: "https://attacker.invalid" });

  assert.equal(hasValidRecoveryActionCsrf(external, emptyForm, "recovery-request", env), false);
});
