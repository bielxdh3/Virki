import assert from "node:assert/strict";
import test from "node:test";
import { hasValidOidcStateAndNonce, requiresProjectAccessInteraction } from "./authorization-policy";

test("project authorization requires an active account, client, and grant", () => {
  assert.equal(requiresProjectAccessInteraction("account", "client", true), false);
  assert.equal(requiresProjectAccessInteraction("account", "client", false), true, "missing, revoked, and disabled access is denied");
  assert.equal(requiresProjectAccessInteraction(undefined, "client", true), false);
  assert.equal(requiresProjectAccessInteraction("account", undefined, true), false);
});

test("OIDC state is required and nonce is required for OpenID requests", () => {
  const opaqueValue = "0123456789abcdef";
  assert.equal(hasValidOidcStateAndNonce(opaqueValue, opaqueValue, true), true);
  assert.equal(hasValidOidcStateAndNonce(opaqueValue, "", true), false);
  assert.equal(hasValidOidcStateAndNonce("", "", false), false);
  assert.equal(hasValidOidcStateAndNonce(`${opaqueValue}\n`, opaqueValue, true), false);
});
